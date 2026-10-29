// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 SpacemiT Co., Ltd.
 *
 * K1 (Saturn) DPU backend for the SpacemiT DRM/KMS driver.
 *
 * The K1 display controller shares the Saturn architecture with the K3 one but
 * has a different register map: DPU_CTL sits at 0x500 instead of 0x3c0, there
 * are twelve RDMA channels instead of four, and three compositors instead of
 * one.  It therefore plugs in through the spacemit_hw_device vtable rather
 * than the K3 field tables.
 *
 * Register access uses the generated bitfield unions in saturn_regs/k1/, which
 * mirror what the vendor BSP uses: a field write is a read-modify-write of the
 * 32-bit word the field lives in.
 */

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/of.h>
#include <linux/of_graph.h>
#include <linux/regmap.h>
#include <linux/types.h>

#include <drm/drm_atomic.h>
#include <drm/drm_blend.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_framebuffer.h>
#include <drm/drm_print.h>

#include "dpu_k1.h"
#include "saturn_regs/k1/reg_map.h"
#include "../spacemit_cmdlist.h"
#include "../spacemit_dmmu.h"
#include "../spacemit_drm.h"

#define DPU_CTRL_MAX_TIMING_INTER1 0xf

/*
 * The K1 backend is a single instance per system, and some of the vtable
 * callbacks only receive a drm_crtc, from which the driver private data is not
 * reliably reachable during a commit.  Cache the hardware description when the
 * pipeline is initialised and use it from there.
 */
static struct spacemit_hw_device *k1_hwdev;

/* True between drm_crtc_vblank_get() in run() and the matching put in the ISR. */
static bool k1_vblank_armed;

/* ------------------------------------------------------------------------- */
/* Register access                                                            */
/* ------------------------------------------------------------------------- */

/*
 * The register map is a union of a bitfield view and a raw word view per
 * block, so a field access is a plain assignment through a volatile pointer.
 * The parameters are prefixed to avoid clashing with the "base" member of
 * struct spacemit_hw_device when the macro is expanded.
 */
#define k1_reg(_k1hw, _k1type, _k1off) \
	((volatile _k1type *)((char *)(_k1hw)->base + (_k1off)))

#define k1_read(_k1hw, _k1type, _k1off, _k1field) \
	(k1_reg(_k1hw, _k1type, _k1off)->_k1field)

#define k1_write(_k1hw, _k1type, _k1off, _k1field, _k1data) \
	(k1_reg(_k1hw, _k1type, _k1off)->_k1field = (_k1data))

/*
 * Stage one whole-word write.  K1's register map exposes the command-list
 * offsets as the named members of the "v" view, so the word index is the
 * member offset inside the block divided by four.
 */
#define k1_queue(_k1type, _k1base, _k1field, _k1cl, _k1val)                 \
	do {                                                                \
		struct cmdlist_regs *__c = (_k1cl);                         \
		const unsigned int __w = offsetof(_k1type, v._k1field) / 4; \
                                                                            \
		if (__c && __w < __c->size) {                               \
			__c->module[__w] = (_k1val);                        \
			__c->flags[__w] = 1;                                \
			__c->base = (_k1base);                              \
		}                                                           \
	} while (0)

/* Same as k1_queue() but takes the module base at run time (TBU banks). */
#define k1_queue_at(_k1base, _k1off, _k1cl, _k1val)              \
	do {                                                     \
		struct cmdlist_regs *__c = (_k1cl);              \
		const unsigned int __w = (_k1off) / sizeof(u32); \
                                                                 \
		if (__c && __w < __c->size) {                    \
			__c->module[__w] = (_k1val);             \
			__c->flags[__w] = 1;                     \
			__c->base = (_k1base);                   \
		}                                                \
	} while (0)

static struct cmdlist_regs *k1_alloc_cl_regs_n(unsigned int nwords);

/*
 * OUTCTRL keeps a second set of latched irq status bits (per output: sof,
 * eof, cfg_eof, cfg_eol, underflow) and shares the level-triggered DPU line
 * with DPU_INT.  Nothing clears them for us, so as soon as one latches the
 * line stays asserted and the CPU drowns in interrupts.  W1C, one whole word;
 * an RMW through a bitfield would ack whatever else raced in.
 */
#define K1_OUTCTRL_IRQ_STATUS	0xc0
#define K1_OUTCTRL_IRQ_BITS(ch)						\
	(BIT(1) | BIT(4) | ((ch) ? (BIT(6) | BIT(9)) : 0))

static void k1_clear_outctrl_irq(struct spacemit_hw_device *hwdev, u8 channel)
{
	writel(K1_OUTCTRL_IRQ_BITS(channel),
	       hwdev->base + OUTCTRL_BASE_ADDR(channel) + K1_OUTCTRL_IRQ_STATUS);
}

/* ------------------------------------------------------------------------- */
/* Static descriptions                                                        */
/* ------------------------------------------------------------------------- */

/* The K1 compositors scan out RGB; YUV is converted by the RDMA CSC. */
/*
 * Only four read channels are wired up for the online compositors; the
 * register map describes twelve, but the rest belong to the offline and
 * writeback paths this backend does not expose.
 */
static const struct spacemit_hw_rdma k1_rdmas[] = {
	{ FORMAT_RGB },
	{ FORMAT_RGB },
	{ FORMAT_RGB },
	{ FORMAT_RGB },
};

static const u32 k1_fbcmem_sizes[] = {
	44544, /* 43.5k */
	35712, /* 34.875k */
};

static const struct dpu_format_id k1_primary_fmts[] = {
	{ DRM_FORMAT_XRGB8888, 8, 32 }, /* RDMA_FMT_XRGB_8888 */
	{ DRM_FORMAT_ARGB8888, 4, 32 }, /* RDMA_FMT_ARGB_8888 */
	{ DRM_FORMAT_XBGR8888, 9, 32 }, /* RDMA_FMT_XBGR_8888 */
	{ DRM_FORMAT_ABGR8888, 5, 32 }, /* RDMA_FMT_ABGR_8888 */
	{ DRM_FORMAT_RGBX8888, 10, 32 }, /* RDMA_FMT_RGBX_8888 */
	{ DRM_FORMAT_RGBA8888, 6, 32 }, /* RDMA_FMT_RGBA_8888 */
	{ DRM_FORMAT_BGRX8888, 11, 32 }, /* RDMA_FMT_BGRX_8888 */
	{ DRM_FORMAT_BGRA8888, 7, 32 }, /* RDMA_FMT_BGRA_8888 */
	{ DRM_FORMAT_ABGR2101010, 1, 32 }, /* RDMA_FMT_ABGR_2101010 */
	{ DRM_FORMAT_RGB888, 12, 24 }, /* RDMA_FMT_RGB_888 */
	{ DRM_FORMAT_BGR888, 13, 24 }, /* RDMA_FMT_BGR_888 */
	{ DRM_FORMAT_RGB565, 22, 16 }, /* RDMA_FMT_RGB_565 */
	{ DRM_FORMAT_BGR565, 23, 16 }, /* RDMA_FMT_BGR_565 */
};

/* ------------------------------------------------------------------------- */
/* Interrupt plumbing                                                         */
/* ------------------------------------------------------------------------- */

static u32 k1_get_irq_bit(enum spacemit_dpu_irq irq_id, int dev_id)
{
	switch (irq_id) {
	case INT_UNDERRUN:
		return DPU_INT_FRM_TIMING_UNFLOW;
	case INT_CFG_RDY:
		return DPU_INT_CFG_RDY_CLR;
	case INT_VSYNC:
		return DPU_INT_FRM_TIMING_VSYNC;
	case INT_EOF:
		return DPU_INT_FRM_TIMING_EOF;
	case INT_REST:
		return DPU_REST_INT_BITS;
	}

	return 0;
}

static u32 k1_get_int_sts(struct spacemit_hw_device *hwdev, int dev_id)
{
	return k1_read(hwdev, DPU_INTP_REG, DPU_INT_BASE_ADDR,
		       v.dpu_int_reg_24);
}

static void k1_clr_int_sts(struct spacemit_crtc *a_crtc, u32 data, int dev_id)
{
	struct spacemit_drm_private *priv = a_crtc->crtc.dev->dev_private;
	struct spacemit_hw_device *hwdev = priv->hwdev;

	k1_write(hwdev, DPU_INTP_REG, DPU_INT_BASE_ADDR, v.dpu_int_reg_14,
		 data);
}

static void k1_irq_enable(struct spacemit_crtc *a_crtc, bool enable)
{
	struct spacemit_drm_private *priv = a_crtc->crtc.dev->dev_private;
	struct spacemit_hw_device *hwdev = priv->hwdev;
	u32 base = DPU_INT_BASE_ADDR;

	/*
	 * Nothing in this driver consumes the frame-timing EOF status, and on
	 * K1 it latches: the DPU line is level triggered, so an EOF that is
	 * enabled but never cleared holds the line high and storms the CPU.
	 * Keep it masked and scrub the latched raw bit in the ISR.
	 */
	k1_write(hwdev, DPU_INTP_REG, base, b.onl2_nml_frm_timing_eof_int_msk,
		 0);
	k1_write(hwdev, DPU_INTP_REG, base, b.onl2_nml_cfg_rdy_clr_int_msk,
		 enable ? 1 : 0);
	k1_write(hwdev, DPU_INTP_REG, base,
		 b.onl2_nml_frm_timing_unflow_int_msk, enable ? 1 : 0);
	if (enable)
		a_crtc->ur_mask_armed = true;
	k1_write(hwdev, DPU_INTP_REG, base,
		 b.onl2_nml_cmdlist_ch_frm_cfg_done_int_msk, enable ? 0xf : 0);
}

static void k1_enable_vsync(struct spacemit_crtc *a_crtc,
			    struct spacemit_hw_device *hwdev, bool enable)
{
	k1_write(hwdev, DPU_INTP_REG, DPU_INT_BASE_ADDR,
		 b.onl2_nml_frm_timing_vsync_int_msk, enable ? 1 : 0);
}

static void k1_core_enable_vsync(struct spacemit_crtc *a_crtc)
{
	struct spacemit_drm_private *priv = a_crtc->crtc.dev->dev_private;
	struct spacemit_hw_device *hwdev = priv->hwdev;

	hwdev->enable_vsync(a_crtc, hwdev, true);
}

static void k1_disable_vsync(struct spacemit_crtc *a_crtc)
{
	struct spacemit_drm_private *priv = a_crtc->crtc.dev->dev_private;
	struct spacemit_hw_device *hwdev = priv->hwdev;

	hwdev->enable_vsync(a_crtc, hwdev, false);
}

static void k1_cfg_ready(struct spacemit_crtc *a_crtc,
			 struct spacemit_hw_device *hwdev)
{
	/* Re-arm the underrun report for the commit that starts here. */
	k1_write(hwdev, DPU_INTP_REG, DPU_INT_BASE_ADDR,
		 b.onl2_nml_frm_timing_unflow_int_msk, 1);
	a_crtc->ur_mask_armed = true;

	k1_write(hwdev, DPU_CTL_REG, DPU_CTRL_BASE_ADDR, ctl2_nml_cfg_rdy, 1);
}

static u32 k1_get_cfg_rdy(struct spacemit_crtc *a_crtc,
			  struct spacemit_hw_device *hwdev)
{
	return k1_read(hwdev, DPU_CTL_REG, DPU_CTRL_BASE_ADDR,
		       ctl2_nml_cfg_rdy);
}

static void k1_sw_start(struct spacemit_crtc *a_crtc,
			struct spacemit_hw_device *hwdev)
{
	k1_write(hwdev, DPU_CTL_REG, DPU_CTRL_BASE_ADDR, ctl2_sw_start, 1);
}

/* ------------------------------------------------------------------------- */
/* Init / teardown                                                            */
/* ------------------------------------------------------------------------- */

static void k1_setup_dma_top(struct spacemit_hw_device *hwdev)
{
	u32 base = DMA_TOP_BASE_ADDR;

	k1_write(hwdev, DMA_TOP_REG, base, img_rr_ratio, 0x10);
	k1_write(hwdev, DMA_TOP_REG, base, round_robin_mode, 0);
	k1_write(hwdev, DMA_TOP_REG, base, pixel_num_th, 4);
	k1_write(hwdev, DMA_TOP_REG, base, rdma_timeout_limit, 0xfffe);
	k1_write(hwdev, DMA_TOP_REG, base, wdma_timeout_limit, 0xffff);
	k1_write(hwdev, DMA_TOP_REG, base, online_rqos, DPU_QOS_NORMAL);
	k1_write(hwdev, DMA_TOP_REG, base, offline_rqos, DPU_QOS_LOW);
	k1_write(hwdev, DMA_TOP_REG, base, online_wqos, DPU_QOS_LOW);
	k1_write(hwdev, DMA_TOP_REG, base, offline_wqos, DPU_QOS_LOW);
	k1_write(hwdev, DMA_TOP_REG, base, cmdlist_rqos, 4);
	k1_write(hwdev, DMA_TOP_REG, base, dmac0_burst_length, 1);
	k1_write(hwdev, DMA_TOP_REG, base, dmac0_rd_outs_num, 8);
}

static void k1_setup_composer(struct spacemit_hw_device *hwdev,
			      struct drm_display_mode *mode, u8 channel)
{
	u32 base = CMP_BASE_ADDR(channel);

	/* Green background, matching the vendor bring-up sequence. */
	k1_write(hwdev, CMPS_X_REG, base, m_nbg_color_B, 0x0);
	k1_write(hwdev, CMPS_X_REG, base, m_nbg_color_R, 0x0);
	k1_write(hwdev, CMPS_X_REG, base, m_nbg_color_G, 0xff);
	k1_write(hwdev, CMPS_X_REG, base, m_nbg_color_A, 0xff);
	k1_write(hwdev, CMPS_X_REG, base, m_ncmps_en, 1);
	k1_write(hwdev, CMPS_X_REG, base, m_noutput_width, mode->hdisplay);
	k1_write(hwdev, CMPS_X_REG, base, m_noutput_height, mode->vdisplay);

	/*
	 * Disable every composer layer.  The bootloader leaves its own layer
	 * bound to an RDMA channel this driver never enables, and a layer that
	 * stays enabled keeps the composer from ever completing a frame.
	 */
	k1_write(hwdev, CMPS_X_REG, base, m_nl0_en, 0);
	k1_write(hwdev, CMPS_X_REG, base, m_nl1_en, 0);
	k1_write(hwdev, CMPS_X_REG, base, m_nl2_en, 0);
	k1_write(hwdev, CMPS_X_REG, base, m_nl3_en, 0);
	k1_write(hwdev, CMPS_X_REG, base, m_nl4_en, 0);
	k1_write(hwdev, CMPS_X_REG, base, m_nl5_en, 0);
	k1_write(hwdev, CMPS_X_REG, base, m_nl6_en, 0);
	k1_write(hwdev, CMPS_X_REG, base, m_nl7_en, 0);
}

static void k1_setup_outctrl(struct spacemit_hw_device *hwdev,
			     struct drm_display_mode *mode, u8 channel)
{
	u32 base = OUTCTRL_BASE_ADDR(channel);
	u16 hsync = mode->hsync_end - mode->hsync_start;
	u16 hbp = mode->htotal - mode->hsync_end;
	u16 hfp = mode->hsync_start - mode->hdisplay;
	u16 vsync = mode->vsync_end - mode->vsync_start;
	u16 vbp = mode->vtotal - mode->vsync_end;
	u16 vfp = mode->vsync_start - mode->vdisplay;

	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, m_n_inheight, mode->vdisplay);
	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, m_n_inwdith, mode->hdisplay);
	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, scale_en, 0);
	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, dither_en, 1);
	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, sbs_en, 0);
	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, split_en, 0);
	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, narrow_yuv_en, 0);

	/* HDMI always runs the free-running (video) output mode. */
	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, cmd_screen, 0);

	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, frame_timing_en, 1);
	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, split_overlap, 0);
	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, hblank, 0);
	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, back_ground_r, 0xfff);
	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, back_ground_g, 0x0);
	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, back_ground_b, 0x0);
	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, sof_pre_ln_num, 0x0);
	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, cfg_ln_num_intp, 0x0);

	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, hbp, hbp);
	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, hfp, hfp);
	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, vfp, vfp);
	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, vbp, vbp);
	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, hsync_width, hsync);
	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, hsp, 1);
	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, vsync_width, vsync);
	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, vsp, 1);
	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, h_active, mode->hdisplay);
	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, v_active, mode->vdisplay);

	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, user, 2); /* RGB888 */

	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, eof_ln_dly, 16);
	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, eof0_irq_mask, 1);
	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, underflow0_irq_mask, 1);
	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, eof1_irq_mask, 1);
	k1_write(hwdev, OUTCTRL_TOP_X_REG, base, underflow1_irq_mask, 1);
}

static void k1_dpu_init(struct spacemit_crtc *a_crtc)
{
	struct spacemit_drm_private *priv = a_crtc->crtc.dev->dev_private;
	struct spacemit_hw_device *hwdev = priv->hwdev;
	struct drm_display_mode *mode = &a_crtc->crtc.mode;
	u8 channel = a_crtc->dev_id;

	k1_setup_composer(hwdev, mode, channel);
	k1_setup_outctrl(hwdev, mode, channel);

	k1_write(hwdev, DPU_CTL_REG, DPU_CTRL_BASE_ADDR, ctl2_video_mod, 0x1);
	k1_write(hwdev, DPU_CTL_REG, DPU_CTRL_BASE_ADDR, ctl2_dbg_mod, 0x0);

	/*
	 * ctl2_timing_inter0 uses its default; ctl2_timing_inter1 is
	 * 2 * ceil(fmclk / fdscclk), clamped to the maximum.
	 */
	k1_write(hwdev, DPU_CTL_REG, DPU_CTRL_BASE_ADDR, ctl2_timing_inter1,
		 DPU_CTRL_MAX_TIMING_INTER1);

	k1_write(hwdev, MMU_REG, MMU_BASE_ADDR, b.cfg_dmac0_rd_outs_num, 16);
	k1_write(hwdev, MMU_REG, MMU_BASE_ADDR, b.cfg_dmac0_axi_burst, 1);

	/* No post-processing on the K1 HDMI path. */
	k1_write(hwdev, OUTCTRL_PROC_X_REG, PP2_BASE_ADDR, m_npost_proc_en, 0);

	k1_setup_dma_top(hwdev);

	/* TODO(k1-port): program the RDMA CSC tables for YUV planes. */
}

static void k1_write_fbcmem_regs(struct drm_plane_state *state, u32 rdma_id,
				 u32 module_base, struct cmdlist_regs *cl);

/* ------------------------------------------------------------------------- */
/* Plane programming                                                          */
/* ------------------------------------------------------------------------- */

/*
 * Program one compositor layer.  The bitfield names are per layer, so the
 * whole sequence is a macro instantiated by the switch below; the raw word
 * write at offset +5 is what the vendor driver does to latch the vertical
 * rectangle, and the hardware needs it in addition to the named fields.
 */
#define K1_COMPOSER_LAYER(_k1id)                                              \
	do {                                                                  \
		void __iomem *__raw =                                         \
			(void __iomem *)((char *)hwdev->base + base +         \
					 (14 + (_k1id) * 8 + 5) * 4);         \
		k1_write(hwdev, CMPS_X_REG, base, m_nl##_k1id##_rect_ltopx,   \
			 crtc_x);                                             \
		k1_write(hwdev, CMPS_X_REG, base, m_nl##_k1id##_rect_ltopy,   \
			 crtc_y);                                             \
		k1_write(hwdev, CMPS_X_REG, base, m_nl##_k1id##_rect_rbotx,   \
			 crtc_x + crtc_w - 1);                                \
		k1_write(hwdev, CMPS_X_REG, base, m_nl##_k1id##_rect_rboty,   \
			 crtc_y + crtc_h - 1);                                \
		k1_write(hwdev, CMPS_X_REG, base, m_nl##_k1id##_color_key_en, \
			 0);                                                  \
		k1_write(hwdev, CMPS_X_REG, base, m_nl##_k1id##_blend_mode,   \
			 blend_mode);                                         \
		k1_write(hwdev, CMPS_X_REG, base, m_nl##_k1id##_alpha_sel,    \
			 alpha_sel);                                          \
		k1_write(hwdev, CMPS_X_REG, base, m_nl##_k1id##_layer_alpha,  \
			 alpha);                                              \
		k1_write(hwdev, CMPS_X_REG, base, m_nl##_k1id##_solid_en, 0); \
		k1_write(hwdev, CMPS_X_REG, base, m_nl##_k1id##_layer_id,     \
			 rdma_id);                                            \
		writel((crtc_y & 0xffff) | ((crtc_x + crtc_w - 1) << 16),     \
		       __raw);                                                \
		k1_write(hwdev, CMPS_X_REG, base, m_nl##_k1id##_en, 1);       \
	} while (0)

static void k1_plane_update_hw_channel(struct drm_plane *plane)
{
	struct drm_plane_state *state = plane->state;
	struct drm_framebuffer *fb = state->fb;
	struct spacemit_plane_state *pstate = to_spacemit_plane_state(state);
	struct spacemit_drm_private *priv = plane->dev->dev_private;
	struct spacemit_hw_device *hwdev = priv->hwdev;
	struct spacemit_crtc *a_crtc = to_spacemit_crtc(state->crtc);
	struct cmdlist_regs *cl_rdma = a_crtc->cl_rdma;
	u32 rdma_id = pstate->rdma_id;

	u32 module_base = RDMA_BASE_ADDR(rdma_id);
	u32 base, val;
	u32 src_w, src_h, src_x, src_y, crtc_w, crtc_h, crtc_x, crtc_y;
	u8 alpha = state->alpha >> 8;
	u32 alpha_sel, blend_mode;
	u8 channel = to_spacemit_crtc(state->crtc)->dev_id;

	src_w = state->src_w >> 16;
	src_h = state->src_h >> 16;
	src_x = state->src_x >> 16;
	src_y = state->src_y >> 16;
	crtc_w = state->crtc_w;
	crtc_h = state->crtc_h;
	crtc_x = state->crtc_x;
	crtc_y = state->crtc_y;

	/*
	 * Layer control: RGB source, no prefix merge, the compositor instance
	 * encoded in bits [15:12], 4-bit alpha and no AFBC.
	 */
	val = 0xf << 17 | channel << 12 | 0xf << 2;
	k1_queue(RDMA_PATH_X_REG, module_base, LAYER_CTRL, cl_rdma, val);
	k1_queue(RDMA_PATH_X_REG, module_base, COMPSR_Y_OFST, cl_rdma, crtc_y);
	k1_queue(RDMA_PATH_X_REG, module_base, LEFT_SCL_RATIO_V, cl_rdma, 0);
	k1_queue(RDMA_PATH_X_REG, module_base, LEFT_IMG_SIZE, cl_rdma,
		 fb->height << 16 | fb->width);
	k1_queue(RDMA_PATH_X_REG, module_base, LEFT_CROP_POS_START, cl_rdma,
		 src_y << 16 | src_x);
	k1_queue(RDMA_PATH_X_REG, module_base, LEFT_CROP_POS_END, cl_rdma,
		 ((src_y + src_h - 1) << 16) | (src_x + src_w - 1));
	k1_queue(RDMA_PATH_X_REG, module_base, LEFT_ALPHA01, cl_rdma, 0);
	k1_queue(RDMA_PATH_X_REG, module_base, LEFT_ALPHA23, cl_rdma, 0);

	k1_write_fbcmem_regs(state, rdma_id, module_base, cl_rdma);

	/* Rotation and pixel format, no UV swap for RGB. */
	val = 0;
	if (state->rotation & DRM_MODE_ROTATE_MASK)
		val = ilog2(state->rotation & DRM_MODE_ROTATE_MASK) & 0x3;
	if (state->rotation & DRM_MODE_REFLECT_MASK)
		val = ilog2(state->rotation & DRM_MODE_REFLECT_MASK);
	k1_queue(RDMA_PATH_X_REG, module_base, ROT_MODE, cl_rdma,
		 val << 7 | pstate->format);

	alpha_sel = fb->format->has_alpha ? 0x1 : 0x0;
	switch (state->pixel_blend_mode) {
	case DRM_MODE_BLEND_PIXEL_NONE:
		alpha_sel = 0x0;
		blend_mode = 0x0;
		break;
	case DRM_MODE_BLEND_COVERAGE:
		blend_mode = 0x0;
		break;
	case DRM_MODE_BLEND_PREMULTI:
		blend_mode = 0x1;
		break;
	default:
		drm_err(plane->dev, "unsupported blend mode %u\n",
			state->pixel_blend_mode);
		blend_mode = 0x0;
		break;
	}

	/* Bind the layer to the RDMA channel and switch it on. */
	base = CMP_BASE_ADDR(channel);
	switch (rdma_id) {
	case 0:
		K1_COMPOSER_LAYER(0);
		break;
	case 1:
		K1_COMPOSER_LAYER(1);
		break;
	case 2:
		K1_COMPOSER_LAYER(2);
		break;
	case 3:
		K1_COMPOSER_LAYER(3);
		break;
	case 4:
		K1_COMPOSER_LAYER(4);
		break;
	case 5:
		K1_COMPOSER_LAYER(5);
		break;
	case 6:
		K1_COMPOSER_LAYER(6);
		break;
	case 7:
		K1_COMPOSER_LAYER(7);
		break;
	default:
		drm_err(plane->dev, "unsupported layer %u\n", rdma_id);
		break;
	}
}

#define K1_LAYER_DISABLE(_k1id)                                         \
	do {                                                            \
		k1_write(hwdev, CMPS_X_REG, base, m_nl##_k1id##_en, 0); \
	} while (0)

static void k1_plane_disable_hw_channel(struct drm_plane *plane,
					struct drm_plane_state *old_state)
{
	struct spacemit_drm_private *priv = plane->dev->dev_private;
	struct spacemit_hw_device *hwdev = priv->hwdev;
	u32 rdma_id = to_spacemit_plane_state(old_state)->rdma_id;
	u32 base;

	if (rdma_id >= 8) {
		drm_err(plane->dev, "unsupported layer %u\n", rdma_id);
		return;
	}

	base = CMP_BASE_ADDR(to_spacemit_crtc(old_state->crtc)->dev_id);
	switch (rdma_id) {
	case 0:
		K1_LAYER_DISABLE(0);
		break;
	case 1:
		K1_LAYER_DISABLE(1);
		break;
	case 2:
		K1_LAYER_DISABLE(2);
		break;
	case 3:
		K1_LAYER_DISABLE(3);
		break;
	case 4:
		K1_LAYER_DISABLE(4);
		break;
	case 5:
		K1_LAYER_DISABLE(5);
		break;
	case 6:
		K1_LAYER_DISABLE(6);
		break;
	case 7:
		K1_LAYER_DISABLE(7);
		break;
	}
}

/* ------------------------------------------------------------------------- */
/* Display MMU                                                                */
/* ------------------------------------------------------------------------- */

/*
 * Point the RDMA at the TBU window and load the page table the shared dmmu
 * code filled in.  The TBU control word is K1 specific: bit 0 enable, bit 1
 * AFBC (never set here), bits [3:2] plane count minus one, [15:8] QoS.
 *
 * The page tables live in the MMU block while the channel registers live in
 * the RDMA block, and a cmdlist register cache carries a single module base,
 * so the TBU writes get a cache of their own; its rows carry absolute word
 * addresses and are appended to the same plane list.
 */
static void k1_rdma_dmmu(struct spacemit_hw_device *hwdev, u8 tbu_id,
			 struct tbu_instance *tbu, struct drm_framebuffer *fb,
			 u32 val, struct cmdlist_regs *cl_rdma,
			 struct drm_plane *plane)
{
	u8 rdma_id = tbu_id / 2;
	u32 module_base = RDMA_BASE_ADDR(rdma_id);
	struct cmdlist_regs *cl_tbu;

	k1_queue(RDMA_PATH_X_REG, module_base, LEFT_BASE_ADDR0_LOW, cl_rdma,
		 lower_32_bits(tbu->tbu_va[0]));
	k1_queue(RDMA_PATH_X_REG, module_base, LEFT_BASE_ADDR0_HIGH, cl_rdma,
		 upper_32_bits(tbu->tbu_va[0]) & 0x3);
	k1_queue(RDMA_PATH_X_REG, module_base, LEFT_BASE_ADDR1_LOW, cl_rdma, 0);
	k1_queue(RDMA_PATH_X_REG, module_base, LEFT_BASE_ADDR1_HIGH, cl_rdma,
		 0);
	k1_queue(RDMA_PATH_X_REG, module_base, LEFT_BASE_ADDR2_LOW, cl_rdma, 0);
	k1_queue(RDMA_PATH_X_REG, module_base, LEFT_BASE_ADDR2_HIGH, cl_rdma,
		 0);

	k1_queue(RDMA_PATH_X_REG, module_base, LEFT_RDMA_STRIDE0, cl_rdma,
		 (fb->pitches[1] << 16) | fb->pitches[0]);

	cl_tbu = k1_alloc_cl_regs_n(sizeof(MMU_REG) / sizeof(u32));
	if (!cl_tbu)
		return;

	k1_queue_at(MMU_BASE_ADDR,
		    (size_t)&((MMU_REG *)0)->v.TBU[tbu_id].TBU_Base_Addr0_Low,
		    cl_tbu, lower_32_bits(tbu->ttb_pa[0]));
	k1_queue_at(MMU_BASE_ADDR,
		    (size_t)&((MMU_REG *)0)->v.TBU[tbu_id].TBU_Base_Addr0_High,
		    cl_tbu, upper_32_bits(tbu->ttb_pa[0]) & 0x3);
	k1_queue_at(MMU_BASE_ADDR,
		    (size_t)&((MMU_REG *)0)->v.TBU[tbu_id].TBU_VA0, cl_tbu,
		    (tbu->tbu_va[0] >> 12) & 0x3fffff);
	k1_queue_at(MMU_BASE_ADDR,
		    (size_t)&((MMU_REG *)0)->v.TBU[tbu_id].TBU_SIZE0, cl_tbu,
		    tbu->ttb_size[0]);
	k1_queue_at(MMU_BASE_ADDR,
		    (size_t)&((MMU_REG *)0)->v.TBU[tbu_id].TBU_Ctrl, cl_tbu,
		    val | (DPU_QOS_URGENT << 8));

	cmdlist_regs_packing(plane_to_cl(plane), CMDLIST_MOD_DMMU, cl_tbu);
	free_cmdlist_regs(cl_tbu);
}

/* ------------------------------------------------------------------------- */
/* Pipeline control                                                           */
/* ------------------------------------------------------------------------- */

static void k1_conf_dpuctrl(struct drm_crtc *crtc,
			    struct drm_crtc_state *old_state)
{
	struct spacemit_hw_device *hwdev = k1_hwdev;
	struct drm_plane *plane;
	u32 rdma_en = 0;

	if (!hwdev)
		return;

	/*
	 * Walk the CRTC's planes directly: at commit_planes() time the CRTC
	 * state is no longer attached to an atomic state, so the
	 * *_for_each_plane_state() helper would dereference a NULL
	 * crtc_state->state.
	 */
	drm_atomic_crtc_for_each_plane(plane, crtc)
		rdma_en |= BIT(to_spacemit_plane_state(plane->state)->rdma_id);

	/*
	 * Hand the packed command lists to the hardware: sort the per-RDMA
	 * lists, then program each channel and switch its read engine on.  This
	 * is what makes the queued plane registers take effect at the frame
	 * boundary; without it the RDMA keeps the loader's state.
	 */
	cmdlist_sort_by_group(crtc);
	cmdlist_atomic_commit(crtc, old_state);

	k1_write(hwdev, DPU_CTL_REG, DPU_CTRL_BASE_ADDR, ctl2_nml_scl_en, 0);
	k1_write(hwdev, DPU_CTL_REG, DPU_CTRL_BASE_ADDR, ctl2_nml_rch_en,
		 rdma_en);
	k1_write(hwdev, DPU_CTL_REG, DPU_CTRL_BASE_ADDR, ctl2_nml_outctl_en, 1);
}

/* ------------------------------------------------------------------------- */
/* Command lists                                                              */
/* ------------------------------------------------------------------------- */

/*
 * The K1 command list packet format: a 16-byte header followed by 16-byte
 * rows, each row carrying a register offset (in words, module relative) and up
 * to three consecutive 32-bit writes.  The layout is the same as on K3 but the
 * field names here are K1's.
 */
/*
 * The command list packet: a 16-byte header and 16-byte rows.  Both are laid
 * out as four 32-bit words; they are packed explicitly instead of through C
 * bitfields so the layout does not depend on the compiler.
 *
 * header word 0     : next_list_addr[31:0]
 * header word 1     : next_list_addr[33:32] | nod_len << 8 | last << 24
 * header words 2, 3 : reserved
 *
 * row word 0        : cfg_addr[15:0] | cfg_num << 16 | strobe << 18 |
 *		       eof_tag << 30   (cfg_addr is a word offset)
 * row words 1..3    : the three register payload words
 */
#define K1_CL_HEADER_SZ 16
#define K1_CL_ROW_SZ 16

static void k1_cl_header_set(u32 *hdr, dma_addr_t next, u32 nod_len, bool last)
{
	hdr[0] = lower_32_bits(next);
	hdr[1] = (upper_32_bits(next) & 0x3) | ((nod_len & 0xffff) << 8) |
		 (last ? BIT(24) : 0);
	hdr[2] = 0;
	hdr[3] = 0;
}

static void k1_cl_row_set(u32 *row, u32 offset, u32 num, u32 strobe, u32 eof,
			  const u32 *regs)
{
	row[0] = ((offset >> 2) & 0xffff) | ((num & 0x3) << 16) |
		 ((strobe & 0xfff) << 18) | ((eof & 0x3) << 30);
	row[1] = regs[0];
	row[2] = regs[1];
	row[3] = regs[2];
}

#define K1_RDMA_NWORDS (sizeof(RDMA_PATH_X_REG) / sizeof(u32))
/*
 * K1 command-list channel register offsets, relative to CMDLIST_BASE_ADDR and
 * DPU_CTRL_BASE_ADDR respectively.  The K3 layout uses different values, so
 * they live here rather than in the shared header.
 */
#define K1_DPU_NUM_REUSE_SCL 0xf4
#define K1_CMDLIST_CH_Y 0x38
#define K1_CMDLIST_CFG_READY 0x14c
#define K1_CL_CFG_RDY_OFF (DPU_CTRL_BASE_ADDR + K1_CMDLIST_CFG_READY)
#define K1_CL_CH_Y_OFF (CMDLIST_BASE_ADDR + K1_CMDLIST_CH_Y)

static struct cmdlist_regs *k1_alloc_cl_regs_n(unsigned int nwords)
{
	struct cmdlist_regs *cl = kzalloc(sizeof(*cl), GFP_KERNEL);

	if (!cl)
		return NULL;

	cl->size = nwords;
	cl->module = kzalloc(4 * nwords, GFP_KERNEL);
	cl->flags = kzalloc(nwords, GFP_KERNEL);
	if (!cl->module || !cl->flags) {
		kfree(cl->module);
		kfree(cl->flags);
		kfree(cl);
		return NULL;
	}

	return cl;
}

static struct cmdlist_regs *k1_alloc_cl_regs(void)
{
	return k1_alloc_cl_regs_n(K1_RDMA_NWORDS);
}

static int k1_get_cl_rdma_buf(struct spacemit_crtc *a_crtc)
{
	/*
	 * spacemit_plane_atomic_update() frees this cache at the end of every
	 * update but leaves the pointer in place, so a non-NULL value here is
	 * dangling: always hand out a fresh cache, like the K3 backend does.
	 */
	a_crtc->cl_rdma = k1_alloc_cl_regs();

	return a_crtc->cl_rdma ? 0 : -ENOMEM;
}

static void k1_cmdlist_fill_data_row(struct cmdlist *cl, u32 strobe, u32 offset,
				     u32 value[])
{
	u32 *row;

	if (WARN_ONCE(K1_CL_HEADER_SZ + (cl->nod_len + 1) * K1_CL_ROW_SZ >
			      cl->size,
		      "cmdlist buffer full (rows %u)\n", cl->nod_len))
		return;

	row = (u32 *)((char *)cl->va + K1_CL_HEADER_SZ +
		      cl->nod_len * K1_CL_ROW_SZ);
	/*
	 * K1's row carries the number of 32-bit registers it writes next to a
	 * strobe that holds one 0xf byte-enable nibble per register, so
	 * 0xf/0xff/0xfff mean 1/2/3 - not the popcount of the strobe (which
	 * would truncate to 0 in the 2-bit field and write nothing at all).
	 */
	k1_cl_row_set(row, offset, hweight32(strobe) / 4, strobe, 0, value);
}

static void k1_enable_cmdlist(struct spacemit_crtc *a_crtc,
			      struct spacemit_hw_device *hwdev, int id,
			      bool enable)
{
	if (id >= hwdev->rdma_nums)
		return;

	k1_write(hwdev, DPU_CTL_REG, DPU_CTRL_BASE_ADDR,
		 dpu_ctl_reg_69[id].ctl_nml_cmdlist_rch_en, enable ? 1 : 0);

}

static void k1_cfg_cmdlist(struct spacemit_hw_device *hwdev, int id, u32 chy,
			   u32 addrl, u32 addrh)
{
	k1_write(hwdev, CMDLIST_REG, CMDLIST_BASE_ADDR,
		 cmdlist_reg_14[id].cmdlist_ch_y, chy);
	k1_write(hwdev, CMDLIST_REG, CMDLIST_BASE_ADDR,
		 cmdlist_reg_0[id].cmdlist_ch_start_addrl, addrl);
	k1_write(hwdev, CMDLIST_REG, CMDLIST_BASE_ADDR,
		 cmdlist_reg_14[id].cmdlist_ch_start_addrh, addrh);

}

static void k1_crtc_cmdlist(struct spacemit_hw_device *hwdev,
			    struct spacemit_drm_private *priv, u8 crtc_id,
			    u8 dev_id)
{
	u32 ch = hwdev->rdma_nums + crtc_id;
	struct cmdlist *cl = priv->cmdlist_groups[ch];

	if (!cl)
		return;

	k1_write(hwdev, CMDLIST_REG, CMDLIST_BASE_ADDR,
		 cmdlist_reg_14[ch].cmdlist_ch_y, 0);
	k1_write(hwdev, CMDLIST_REG, CMDLIST_BASE_ADDR,
		 cmdlist_reg_0[ch].cmdlist_ch_start_addrl,
		 (lower_32_bits(cl->pa) & CMDLIST_ADDRL_ALIGN_MASK) >>
			 CMDLIST_ADDRL_ALIGN_BITS);
	k1_write(hwdev, CMDLIST_REG, CMDLIST_BASE_ADDR,
		 cmdlist_reg_14[ch].cmdlist_ch_start_addrh,
		 upper_32_bits(cl->pa));

	priv->cmdlist_groups[ch] = NULL;
}

static void k1_cmdlist_dump_node(struct cmdlist *cl)
{
}

static void k1_enable_cfg_irq(struct spacemit_crtc *a_crtc,
			      struct spacemit_hw_device *hwdev, bool enable)
{
	k1_write(hwdev, DPU_INTP_REG, DPU_INT_BASE_ADDR,
		 b.onl2_nml_cfg_rdy_clr_int_msk, enable ? 1 : 0);
}

static void k1_cmdlist_fill_conf_row(struct cmdlist *cl,
				     struct spacemit_hw_device *hwdev,
				     u8 dev_id)
{
	u32 reuse_regs[3] = { 0 };
	u32 ch_y_regs[3] = { 0 }, rdy_regs[3] = { 0 };
	u32 *row, *hdr;
	u8 rch_id = 0;
	bool has_next = cl->next != NULL;

	if (cl->type == CMDLIST_PLANE)
		rch_id = cl_to_spacemit_pstate(cl)->rdma_id;

	if (WARN_ONCE(K1_CL_HEADER_SZ + (cl->nod_len + 3) * K1_CL_ROW_SZ >
			      cl->size,
		      "cmdlist buffer full (rows %u)\n", cl->nod_len))
		return;

	hdr = (u32 *)cl->va;
	row = (u32 *)((char *)hdr + K1_CL_HEADER_SZ +
		      cl->nod_len * K1_CL_ROW_SZ);

	/*
	 * Scaler-reuse row.  It is always part of the packet; without a scaler
	 * attached cfg_num is 0, so it programs nothing (k1_cl_row_set() takes
	 * the byte offset and shifts it itself).
	 */
	k1_cl_row_set(row, DPU_CTRL_BASE_ADDR + K1_DPU_NUM_REUSE_SCL, 0, 0xff,
		      0, reuse_regs);
	cl->nod_len++;
	row += 4;

	/*
	 * Chained lists program the next list's start row before being
	 * released; a single-node list leaves this row empty.
	 */
	if (has_next)
		ch_y_regs[0] = cl_to_spacemit_pstate(cl->next)->state.crtc_y
				       << 8 |
			       (u32)((cl->next->pa >> 32) & 0x3);
	k1_cl_row_set(row, K1_CL_CH_Y_OFF + rch_id * 4, has_next ? 1 : 0, 0xf,
		      0, ch_y_regs);
	cl->nod_len++;
	row += 4;

	/* Final row: raise CFG_RDY for the channel this list programs. */
	rdy_regs[0] = BIT(rch_id);
	rdy_regs[2] = rch_id;
	k1_cl_row_set(row, K1_CL_CFG_RDY_OFF, 1, 0xf0f, 3, rdy_regs);
	cl->nod_len++;

	/*
	 * nod_len counts 16-byte units including the header itself, and
	 * cl->nod_len already includes the three rows appended above: the
	 * vendor's "data rows + 4" is cl->nod_len + 1 at this point.
	 */
	k1_cl_header_set(hdr, has_next ? cl->next->pa : 0, cl->nod_len + 1,
			 !has_next);
}

/* ------------------------------------------------------------------------- */
/* Pipeline operations                                                        */
/* ------------------------------------------------------------------------- */

static int k1_parse_clocks(struct device *dev, struct dpu_clk_context *clk_ctx)
{
	const struct {
		const char *name;
		struct clk **clk;
	} clocks[] = {
		{ "mclk", &clk_ctx->mclk },
		{ "hclk", &clk_ctx->hclk },
		{ "spiclk", &clk_ctx->spiclk },
		{ "spi_hbus", &clk_ctx->spi_hbus },
		{ "spibus", &clk_ctx->spibus },
		{ "spi_aclk", &clk_ctx->spi_aclk },
		{ "hmclk", &clk_ctx->hmclk },
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(clocks); i++) {
		/* The HDMI transmitter owns hmclk; the DPU only borrows it. */
		if (!strcmp(clocks[i].name, "hmclk"))
			*clocks[i].clk =
				devm_clk_get_optional(dev, clocks[i].name);
		else
			*clocks[i].clk = devm_clk_get(dev, clocks[i].name);
		if (IS_ERR(*clocks[i].clk))
			return dev_err_probe(dev, PTR_ERR(*clocks[i].clk),
					     "failed to get %s\n",
					     clocks[i].name);
	}

	return 0;
}

/*
 * K1 has no pxclk/aclk: the pixel clock is generated by the HDMI block, so the
 * DPU only needs its master, AHB and SPI (command list) clocks running.
 */
static int k1_enable_clk(struct spacemit_crtc *a_crtc)
{
	struct dpu_clk_context *clk = &a_crtc->clk_ctx;
	u64 mclk_val;
	int ret;

	ret = clk_prepare_enable(clk->mclk);
	if (ret)
		return ret;

	mclk_val = clk_get_rate(clk->mclk);
	if (mclk_val != DPU_MCLK_DEFAULT) {
		mclk_val = clk_round_rate(clk->mclk, DPU_MCLK_DEFAULT);
		clk_set_rate(clk->mclk, mclk_val);
	}

	ret = clk_prepare_enable(clk->hclk);
	if (ret)
		goto err_mclk;

	/* The SPI block clocks the command-list fetch engine. */
	ret = clk_prepare_enable(clk->spiclk);
	if (ret)
		goto err_hclk;
	ret = clk_prepare_enable(clk->spi_hbus);
	if (ret)
		goto err_spiclk;
	ret = clk_prepare_enable(clk->spibus);
	if (ret)
		goto err_spi_hbus;
	ret = clk_prepare_enable(clk->spi_aclk);
	if (ret)
		goto err_spibus;
	if (clk->hmclk) {
		ret = clk_prepare_enable(clk->hmclk);
		if (ret)
			goto err_spi_aclk;
	}

	return 0;

err_spi_aclk:
	clk_disable_unprepare(clk->spi_aclk);
err_spibus:
	clk_disable_unprepare(clk->spibus);
err_spi_hbus:
	clk_disable_unprepare(clk->spi_hbus);
err_spiclk:
	clk_disable_unprepare(clk->spiclk);
err_hclk:
	clk_disable_unprepare(clk->hclk);
err_mclk:
	clk_disable_unprepare(clk->mclk);
	return ret;
}

static int k1_disable_clk(struct spacemit_crtc *a_crtc)
{
	struct dpu_clk_context *clk = &a_crtc->clk_ctx;

	if (clk->hmclk)
		clk_disable_unprepare(clk->hmclk);
	clk_disable_unprepare(clk->spi_aclk);
	clk_disable_unprepare(clk->spibus);
	clk_disable_unprepare(clk->spi_hbus);
	clk_disable_unprepare(clk->spiclk);
	clk_disable_unprepare(clk->hclk);
	clk_disable_unprepare(clk->mclk);

	return 0;
}

static int k1_init(struct spacemit_crtc *a_crtc)
{
	unsigned int timeout = 1000;
	struct spacemit_drm_private *priv = a_crtc->crtc.dev->dev_private;
	struct spacemit_hw_device *hwdev = priv->hwdev;

	if (!a_crtc->clocks_on)
		return 0;

	k1_hwdev = priv->hwdev;

	while (timeout) {
		if (hwdev->get_cfg_rdy(a_crtc, hwdev) == 0)
			break;
		usleep_range(100, 200);
		timeout--;
	}
	if (timeout == 0)
		drm_err(a_crtc->crtc.dev, "wait for cfg ready timed out\n");

	hwdev->dpu_init(a_crtc);


	/*
	 * Arm the interrupts on every enable: k1_uninit() masks them when the
	 * CRTC goes down, and a latch that survived that would leave the
	 * handshake and vsync dead after a hotplug re-modeset (the composer
	 * then starves and outctrl shows its background colour).
	 */
	hwdev->irq_enable(a_crtc, true);

	return 0;
}

static void k1_uninit(struct spacemit_crtc *a_crtc)
{
	struct spacemit_drm_private *priv = a_crtc->crtc.dev->dev_private;
	struct spacemit_hw_device *hwdev = priv->hwdev;

	if (!a_crtc->clocks_on)
		return;


	/* Do not leave a CFG_RDY the hardware never consumed pending. */
	k1_write(hwdev, DPU_CTL_REG, DPU_CTRL_BASE_ADDR, ctl2_nml_cfg_rdy, 0);
	hwdev->irq_enable(a_crtc, false);
}

static void k1_run(struct drm_crtc *crtc, struct drm_crtc_state *old_state)
{
	struct spacemit_crtc *a_crtc = to_spacemit_crtc(crtc);
	struct spacemit_drm_private *priv = crtc->dev->dev_private;
	struct spacemit_hw_device *hwdev = priv->hwdev;

	if (hwdev->conf_dpuctrl) {
		hwdev->conf_dpuctrl(crtc, old_state);
	}

	/* Flush every config write before CFG_RDY is raised. */
	mb();

	a_crtc->flip_done = false;
	spacemit_crtc_vblank_get(a_crtc);
	k1_vblank_armed = true;

	/* Arm the handshake watchdog before raising CFG_RDY. */
	mod_timer(&a_crtc->cfg_rdy_timer, jiffies + msecs_to_jiffies(3000));

	hwdev->cfg_ready(a_crtc, hwdev);

	if (unlikely(a_crtc->is_1st_f)) {
		a_crtc->is_1st_f = false;
		hwdev->sw_start(a_crtc, hwdev);
	}

	dma_rmb();
}

static void k1_isr_vblank(struct spacemit_crtc *a_crtc, bool *flip)
{
	struct drm_crtc *crtc = &a_crtc->crtc;
	struct drm_device *drm = crtc->dev;
	struct drm_pending_vblank_event *event;

	if (*flip)
		return;
	*flip = true;

	spin_lock(&drm->event_lock);
	event = crtc->state->event;
	if (event) {
		crtc->state->event = NULL;
		drm_crtc_send_vblank_event(crtc, event);
	}
	spin_unlock(&drm->event_lock);

	spacemit_crtc_vblank_put(a_crtc);
}

static u32 k1_online_isr(struct spacemit_crtc *a_crtc)
{
	struct spacemit_drm_private *priv = a_crtc->crtc.dev->dev_private;
	struct spacemit_hw_device *hwdev = priv->hwdev;
	u32 irq_raw, irq_bit, irq_ur_bit;
	int dev_id = a_crtc->dev_id;

	irq_raw = hwdev->get_int_sts(hwdev, dev_id);

	/* Ack the OUTCTRL status first: it drives the same level line. */
	k1_clear_outctrl_irq(hwdev, dev_id);

	/*
	 * Always drop the underrun status.  ur_reported only spares the log:
	 * leaving the bit set keeps the level-triggered line asserted, and a
	 * stuck CFG_RDY handshake keeps ur_reported set forever.
	 */
	irq_bit = hwdev->get_irq_bit(INT_UNDERRUN, dev_id);
	irq_ur_bit = irq_raw & irq_bit;
	if (irq_ur_bit) {
		hwdev->clr_int_sts(a_crtc, irq_ur_bit, dev_id);
		if (!a_crtc->ur_reported) {
			drm_err_ratelimited(a_crtc->crtc.dev, "underrun\n");
			a_crtc->ur_reported = true;
		}

		/*
		 * A stalled pipeline underflows continuously, so a level
		 * interrupt left armed here becomes an interrupt storm.  Report
		 * it once and mask it until the next CFG_RDY re-arms it.
		 */
		if (a_crtc->ur_mask_armed) {
			a_crtc->ur_mask_armed = false;
			k1_write(hwdev, DPU_INTP_REG, DPU_INT_BASE_ADDR,
				 b.onl2_nml_frm_timing_unflow_int_msk, 0);
		}
	}

	irq_bit = hwdev->get_irq_bit(INT_CFG_RDY, dev_id);
	if (irq_raw & irq_bit) {
		hwdev->clr_int_sts(a_crtc, irq_bit, dev_id);
		if (timer_delete(&a_crtc->cfg_rdy_timer))
			a_crtc->flip_done = false;
		a_crtc->ur_reported = false;
	}

	irq_bit = hwdev->get_irq_bit(INT_VSYNC, dev_id);
	if (irq_raw & irq_bit) {
		hwdev->clr_int_sts(a_crtc, irq_bit, dev_id);
		/*
		 * Account every vblank, not only the ones a commit is waiting
		 * for: drm_crtc_wait_one_vblank() (the fbdev damage worker, the
		 * atomic helpers) only makes progress when the counter advances
		 * here, and without it the console redraws time out and leave
		 * stale text behind.
		 */
		drm_crtc_handle_vblank(&a_crtc->crtc);

		if (k1_vblank_armed) {
			k1_vblank_armed = false;
			k1_isr_vblank(a_crtc, &a_crtc->flip_done);
		}
	}

	irq_bit = hwdev->get_irq_bit(INT_REST, dev_id) | irq_ur_bit;
	if (irq_raw & irq_bit)
		hwdev->clr_int_sts(a_crtc, irq_bit, dev_id);

	/* Latched EOF status: it is masked, but never leave it pending. */
	irq_bit = hwdev->get_irq_bit(INT_EOF, dev_id);
	if (irq_raw & irq_bit)
		hwdev->clr_int_sts(a_crtc, irq_bit, dev_id);

	return 0;
}

/* ------------------------------------------------------------------------- */
/* FBC line buffers                                                           */
/* ------------------------------------------------------------------------- */

/*
 * The DPU keeps a small on-chip line buffer per RDMA channel, addressed in
 * 32-byte units.  Each plane requests a slice sized from its crop width; the
 * allocator below hands out start offsets inside the two hardware pools.
 */
#define K1_FBCMEM_UNIT 32

static u32 k1_raw_plane_fbcmem_size(u32 format, bool rot_90_270, u32 crop_w)
{
	const struct drm_format_info *info;
	u32 size = 0, plane_size;

	if (rot_90_270) {
		/* Rotation asks for a fixed 32K window. */
		return 1024;
	}

	info = drm_format_info(format);
	if (!info || !info->cpp[0])
		return 0;

	if (info->num_planes == 1) {
		plane_size = crop_w * info->cpp[0];
		size += roundup(plane_size, 64);
	} else if (info->num_planes >= 2 && info->is_yuv) {
		size += roundup(crop_w * info->cpp[0], 64);
		size += roundup(crop_w * info->cpp[1] / info->hsub, 64);
		if (info->num_planes == 3)
			size += roundup(crop_w * info->cpp[2] / info->vsub, 64);
	} else {
		return 0;
	}

	return roundup(size, 64) / K1_FBCMEM_UNIT;
}

static void k1_write_fbcmem_regs(struct drm_plane_state *state, u32 rdma_id,
				 u32 module_base, struct cmdlist_regs *cl)
{
	const struct spacemit_crtc_rdma *rdmas =
		to_spacemit_crtc_state(state->crtc->state)->rdmas;
	u32 size = rdmas[rdma_id].fbcmem.size;
	u32 start = rdmas[rdma_id].fbcmem.start;
	bool map = rdmas[rdma_id].fbcmem.map;

	k1_queue(RDMA_PATH_X_REG, module_base, FBC_MEM_SIZE, cl,
		 map << 28 | start << 16 | size);
}

static int k1_cal_layer_fbcmem_size(struct drm_plane *plane,
				    struct drm_plane_state *state)
{
	struct spacemit_plane_state *pstate = to_spacemit_plane_state(state);
	struct drm_framebuffer *fb = state->fb;
	bool rot_90_270;
	u32 size = 0;

	if (!fb)
		return 0;

	/*
	 * Only linear scanout is supported: AFBC modifiers would need the
	 * block-size based sizing the vendor driver carries.
	 */
	if (fb->modifier)
		return -EINVAL;

	rot_90_270 = state->rotation &
		     (DRM_MODE_ROTATE_90 | DRM_MODE_ROTATE_270);
	size = k1_raw_plane_fbcmem_size(fb->format->format, rot_90_270,
					state->src_w >> 16);
	if (!size)
		return -EINVAL;

	pstate->fbcmem_size = size;
	drm_dbg(plane->dev, "plane %u: fbcmem %u units\n", pstate->rdma_id,
		size);

	return 0;
}

static int k1_adjust_rdma_fbcmem(struct spacemit_hw_device *hwdev,
				 struct spacemit_crtc_rdma *rdmas)
{
	u32 *left;
	u8 n = hwdev->rdma_nums, i;
	int ret = -ENOSPC;

	if (n < 2 || n % 2 || hwdev->n_fbcmems < n / 2)
		return -EINVAL;

	left = kcalloc(n / 2, sizeof(*left), GFP_KERNEL);
	if (!left)
		return -ENOMEM;

	for (i = 0; i < n / 2; i++) {
		left[i] = hwdev->fbcmem_sizes[i] / K1_FBCMEM_UNIT;
		if (!left[i])
			goto out;
	}

	for (i = 0; i < n; i++) {
		u32 want = rdmas[i].fbcmem.size;
		u32 pri = hwdev->fbcmem_sizes[i / 2] / K1_FBCMEM_UNIT;
		u32 sec, idx;

		if (!want)
			continue;

		if (i % 2 == 0) {
			/* Even channels own the head of their pool. */
			if (want > pri)
				goto out;
			if (i > 0 && rdmas[i - 1].fbcmem.map)
				goto out;
			rdmas[i].fbcmem.start = 0;
			rdmas[i].fbcmem.map = true;
			left[i / 2] -= want;
		} else if (want <= left[i / 2]) {
			/* Odd channels take the tail of the same pool. */
			rdmas[i].fbcmem.map = false;
			rdmas[i].fbcmem.start = pri - left[i / 2];
			rdmas[i].fbcmem.size = left[i / 2];
			left[i / 2] = 0;
		} else {
			/* Spill into the neighbouring pool. */
			idx = (i / 2 + 1) % (n / 2);
			sec = hwdev->fbcmem_sizes[idx] / K1_FBCMEM_UNIT;
			if (want > left[i / 2] + sec)
				goto out;
			if (i == n - 1) {
				if (left[0] !=
				    hwdev->fbcmem_sizes[0] / K1_FBCMEM_UNIT)
					goto out;
				rdmas[i].fbcmem.size = left[i / 2] + sec;
				want = rdmas[i].fbcmem.size;
			}
			left[idx] -= (want - left[i / 2]);
			rdmas[i].fbcmem.start = pri - left[i / 2];
			rdmas[i].fbcmem.map = true;
			left[i / 2] = 0;
		}
	}

	ret = 0;
out:
	kfree(left);
	return ret;
}

const struct spacemit_hw_device k1_saturn_dpu = {
	.plane_nums = 8,
	.crtc_nums = 2,
	.rdma_nums = ARRAY_SIZE(k1_rdmas),
	.rdmas = k1_rdmas,
	.n_formats = ARRAY_SIZE(k1_primary_fmts),
	.formats = k1_primary_fmts,
	.n_fbcmems = ARRAY_SIZE(k1_fbcmem_sizes),
	.fbcmem_sizes = k1_fbcmem_sizes,
	.enable_vsync = k1_enable_vsync,
	.enable_cfg_irq = k1_enable_cfg_irq,
	.cfg_ready = k1_cfg_ready,
	.sw_start = k1_sw_start,
	.irq_enable = k1_irq_enable,
	.dpu_init = k1_dpu_init,
	.plane_update_hw_channel = k1_plane_update_hw_channel,
	.plane_disable_hw_channel = k1_plane_disable_hw_channel,
	.conf_dpuctrl = k1_conf_dpuctrl,
	.get_cfg_rdy = k1_get_cfg_rdy,
	.get_int_sts = k1_get_int_sts,
	.get_irq_bit = k1_get_irq_bit,
	.clr_int_sts = k1_clr_int_sts,
	.enable_cmdlist = k1_enable_cmdlist,
	.cfg_cmdlist = k1_cfg_cmdlist,
	.rdma_dmmu = k1_rdma_dmmu,
	.get_cl_rdma_buf = k1_get_cl_rdma_buf,
	.cmdlist_fill_data_row = k1_cmdlist_fill_data_row,
	.cmdlist_fill_conf_row = k1_cmdlist_fill_conf_row,
	.crtc_cmdlist = k1_crtc_cmdlist,
	.cmdlist_dump_node = k1_cmdlist_dump_node,
};

const struct dpu_core_ops dpu_k1_ops = {
	.init = k1_init,
	.uninit = k1_uninit,
	.run = k1_run,
	.online_isr = k1_online_isr,
	.enable_clk = k1_enable_clk,
	.disable_clk = k1_disable_clk,
	.enable_vsync = k1_core_enable_vsync,
	.disable_vsync = k1_disable_vsync,
	.cal_layer_fbcmem_size = k1_cal_layer_fbcmem_size,
	.adjust_rdma_fbcmem = k1_adjust_rdma_fbcmem,
};

int k1_parse_dt_clocks(struct device *dev, struct dpu_clk_context *clk_ctx)
{
	return k1_parse_clocks(dev, clk_ctx);
}
