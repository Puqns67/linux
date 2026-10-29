// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 SpacemiT Co., Ltd.
 *
 * SpacemiT K1 HDMI transmitter.
 *
 * The register level bring-up (PLL, PHY bias, infoframes and the bit-banged
 * DDC read) is the vendor sequence; the DRM side is modelled as a
 * drm_bridge so it chains the same way as the K3 DisplayPort block.
 */

#include <linux/clk.h>
#include <linux/component.h>
#include <linux/delay.h>
#include <linux/hdmi.h>
#include <linux/irq.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/platform_device.h>

#include <drm/drm_atomic_helper.h>
#include <drm/drm_atomic_state_helper.h>
#include <drm/drm_bridge.h>
#include <drm/drm_bridge_connector.h>
#include <drm/drm_edid.h>
#include <drm/drm_encoder.h>
#include <drm/drm_of.h>
#include <drm/drm_print.h>

#define SPACEMIT_HDMI_DDC_OTHER_MASK BIT(31)
#define SPACEMIT_HDMI_DDC_DONE_MASK BIT(30)
#define SPACEMIT_HDMI_HPD_IQR_MASK BIT(29)

#define SPACEMIT_HDMI_DDC_NACK BIT(15)
#define SPACEMIT_HDMI_DDC_DONE BIT(14)
#define SPACEMIT_HDMI_HPD_IQR BIT(13)
#define SPACEMIT_HDMI_HPD_STATUS BIT(12)

#define SPACEMIT_HDMI_PHY_STATUS 0xc

#define EIGHT_BPP 8
#define TEN_BPP 10

struct hdmi_data_info {
	uint8_t edid[256];
	int vic;
	bool sink_has_audio;
	unsigned int enc_in_format;
	unsigned int enc_out_format;
	unsigned int colorimetry;
};

struct spacemit_hdmi {
	struct device *dev;
	struct drm_device *drm_dev;

	int irq;
	void __iomem *regs;

	struct drm_bridge bridge;
	struct drm_encoder encoder;
	struct drm_connector *connector;
	struct drm_bridge *next_bridge;

	struct clk *hdmi_mclk;

	unsigned int tmds_rate;

	struct mutex lock;
	bool suspended;
	bool irq_enabled;
	bool edid_done;
	bool use_no_edid;
	struct hdmi_data_info *hdmi_data;
	struct drm_display_mode previous_mode;
	struct drm_display_mode preferred_mode;
};

static inline struct spacemit_hdmi *
bridge_to_spacemit_hdmi(struct drm_bridge *bridge)
{
	return container_of(bridge, struct spacemit_hdmi, bridge);
}

static int hdmi_i2c_write(struct spacemit_hdmi *hdmi, u8 addr, u8 *buf,
			  u32 len);

static inline u32 hdmi_readb(struct spacemit_hdmi *hdmi, u16 offset)
{
	return readl_relaxed(hdmi->regs + (offset));
}

static inline void hdmi_writeb(struct spacemit_hdmi *hdmi, u16 offset, u32 val)
{
	writel_relaxed(val, hdmi->regs + (offset));
}

enum {
	NORMAL = 0,
	LOWER_PWR,
	INFOFRAME_VSI = 0x05,
	INFOFRAME_AVI = 0x06,
	INFOFRAME_AAI = 0x08,
};

/* PLL9 divider selector indexed by the colour depth. */
static const int pll9_bit0_1[3] = { 0x0, 0x1, 0x2 };

static int hdmi_get_plug_in_status(struct spacemit_hdmi *hdmi)
{
	u32 value;
	value = readl_relaxed(hdmi->regs + SPACEMIT_HDMI_PHY_STATUS) &
		SPACEMIT_HDMI_HPD_STATUS;

	return !!value;
}

/*
 * The HPD/DDC status register holds one level source per bit: the line stays
 * asserted for as long as a latched bit is set, so a DDC completion that is
 * left enabled latches it after every transfer and the handler ends up
 * re-detecting in a loop.  Mask the DDC sources and acknowledge the pending
 * bits before starting a transfer, like the vendor driver does; only HPD stays
 * armed, which is the only source that needs to wake the driver.
 */
/*
 * Arm the hotplug interrupt.  The PHY status word doubles as the interrupt
 * enable, and the DPU pulses the shared reset on every enable, which clears
 * it - without this the connector never sees another plug event.
 */
static void spacemit_hdmi_hpd_arm(struct spacemit_hdmi *hdmi)
{
	u32 value;

	value = hdmi_readb(hdmi, SPACEMIT_HDMI_PHY_STATUS);
	value |= SPACEMIT_HDMI_HPD_IQR_MASK | SPACEMIT_HDMI_HPD_IQR;
	hdmi_writeb(hdmi, SPACEMIT_HDMI_PHY_STATUS, value);
	udelay(5);
}

static void spacemit_hdmi_ddc_quiesce(struct spacemit_hdmi *hdmi)
{
	u32 value;

	value = hdmi_readb(hdmi, SPACEMIT_HDMI_PHY_STATUS);
	value &= ~(SPACEMIT_HDMI_DDC_OTHER_MASK | SPACEMIT_HDMI_DDC_DONE_MASK);
	value |= SPACEMIT_HDMI_HPD_IQR | SPACEMIT_HDMI_DDC_DONE |
		 SPACEMIT_HDMI_DDC_NACK;
	hdmi_writeb(hdmi, SPACEMIT_HDMI_PHY_STATUS, value);
	udelay(5);
}
static int spacemit_hdmi_config_video_vsi(struct spacemit_hdmi *hdmi,
					  struct drm_display_mode *mode)
{
	union hdmi_infoframe frame;
	int rc;

	rc = drm_hdmi_vendor_infoframe_from_display_mode(&frame.vendor.hdmi,
							 hdmi->connector, mode);
	if (rc)
		return rc;

	return 0;
}
static int spacemit_hdmi_upload_frame(struct spacemit_hdmi *hdmi, int setup_rc,
				      union hdmi_infoframe *frame,
				      u32 frame_index, u32 mask, u32 disable,
				      u32 enable)
{
	if (setup_rc >= 0) {
		u8 packed_frame[0x11];
		ssize_t rc;

		rc = hdmi_infoframe_pack(frame, packed_frame,
					 sizeof(packed_frame));
		if (rc < 0)
			return rc;
	}

	return setup_rc;
}
static int spacemit_hdmi_config_video_avi(struct spacemit_hdmi *hdmi,
					  struct drm_display_mode *mode)
{
	union hdmi_infoframe frame;
	int rc;

	rc = drm_hdmi_avi_infoframe_from_display_mode(&frame.avi,
						      hdmi->connector, mode);

	if (hdmi->hdmi_data->enc_out_format == HDMI_COLORSPACE_YUV444)
		frame.avi.colorspace = HDMI_COLORSPACE_YUV444;
	else if (hdmi->hdmi_data->enc_out_format == HDMI_COLORSPACE_YUV422)
		frame.avi.colorspace = HDMI_COLORSPACE_YUV422;
	else
		frame.avi.colorspace = HDMI_COLORSPACE_RGB;

	return spacemit_hdmi_upload_frame(hdmi, rc, &frame, INFOFRAME_AVI, 0, 0,
					  0);
}
static int spacemit_hdmi_config_video_timing(struct spacemit_hdmi *hdmi,
					     struct drm_display_mode *mode)
{
	return 0;
}
static int power_of_two(int n)
{
	int result = 1;
	for (int i = 0; i < n; ++i) {
		result <<= 1;
	}

	return result;
}
static int pll8_bit_5_6(int bit_clock, int n)
{
	int ret = 0;
	bit_clock = bit_clock / n;

	if (bit_clock < 425)
		ret = 3;
	else if (bit_clock < 850)
		ret = 2;
	else if (bit_clock < 1700)
		ret = 1;
	else
		ret = 0;

	return ret;
}
static int pll6_bit_4_5(int bit_clock, int n)
{
	int ret = 0;
	bit_clock = bit_clock / n;

	if (bit_clock <= 337)
		ret = 0;
	else if (bit_clock < 425)
		ret = 1;
	else if (bit_clock < 675)
		ret = 0;
	else if (bit_clock < 850)
		ret = 1;
	else if (bit_clock < 1350)
		ret = 0;
	else if (bit_clock < 1700)
		ret = 1;
	else
		ret = 0;

	return ret;
}
static int pll5_bit_0_2(int bit_clock, int n)
{
	int value = bit_clock * power_of_two(pll8_bit_5_6(bit_clock, n)) / n;
	int ret;

	if (value < 1830)
		ret = 0;
	else if (value < 2030)
		ret = 1;
	else if (value < 2275)
		ret = 2;
	else if (value < 2520)
		ret = 3;
	else if (value < 2765)
		ret = 4;
	else if (value < 3015)
		ret = 5;
	else if (value < 3260)
		ret = 6;
	else
		ret = 7;

	return ret;
}
static void pll_reg_cal(int bit_clock, int ref_clock, int n, int *integer_part,
			u32 *hmdi_e8_reg)
{
	long long int_para = 1000000000;
	long long value = (power_of_two(pll8_bit_5_6(bit_clock, n))) *
			  bit_clock * int_para /
			  (n * (pll6_bit_4_5(bit_clock, n) + 1) * ref_clock);
	long long integer =
		(power_of_two(pll8_bit_5_6(bit_clock, n))) * bit_clock /
		(n * (pll6_bit_4_5(bit_clock, n) + 1) * ref_clock) * int_para;
	long long fraction = value - integer;
	bool negative = false;
	int bit = 0;
	int frac_20bit = 0;
	int pll2_reg = 0;
	int pll1_reg = 0;
	int pll0_reg = 0;

	negative = fraction > 500000000 ? true : false;
	fraction = negative ? 1000000000 - fraction : fraction;
	*integer_part = negative ? integer / int_para + 1 : integer / int_para;

	for (int i = 0; i < 20; i++) {
		if (bit >= int_para) {
			frac_20bit |= 1 << (19 - i);
			fraction -= int_para;
		}
		fraction *= 2;
		bit = fraction;
	}

	if (!negative) {
		pll2_reg = ((frac_20bit & 0xF0000) >> 16) | (1 << 5);
	} else {
		frac_20bit = (~frac_20bit + 1) & 0xfffff;
		pll2_reg = 0x10 | ((frac_20bit & 0xF0000) >> 16) | (1 << 5);
	}

	pll1_reg = (frac_20bit & 0xFF00) >> 8;
	pll0_reg = frac_20bit & 0xFF;
	*hmdi_e8_reg = (0x20 << 24) | (pll2_reg << 16) | (pll1_reg << 8) |
		       pll0_reg;
}
static int pll_reg(struct spacemit_hdmi *hdmi, int pixel_clock, int bit_depth)
{
	int pll9_reg = 0, pll8_reg = 0, pll7_reg = 0, pll6_reg = 0,
	    pll5_reg = 0, pll4_reg = 0;
	int n = 100;
	int ref_clock = 24;
	int hdmi_ec_reg = 0;
	int hdmi_f0_reg = 0;
	int hdmi_e8_reg = 0;
	int bit_clock = bit_depth == EIGHT_BPP ? pixel_clock :
						 pixel_clock * 125 / 100;

	int integer_part = 0;

	DRM_DEBUG("%s()\n", __func__);

	pll_reg_cal(bit_clock, ref_clock, n, &integer_part, &hdmi_e8_reg);

	pll9_reg = 2 << 2 | pll9_bit0_1[bit_depth];
	pll8_reg = (0 << 7) | (pll8_bit_5_6(bit_clock, n) << 5) | 1;
	pll7_reg = 0x50;
	pll6_reg = 0xD | (pll6_bit_4_5(bit_clock, n) << 4) | (2 << 6);
	pll5_reg = 0x40 | pll5_bit_0_2(bit_clock, n);

	pll4_reg = integer_part;

	hdmi_ec_reg = (pll7_reg << 24) | (pll6_reg << 16) | (pll5_reg << 8) |
		      pll4_reg;
	hdmi_f0_reg = (pll9_reg << 8) | pll8_reg;

	writel(hdmi_e8_reg, hdmi->regs + 0xe8);
	DRM_DEBUG("%s() hdmi 0xe8 0x%x\n", __func__, hdmi_e8_reg);

	writel(hdmi_ec_reg, hdmi->regs + 0xec);
	DRM_DEBUG("%s() hdmi 0xec 0x%x\n", __func__, hdmi_ec_reg);

	writel(hdmi_f0_reg, hdmi->regs + 0xf0);
	DRM_DEBUG("%s() hdmi 0xf0 0x%x\n", __func__, hdmi_f0_reg);

	return 0;
}
static void hdmi_i2c_timing(struct spacemit_hdmi *hdmi)
{
	uint32_t reg = 0;
	uint32_t apb_clk = 153500 * 1000; /*Hz*/
	uint32_t apb_time = 1000 * 1000 * 1000 / apb_clk; /*ns*/
	uint32_t i2c_clk = 100 * 1000; /*Hz*/
	uint32_t i2c_time = 1000 * 1000 * 1000 / i2c_clk; /*ns*/
	uint32_t scl_high_time, scl_low_time; /*ns*/
	uint32_t scl_high_count = 0, scl_low_count = 0;

	DRM_DEBUG("%s()\n", __func__);

	reg = hdmi_readb(hdmi, 0x18);
	DRM_DEBUG("%s() hdmi 0x18 #1 0x%x\n", __func__, reg);

	scl_high_time = i2c_time / 2;
	scl_low_time = i2c_time / 2;
	scl_high_count = scl_high_time / apb_time;
	scl_low_count = scl_low_time / apb_time;

	scl_high_count = (scl_high_count - 3) >> 2;
	scl_low_count = (scl_low_count - 3) >> 2;

	reg &= ~0x7FFFF;
	reg |= (5 << 16); /*glitch*/
	reg |= scl_high_count << 8; /*high. time = value *4 + 3*/
	reg |= scl_low_count; /*low. time = value *4 +3*/
	DRM_DEBUG("%s() scl_high_count %d, scl_low_count %d\n", __func__,
		  scl_high_count, scl_low_count);

	hdmi_writeb(hdmi, 0x18, reg);
	msleep(2);
	reg = hdmi_readb(hdmi, 0x18);
	DRM_DEBUG("%s() hdmi 0x18 #2 0x%x\n", __func__, reg);
}
static int hdmi_i2c_read(struct spacemit_hdmi *hdmi, uint8_t addr,
			 uint8_t *message, uint32_t length)
{
	int i, count = 0, left = length;
	uint8_t *pvalue = message;
	uint32_t value;
	uint32_t reg, num, status;
	int timeout = 1000;

	DRM_DEBUG("hdmi_i2c_read ++%u\r\n", length);

	do {
		if (left <= 16)
			count = left;
		else
			count = 16;
		left -= count;

		value = ((count - 1) << 8) + (addr << 1) + 1;
		hdmi_writeb(hdmi, 0x8, value & 0xFFFF);

		reg = hdmi_readb(hdmi, 0xC);
		num = (reg & 0x1f0) >> 4;

		while (num < count) {
			reg = hdmi_readb(hdmi, 0xC);
			status = reg & SPACEMIT_HDMI_HPD_STATUS;
			if (!status) {
				DRM_INFO("hdmi disconnected while read edid\n");
				return -1;
			}
			num = (reg & 0x1f0) >> 4;
		}

		for (i = 0; i < count; i++) {
			value = hdmi_readb(hdmi, 0x4);
			*pvalue++ = value;
		}
	} while (left > 0);

	while (timeout) {
		if ((hdmi_readb(hdmi, 0xc) & BIT(14)) != 0)
			break;

		udelay(100);
		timeout--;
	};

	if (timeout == 0)
		DRM_INFO("%s wait hdmi ddc command done timeout\n", __func__);

	value = hdmi_readb(hdmi, 0xc);
	DRM_DEBUG("%s hdmi status 0x%x\n", __func__, value);
	value |= SPACEMIT_HDMI_DDC_DONE;

	hdmi_writeb(hdmi, 0xc, value);
	udelay(100);

	DRM_DEBUG("hdmi_i2c_read --%u\r\n", length);

	return 0;
}
static int edid_read(struct spacemit_hdmi *hdmi)
{
	int i;
	struct hdmi_data_info *hdmi_data = hdmi->hdmi_data;
	uint8_t offset;
	int result;

	DRM_DEBUG("%s()\n", __func__);

	for (i = 0; i < 8; i++) {
		offset = i * 16;
		result = hdmi_i2c_write(hdmi, 0x50, &offset, 1);
		if (result < 0)
			break;
		result =
			hdmi_i2c_read(hdmi, 0x50, hdmi_data->edid + offset, 16);
		if (result < 0)
			break;
	}

	if (result < 0) {
		// memset(hdmi_data->edid, 0x00, EDID_LENGTH);
		memset(hdmi_data->edid, 0x00, 256);
		return result;
	}

	if (hdmi_data->edid[0x7e] == 0x01) {
		// extend edid
		for (i = 8; i < 16; i++) {
			offset = i * 16;
			result = hdmi_i2c_write(hdmi, 0x50, &offset, 1);
			if (result < 0)
				break;
			result = hdmi_i2c_read(hdmi, 0x50,
					       hdmi_data->edid + offset, 16);
			if (result < 0)
				break;
		}
	}

	if (result < 0) {
		// memset(hdmi_data->edid, 0x00, EDID_LENGTH);
		memset(hdmi_data->edid, 0x00, 256);
		return result;
	}

	for (i = 0; i < 256; i += 8) {
		DRM_DEBUG(
			"EDID 0x%x: 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x\r\n",
			i, hdmi_data->edid[i], hdmi_data->edid[i + 1],
			hdmi_data->edid[i + 2], hdmi_data->edid[i + 3],
			hdmi_data->edid[i + 4], hdmi_data->edid[i + 5],
			hdmi_data->edid[i + 6], hdmi_data->edid[i + 7]);
	}

	if ((hdmi_data->edid[0] == 0x00) && (hdmi_data->edid[1] == 0xff) &&
	    (hdmi_data->edid[2] == 0xff) && (hdmi_data->edid[3] == 0xff) &&
	    (hdmi_data->edid[4] == 0xff) && (hdmi_data->edid[5] == 0xff) &&
	    (hdmi_data->edid[6] == 0xff) && (hdmi_data->edid[7] == 0x00)) {
		hdmi->edid_done = true;
	} else {
		hdmi->edid_done = false;
	}

	return 0;
}
static void hdmi_write_bits(struct spacemit_hdmi *hdmi, u16 offset, u32 value,
			    u32 mask, u32 shifts)
{
	u32 reg_val;

	reg_val = readl_relaxed(hdmi->regs + (offset));
	reg_val &= ~(mask << shifts);
	reg_val |= (value << shifts);
	writel_relaxed(reg_val, hdmi->regs + (offset));
}
static int hdmi_init(struct spacemit_hdmi *hdmi, int pixel_clock, int bit_depth)
{
	u32 value = 0;
	int timeout;
	int color_depth = bit_depth == EIGHT_BPP ? 4 : 5;

	u32 good_phase = 0x00;
	u32 bias_current = 0x01;
	u32 bias_risistor = 0x07;

	DRM_DEBUG("%s()\n", __func__);

	writel(0xAE5C410F, hdmi->regs + 0xe0);
	hdmi_write_bits(hdmi, 0xe0, bias_current, 0x03, 29);
	hdmi_write_bits(hdmi, 0xe0, bias_risistor, 0x0F, 18);
	hdmi_write_bits(hdmi, 0xe0, good_phase, 0x03, 14);
	// writel(0xEE40410F, hdmi->regs + 0xe0);
	// value = readl_relaxed(hdmi->regs + 0xe0);
	// DRM_DEBUG("%s() hdmi 0xe0 0x%x\n", __func__, value);

	value = 0x0000000d | (color_depth << 4);
	writel(value, hdmi->regs + 0x34);
	DRM_DEBUG("%s() hdmi 0x34 0x%x\n", __func__, value);

	pll_reg(hdmi, pixel_clock, bit_depth);
	writel(0x0, hdmi->regs + 0xe4);
	writel(0x03, hdmi->regs + 0xe4);
	// wait for hdmi pll lock
	timeout = 100;
	while (timeout) {
		if ((readl(hdmi->regs + 0xe4) & BIT(16)) != 0)
			break;
		mdelay(2);
		timeout--;
	};
	value = readl_relaxed(hdmi->regs + 0xe4);
	DRM_DEBUG("%s() hdmi pll lock status 0x%x\n", __func__, value);

	value = 0x1C208000 | bit_depth;
	writel(value, hdmi->regs + 0x28);
	DRM_DEBUG("%s() hdmi 0x28 0x%x\n", __func__, value);

	if (timeout == 0) {
		DRM_INFO("%s wait hdmi pll lock timeout\n", __func__);
		return -1;
	} else
		return 0;
}
static int spacemit_hdmi_setup(struct spacemit_hdmi *hdmi,
			       struct drm_display_mode *mode)
{
	void __iomem *ciu = (void __iomem *)ioremap(0xD4282C00, 0x200);
	struct hdmi_data_info *hdmi_data = hdmi->hdmi_data;
	int bit_depth = EIGHT_BPP;
	u32 value;
	int ret;

	DRM_DEBUG("%s() \n", __func__);

	// ciu chip id
	value = readl_relaxed(ciu);
	if (value == 0xa08501) {
		// default 10bpc
		bit_depth = TEN_BPP;

		// 08H, 09H: ID Manufacturer Nanme
		// 0AH, 0BH: ID Product Code
		if ((hdmi_data->edid[8] == 0x30) &&
		    (hdmi_data->edid[9] == 0xa3) &&
		    ((hdmi_data->edid[10] == 0x88) ||
		     (hdmi_data->edid[10] == 0x89)) &&
		    (hdmi_data->edid[11] == 0x23)) {
			// Lecoo HU20238FB0
			bit_depth = EIGHT_BPP;
		} else if ((hdmi_data->edid[8] == 0x26) &&
			   (hdmi_data->edid[9] == 0x01) &&
			   (hdmi_data->edid[10] == 0x12) &&
			   (hdmi_data->edid[11] == 0x24)) {
			// IPASON XC242-J
			bit_depth = EIGHT_BPP;
		} else if ((hdmi_data->edid[8] == 0x05) &&
			   (hdmi_data->edid[9] == 0xe3) &&
			   (hdmi_data->edid[10] == 0x90) &&
			   (hdmi_data->edid[11] == 0x24)) {
			// AOC Q2490W1
			bit_depth = EIGHT_BPP;
		}
	}

	if (bit_depth == EIGHT_BPP) {
		DRM_INFO("%s() id 0x%x, hdmi 8bpc \n", __func__, value);
	} else if (bit_depth == TEN_BPP) {
		DRM_INFO("%s() id 0x%x, hdmi 10bpc \n", __func__, value);
	}

	ret = hdmi_init(hdmi, hdmi->previous_mode.clock, bit_depth);
	if ((ret < 0) && (bit_depth == EIGHT_BPP)) {
		bit_depth = TEN_BPP;
		hdmi_init(hdmi, hdmi->previous_mode.clock, bit_depth);
	}

	spacemit_hdmi_config_video_timing(hdmi, mode);
	spacemit_hdmi_config_video_avi(hdmi, mode);
	spacemit_hdmi_config_video_vsi(hdmi, mode);

	iounmap(ciu);

	return 0;
}
static int hdmi_i2c_write(struct spacemit_hdmi *hdmi, uint8_t addr,
			  uint8_t *message, uint32_t length)
{
	int i, count = 0, left = length;
	uint8_t *pvalue = message;
	uint32_t value, reg;
	int timeout = 1000;

	DRM_DEBUG("hdmi_i2c_write ++ %u\r\n", length);

	do {
		if (left <= 16)
			count = left;
		else
			count = 16;
		left -= count;

		for (i = 0; i < count; i++) {
			value = *pvalue++;
			hdmi_writeb(hdmi, 0x0, value & 0xFF);
		}
		value = ((count - 1) << 8) + (addr << 1);

		hdmi_writeb(hdmi, 0x8, value & 0xFFFF);
		reg = hdmi_readb(hdmi, 0x0C);

		if (reg & BIT(16)) {
			DRM_INFO("hdmi_i2c_write  i2c ARB FAIL!!");
			return -1;
		}
	} while (left > 0);

	while (timeout) {
		if ((hdmi_readb(hdmi, 0x0C) & BIT(14)) != 0)
			break;

		udelay(100);
		timeout--;
	};

	if (timeout == 0) {
		DRM_INFO("%s wait hdmi ddc command done timeout\n", __func__);
		return -1;
	}
	udelay(100);

	DRM_DEBUG("hdmi_i2c_write --%u\r\n", length);

	return 0;
}

/* ------------------------------------------------------------------------- */
/* DRM bridge                                                                 */
/* ------------------------------------------------------------------------- */

static int spacemit_hdmi_bridge_attach(struct drm_bridge *bridge,
				       struct drm_encoder *encoder,
				       enum drm_bridge_attach_flags flags)
{
	struct spacemit_hdmi *hdmi = bridge_to_spacemit_hdmi(bridge);
	struct device_node *ep;
	int ret;

	if (!(flags & DRM_BRIDGE_ATTACH_NO_CONNECTOR))
		return -EINVAL;

	ep = of_graph_get_endpoint_by_regs(hdmi->dev->of_node, 0, -1);
	if (ep) {
		struct device_node *remote = of_graph_get_remote_port(ep);

		encoder->possible_crtcs =
			drm_of_crtc_port_mask(encoder->dev, remote);
		of_node_put(remote);
		of_node_put(ep);
	}

	if (hdmi->next_bridge) {
		ret = drm_bridge_attach(encoder, hdmi->next_bridge, bridge,
					DRM_BRIDGE_ATTACH_NO_CONNECTOR);
		if (ret)
			return ret;
	}

	return 0;
}

static enum drm_connector_status
spacemit_hdmi_bridge_detect(struct drm_bridge *bridge,
			    struct drm_connector *connector)
{
	struct spacemit_hdmi *hdmi = bridge_to_spacemit_hdmi(bridge);
	enum drm_connector_status status;

	mutex_lock(&hdmi->lock);
	if (hdmi->suspended) {
		mutex_unlock(&hdmi->lock);
		return connector_status_disconnected;
	}

	if (!hdmi_get_plug_in_status(hdmi)) {
		mutex_unlock(&hdmi->lock);
		return connector_status_disconnected;
	}

	/* Debounce the plug signal the same way the vendor driver does. */
	mdelay(2);
	if (!hdmi_get_plug_in_status(hdmi)) {
		mutex_unlock(&hdmi->lock);
		return connector_status_disconnected;
	}

	status = connector_status_connected;
	if (!hdmi->edid_done) {
		hdmi_i2c_timing(hdmi);
		spacemit_hdmi_ddc_quiesce(hdmi);
		if (edid_read(hdmi) < 0) {
			dev_dbg(hdmi->dev, "failed to read EDID\n");
			status = connector_status_connected;
		}
	}
	mutex_unlock(&hdmi->lock);

	return status;
}

static const struct drm_edid *
spacemit_hdmi_bridge_edid_read(struct drm_bridge *bridge,
			       struct drm_connector *connector)
{
	struct spacemit_hdmi *hdmi = bridge_to_spacemit_hdmi(bridge);
	const struct drm_edid *drm_edid;
	u32 blocks;

	if (!hdmi->edid_done) {
		hdmi_i2c_timing(hdmi);
		spacemit_hdmi_ddc_quiesce(hdmi);
		if (edid_read(hdmi) < 0)
			return NULL;
	}

	blocks = hdmi->hdmi_data->edid[0x7e] + 1;
	if (blocks > 2)
		blocks = 2;

	drm_edid = drm_edid_alloc(hdmi->hdmi_data->edid, blocks * EDID_LENGTH);
	if (IS_ERR(drm_edid))
		return NULL;

	drm_edid_connector_update(connector, drm_edid);

	return drm_edid;
}

static enum drm_mode_status
spacemit_hdmi_bridge_mode_valid(struct drm_bridge *bridge,
				const struct drm_display_info *info,
				const struct drm_display_mode *mode)
{
	if (mode->clock > 297000)
		return MODE_CLOCK_HIGH;

	if (mode->clock < 25000)
		return MODE_CLOCK_LOW;

	return MODE_OK;
}

static void spacemit_hdmi_bridge_atomic_enable(struct drm_bridge *bridge,
					       struct drm_atomic_commit *state)
{
	struct spacemit_hdmi *hdmi = bridge_to_spacemit_hdmi(bridge);
	struct drm_connector_state *conn_state;
	struct drm_crtc_state *crtc_state;
	struct drm_display_mode *mode;

	conn_state = drm_atomic_get_new_connector_state(state, hdmi->connector);
	if (!conn_state || !conn_state->crtc)
		return;

	crtc_state = drm_atomic_get_new_crtc_state(state, conn_state->crtc);
	if (!crtc_state)
		return;

	mode = &crtc_state->adjusted_mode;

	mutex_lock(&hdmi->lock);
	hdmi->previous_mode = *mode;
	spacemit_hdmi_setup(hdmi, mode);
	spacemit_hdmi_hpd_arm(hdmi);
	mutex_unlock(&hdmi->lock);

	/*
	 * Hot plug is only wired up once the pipeline has come up: the handler
	 * reads HDMI registers, and doing that before the block is running
	 * stalls the bus.
	 */
	if (!hdmi->irq_enabled) {
		hdmi->irq_enabled = true;
		enable_irq(hdmi->irq);
	}
}

static void spacemit_hdmi_bridge_atomic_disable(struct drm_bridge *bridge,
						struct drm_atomic_commit *state)
{
	/*
	 * The K1 HDMI block has no power-down path in the vendor sequence: the
	 * DPU stops scanning and the transmitter idles on its own.
	 */
}

/*
 * The bridge keeps no private atomic state, but the atomic helpers still
 * require the three state callbacks to allocate it.
 */
static struct drm_bridge_state *
spacemit_hdmi_bridge_atomic_create_state(struct drm_bridge *bridge)
{
	struct drm_bridge_state *state;

	state = kzalloc_obj(*state);
	if (!state)
		return ERR_PTR(-ENOMEM);

	__drm_atomic_helper_bridge_state_init(state, bridge);

	return state;
}

static struct drm_bridge_state *
spacemit_hdmi_bridge_atomic_duplicate_state(struct drm_bridge *bridge)
{
	struct drm_bridge_state *new;

	new = kzalloc_obj(*new);
	if (!new)
		return NULL;

	__drm_atomic_helper_bridge_duplicate_state(bridge, new);

	return new;
}

static void
spacemit_hdmi_bridge_atomic_destroy_state(struct drm_bridge *bridge,
					  struct drm_bridge_state *state)
{
	kfree(state);
}

static const struct drm_bridge_funcs spacemit_hdmi_bridge_funcs = {
	.attach = spacemit_hdmi_bridge_attach,
	.detect = spacemit_hdmi_bridge_detect,
	.edid_read = spacemit_hdmi_bridge_edid_read,
	.mode_valid = spacemit_hdmi_bridge_mode_valid,
	.atomic_create_state = spacemit_hdmi_bridge_atomic_create_state,
	.atomic_duplicate_state = spacemit_hdmi_bridge_atomic_duplicate_state,
	.atomic_destroy_state = spacemit_hdmi_bridge_atomic_destroy_state,
	.atomic_enable = spacemit_hdmi_bridge_atomic_enable,
	.atomic_disable = spacemit_hdmi_bridge_atomic_disable,
};

/* ------------------------------------------------------------------------- */
/* Hot plug                                                                   */
/* ------------------------------------------------------------------------- */

static irqreturn_t spacemit_hdmi_hardirq(int irq, void *dev_id)
{
	struct spacemit_hdmi *hdmi = dev_id;
	static int probes;
	u32 value;

	/* The hot plug bit lives in the PHY status register. */
	value = readl_relaxed(hdmi->regs + SPACEMIT_HDMI_PHY_STATUS);

	if (probes < 3) {
		probes++;
	}

	/*
	 * Acknowledge every latched source, not only HPD: the line is level
	 * triggered, so a DDC completion left pending keeps it asserted and
	 * the handler runs forever.  Only HPD needs the thread.
	 */
	writel_relaxed(value | SPACEMIT_HDMI_HPD_IQR | SPACEMIT_HDMI_DDC_DONE |
			       SPACEMIT_HDMI_DDC_NACK,
		       hdmi->regs + SPACEMIT_HDMI_PHY_STATUS);

	return (value & SPACEMIT_HDMI_HPD_IQR) ? IRQ_WAKE_THREAD : IRQ_HANDLED;
}

static irqreturn_t spacemit_hdmi_irq(int irq, void *dev_id)
{
	struct spacemit_hdmi *hdmi = dev_id;
	enum drm_connector_status status;

	mutex_lock(&hdmi->lock);
	hdmi->edid_done = false;
	mutex_unlock(&hdmi->lock);

	if (!hdmi->drm_dev)
		return IRQ_HANDLED;

	status = spacemit_hdmi_bridge_detect(&hdmi->bridge, NULL);
	drm_bridge_hpd_notify(&hdmi->bridge, status);

	return IRQ_HANDLED;
}

static const struct drm_encoder_funcs spacemit_hdmi_encoder_funcs = {
	.destroy = drm_encoder_cleanup,
};

static int spacemit_hdmi_bind(struct device *dev, struct device *master,
			      void *data)
{
	struct spacemit_hdmi *hdmi = dev_get_drvdata(dev);
	struct drm_device *drm = data;
	int ret;

	hdmi->drm_dev = drm;

	ret = drm_encoder_init(drm, &hdmi->encoder,
			       &spacemit_hdmi_encoder_funcs,
			       DRM_MODE_ENCODER_TMDS, NULL);
	if (ret)
		return ret;

	ret = drm_bridge_attach(&hdmi->encoder, &hdmi->bridge, NULL,
				DRM_BRIDGE_ATTACH_NO_CONNECTOR);
	if (ret)
		goto err_encoder;

	hdmi->connector = drm_bridge_connector_init(drm, &hdmi->encoder);
	if (IS_ERR(hdmi->connector)) {
		ret = PTR_ERR(hdmi->connector);
		goto err_encoder;
	}

	drm_connector_attach_encoder(hdmi->connector, &hdmi->encoder);

	return 0;

err_encoder:
	drm_encoder_cleanup(&hdmi->encoder);
	return ret;
}

static void spacemit_hdmi_unbind(struct device *dev, struct device *master,
				 void *data)
{
	struct spacemit_hdmi *hdmi = dev_get_drvdata(dev);

	disable_irq(hdmi->irq);
	drm_encoder_cleanup(&hdmi->encoder);
}

static const struct component_ops spacemit_hdmi_ops = {
	.bind = spacemit_hdmi_bind,
	.unbind = spacemit_hdmi_unbind,
};

static int spacemit_hdmi_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct spacemit_hdmi *hdmi;
	int ret;

	/*
	 * The bridge has to be allocated by the DRM bridge code: it embeds the
	 * reference counting devres that drm_bridge_add()/drm_bridge_put()
	 * rely on.
	 */
	hdmi = devm_drm_bridge_alloc(dev, struct spacemit_hdmi, bridge,
				     &spacemit_hdmi_bridge_funcs);
	if (IS_ERR(hdmi))
		return PTR_ERR(hdmi);
	hdmi->dev = dev;
	hdmi->suspended = false;
	mutex_init(&hdmi->lock);

	hdmi->hdmi_data =
		devm_kzalloc(dev, sizeof(*hdmi->hdmi_data), GFP_KERNEL);
	if (!hdmi->hdmi_data)
		return -ENOMEM;

	hdmi->regs = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(hdmi->regs))
		return PTR_ERR(hdmi->regs);

	hdmi->hdmi_mclk = devm_clk_get(dev, "hmclk");
	if (IS_ERR(hdmi->hdmi_mclk))
		return dev_err_probe(dev, PTR_ERR(hdmi->hdmi_mclk),
				     "failed to get hmclk\n");

	hdmi->irq = platform_get_irq(pdev, 0);
	if (hdmi->irq < 0)
		return hdmi->irq;

	/*
	 * The reset line belongs to the DPU: it deasserts it in
	 * dpu_pm_resume() before anything touches this block, and holding a
	 * second reference here would make that assert a no-op.
	 */
	ret = clk_prepare_enable(hdmi->hdmi_mclk);
	if (ret)
		return dev_err_probe(dev, ret, "failed to enable hmclk\n");

	dev_set_drvdata(dev, hdmi);

	hdmi->bridge.of_node = dev->of_node;
	hdmi->bridge.type = DRM_MODE_CONNECTOR_HDMIA;
	hdmi->bridge.ops = DRM_BRIDGE_OP_DETECT | DRM_BRIDGE_OP_EDID |
			   DRM_BRIDGE_OP_HPD;

	ret = devm_drm_bridge_add(dev, &hdmi->bridge);
	if (ret)
		return ret;

	ret = devm_request_threaded_irq(dev, hdmi->irq, spacemit_hdmi_hardirq,
					spacemit_hdmi_irq, IRQF_NO_AUTOEN,
					"spacemit-hdmi", hdmi);
	if (ret)
		return dev_err_probe(dev, ret, "failed to request HPD IRQ\n");

	return component_add(dev, &spacemit_hdmi_ops);
}

static void spacemit_hdmi_remove(struct platform_device *pdev)
{
	component_del(&pdev->dev, &spacemit_hdmi_ops);
}

static const struct of_device_id spacemit_hdmi_of_match[] = {
	{ .compatible = "spacemit,hdmi" },
	{},
};
MODULE_DEVICE_TABLE(of, spacemit_hdmi_of_match);

static struct platform_driver spacemit_hdmi_driver = {
	.probe	= spacemit_hdmi_probe,
	.remove	= spacemit_hdmi_remove,
	.driver	= {
		.name		= "spacemit-hdmi",
		.of_match_table	= spacemit_hdmi_of_match,
	},
};
module_platform_driver(spacemit_hdmi_driver);

MODULE_DESCRIPTION("SpacemiT K1 HDMI transmitter");
MODULE_LICENSE("GPL");
