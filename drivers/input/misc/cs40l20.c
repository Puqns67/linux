// SPDX-License-Identifier: GPL-2.0
/*
 * Cirrus Logic CS40L20 boosted haptic driver
 *
 * Copyright 2018 Cirrus Logic, Inc.
 * Copyright 2026 David Heidelberg <david@ixit.cz>
 *
 * Register layout, boost coefficients, errata and OTP trim tables come from
 * the downstream cs40l2x driver by Jeff LaBundy for Cirrus Logic.
 */

#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/delay.h>
#include <linux/firmware.h>
#include <linux/firmware/cirrus/cs_dsp.h>
#include <linux/firmware/cirrus/wmfw.h>
#include <linux/gpio/consumer.h>
#include <linux/i2c.h>
#include <linux/input.h>
#include <linux/int_log.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/property.h>
#include <linux/regmap.h>
#include <linux/regulator/consumer.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>

/* Registers */
#define CS40L20_DEVID			0x0
#define CS40L20_REVID			0x4
#define CS40L20_OTPID			0x10
#define CS40L20_TEST_KEY_CTL		0x40
#define CS40L20_CTRL_ASYNC1		0x54
#define CS40L20_OTP_MEM0		0x400
#define CS40L20_PWR_CTRL1		0x2014
#define CS40L20_PLL_LOOP_PARAM		0x3008
#define CS40L20_PLL_MISC_CTRL		0x3014
#define CS40L20_BSTCVRT_PEAK_CUR	0x3808
#define CS40L20_BSTCVRT_COEFF		0x3810
#define CS40L20_BSTCVRT_SLOPE_LBST	0x3814
#define CS40L20_BSTCVRT_DCM_CTRL	0x381c
#define CS40L20_DAC_PCM1_SRC		0x4c00
#define CS40L20_DSP1_RX2_SRC		0x4c44
#define CS40L20_DSP1_RX3_SRC		0x4c48
#define CS40L20_DSP1_RX4_SRC		0x4c4c
#define CS40L20_OTP_TRIM_30		0x7418
#define CS40L20_IRQ1_STATUS3		0x10018
#define CS40L20_IRQ1_STATUS4		0x1001c
#define CS40L20_IRQ1_DB3		0x10318
#define CS40L20_IRQ2_DB3		0x10b18
#define CS40L20_DSP_VIRT1_MBOX_1	0x13020
#define CS40L20_DSP_VIRT1_MBOX_2	0x13024
#define CS40L20_DSP1_XMEM_PACKED_0	0x2000000
#define CS40L20_DSP1_SYS_ID		0x25e0000
#define CS40L20_DSP1_XMEM_UNPACKED24_0	0x2800000
#define CS40L20_DSP1_CORE_BASE		0x2b80000
#define CS40L20_DSP1_YMEM_PACKED_0	0x2c00000
#define CS40L20_DSP1_YMEM_UNPACKED24_0	0x3400000
#define CS40L20_DSP1_PMEM_0		0x3800000
#define CS40L20_LASTREG			0x3804fe8

/* Fields */
#define CS40L20_DEVID_A			0x035a40
#define CS40L20_REVID_A0		0xa0
#define CS40L20_OTP_BOOT_ERR		BIT(31)
#define CS40L20_OTP_BOOT_DONE		BIT(1)
#define CS40L20_GLOBAL_EN		BIT(0)
#define CS40L20_TEST_KEY_UNLOCK1	0x55
#define CS40L20_TEST_KEY_UNLOCK2	0xaa
#define CS40L20_TEST_KEY_RELOCK1	0xcc
#define CS40L20_TEST_KEY_RELOCK2	0x33
#define CS40L20_NUM_OTP_WORDS		32
#define CS40L20_BST_K1_MASK		GENMASK(7, 0)
#define CS40L20_BST_K2_MASK		GENMASK(15, 8)
#define CS40L20_BST_SLOPE_MASK		GENMASK(15, 8)
#define CS40L20_BST_LBST_VAL_MASK	GENMASK(1, 0)
#define CS40L20_BST_IPK_MASK		GENMASK(6, 0)
#define CS40L20_BST_IPK_MIN_MA		1600
#define CS40L20_BST_IPK_MAX_MA		4500
#define CS40L20_BST_IPK_STEP_MA		50
#define CS40L20_BST_IPK_BASE		0x10
#define CS40L20_SRC_MASK		GENMASK(6, 0)
#define CS40L20_SRC_VMON		0x18
#define CS40L20_SRC_IMON		0x19
#define CS40L20_SRC_VPMON		0x28
#define CS40L20_SRC_DSP1TX1		0x32

/* Timings */
#define CS40L20_RESET_PULSE_US		2000
#define CS40L20_CP_READY_US		1000
#define CS40L20_OTP_POLL_US		10000
#define CS40L20_OTP_TIMEOUT_US		100000
#define CS40L20_DSP_POLL_US		10000
#define CS40L20_DSP_TIMEOUT_US		1000000

/* DSP firmware and controls */
#define CS40L20_FW			"cs40l20.wmfw"
#define CS40L20_WT			"cs40l20.bin"
/* Algorithm IDs of the CS40L20 firmware: FIRMWARE_HAPTICS and VIBEGEN */
#define CS40L20_ALG_FW			0x1400a7
#define CS40L20_ALG_VIBEGEN		0xbd
#define CS40L20_HALO_STATE_RUNNING	2
#define CS40L20_TIMEOUT_MS_MAX		0x02aaaa
#define CS40L20_ENDPLAYBACK_REQ		1
#define CS40L20_GPIO1_DISABLED		0
#define CS40L20_GAIN_CTRL_TRIG_MASK	GENMASK(13, 4)
#define CS40L20_DIG_SCALE_MAX		816	/* -102 dB, in 0.125 dB steps */
#define CS40L20_RUMBLE_INDEX		0	/* the firmware's built-in buzz */

/* Force feedback */
#define CS40L20_MAX_EFFECTS		1
#define CS40L20_CUSTOM_DATA_LEN		2
#define CS40L20_BANK_RAM		0

struct cs40l20_trim {
	u32 reg;
	u8 shift;
	u8 size;
};

struct cs40l20_otp_map {
	u8 id;
	u8 row_start;
	u8 col_start;
	unsigned int num_trims;
	const struct cs40l20_trim *trims;
};

struct cs40l20 {
	struct device *dev;
	struct regmap *regmap;
	struct cs_dsp dsp;
	struct gpio_desc *reset_gpio;
	const struct firmware *wmfw;
	/* Serialises effect upload/erase against the play worker */
	struct mutex lock;
	struct delayed_work play_work;
	atomic_t play_count;
	u32 endplayback_reg;
	u32 gain_reg;
	u32 num_waves;
	u32 index;
	u16 gain;
	bool rumble;
	unsigned int replay_ms;
};

static const struct cs40l20_trim cs40l20_trims_c[] = {
	/* addr         shift   size */
	{0x00002030,	0,	4}, /*TRIM_OSC_FREQ_TRIM*/
	{0x00002030,	7,	1}, /*TRIM_OSC_TRIM_DONE*/
	{0x0000208C,	24,	6}, /*TST_DIGREG_VREF_TRIM*/
	{0x00002090,	14,	4}, /*TST_REF_TRIM*/
	{0x00002090,	10,	4}, /*TST_REF_TEMPCO_TRIM*/
	{0x0000300C,	11,	4}, /*PLL_LDOA_TST_VREF_TRIM*/
	{0x0000394C,	23,	2}, /*BST_ATEST_CM_VOFF*/
	{0x00003950,	0,	7}, /*BST_ATRIM_IADC_OFFSET*/
	{0x00003950,	8,	7}, /*BST_ATRIM_IADC_GAIN1*/
	{0x00003950,	16,	8}, /*BST_ATRIM_IPKCOMP_OFFSET1*/
	{0x00003950,	24,	8}, /*BST_ATRIM_IPKCOMP_GAIN1*/
	{0x00003954,	0,	7}, /*BST_ATRIM_IADC_OFFSET2*/
	{0x00003954,	8,	7}, /*BST_ATRIM_IADC_GAIN2*/
	{0x00003954,	16,	8}, /*BST_ATRIM_IPKCOMP_OFFSET2*/
	{0x00003954,	24,	8}, /*BST_ATRIM_IPKCOMP_GAIN2*/
	{0x00003958,	0,	7}, /*BST_ATRIM_IADC_OFFSET3*/
	{0x00003958,	8,	7}, /*BST_ATRIM_IADC_GAIN3*/
	{0x00003958,	16,	8}, /*BST_ATRIM_IPKCOMP_OFFSET3*/
	{0x00003958,	24,	8}, /*BST_ATRIM_IPKCOMP_GAIN3*/
	{0x0000395C,	0,	7}, /*BST_ATRIM_IADC_OFFSET4*/
	{0x0000395C,	8,	7}, /*BST_ATRIM_IADC_GAIN4*/
	{0x0000395C,	16,	8}, /*BST_ATRIM_IPKCOMP_OFFSET4*/
	{0x0000395C,	24,	8}, /*BST_ATRIM_IPKCOMP_GAIN4*/
	{0x0000416C,	0,	8}, /*VMON_GAIN_OTP_VAL*/
	{0x00004160,	0,	7}, /*VMON_OFFSET_OTP_VAL*/
	{0x0000416C,	8,	8}, /*IMON_GAIN_OTP_VAL*/
	{0x00004160,	16,	10}, /*IMON_OFFSET_OTP_VAL*/
	{0x0000416C,	16,	12}, /*VMON_CM_GAIN_OTP_VAL*/
	{0x0000416C,	28,	1}, /*VMON_CM_GAIN_SIGN_OTP_VAL*/
	{0x00004170,	0,	6}, /*IMON_CAL_TEMPCO_OTP_VAL*/
	{0x00004170,	6,	1}, /*IMON_CAL_TEMPCO_SIGN_OTP*/
	{0x00004170,	8,	6}, /*IMON_CAL_TEMPCO2_OTP_VAL*/
	{0x00004170,	14,	1}, /*IMON_CAL_TEMPCO2_DN_UPB_OTP_VAL*/
	{0x00004170,	16,	9}, /*IMON_CAL_TEMPCO_TBASE_OTP_VAL*/
	{0x00004360,	0,	5}, /*TEMP_GAIN_OTP_VAL*/
	{0x00004360,	6,	9}, /*TEMP_OFFSET_OTP_VAL*/
	{0x00004448,	0,	8}, /*VP_SARADC_OFFSET*/
	{0x00004448,	8,	8}, /*VP_GAIN_INDEX*/
	{0x00004448,	16,	8}, /*VBST_SARADC_OFFSET*/
	{0x00004448,	24,	8}, /*VBST_GAIN_INDEX*/
	{0x0000444C,	0,	3}, /*ANA_SELINVREF*/
	{0x00006E30,	0,	5}, /*GAIN_ERR_COEFF_0*/
	{0x00006E30,	8,	5}, /*GAIN_ERR_COEFF_1*/
	{0x00006E30,	16,	5}, /*GAIN_ERR_COEFF_2*/
	{0x00006E30,	24,	5}, /*GAIN_ERR_COEFF_3*/
	{0x00006E34,	0,	5}, /*GAIN_ERR_COEFF_4*/
	{0x00006E34,	8,	5}, /*GAIN_ERR_COEFF_5*/
	{0x00006E34,	16,	5}, /*GAIN_ERR_COEFF_6*/
	{0x00006E34,	24,	5}, /*GAIN_ERR_COEFF_7*/
	{0x00006E38,	0,	5}, /*GAIN_ERR_COEFF_8*/
	{0x00006E38,	8,	5}, /*GAIN_ERR_COEFF_9*/
	{0x00006E38,	16,	5}, /*GAIN_ERR_COEFF_10*/
	{0x00006E38,	24,	5}, /*GAIN_ERR_COEFF_11*/
	{0x00006E3C,	0,	5}, /*GAIN_ERR_COEFF_12*/
	{0x00006E3C,	8,	5}, /*GAIN_ERR_COEFF_13*/
	{0x00006E3C,	16,	5}, /*GAIN_ERR_COEFF_14*/
	{0x00006E3C,	24,	5}, /*GAIN_ERR_COEFF_15*/
	{0x00006E40,	0,	5}, /*GAIN_ERR_COEFF_16*/
	{0x00006E40,	8,	5}, /*GAIN_ERR_COEFF_17*/
	{0x00006E40,	16,	5}, /*GAIN_ERR_COEFF_18*/
	{0x00006E40,	24,	5}, /*GAIN_ERR_COEFF_19*/
	{0x00006E44,	0,	5}, /*GAIN_ERR_COEFF_20*/
	{0x00006E48,	0,	10}, /*VOFF_GAIN_0*/
	{0x00006E48,	10,	10}, /*VOFF_GAIN_1*/
	{0x00006E48,	20,	10}, /*VOFF_GAIN_2*/
	{0x00006E4C,	0,	10}, /*VOFF_GAIN_3*/
	{0x00006E4C,	10,	10}, /*VOFF_GAIN_4*/
	{0x00006E4C,	20,	10}, /*VOFF_GAIN_5*/
	{0x00006E50,	0,	10}, /*VOFF_GAIN_6*/
	{0x00006E50,	10,	10}, /*VOFF_GAIN_7*/
	{0x00006E50,	20,	10}, /*VOFF_GAIN_8*/
	{0x00006E54,	0,	10}, /*VOFF_GAIN_9*/
	{0x00006E54,	10,	10}, /*VOFF_GAIN_10*/
	{0x00006E54,	20,	10}, /*VOFF_GAIN_11*/
	{0x00006E58,	0,	10}, /*VOFF_GAIN_12*/
	{0x00006E58,	10,	10}, /*VOFF_GAIN_13*/
	{0x00006E58,	20,	10}, /*VOFF_GAIN_14*/
	{0x00006E5C,	0,	10}, /*VOFF_GAIN_15*/
	{0x00006E5C,	10,	10}, /*VOFF_GAIN_16*/
	{0x00006E5C,	20,	10}, /*VOFF_GAIN_17*/
	{0x00006E60,	0,	10}, /*VOFF_GAIN_18*/
	{0x00006E60,	10,	10}, /*VOFF_GAIN_19*/
	{0x00006E60,	20,	10}, /*VOFF_GAIN_20*/
	{0x00006E64,	0,	10}, /*VOFF_INT1*/
	{0x00007418,	7,	5}, /*DS_SPK_INT1_CAP_TRIM*/
	{0x0000741C,	0,	5}, /*DS_SPK_INT2_CAP_TRIM*/
	{0x0000741C,	11,	4}, /*DS_SPK_LPF_CAP_TRIM*/
	{0x0000741C,	19,	4}, /*DS_SPK_QUAN_CAP_TRIM*/
	{0x00007434,	17,	1}, /*FORCE_CAL*/
	{0x00007434,	18,	7}, /*CAL_OVERRIDE*/
	{0x00007068,	0,	9}, /*MODIX*/
	{0x0000410C,	7,	1}, /*VIMON_DLY_NOT_COMB*/
	{0x0000400C,	0,	7}, /*VIMON_DLY*/
	{0x00000000,	0,	1}, /*extra bit*/
	{0x00017040,	0,	8}, /*X_COORDINATE*/
	{0x00017040,	8,	8}, /*Y_COORDINATE*/
	{0x00017040,	16,	8}, /*WAFER_ID*/
	{0x00017040,	24,	8}, /*DVS*/
	{0x00017044,	0,	24}, /*LOT_NUMBER*/
};

static const struct cs40l20_trim cs40l20_trims_d[] = {
	/* addr         shift   size */
	{0x00002030,	0,	4}, /*TRIM_OSC_FREQ_TRIM*/
	{0x00002030,	7,	1}, /*TRIM_OSC_TRIM_DONE*/
	{0x0000208C,	24,	6}, /*TST_DIGREG_VREF_TRIM*/
	{0x00002090,	14,	4}, /*TST_REF_TRIM*/
	{0x00002090,	10,	4}, /*TST_REF_TEMPCO_TRIM*/
	{0x0000300C,	11,	4}, /*PLL_LDOA_TST_VREF_TRIM*/
	{0x0000394C,	23,	2}, /*BST_ATEST_CM_VOFF*/
	{0x00003950,	0,	7}, /*BST_ATRIM_IADC_OFFSET*/
	{0x00003950,	8,	7}, /*BST_ATRIM_IADC_GAIN1*/
	{0x00003950,	16,	8}, /*BST_ATRIM_IPKCOMP_OFFSET1*/
	{0x00003950,	24,	8}, /*BST_ATRIM_IPKCOMP_GAIN1*/
	{0x00003954,	0,	7}, /*BST_ATRIM_IADC_OFFSET2*/
	{0x00003954,	8,	7}, /*BST_ATRIM_IADC_GAIN2*/
	{0x00003954,	16,	8}, /*BST_ATRIM_IPKCOMP_OFFSET2*/
	{0x00003954,	24,	8}, /*BST_ATRIM_IPKCOMP_GAIN2*/
	{0x00003958,	0,	7}, /*BST_ATRIM_IADC_OFFSET3*/
	{0x00003958,	8,	7}, /*BST_ATRIM_IADC_GAIN3*/
	{0x00003958,	16,	8}, /*BST_ATRIM_IPKCOMP_OFFSET3*/
	{0x00003958,	24,	8}, /*BST_ATRIM_IPKCOMP_GAIN3*/
	{0x0000395C,	0,	7}, /*BST_ATRIM_IADC_OFFSET4*/
	{0x0000395C,	8,	7}, /*BST_ATRIM_IADC_GAIN4*/
	{0x0000395C,	16,	8}, /*BST_ATRIM_IPKCOMP_OFFSET4*/
	{0x0000395C,	24,	8}, /*BST_ATRIM_IPKCOMP_GAIN4*/
	{0x0000416C,	0,	8}, /*VMON_GAIN_OTP_VAL*/
	{0x00004160,	0,	7}, /*VMON_OFFSET_OTP_VAL*/
	{0x0000416C,	8,	8}, /*IMON_GAIN_OTP_VAL*/
	{0x00004160,	16,	10}, /*IMON_OFFSET_OTP_VAL*/
	{0x0000416C,	16,	12}, /*VMON_CM_GAIN_OTP_VAL*/
	{0x0000416C,	28,	1}, /*VMON_CM_GAIN_SIGN_OTP_VAL*/
	{0x00004170,	0,	6}, /*IMON_CAL_TEMPCO_OTP_VAL*/
	{0x00004170,	6,	1}, /*IMON_CAL_TEMPCO_SIGN_OTP*/
	{0x00004170,	8,	6}, /*IMON_CAL_TEMPCO2_OTP_VAL*/
	{0x00004170,	14,	1}, /*IMON_CAL_TEMPCO2_DN_UPB_OTP_VAL*/
	{0x00004170,	16,	9}, /*IMON_CAL_TEMPCO_TBASE_OTP_VAL*/
	{0x00004360,	0,	5}, /*TEMP_GAIN_OTP_VAL*/
	{0x00004360,	6,	9}, /*TEMP_OFFSET_OTP_VAL*/
	{0x00004448,	0,	8}, /*VP_SARADC_OFFSET*/
	{0x00004448,	8,	8}, /*VP_GAIN_INDEX*/
	{0x00004448,	16,	8}, /*VBST_SARADC_OFFSET*/
	{0x00004448,	24,	8}, /*VBST_GAIN_INDEX*/
	{0x0000444C,	0,	3}, /*ANA_SELINVREF*/
	{0x00006E30,	0,	5}, /*GAIN_ERR_COEFF_0*/
	{0x00006E30,	8,	5}, /*GAIN_ERR_COEFF_1*/
	{0x00006E30,	16,	5}, /*GAIN_ERR_COEFF_2*/
	{0x00006E30,	24,	5}, /*GAIN_ERR_COEFF_3*/
	{0x00006E34,	0,	5}, /*GAIN_ERR_COEFF_4*/
	{0x00006E34,	8,	5}, /*GAIN_ERR_COEFF_5*/
	{0x00006E34,	16,	5}, /*GAIN_ERR_COEFF_6*/
	{0x00006E34,	24,	5}, /*GAIN_ERR_COEFF_7*/
	{0x00006E38,	0,	5}, /*GAIN_ERR_COEFF_8*/
	{0x00006E38,	8,	5}, /*GAIN_ERR_COEFF_9*/
	{0x00006E38,	16,	5}, /*GAIN_ERR_COEFF_10*/
	{0x00006E38,	24,	5}, /*GAIN_ERR_COEFF_11*/
	{0x00006E3C,	0,	5}, /*GAIN_ERR_COEFF_12*/
	{0x00006E3C,	8,	5}, /*GAIN_ERR_COEFF_13*/
	{0x00006E3C,	16,	5}, /*GAIN_ERR_COEFF_14*/
	{0x00006E3C,	24,	5}, /*GAIN_ERR_COEFF_15*/
	{0x00006E40,	0,	5}, /*GAIN_ERR_COEFF_16*/
	{0x00006E40,	8,	5}, /*GAIN_ERR_COEFF_17*/
	{0x00006E40,	16,	5}, /*GAIN_ERR_COEFF_18*/
	{0x00006E40,	24,	5}, /*GAIN_ERR_COEFF_19*/
	{0x00006E44,	0,	5}, /*GAIN_ERR_COEFF_20*/
	{0x00006E48,	0,	10}, /*VOFF_GAIN_0*/
	{0x00006E48,	10,	10}, /*VOFF_GAIN_1*/
	{0x00006E48,	20,	10}, /*VOFF_GAIN_2*/
	{0x00006E4C,	0,	10}, /*VOFF_GAIN_3*/
	{0x00006E4C,	10,	10}, /*VOFF_GAIN_4*/
	{0x00006E4C,	20,	10}, /*VOFF_GAIN_5*/
	{0x00006E50,	0,	10}, /*VOFF_GAIN_6*/
	{0x00006E50,	10,	10}, /*VOFF_GAIN_7*/
	{0x00006E50,	20,	10}, /*VOFF_GAIN_8*/
	{0x00006E54,	0,	10}, /*VOFF_GAIN_9*/
	{0x00006E54,	10,	10}, /*VOFF_GAIN_10*/
	{0x00006E54,	20,	10}, /*VOFF_GAIN_11*/
	{0x00006E58,	0,	10}, /*VOFF_GAIN_12*/
	{0x00006E58,	10,	10}, /*VOFF_GAIN_13*/
	{0x00006E58,	20,	10}, /*VOFF_GAIN_14*/
	{0x00006E5C,	0,	10}, /*VOFF_GAIN_15*/
	{0x00006E5C,	10,	10}, /*VOFF_GAIN_16*/
	{0x00006E5C,	20,	10}, /*VOFF_GAIN_17*/
	{0x00006E60,	0,	10}, /*VOFF_GAIN_18*/
	{0x00006E60,	10,	10}, /*VOFF_GAIN_19*/
	{0x00006E60,	20,	10}, /*VOFF_GAIN_20*/
	{0x00006E64,	0,	10}, /*VOFF_INT1*/
	{0x00007418,	7,	5}, /*DS_SPK_INT1_CAP_TRIM*/
	{0x0000741C,	0,	5}, /*DS_SPK_INT2_CAP_TRIM*/
	{0x0000741C,	11,	4}, /*DS_SPK_LPF_CAP_TRIM*/
	{0x0000741C,	19,	4}, /*DS_SPK_QUAN_CAP_TRIM*/
	{0x00007434,	17,	1}, /*FORCE_CAL*/
	{0x00007434,	18,	7}, /*CAL_OVERRIDE*/
	{0x00007068,	0,	9}, /*MODIX*/
	{0x0000410C,	7,	1}, /*VIMON_DLY_NOT_COMB*/
	{0x0000400C,	0,	7}, /*VIMON_DLY*/
	{0x00004000,	11,	1}, /*VMON_POL*/
	{0x00017040,	0,	8}, /*X_COORDINATE*/
	{0x00017040,	8,	8}, /*Y_COORDINATE*/
	{0x00017040,	16,	8}, /*WAFER_ID*/
	{0x00017040,	24,	8}, /*DVS*/
	{0x00017044,	0,	24}, /*LOT_NUMBER*/
};

static const struct cs40l20_trim cs40l20_trims_e[] = {
	/* addr         shift   size */
	{0x00002030,	0,	4}, /*TRIM_OSC_FREQ_TRIM*/
	{0x00002030,	7,	1}, /*TRIM_OSC_TRIM_DONE*/
	{0x0000208C,	24,	6}, /*TST_DIGREG_VREF_TRIM*/
	{0x00002090,	14,	4}, /*TST_REF_TRIM*/
	{0x00002090,	10,	4}, /*TST_REF_TEMPCO_TRIM*/
	{0x0000300C,	11,	4}, /*PLL_LDOA_TST_VREF_TRIM*/
	{0x0000394C,	23,	2}, /*BST_ATEST_CM_VOFF*/
	{0x00003950,	0,	7}, /*BST_ATRIM_IADC_OFFSET*/
	{0x00003950,	8,	7}, /*BST_ATRIM_IADC_GAIN1*/
	{0x00003950,	16,	8}, /*BST_ATRIM_IPKCOMP_OFFSET1*/
	{0x00003950,	24,	8}, /*BST_ATRIM_IPKCOMP_GAIN1*/
	{0x00003954,	0,	7}, /*BST_ATRIM_IADC_OFFSET2*/
	{0x00003954,	8,	7}, /*BST_ATRIM_IADC_GAIN2*/
	{0x00003954,	16,	8}, /*BST_ATRIM_IPKCOMP_OFFSET2*/
	{0x00003954,	24,	8}, /*BST_ATRIM_IPKCOMP_GAIN2*/
	{0x00003958,	0,	7}, /*BST_ATRIM_IADC_OFFSET3*/
	{0x00003958,	8,	7}, /*BST_ATRIM_IADC_GAIN3*/
	{0x00003958,	16,	8}, /*BST_ATRIM_IPKCOMP_OFFSET3*/
	{0x00003958,	24,	8}, /*BST_ATRIM_IPKCOMP_GAIN3*/
	{0x0000395C,	0,	7}, /*BST_ATRIM_IADC_OFFSET4*/
	{0x0000395C,	8,	7}, /*BST_ATRIM_IADC_GAIN4*/
	{0x0000395C,	16,	8}, /*BST_ATRIM_IPKCOMP_OFFSET4*/
	{0x0000395C,	24,	8}, /*BST_ATRIM_IPKCOMP_GAIN4*/
	{0x0000416C,	0,	8}, /*VMON_GAIN_OTP_VAL*/
	{0x00004160,	0,	7}, /*VMON_OFFSET_OTP_VAL*/
	{0x0000416C,	8,	8}, /*IMON_GAIN_OTP_VAL*/
	{0x00004160,	16,	10}, /*IMON_OFFSET_OTP_VAL*/
	{0x0000416C,	16,	12}, /*VMON_CM_GAIN_OTP_VAL*/
	{0x0000416C,	28,	1}, /*VMON_CM_GAIN_SIGN_OTP_VAL*/
	{0x00004170,	0,	6}, /*IMON_CAL_TEMPCO_OTP_VAL*/
	{0x00004170,	6,	1}, /*IMON_CAL_TEMPCO_SIGN_OTP*/
	{0x00004170,	8,	6}, /*IMON_CAL_TEMPCO2_OTP_VAL*/
	{0x00004170,	14,	1}, /*IMON_CAL_TEMPCO2_DN_UPB_OTP_VAL*/
	{0x00004170,	16,	9}, /*IMON_CAL_TEMPCO_TBASE_OTP_VAL*/
	{0x00004360,	0,	5}, /*TEMP_GAIN_OTP_VAL*/
	{0x00004360,	6,	9}, /*TEMP_OFFSET_OTP_VAL*/
	{0x00004448,	0,	8}, /*VP_SARADC_OFFSET*/
	{0x00004448,	8,	8}, /*VP_GAIN_INDEX*/
	{0x00004448,	16,	8}, /*VBST_SARADC_OFFSET*/
	{0x00004448,	24,	8}, /*VBST_GAIN_INDEX*/
	{0x0000444C,	0,	3}, /*ANA_SELINVREF*/
	{0x00006E30,	0,	5}, /*GAIN_ERR_COEFF_0*/
	{0x00006E30,	8,	5}, /*GAIN_ERR_COEFF_1*/
	{0x00006E30,	16,	5}, /*GAIN_ERR_COEFF_2*/
	{0x00006E30,	24,	5}, /*GAIN_ERR_COEFF_3*/
	{0x00006E34,	0,	5}, /*GAIN_ERR_COEFF_4*/
	{0x00006E34,	8,	5}, /*GAIN_ERR_COEFF_5*/
	{0x00006E34,	16,	5}, /*GAIN_ERR_COEFF_6*/
	{0x00006E34,	24,	5}, /*GAIN_ERR_COEFF_7*/
	{0x00006E38,	0,	5}, /*GAIN_ERR_COEFF_8*/
	{0x00006E38,	8,	5}, /*GAIN_ERR_COEFF_9*/
	{0x00006E38,	16,	5}, /*GAIN_ERR_COEFF_10*/
	{0x00006E38,	24,	5}, /*GAIN_ERR_COEFF_11*/
	{0x00006E3C,	0,	5}, /*GAIN_ERR_COEFF_12*/
	{0x00006E3C,	8,	5}, /*GAIN_ERR_COEFF_13*/
	{0x00006E3C,	16,	5}, /*GAIN_ERR_COEFF_14*/
	{0x00006E3C,	24,	5}, /*GAIN_ERR_COEFF_15*/
	{0x00006E40,	0,	5}, /*GAIN_ERR_COEFF_16*/
	{0x00006E40,	8,	5}, /*GAIN_ERR_COEFF_17*/
	{0x00006E40,	16,	5}, /*GAIN_ERR_COEFF_18*/
	{0x00006E40,	24,	5}, /*GAIN_ERR_COEFF_19*/
	{0x00006E44,	0,	5}, /*GAIN_ERR_COEFF_20*/
	{0x00006E48,	0,	10}, /*VOFF_GAIN_0*/
	{0x00006E48,	10,	10}, /*VOFF_GAIN_1*/
	{0x00006E48,	20,	10}, /*VOFF_GAIN_2*/
	{0x00006E4C,	0,	10}, /*VOFF_GAIN_3*/
	{0x00006E4C,	10,	10}, /*VOFF_GAIN_4*/
	{0x00006E4C,	20,	10}, /*VOFF_GAIN_5*/
	{0x00006E50,	0,	10}, /*VOFF_GAIN_6*/
	{0x00006E50,	10,	10}, /*VOFF_GAIN_7*/
	{0x00006E50,	20,	10}, /*VOFF_GAIN_8*/
	{0x00006E54,	0,	10}, /*VOFF_GAIN_9*/
	{0x00006E54,	10,	10}, /*VOFF_GAIN_10*/
	{0x00006E54,	20,	10}, /*VOFF_GAIN_11*/
	{0x00006E58,	0,	10}, /*VOFF_GAIN_12*/
	{0x00006E58,	10,	10}, /*VOFF_GAIN_13*/
	{0x00006E58,	20,	10}, /*VOFF_GAIN_14*/
	{0x00006E5C,	0,	10}, /*VOFF_GAIN_15*/
	{0x00006E5C,	10,	10}, /*VOFF_GAIN_16*/
	{0x00006E5C,	20,	10}, /*VOFF_GAIN_17*/
	{0x00006E60,	0,	10}, /*VOFF_GAIN_18*/
	{0x00006E60,	10,	10}, /*VOFF_GAIN_19*/
	{0x00006E60,	20,	10}, /*VOFF_GAIN_20*/
	{0x00006E64,	0,	10}, /*VOFF_INT1*/
	{0x00007418,	7,	5}, /*DS_SPK_INT1_CAP_TRIM*/
	{0x0000741C,	0,	5}, /*DS_SPK_INT2_CAP_TRIM*/
	{0x0000741C,	11,	4}, /*DS_SPK_LPF_CAP_TRIM*/
	{0x0000741C,	19,	4}, /*DS_SPK_QUAN_CAP_TRIM*/
	{0x00007434,	17,	1}, /*FORCE_CAL*/
	{0x00007434,	18,	7}, /*CAL_OVERRIDE*/
	{0x00007068,	0,	9}, /*MODIX*/
	{0x0000410C,	7,	1}, /*VIMON_DLY_NOT_COMB*/
	{0x0000400C,	0,	7}, /*VIMON_DLY*/
	{0x00004000,	11,	1}, /*VMON_POL*/
	{0x00017040,	0,	8}, /*X_COORDINATE*/
	{0x00017040,	8,	8}, /*Y_COORDINATE*/
	{0x00017040,	16,	8}, /*WAFER_ID*/
	{0x00017040,	24,	8}, /*DVS*/
	{0x00017044,	0,	24}, /*LOT_NUMBER*/
	{0x00003010,	2,	6}, /*PLL_DCO_CAL_TRIM*/
};

static const struct cs40l20_otp_map cs40l20_otp_maps[] = {
	{ 0xc, 2, 16, ARRAY_SIZE(cs40l20_trims_c), cs40l20_trims_c },
	{ 0xd, 2, 16, ARRAY_SIZE(cs40l20_trims_d), cs40l20_trims_d },
	{ 0xe, 2, 16, ARRAY_SIZE(cs40l20_trims_e), cs40l20_trims_e },
};

static const struct reg_sequence cs40l20_test_key_unlock[] = {
	{ CS40L20_TEST_KEY_CTL, CS40L20_TEST_KEY_UNLOCK1 },
	{ CS40L20_TEST_KEY_CTL, CS40L20_TEST_KEY_UNLOCK2 },
};

static const struct reg_sequence cs40l20_test_key_relock[] = {
	{ CS40L20_TEST_KEY_CTL, CS40L20_TEST_KEY_RELOCK1 },
	{ CS40L20_TEST_KEY_CTL, CS40L20_TEST_KEY_RELOCK2 },
};

static const struct reg_sequence cs40l20_rev_a0_errata[] = {
	{ CS40L20_OTP_TRIM_30,		0x9091a1c8 },
	{ CS40L20_PLL_LOOP_PARAM,	0x000c1837 },
	{ CS40L20_PLL_MISC_CTRL,	0x03008e0e },
	{ CS40L20_BSTCVRT_DCM_CTRL,	0x00000051 },
	{ CS40L20_CTRL_ASYNC1,		0x00000004 },
	{ CS40L20_IRQ1_DB3,		0x00000000 },
	{ CS40L20_IRQ2_DB3,		0x00000000 },
};

/* Indexed by inductor code, then capacitance bucket */
static const u8 cs40l20_bst_k1[4][5] = {
	{ 0x24, 0x32, 0x32, 0x4f, 0x57 },
	{ 0x24, 0x32, 0x32, 0x4f, 0x57 },
	{ 0x40, 0x32, 0x32, 0x4f, 0x57 },
	{ 0x40, 0x32, 0x32, 0x4f, 0x57 },
};

static const u8 cs40l20_bst_k2[4][5] = {
	{ 0x24, 0x49, 0x66, 0xa3, 0xea },
	{ 0x24, 0x49, 0x66, 0xa3, 0xea },
	{ 0x48, 0x49, 0x66, 0xa3, 0xea },
	{ 0x48, 0x49, 0x66, 0xa3, 0xea },
};

static const u8 cs40l20_bst_slope[4] = { 0x75, 0x6b, 0x3b, 0x28 };

static const struct reg_sequence cs40l20_routing[] = {
	{ CS40L20_DAC_PCM1_SRC,	CS40L20_SRC_DSP1TX1 },
	{ CS40L20_DSP1_RX2_SRC,	CS40L20_SRC_VMON },
	{ CS40L20_DSP1_RX3_SRC,	CS40L20_SRC_IMON },
	{ CS40L20_DSP1_RX4_SRC,	CS40L20_SRC_VPMON },
};

static const char * const cs40l20_supplies[] = {
	"vdd-a",
	"vdd-p",
};

static const struct regmap_config cs40l20_regmap = {
	.reg_bits = 32,
	.val_bits = 32,
	.reg_stride = 4,
	.reg_format_endian = REGMAP_ENDIAN_BIG,
	.val_format_endian = REGMAP_ENDIAN_BIG,
	.max_register = CS40L20_LASTREG,
};

static const struct cs_dsp_region cs40l20_dsp_regions[] = {
	{ .type = WMFW_HALO_PM_PACKED, .base = CS40L20_DSP1_PMEM_0 },
	{ .type = WMFW_HALO_XM_PACKED, .base = CS40L20_DSP1_XMEM_PACKED_0 },
	{ .type = WMFW_HALO_YM_PACKED, .base = CS40L20_DSP1_YMEM_PACKED_0 },
	{ .type = WMFW_ADSP2_XM, .base = CS40L20_DSP1_XMEM_UNPACKED24_0 },
	{ .type = WMFW_ADSP2_YM, .base = CS40L20_DSP1_YMEM_UNPACKED24_0 },
};

static int cs40l20_otp_unpack(struct cs40l20 *cs40l20)
{
	const struct cs40l20_otp_map *map = NULL;
	struct regmap *regmap = cs40l20->regmap;
	unsigned int row, col, val;
	int ret, i;

	ret = regmap_read(regmap, CS40L20_OTPID, &val);
	if (ret)
		return ret;

	for (i = 0; i < ARRAY_SIZE(cs40l20_otp_maps); i++)
		if (cs40l20_otp_maps[i].id == val)
			map = &cs40l20_otp_maps[i];

	/* Also rejects untrimmed devices, whose OTP ID reads as zero */
	if (!map)
		return dev_err_probe(cs40l20->dev, -ENODEV,
				     "Unrecognized OTP ID %#x\n", val);

	u32 *otp __free(kfree) = kmalloc_array(CS40L20_NUM_OTP_WORDS,
					       sizeof(*otp), GFP_KERNEL);
	if (!otp)
		return -ENOMEM;

	ret = regmap_bulk_read(regmap, CS40L20_OTP_MEM0, otp,
			       CS40L20_NUM_OTP_WORDS);
	if (ret)
		return ret;

	ret = regmap_multi_reg_write(regmap, cs40l20_test_key_unlock,
				     ARRAY_SIZE(cs40l20_test_key_unlock));
	if (ret)
		return ret;

	row = map->row_start;
	col = map->col_start;

	for (i = 0; i < map->num_trims; i++) {
		const struct cs40l20_trim *trim = &map->trims[i];

		if (col + trim->size > 32) {
			/* Trim straddles a word boundary */
			val = (otp[row] & GENMASK(31, col)) >> col;
			val |= (otp[row + 1] & GENMASK(col + trim->size - 33, 0))
				<< (32 - col);
		} else {
			val = (otp[row] & GENMASK(col + trim->size - 1, col)) >> col;
		}

		col += trim->size;
		if (col > 31) {
			col -= 32;
			row++;
		}

		/* Blank trims only advance the bit cursor */
		if (!trim->reg)
			continue;

		ret = regmap_update_bits(regmap, trim->reg,
					 GENMASK(trim->shift + trim->size - 1,
						 trim->shift),
					 val << trim->shift);
		if (ret)
			return ret;
	}

	return regmap_multi_reg_write(regmap, cs40l20_test_key_relock,
				      ARRAY_SIZE(cs40l20_test_key_relock));
}

static int cs40l20_boost_config(struct cs40l20 *cs40l20)
{
	struct device *dev = cs40l20->dev;
	unsigned int lbst, cbst;
	u32 ind, cap, ipk;
	int ret;

	ret = device_property_read_u32(dev, "cirrus,boost-ind-nanohenry", &ind);
	if (ret)
		return dev_err_probe(dev, ret, "Missing boost inductor value\n");

	ret = device_property_read_u32(dev, "cirrus,boost-cap-microfarad", &cap);
	if (ret)
		return dev_err_probe(dev, ret, "Missing boost capacitor value\n");

	ret = device_property_read_u32(dev, "cirrus,boost-peak-milliamp", &ipk);
	if (ret)
		return dev_err_probe(dev, ret, "Missing boost peak current\n");

	switch (ind) {
	case 1000:
		lbst = 0;
		break;
	case 1200:
		lbst = 1;
		break;
	case 1500:
		lbst = 2;
		break;
	case 2200:
		lbst = 3;
		break;
	default:
		return dev_err_probe(dev, -EINVAL,
				     "Invalid boost inductor value: %u nH\n", ind);
	}

	if (cap <= 19)
		cbst = 0;
	else if (cap <= 50)
		cbst = 1;
	else if (cap <= 100)
		cbst = 2;
	else if (cap <= 200)
		cbst = 3;
	else
		cbst = 4;

	if (ipk < CS40L20_BST_IPK_MIN_MA || ipk > CS40L20_BST_IPK_MAX_MA ||
	    ipk % CS40L20_BST_IPK_STEP_MA)
		return dev_err_probe(dev, -EINVAL,
				     "Invalid boost peak current: %u mA\n", ipk);

	ret = regmap_update_bits(cs40l20->regmap, CS40L20_BSTCVRT_COEFF,
				 CS40L20_BST_K1_MASK | CS40L20_BST_K2_MASK,
				 FIELD_PREP(CS40L20_BST_K1_MASK, cs40l20_bst_k1[lbst][cbst]) |
				 FIELD_PREP(CS40L20_BST_K2_MASK, cs40l20_bst_k2[lbst][cbst]));
	if (ret)
		return ret;

	ret = regmap_update_bits(cs40l20->regmap, CS40L20_BSTCVRT_SLOPE_LBST,
				 CS40L20_BST_SLOPE_MASK | CS40L20_BST_LBST_VAL_MASK,
				 FIELD_PREP(CS40L20_BST_SLOPE_MASK, cs40l20_bst_slope[lbst]) |
				 FIELD_PREP(CS40L20_BST_LBST_VAL_MASK, lbst));
	if (ret)
		return ret;

	ipk = (ipk - CS40L20_BST_IPK_MIN_MA) / CS40L20_BST_IPK_STEP_MA +
	      CS40L20_BST_IPK_BASE;

	return regmap_update_bits(cs40l20->regmap, CS40L20_BSTCVRT_PEAK_CUR,
				  CS40L20_BST_IPK_MASK,
				  FIELD_PREP(CS40L20_BST_IPK_MASK, ipk));
}

static int cs40l20_routing_config(struct cs40l20 *cs40l20)
{
	int ret, i;

	for (i = 0; i < ARRAY_SIZE(cs40l20_routing); i++) {
		ret = regmap_update_bits(cs40l20->regmap, cs40l20_routing[i].reg,
					 CS40L20_SRC_MASK, cs40l20_routing[i].def);
		if (ret)
			return ret;
	}

	return 0;
}

/*
 * Firmware controls are 24-bit words in unpacked XM. Their addresses are
 * looked up through cs_dsp once and then accessed directly: the firmware
 * clears ENDPLAYBACK after acting on it, which the cs_dsp control cache
 * would not see, so repeated requests would be dropped as unchanged, and
 * HALO_STATE is not flagged volatile, so reads through the cache would
 * never refresh.
 */
static int cs40l20_ctl_reg(struct cs40l20 *cs40l20, const char *name,
			   unsigned int alg, u32 *reg)
{
	struct cs_dsp_coeff_ctl *ctl;

	ctl = cs_dsp_get_ctl(&cs40l20->dsp, name, WMFW_ADSP2_XM, alg);
	if (!ctl) {
		dev_err(cs40l20->dev, "Control %s not found\n", name);
		return -ENOENT;
	}

	*reg = CS40L20_DSP1_XMEM_UNPACKED24_0 +
	       (ctl->alg_region.base + ctl->offset) * sizeof(u32);

	return 0;
}

static int cs40l20_ctl_write(struct cs40l20 *cs40l20, const char *name,
			     unsigned int alg, u32 val)
{
	u32 reg;
	int ret;

	ret = cs40l20_ctl_reg(cs40l20, name, alg, &reg);
	if (ret)
		return ret;

	return regmap_write(cs40l20->regmap, reg, val);
}

static int cs40l20_ctl_read(struct cs40l20 *cs40l20, const char *name,
			    unsigned int alg, u32 *val)
{
	u32 reg;
	int ret;

	ret = cs40l20_ctl_reg(cs40l20, name, alg, &reg);
	if (ret)
		return ret;

	return regmap_read(cs40l20->regmap, reg, val);
}

static int cs40l20_dsp_pre_run(struct cs_dsp *dsp)
{
	struct cs40l20 *cs40l20 = container_of(dsp, struct cs40l20, dsp);

	return regmap_set_bits(cs40l20->regmap, CS40L20_PWR_CTRL1,
			       CS40L20_GLOBAL_EN);
}

static int cs40l20_dsp_post_run(struct cs_dsp *dsp)
{
	struct cs40l20 *cs40l20 = container_of(dsp, struct cs40l20, dsp);
	unsigned int state = 0;
	u32 reg;
	int ret;

	ret = cs40l20_ctl_reg(cs40l20, "HALO_STATE", CS40L20_ALG_FW, &reg);
	if (ret)
		return ret;

	ret = regmap_read_poll_timeout(cs40l20->regmap, reg, state,
				       state == CS40L20_HALO_STATE_RUNNING,
				       CS40L20_DSP_POLL_US,
				       CS40L20_DSP_TIMEOUT_US);
	if (ret) {
		dev_err(cs40l20->dev, "DSP not running, state %u: %d\n",
			state, ret);
		return ret;
	}

	ret = cs40l20_ctl_write(cs40l20, "GPIO_ENABLE", CS40L20_ALG_FW,
				CS40L20_GPIO1_DISABLED);
	if (ret)
		return ret;

	ret = cs40l20_ctl_write(cs40l20, "TIMEOUT_MS", CS40L20_ALG_VIBEGEN,
				CS40L20_TIMEOUT_MS_MAX);
	if (ret)
		return ret;

	ret = cs40l20_ctl_read(cs40l20, "NUMBEROFWAVES", CS40L20_ALG_VIBEGEN,
			       &cs40l20->num_waves);
	if (ret)
		return ret;

	ret = cs40l20_ctl_reg(cs40l20, "ENDPLAYBACK", CS40L20_ALG_FW,
			      &cs40l20->endplayback_reg);
	if (ret)
		return ret;

	ret = cs40l20_ctl_reg(cs40l20, "GAIN_CONTROL", CS40L20_ALG_FW,
			      &cs40l20->gain_reg);
	if (ret)
		return ret;

	dev_info(cs40l20->dev, "%u wavetable entries\n", cs40l20->num_waves);

	return 0;
}

static const struct cs_dsp_client_ops cs40l20_dsp_ops = {
	.pre_run = cs40l20_dsp_pre_run,
	.post_run = cs40l20_dsp_post_run,
};

/* Attenuation in 0.125 dB steps for an amplitude of magnitude / 0xffff */
static u16 cs40l20_gain(u16 magnitude)
{
	u64 steps;

	if (!magnitude)
		return CS40L20_DIG_SCALE_MAX;

	/* 160 * log10(0xffff / magnitude); intlog10() returns a Q24 result */
	steps = (160ULL * (intlog10(0xffff) - intlog10(magnitude))) >> 24;

	return min_t(u64, steps, CS40L20_DIG_SCALE_MAX);
}

static void cs40l20_play_work(struct work_struct *work)
{
	struct cs40l20 *cs40l20 = container_of(work, struct cs40l20,
					       play_work.work);
	int count, ret;

	guard(mutex)(&cs40l20->lock);

	count = atomic_read(&cs40l20->play_count);
	if (count <= 0) {
		ret = regmap_write(cs40l20->regmap, cs40l20->endplayback_reg,
				   CS40L20_ENDPLAYBACK_REQ);
		if (ret)
			dev_err(cs40l20->dev, "Failed to stop playback: %d\n", ret);
		return;
	}

	/* Erased while a repeat was pending */
	if (!cs40l20->rumble && !cs40l20->index)
		return;

	ret = regmap_update_bits(cs40l20->regmap, cs40l20->gain_reg,
				 CS40L20_GAIN_CTRL_TRIG_MASK,
				 FIELD_PREP(CS40L20_GAIN_CTRL_TRIG_MASK,
					    cs40l20->gain));
	if (ret) {
		dev_err(cs40l20->dev, "Failed to set gain: %d\n", ret);
		return;
	}

	if (cs40l20->rumble) {
		ret = regmap_write(cs40l20->regmap, CS40L20_DSP_VIRT1_MBOX_2,
				   CS40L20_RUMBLE_INDEX);
		if (ret) {
			dev_err(cs40l20->dev, "Failed to start rumble: %d\n", ret);
			return;
		}

		/*
		 * The buzz runs until told to stop: come back after the effect
		 * length times the repeat count, or only when asked to stop.
		 */
		atomic_set(&cs40l20->play_count, 0);
		if (cs40l20->replay_ms) {
			u64 ms = min_t(u64, (u64)cs40l20->replay_ms * count,
				       UINT_MAX);

			queue_delayed_work(system_dfl_wq, &cs40l20->play_work,
					   msecs_to_jiffies(ms));
		}
		return;
	}

	ret = regmap_write(cs40l20->regmap, CS40L20_DSP_VIRT1_MBOX_1,
			   cs40l20->index);
	if (ret) {
		dev_err(cs40l20->dev, "Failed to trigger index %u: %d\n",
			cs40l20->index, ret);
		return;
	}

	if (atomic_dec_return(&cs40l20->play_count) > 0)
		queue_delayed_work(system_dfl_wq, &cs40l20->play_work,
				   msecs_to_jiffies(cs40l20->replay_ms));
}

static int cs40l20_ff_upload(struct input_dev *input, struct ff_effect *effect,
			     struct ff_effect *old)
{
	struct ff_periodic_effect *periodic = &effect->u.periodic;
	struct cs40l20 *cs40l20 = input_get_drvdata(input);
	s16 data[CS40L20_CUSTOM_DATA_LEN];
	u16 index = 0, gain = 0;
	bool rumble = false;

	switch (effect->type) {
	case FF_RUMBLE:
		rumble = true;
		gain = cs40l20_gain(max(effect->u.rumble.strong_magnitude,
					effect->u.rumble.weak_magnitude));
		break;
	case FF_PERIODIC:
		if (periodic->waveform != FF_CUSTOM) {
			dev_err(cs40l20->dev, "Waveform %#x unsupported\n",
				periodic->waveform);
			return -EINVAL;
		}

		if (periodic->custom_len != CS40L20_CUSTOM_DATA_LEN) {
			dev_err(cs40l20->dev, "Invalid custom data length %u\n",
				periodic->custom_len);
			return -EINVAL;
		}

		if (copy_from_user(data, periodic->custom_data, sizeof(data)))
			return -EFAULT;

		if (data[0] != CS40L20_BANK_RAM) {
			dev_err(cs40l20->dev, "Invalid bank %d\n", data[0]);
			return -EINVAL;
		}

		index = data[1];
		if (index < 1 || index >= cs40l20->num_waves) {
			dev_err(cs40l20->dev, "Index %u out of range 1..%u\n",
				index, cs40l20->num_waves - 1);
			return -EINVAL;
		}
		break;
	default:
		dev_err(cs40l20->dev, "Type %#x unsupported\n", effect->type);
		return -EINVAL;
	}

	guard(mutex)(&cs40l20->lock);

	cs40l20->rumble = rumble;
	cs40l20->index = index;
	cs40l20->gain = gain;
	cs40l20->replay_ms = effect->replay.length;

	return 0;
}

static int cs40l20_ff_erase(struct input_dev *input, int effect_id)
{
	struct cs40l20 *cs40l20 = input_get_drvdata(input);

	/* The core has already requested a stop; let it reach the hardware */
	flush_delayed_work(&cs40l20->play_work);

	guard(mutex)(&cs40l20->lock);

	cs40l20->index = 0;
	cs40l20->rumble = false;

	return 0;
}

/* Runs under the input event lock: no sleeping, no I/O */
static int cs40l20_ff_playback(struct input_dev *input, int effect_id,
			       int value)
{
	struct cs40l20 *cs40l20 = input_get_drvdata(input);

	atomic_set(&cs40l20->play_count, max(value, 0));
	mod_delayed_work(system_dfl_wq, &cs40l20->play_work, 0);

	return 0;
}

static void cs40l20_cancel_play(void *data)
{
	cancel_delayed_work_sync(data);
}

static int cs40l20_input_init(struct cs40l20 *cs40l20)
{
	struct input_dev *input;
	int ret;

	ret = devm_add_action_or_reset(cs40l20->dev, cs40l20_cancel_play,
				       &cs40l20->play_work);
	if (ret)
		return ret;

	input = devm_input_allocate_device(cs40l20->dev);
	if (!input)
		return -ENOMEM;

	input->name = "cs40l20";
	input->id.bustype = BUS_I2C;
	input_set_drvdata(input, cs40l20);
	input_set_capability(input, EV_FF, FF_PERIODIC);
	input_set_capability(input, EV_FF, FF_CUSTOM);
	input_set_capability(input, EV_FF, FF_RUMBLE);

	ret = input_ff_create(input, CS40L20_MAX_EFFECTS);
	if (ret)
		return ret;

	input->ff->upload = cs40l20_ff_upload;
	input->ff->erase = cs40l20_ff_erase;
	input->ff->playback = cs40l20_ff_playback;

	return input_register_device(input);
}

static void cs40l20_dsp_power_down(void *data)
{
	cs_dsp_power_down(data);
}

static void cs40l20_dsp_stop(void *data)
{
	cs_dsp_stop(data);
}

static void cs40l20_wavetable_loaded(const struct firmware *bin, void *context)
{
	struct cs40l20 *cs40l20 = context;
	struct device *dev = cs40l20->dev;
	int ret;

	/* The wavetable is optional; the DSP boots without it */
	ret = cs_dsp_power_up(&cs40l20->dsp, cs40l20->wmfw, CS40L20_FW, bin,
			      CS40L20_WT, "cs40l20");
	release_firmware(bin);
	release_firmware(cs40l20->wmfw);
	cs40l20->wmfw = NULL;
	if (ret) {
		dev_err(dev, "Failed to load firmware: %d\n", ret);
		return;
	}

	ret = devm_add_action_or_reset(dev, cs40l20_dsp_power_down, &cs40l20->dsp);
	if (ret)
		return;

	ret = cs_dsp_run(&cs40l20->dsp);
	if (ret) {
		dev_err(dev, "Failed to start DSP: %d\n", ret);
		return;
	}

	ret = devm_add_action_or_reset(dev, cs40l20_dsp_stop, &cs40l20->dsp);
	if (ret)
		return;

	ret = cs40l20_input_init(cs40l20);
	if (ret)
		dev_err(dev, "Failed to register input device: %d\n", ret);
}

static void cs40l20_firmware_loaded(const struct firmware *wmfw, void *context)
{
	struct cs40l20 *cs40l20 = context;
	int ret;

	if (!wmfw) {
		dev_err(cs40l20->dev, "Firmware %s not found\n", CS40L20_FW);
		return;
	}

	cs40l20->wmfw = wmfw;

	ret = request_firmware_nowait(THIS_MODULE, FW_ACTION_UEVENT, CS40L20_WT,
				      cs40l20->dev, GFP_KERNEL, cs40l20,
				      cs40l20_wavetable_loaded);
	if (ret) {
		dev_err(cs40l20->dev, "Failed to request %s: %d\n", CS40L20_WT, ret);
		release_firmware(wmfw);
		cs40l20->wmfw = NULL;
	}
}

static void cs40l20_dsp_remove(void *data)
{
	cs_dsp_remove(data);
}

static int cs40l20_dsp_init(struct cs40l20 *cs40l20)
{
	int ret;

	cs40l20->dsp.num = 1;
	cs40l20->dsp.type = WMFW_HALO;
	cs40l20->dsp.dev = cs40l20->dev;
	cs40l20->dsp.regmap = cs40l20->regmap;
	cs40l20->dsp.base = CS40L20_DSP1_CORE_BASE;
	cs40l20->dsp.base_sysinfo = CS40L20_DSP1_SYS_ID;
	cs40l20->dsp.mem = cs40l20_dsp_regions;
	cs40l20->dsp.num_mems = ARRAY_SIZE(cs40l20_dsp_regions);
	/*
	 * The firmware reaches device registers through the XM window; with
	 * the window and register regions locked, the MPU halts the core
	 * during initialisation (XM violation at 0xf1000).
	 */
	cs40l20->dsp.lock_regions = 0xffffffff;
	cs40l20->dsp.client_ops = &cs40l20_dsp_ops;

	ret = cs_dsp_halo_init(&cs40l20->dsp);
	if (ret)
		return ret;

	return devm_add_action_or_reset(cs40l20->dev, cs40l20_dsp_remove,
					&cs40l20->dsp);
}

static void cs40l20_reset_assert(void *data)
{
	gpiod_set_value_cansleep(data, 1);
}

static int cs40l20_probe(struct i2c_client *i2c)
{
	struct device *dev = &i2c->dev;
	unsigned int devid, revid, val;
	struct cs40l20 *cs40l20;
	int ret;

	cs40l20 = devm_kzalloc(dev, sizeof(*cs40l20), GFP_KERNEL);
	if (!cs40l20)
		return -ENOMEM;

	cs40l20->dev = dev;
	INIT_DELAYED_WORK(&cs40l20->play_work, cs40l20_play_work);

	ret = devm_mutex_init(dev, &cs40l20->lock);
	if (ret)
		return ret;

	cs40l20->regmap = devm_regmap_init_i2c(i2c, &cs40l20_regmap);
	if (IS_ERR(cs40l20->regmap))
		return dev_err_probe(dev, PTR_ERR(cs40l20->regmap),
				     "Failed to initialize regmap\n");

	ret = devm_regulator_bulk_get_enable(dev, ARRAY_SIZE(cs40l20_supplies),
					     cs40l20_supplies);
	if (ret)
		return dev_err_probe(dev, ret, "Failed to get supplies\n");

	cs40l20->reset_gpio = devm_gpiod_get(dev, "reset", GPIOD_OUT_HIGH);
	if (IS_ERR(cs40l20->reset_gpio))
		return dev_err_probe(dev, PTR_ERR(cs40l20->reset_gpio),
				     "Failed to get reset GPIO\n");

	usleep_range(CS40L20_RESET_PULSE_US, CS40L20_RESET_PULSE_US + 100);
	gpiod_set_value_cansleep(cs40l20->reset_gpio, 0);

	ret = devm_add_action_or_reset(dev, cs40l20_reset_assert,
				       cs40l20->reset_gpio);
	if (ret)
		return ret;

	usleep_range(CS40L20_CP_READY_US, CS40L20_CP_READY_US + 100);

	ret = regmap_read_poll_timeout(cs40l20->regmap, CS40L20_IRQ1_STATUS4, val,
				       val & CS40L20_OTP_BOOT_DONE,
				       CS40L20_OTP_POLL_US, CS40L20_OTP_TIMEOUT_US);
	if (ret)
		return dev_err_probe(dev, ret, "Timed out waiting for OTP boot\n");

	ret = regmap_read(cs40l20->regmap, CS40L20_IRQ1_STATUS3, &val);
	if (ret)
		return ret;

	if (val & CS40L20_OTP_BOOT_ERR)
		return dev_err_probe(dev, -EIO, "OTP boot error\n");

	ret = regmap_read(cs40l20->regmap, CS40L20_DEVID, &devid);
	if (ret)
		return ret;

	ret = regmap_read(cs40l20->regmap, CS40L20_REVID, &revid);
	if (ret)
		return ret;

	if (devid != CS40L20_DEVID_A || revid != CS40L20_REVID_A0)
		return dev_err_probe(dev, -ENODEV,
				     "Unsupported device %#x revision %#x\n",
				     devid, revid);

	ret = regmap_multi_reg_write(cs40l20->regmap, cs40l20_rev_a0_errata,
				     ARRAY_SIZE(cs40l20_rev_a0_errata));
	if (ret)
		return dev_err_probe(dev, ret, "Failed to apply errata\n");

	ret = cs40l20_otp_unpack(cs40l20);
	if (ret)
		return dev_err_probe(dev, ret, "Failed to unpack OTP trims\n");

	ret = cs40l20_boost_config(cs40l20);
	if (ret)
		return ret;

	ret = cs40l20_routing_config(cs40l20);
	if (ret)
		return dev_err_probe(dev, ret, "Failed to configure routing\n");

	ret = cs40l20_dsp_init(cs40l20);
	if (ret)
		return dev_err_probe(dev, ret, "Failed to initialize DSP\n");

	ret = request_firmware_nowait(THIS_MODULE, FW_ACTION_UEVENT, CS40L20_FW,
				      dev, GFP_KERNEL, cs40l20,
				      cs40l20_firmware_loaded);
	if (ret)
		return dev_err_probe(dev, ret, "Failed to request %s\n", CS40L20_FW);

	return 0;
}

static const struct of_device_id cs40l20_of_match[] = {
	{ .compatible = "cirrus,cs40l20" },
	{ }
};
MODULE_DEVICE_TABLE(of, cs40l20_of_match);

static const struct i2c_device_id cs40l20_id[] = {
	{ "cs40l20" },
	{ }
};
MODULE_DEVICE_TABLE(i2c, cs40l20_id);

static struct i2c_driver cs40l20_driver = {
	.driver = {
		.name = "cs40l20",
		.of_match_table = cs40l20_of_match,
	},
	.probe = cs40l20_probe,
	.id_table = cs40l20_id,
};
module_i2c_driver(cs40l20_driver);

MODULE_FIRMWARE(CS40L20_FW);
MODULE_FIRMWARE(CS40L20_WT);
MODULE_DESCRIPTION("Cirrus Logic CS40L20 haptic driver");
MODULE_AUTHOR("David Heidelberg <david@ixit.cz>");
MODULE_LICENSE("GPL");
MODULE_IMPORT_NS("FW_CS_DSP");
