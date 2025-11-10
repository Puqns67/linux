// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/slab.h>
/*
 * Copyright (C) 2014-2020 NXP Semiconductors, All Rights Reserved.
 * Copyright 2020 GOODIX
 */

#include "tfa_container.h"
#include "tfa98xx_tfafieldnames.h"
#include "tfa_dsp_fw.h"

#define TFA_API_SBFW_8_09_00 (31) /**< Corresponds to SB3.5 PRC2 release */
/* handle macro for bitfield */
#define TFA_MK_BF(reg, pos, len) ((reg << 8) | (pos << 4) | (len - 1))

/* abstract family for register */
#define FAM_TFA98XX_CF_CONTROLS (TFA_FAM(tfa, RST) >> 8)
#define FAM_TFA98XX_CF_MEM (TFA_FAM(tfa, MEMA) >> 8)
#define FAM_TFA98XX_MTP0 (TFA_FAM(tfa, MTPOTC) >> 8)
#define FAM_TFA98xx_INT_EN (TFA_FAM(tfa, INTENVDDS) >> 8)

#define CF_STATUS_I2C_CMD_ACK 0x01

/* Defines below are used for irq function (this removed the genregs include) */
#define TFA98XX_INTERRUPT_ENABLE_REG1 0x48
#define TFA98XX_INTERRUPT_IN_REG1 0x44
#define TFA98XX_INTERRUPT_OUT_REG1 0x40
#define TFA98XX_STATUS_POLARITY_REG1 0x4c
#define TFA98XX_KEY2_PROTECTED_MTP0_MTPEX_MSK 0x2
#define TFA98XX_KEY2_PROTECTED_MTP0_MTPOTC_MSK 0x1
#define TFA98XX_KEY2_PROTECTED_MTP0_MTPEX_POS 1
#define TFA98XX_KEY2_PROTECTED_MTP0_MTPOTC_POS 0
#define MIN_BATT_LEVEL 640
#define MAX_BATT_LEVEL 670

/* retry values */
#define CFSTABLE_TRIES 10
#define AMPOFFWAIT_TRIES 50
#define MTPBWAIT_TRIES 50
#define MTPEX_WAIT_NTRIES 50

/* calibration done executed */
/*
 * interrupt bit function to clear
 */
int tfa_irq_clear(struct tfa_device *tfa, enum tfa9912_irq bit)
{
	unsigned char reg;

	/* make bitfield enum */
	if (bit == tfa9912_irq_all) {
		/* operate on all bits */
		for (reg = TFA98XX_INTERRUPT_IN_REG1;
		     reg < TFA98XX_INTERRUPT_IN_REG1 + 3; reg++)
			tfa_reg_write(tfa, reg, 0xffff); /* all bits */
	} else if (bit < tfa9912_irq_max) {
		reg = (unsigned char)(TFA98XX_INTERRUPT_IN_REG1 + (bit >> 4));
		tfa_reg_write(tfa, reg, 1 << (bit & 0x0f)); /* only this bit */
	} else
		return -1;

	return 0;
}
/*
 * return state of irq or -1 if illegal bit
 */
int tfa_irq_get(struct tfa_device *tfa, enum tfa9912_irq bit)
{
	uint16_t value;
	int reg, mask;

	if (bit < tfa9912_irq_max) {
		/* only this bit */
		reg = TFA98XX_INTERRUPT_OUT_REG1 + (bit >> 4);
		mask = 1 << (bit & 0x0f);
		tfa_reg_read(tfa, (unsigned char)reg, &value);
	} else
		return -1;

	return (value & mask) != 0;
}
/*
 * interrupt bit function that operates on the shadow regs in the handle
 */

int tfa_irq_ena(struct tfa_device *tfa, enum tfa9912_irq bit, int state)
{
	uint16_t value, new_value;
	int reg = 0, mask;
	/* */
	if (bit == tfa9912_irq_all) {
		/* operate on all bits */
		for (reg = TFA98XX_INTERRUPT_ENABLE_REG1;
		     reg <=
		     TFA98XX_INTERRUPT_ENABLE_REG1 + tfa9912_irq_max / 16;
		     reg++) {
			tfa_reg_write(tfa, (unsigned char)reg,
				      state ? 0xffff : 0); /* all bits */
			tfa->interrupt_enable[reg -
					      TFA98XX_INTERRUPT_ENABLE_REG1] =
				state ? 0xffff : 0; /* all bits */
		}
	} else if (bit < tfa9912_irq_max) {
		/* only this bit */
		reg = TFA98XX_INTERRUPT_ENABLE_REG1 + (bit >> 4);
		mask = 1 << (bit & 0x0f);
		tfa_reg_read(tfa, (unsigned char)reg, &value);
		if (state) /* set */
			new_value = (uint16_t)(value | mask);
		else /* clear */
			new_value = value & ~mask;
		if (new_value != value) {
			tfa_reg_write(tfa, (unsigned char)reg,
				      new_value); /* only this bit */
			tfa->interrupt_enable[reg -
					      TFA98XX_INTERRUPT_ENABLE_REG1] =
				new_value;
		}
	} else
		return -1;

	return 0;
}

/*
 * mask interrupts by disabling them
 */
int tfa_irq_mask(struct tfa_device *tfa)
{
	int reg;

	/* operate on all bits */
	for (reg = TFA98XX_INTERRUPT_ENABLE_REG1;
	     reg <= TFA98XX_INTERRUPT_ENABLE_REG1 + tfa9912_irq_max / 16; reg++)
		tfa_reg_write(tfa, (unsigned char)reg, 0);

	return 0;
}

/*
 * unmask interrupts by enabling them again
 */
int tfa_irq_unmask(struct tfa_device *tfa)
{
	int reg;

	/* operate on all bits */
	for (reg = TFA98XX_INTERRUPT_ENABLE_REG1;
	     reg <= TFA98XX_INTERRUPT_ENABLE_REG1 + tfa9912_irq_max / 16; reg++)
		tfa_reg_write(
			tfa, (unsigned char)reg,
			tfa->interrupt_enable[reg -
					      TFA98XX_INTERRUPT_ENABLE_REG1]);

	return 0;
}

/*
 * interrupt bit function that sets the polarity
 */

int tfa_irq_set_pol(struct tfa_device *tfa, enum tfa9912_irq bit, int state)
{
	uint16_t value, new_value;
	int reg = 0, mask;

	if (bit == tfa9912_irq_all) {
		/* operate on all bits */
		for (reg = TFA98XX_STATUS_POLARITY_REG1;
		     reg <= TFA98XX_STATUS_POLARITY_REG1 + tfa9912_irq_max / 16;
		     reg++) {
			tfa_reg_write(tfa, (unsigned char)reg,
				      state ? 0xffff : 0); /* all bits */
		}
	} else if (bit < tfa9912_irq_max) {
		/* only this bit */
		reg = TFA98XX_STATUS_POLARITY_REG1 + (bit >> 4);
		mask = 1 << (bit & 0x0f);
		tfa_reg_read(tfa, (unsigned char)reg, &value);
		if (state) /* Active High */
			new_value = (uint16_t)(value | mask);
		else /* Active Low */
			new_value = value & ~mask;
		if (new_value != value) {
			tfa_reg_write(tfa, (unsigned char)reg,
				      new_value); /* only this bit */
		}
	} else
		return -1;

	return 0;
}

/*
 *	set device info and register device ops
 */
void tfa_set_query_info(struct tfa_device *tfa)
{
	/* invalidate device struct cached values */
	tfa->hw_feature_bits = -1;
	tfa->sw_feature_bits[0] = -1;
	tfa->sw_feature_bits[1] = -1;
	tfa->profile = -1;
	tfa->vstep = -1;
	/* defaults */
	tfa->is_probus_device = 0;
	tfa->advance_keys_handling = 0; /*artf65038*/
	tfa->daimap = Tfa98xx_DAI_I2S; /* all others */
	tfa->spkr_count = 1;
	tfa->spkr_select = 0;
	tfa->support_tcoef = supportYes;
	tfa->supportDrc = supportNotSet;
	tfa->support_saam = supportNotSet;
	tfa->ext_dsp =
		-1; /* respond to external DSP: -1:none, 0:no_dsp, 1:cold, 2:warm */
	tfa->bus = 0;
	tfa->partial_enable = 0;
	tfa->convert_dsp32 = 0;
	tfa->sync_iv_delay = 0;
	tfa->dynamicTDMmode =
		-1; /**tracking dynamic TDM setting from alsa input stream*/
	tfa->rate = 0;
	tfa->bitwidth = -1; /**bitwdith from alsa input stream*/

	/* TODO use the getfeatures() for retrieving the features [artf103523]
	tfa->supportDrc = supportNotSet;*/

	switch (tfa->rev & 0xff) {
	case 0x72:
		/* tfa9872 */
		tfa->supportDrc = supportYes;
		tfa->spkr_count = 1;
		tfa->is_probus_device = 1;
		tfa->daimap = Tfa98xx_DAI_TDM;
		tfa9872_ops(&tfa->dev_ops); /* register device operations */
				tfa->bf.swprofil = TFA9872_BF_SWPROFIL;
		tfa->bf.swvstep = TFA9872_BF_SWVSTEP;
		break;
	case 0x73:
		/* tfa9873 */
		tfa->supportDrc = supportYes;
		tfa->spkr_count = 1;
		tfa->is_probus_device = 1;
		tfa->advance_keys_handling = 1; /*artf65038*/
		tfa->daimap = Tfa98xx_DAI_TDM;
		tfa9873_ops(&tfa->dev_ops); /* register device operations */
				tfa->bf.swprofil = TFA9873_BF_SWPROFIL;
		tfa->bf.swvstep = TFA9873_BF_SWVSTEP;
		tfa->bf.mtpb = TFA9873_BF_MTPB;
		tfa->bf.clks = TFA9873_BF_CLKS;
		tfa->bf.openmtp = TFA9873_BF_OPENMTP;
		break;
	case 0x74:
		/* tfa9874 */
		tfa->supportDrc = supportYes;
		tfa->spkr_count = 1;
		tfa->is_probus_device = 1;
		tfa->daimap = Tfa98xx_DAI_TDM;
		tfa9874_ops(&tfa->dev_ops); /* register device operations */
				tfa->bf.swprofil = TFA9874_BF_SWPROFIL;
		tfa->bf.swvstep = TFA9874_BF_SWVSTEP;
		tfa->bf.mtpb = TFA9874_BF_MTPB;
		tfa->bf.clks = TFA9874_BF_CLKS;
		tfa->bf.openmtp = TFA9874_BF_OPENMTP;
		break;
	case 0x75:
		/* tfa9875 */
		tfa->supportDrc = supportYes;
		tfa->spkr_count = 1;
		tfa->is_probus_device = 1;
		tfa->advance_keys_handling = 1; /*artf65038*/
		tfa->daimap = Tfa98xx_DAI_TDM;
		tfa9875_ops(&tfa->dev_ops); /* register device operations */
				tfa->bf.swprofil = TFA9875_BF_SWPROFIL;
		tfa->bf.swvstep = TFA9875_BF_SWVSTEP;
		tfa->bf.mtpb = TFA9875_BF_MTPB;
		tfa->bf.clks = TFA9875_BF_CLKS;
		tfa->bf.openmtp = TFA9875_BF_OPENMTP;
		break;
	case 0x78:
		/* tfa9878 */
		tfa->supportDrc = supportYes;
		tfa->spkr_count = 1;
		tfa->is_probus_device = 1;
		tfa->advance_keys_handling = 1; /*artf65038*/
		tfa->daimap = Tfa98xx_DAI_TDM;
		tfa9878_ops(&tfa->dev_ops); /* register device operations */
				tfa->bf.swprofil = TFA9878_BF_SWPROFIL;
		tfa->bf.swvstep = TFA9878_BF_SWVSTEP;
		tfa->bf.mtpb = TFA9878_BF_MTPB;
		tfa->bf.clks = TFA9878_BF_CLKS;
		tfa->bf.openmtp = TFA9878_BF_OPENMTP;
		break;
	case 0x88:
		/* tfa9888 */
		tfa->spkr_count = 2;
		tfa->daimap = Tfa98xx_DAI_TDM;
		tfa9888_ops(&tfa->dev_ops); /* register device operations */
		break;
	case 0x13:
		/* tfa9912 */
		tfa->spkr_count = 1;
		tfa->daimap = Tfa98xx_DAI_TDM;
		tfa9912_ops(&tfa->dev_ops); /* register device operations */
		tfa->bf.swprofil = TFA9912_BF_SWPROFIL;
		tfa->bf.swvstep = TFA9912_BF_SWVSTEP;
				tfa->bf.swprofil = TFA9912_BF_SWPROFIL;
		tfa->bf.swvstep = TFA9912_BF_SWVSTEP;
		break;
	case 0x94:
		/* tfa9894 */
		tfa->spkr_count = 1;
		tfa->daimap = Tfa98xx_DAI_TDM;
		tfa9894_ops(&tfa->dev_ops); /* register device operations */
				tfa->bf.swprofil = TFA9894_BF_SWPROFIL;
		tfa->bf.swvstep = TFA9894_BF_SWVSTEP;
		tfa->bf.mtpb = TFA9894_BF_MTPB;
		tfa->bf.clks = TFA9894_BF_CLKS;
		tfa->bf.openmtp = TFA9894_BF_OPENMTP;
		break;

	default:
		pr_err("unknown device type : 0x%02x\n", tfa->rev);
		break;
	}
}

/*
 *	return the target address for the filter on this device

	filter_index:
	[0..9] reserved for EQ (not deployed, calc. is available)
	[10..12] anti-alias filter
	[13]	integrator filter

 */
enum Tfa98xx_DMEM tfa98xx_filter_mem(struct tfa_device *tfa, int filter_index,
				     unsigned short *address, int channel)
{
	enum Tfa98xx_DMEM dmem = -1;
	int idx;
	/* TFA9888 stereo biquad filter addresses */
	static const unsigned short bq_table[2][4] = {
		/* index: 10, 11, 12, 13 */
		{ 8832, 8837, 8842, 8847 }, /* 88 part1 (primary) */
		{ 8853, 8858, 8863, 8868 }, /* 88 part2 (secondary) */
	};

	if ((filter_index >= 10) && (filter_index <= 13)) {
		dmem = Tfa98xx_DMEM_YMEM; /* for all devices */
		idx = filter_index - 10;

		switch (tfa->rev & 0xff) { /* only compare lower byte */
		case 0x88:
			/* Channel 1 = primary, 2 = secondary */
			if (channel == 1)
				*address = bq_table[0][idx];
			else
				*address = bq_table[1][idx];
			break;
		default:
			return -1;
		}
	}
	return dmem;
}

/************************ query functions ********************************************************/

/*
 * tfa98xx_supported_saam
 *	returns the supportedspeaker as microphone feature
 */
enum tfa_error tfa98xx_supported_saam(struct tfa_device *tfa,
					  enum Tfa98xx_saam *saam)
{
	int features;
	enum tfa_error error;

	if (tfa->support_saam == supportNotSet) {
		error = tfa98xx_dsp_get_hw_feature_bits(tfa, &features);
		if (error != tfa_error_ok)
			return error;
		tfa->support_saam = (features & 0x8000) ?
					    supportYes :
					    supportNo; /* SAAM is bit15 */
	}
	*saam = tfa->support_saam == supportYes ? Tfa98xx_saam :
						  Tfa98xx_saam_none;

	return tfa_error_ok;
}

/*
 * tfa98xx_compare_features
 *	Obtains features_from_MTP and features_from_cnt
 */
enum tfa_error tfa98xx_compare_features(struct tfa_device *tfa,
					    int features_from_MTP[3],
					    int features_from_cnt[3])
{
	enum tfa_error error = tfa_error_ok;
	uint32_t value;
	uint16_t mtpbf;
	unsigned char bytes[3 * 2];
	int status;

	tfa98xx_dsp_system_stable(tfa, &status);
	if (!status)
		return tfa_error_noclock; /* Only test when we have a clock. */

	mtpbf = 0xf907; /* MTP9 for tfa2, 8 bits */

	/* Read HW features from MTP: */
	value = tfa_read_reg(tfa, mtpbf) & 0xffff;
	features_from_MTP[0] = tfa->hw_feature_bits = value;

	/* Read SW features: */
	error = tfa_dsp_cmd_id_write_read(tfa, MODULE_FRAMEWORK,
					  FW_PAR_ID_GET_FEATURE_INFO,
					  sizeof(bytes), bytes);
	if (error != tfa_error_ok)
		return error; /* old ROM code may respond with tfa_error_rpc_param_id */

	tfa98xx_convert_bytes2data(sizeof(bytes), bytes, &features_from_MTP[1]);

	/* check if feature bits from MTP match feature bits from cnt file: */
	tfa_get_hw_features_from_cnt(tfa, &features_from_cnt[0]);
	tfa_get_sw_features_from_cnt(tfa, &features_from_cnt[1]);

	return error;
}

/********************************* device specific ops ************************************************/

/* the ops wrapper for tfa98xx_dsp_SystemStable */
enum tfa_error tfa98xx_dsp_system_stable(struct tfa_device *tfa, int *ready)
{
	return (tfa->dev_ops.dsp_system_stable)(tfa, ready);
}

/*
 * bring the device into a state similar to reset
 */
enum tfa_error tfa98xx_init(struct tfa_device *tfa)
{
	enum tfa_error error = tfa_error_ok;
	uint16_t value = 0;

	/* reset all i2C registers to default
	 *	Write the register directly to avoid the read in the bitfield function.
	 *	The I2CR bit may overwrite the full register because it is reset anyway.
	 *	This will save a reg read transaction.
	 */
	TFA_SET_BF_VALUE(tfa, I2CR, 1, &value);
	TFA_WRITE_REG(tfa, I2CR, value);

	/* Put DSP in reset */
	tfa->dev_ops.dsp_reset(tfa, 1); /* in pair of tfaRunStartDSP() */

	/* some other registers must be set for optimal amplifier behaviour
	 * This is implemented in a file specific for the type number
	 */
	if (tfa->dev_ops.tfa_init)
		error = (tfa->dev_ops.tfa_init)(tfa);

	return error;
}

/** Set internal oscillator into power down mode.
 *
 *	@param[in] tfa device description structure
 *	@param[in] state new state 0 - oscillator is on, 1 oscillator is off.
 *
 *	@return tfa_error_ok when successful, error otherwise.
 */
static enum tfa_error tfa98xx_set_osc_powerdown(struct tfa_device *tfa, int state)
{
	if (tfa->dev_ops.set_osc_powerdown) {
		return tfa->dev_ops.set_osc_powerdown(tfa, state);
	}

	return tfa_error_not_implemented;
}

/** update low power mode of the device.
 *
 *	@param[in] tfa device description structure
 *	@param[in] state new state 0 - LPMODE is on, 1 LPMODE is off.
 *
 *	@return tfa_error_ok when successful, error otherwise.
 */
static enum tfa_error tfa98xx_update_lpm(struct tfa_device *tfa, int state)
{
	if (tfa->dev_ops.update_lpm) {
		return tfa->dev_ops.update_lpm(tfa, state);
	}

	return tfa_error_not_implemented;
}
/** Check presence of powerswitch=1 in configuration and optimal setting.
 *
 *	@param[in] tfa device description structure
 *
 *	@return -1 when error, 0 or 1 depends on switch settings.
 */
static int tfa98xx_powerswitch_is_enabled(struct tfa_device *tfa)
{
	uint16_t value;
	enum tfa_error ret;

	if (((tfa->rev & 0xff) == 0x13) || ((tfa->rev & 0xff) == 0x88)) {
		ret = tfa_reg_read(tfa, 0xc6, &value);
		if (ret != tfa_error_ok) {
			return -1;
		}
		/* PLMA5539: Check actual value of powerswitch. TODO: regmap v1.40 should make this bit public. */

		return (int)(value & (1u << 6));
	}

	return 1;
}

/********************* new tfa2 *********************************************************************/

/****************************** calibration support **************************/
/*
 * get/set the mtp with user controllable values
 *
 *	check if the relevant clocks are available
 */
enum tfa_error tfa98xx_get_mtp(struct tfa_device *tfa, uint16_t *value)
{
	int status;
	int result;

	/* not possible if PLL in powerdown */
	if (TFA_GET_BF(tfa, PWDN)) {
		pr_debug("PLL in powerdown\n");
		return tfa_error_noclock;
	}

	tfa98xx_dsp_system_stable(tfa, &status);
	if (status == 0) {
		pr_debug("PLL not running\n");
		return tfa_error_noclock;
	}

	result = TFA_READ_REG(tfa, MTP0);
	if (result < 0) {
		return -result;
	}
	*value = (uint16_t)result;

	return tfa_error_ok;
}

/*
 * lock or unlock KEY2
 *	lock = 1 will lock
 *	lock = 0 will unlock
 *
 *	note that on return all the hidden key will be off
 */
void tfa98xx_key2(struct tfa_device *tfa, int lock)
{
	/* unhide lock registers */
	tfa_reg_write(tfa, 0x0F, 0x5A6B);
	/* lock/unlock key2 MTPK */
	TFA_WRITE_REG(tfa, MTPKEY2, lock ? 0 : 0x5A);
	/* unhide lock registers */
	if (!tfa->advance_keys_handling) /*artf65038*/
		tfa_reg_write(tfa, 0x0F, 0);
}
static void tfa2_manual_mtp_cpy(struct tfa_device *tfa, uint16_t reg_row_to_keep,
			 uint16_t reg_row_to_set, uint8_t row) /* /MCH_TO_TEST */
{
	uint16_t value;
	int loop = 0;
	enum tfa_error error;
	/* Assure FAIM is enabled (enable it when neccesery) */
	if (tfa->is_probus_device) {
		error = tfa->dev_ops.faim_protect(tfa, 1);
		if (tfa->verbose) {
			pr_debug("FAIM enabled (err:%d).\n", error);
		}
	}
	tfa_reg_read(tfa, (unsigned char)reg_row_to_keep, &value);
	if (!row) {
		tfa_reg_write(tfa, 0xA7, value);
		tfa_reg_write(tfa, 0xA8, reg_row_to_set);
	} else {
		tfa_reg_write(tfa, 0xA7, reg_row_to_set);
		tfa_reg_write(tfa, 0xA8, value);
	}
	tfa_reg_write(tfa, 0xA3, 0x10 | row);
	if (tfa->is_probus_device) {
		/* Assure FAIM is enabled (enable it when neccesery) */
		for (loop = 0; loop < 100 /*x10ms*/; loop++) {
			msleep_interruptible(
				10); /* wait 10ms to avoid busload */
			if (tfa_dev_get_mtpb(tfa) == 0)
				break;
		}
		error = tfa->dev_ops.faim_protect(tfa, 0);
		if (tfa->verbose) {
			pr_debug("FAIM disabled (err:%d).\n", error);
		}
	}
}

enum tfa_error tfa98xx_set_mtp(struct tfa_device *tfa, uint16_t value,
				   uint16_t mask)
{
	unsigned short mtp_old, mtp_new;
	int loop, status;
	enum tfa_error error;

	error = tfa98xx_get_mtp(tfa, &mtp_old);

	if (error != tfa_error_ok)
		return error;

	mtp_new = (value & mask) | (mtp_old & ~mask);

	if (mtp_old == mtp_new) /* no change */ {
		if (tfa->verbose)
			pr_info("No change in MTP. Value not written!\n");
		return tfa_error_ok;
	}
	error = tfa98xx_update_lpm(tfa, 1);
	if (error) {
		return error;
	}
	/* Assure FAIM is enabled (enable it when neccesery) */
	error = tfa->dev_ops.faim_protect(tfa, 1);
	if (error) {
		return error;
	}
	if (tfa->verbose) {
		pr_debug("MTP clock enabled.\n");
	}

	/* assure that the clock is up, else we can't write MTP */
	error = tfa98xx_dsp_system_stable(tfa, &status);
	if (error) {
		return error;
	}
	if (status == 0) {
		return tfa_error_noclock;
	}

	tfa98xx_key2(tfa, 0); /* unlock */
	TFA_WRITE_REG(tfa, MTP0, mtp_new); /* write to i2c shadow reg */
	/* CIMTP=1 start copying all the data from i2c regs_mtp to mtp*/
	tfa2_manual_mtp_cpy(tfa, 0xF1, mtp_new, 0);
	/* wait until MTP write is done */
	error = tfa_error_timeout;
	for (loop = 0; loop < 100 /*x10ms*/; loop++) {
		msleep_interruptible(10); /* wait 10ms to avoid busload */
		if (tfa_dev_get_mtpb(tfa) == 0) {
			error = tfa_error_ok;
			break;
		}
	}
	tfa98xx_key2(tfa, 1); /* lock */
	/* MTP setting failed due to timeout ?*/
	if (error) {
		tfa->dev_ops.faim_protect(tfa, 0);
		return error;
	}

	/* Disable the FAIM, if this is necessary */
	error = tfa->dev_ops.faim_protect(tfa, 0);
	if (error) {
		return error;
	}
	if (tfa->verbose) {
		pr_debug("MTP clock disabled.\n");
	}
	error = tfa98xx_update_lpm(tfa, 0);
	if (error) {
		return error;
	}
	return error;
}

static short twos(short x)
{
	return (x < 0) ? x + 512 : x;
}

short tfa98xx_get_exttemp(struct tfa_device *tfa)
{
	short ext_temp = (short)TFA_GET_BF(tfa, EXTTS);

	return twos(ext_temp);
}

/************************** tfa simple bitfield interfacing ***************************************/

static enum tfa_error tfa98xx_set_mute(struct tfa_device *tfa,
						enum Tfa98xx_Mute mute)
{
	enum tfa_error error;

	if (tfa->dev_ops.set_mute == NULL)
		return tfa_error_not_supported;

	switch (mute) {
	case Tfa98xx_Mute_Off:
		error = tfa->dev_ops.set_mute(tfa, 0);
		TFA_SET_BF(tfa, AMPE, 1);
		break;
	case Tfa98xx_Mute_Amplifier:
	case Tfa98xx_Mute_Digital:
		error = tfa->dev_ops.set_mute(tfa, 1);
		TFA_SET_BF(tfa, AMPE, 0);
		break;
	default:
		return tfa_error_bad_param;
	}

	return error;
}

/****************** patching **********************************************************/
static enum tfa_error tfa98xx_process_patch_file(struct tfa_device *tfa,
						     int length,
						     const unsigned char *bytes)
{
	unsigned short size;
	int index = 0;
	enum tfa_error error = tfa_error_ok;

	while (index < length) {
		size = bytes[index] + bytes[index + 1] * 256;
		index += 2;
		if ((index + size) > length) {
			/* outside the buffer, error in the input data */
			return tfa_error_bad_param;
		}

		if (size > tfa->buffer_size) {
			/* too big, must fit buffer */
			return tfa_error_bad_param;
		}

		error = tfa98xx_write_raw(tfa, size, &bytes[index]);
		if (error != tfa_error_ok)
			break;
		index += size;
	}
	return error;
}

/* the patch contains a header with the following
 * IC revision register: 1 byte, 0xFF means don't care
 * XMEM address to check: 2 bytes, big endian, 0xFFFF means don't care
 * XMEM value to expect: 3 bytes, big endian
 */
static enum tfa_error
tfa98xx_check_ic_rom_version(struct tfa_device *tfa,
			     const unsigned char patchheader[])
{
	enum tfa_error error = tfa_error_ok;
	unsigned short checkrev, revid;
	unsigned char lsb_revid;
	unsigned short checkaddress;
	int checkvalue;
	int value = 0;
	int status;

	checkrev = patchheader[0];
	lsb_revid = tfa->rev & 0xff; /* only compare lower byte */

	if ((checkrev != 0xFF) && (checkrev != lsb_revid))
		return tfa_error_not_supported;

	checkaddress = (patchheader[1] << 8) + patchheader[2];
	checkvalue =
		(patchheader[3] << 16) + (patchheader[4] << 8) + patchheader[5];
	if (checkaddress != 0xFFFF) {
		/* before reading XMEM, check if we can access the DSP */
		error = tfa98xx_dsp_system_stable(tfa, &status);
		if (error == tfa_error_ok) {
			if (!status) {
				/* DSP subsys not running */
				error = tfa_error_dsp;
			}
		}
		/* read register to check the correct ROM version */
		if (error == tfa_error_ok) {
			error = tfa_mem_read(tfa, checkaddress, 1, &value);
		}
		if (error == tfa_error_ok) {
			if (value != checkvalue) {
				pr_err("patch file romid type check failed [0x%04x]: expected 0x%02x, actual 0x%02x\n",
				       checkaddress, value, checkvalue);
				error = tfa_error_not_supported;
			}
		}
	} else { /* == 0xffff */
		/* check if the revid subtype is in there */
		if (checkvalue != 0xFFFFFF && checkvalue != 0) {
			revid = patchheader[5] << 8 |
				patchheader[0]; /* full revid */
			if (revid != tfa->rev) {
				pr_err("patch file device type check failed: expected 0x%02x, actual 0x%02x\n",
				       tfa->rev, revid);
				return tfa_error_not_supported;
			}
		}
	}

	return error;
}

#define PATCH_HEADER_LENGTH 6
enum tfa_error tfa_dsp_patch(struct tfa_device *tfa, int patchLength,
				 const unsigned char *patchBytes)
{
	enum tfa_error error;
	int status;

	if (patchLength < PATCH_HEADER_LENGTH)
		return tfa_error_bad_param;

	error = tfa98xx_check_ic_rom_version(tfa, patchBytes);
	if (tfa_error_ok != error) {
		return error;
	}
	tfa98xx_dsp_system_stable(tfa, &status);
	if (!status)
		return tfa_error_noclock; /* Only test when we have a clock. */
	/******MCH_TO_TEST**************/
	if (error == tfa_error_ok) {
		error = tfaRunColdboot(tfa, 1);
		if (error)
			return tfa_error_dsp;
	}
	/**************************/
	error = tfa98xx_process_patch_file(tfa,
					   patchLength - PATCH_HEADER_LENGTH,
					   patchBytes + PATCH_HEADER_LENGTH);

	return error;
}

/******************	end patching **********************************************************/

enum tfa_error tfa98xx_wait_result(struct tfa_device *tfa,
						    int wait_retry_count)
{
	enum tfa_error error = tfa_error_ok;
	int cf_status; /* the contents of the CF_STATUS register */
	int tries = 0;

	do {
		cf_status = TFA_GET_BF(tfa, ACK);
		if (cf_status < 0)
			error = -cf_status;
		tries++;
	} while ((error == tfa_error_ok) &&
		 ((cf_status & CF_STATUS_I2C_CMD_ACK) == 0) &&
		 (tries < wait_retry_count));

	/* don't wait forever, DSP is pretty quick to respond (< 1ms) */
	if (tries >= wait_retry_count) {
		/* something wrong with communication with DSP */
		error = tfa_error_dsp;
	}
	return error;
}

/*
 * *	support functions for data conversion
 */
/**
	convert memory bytes to signed 24 bit integers
	input:	bytes contains "num_bytes" byte elements
	output: data contains "num_bytes/3" int24 elements
 */
void tfa98xx_convert_bytes2data(int num_bytes, const unsigned char bytes[],
				int data[])
{
	int i; /* index for data */
	int k; /* index for bytes */
	int d;
	int num_data = num_bytes / 3;

	for (i = 0, k = 0; i < num_data; ++i, k += 3) {
		d = (bytes[k] << 16) | (bytes[k + 1] << 8) | (bytes[k + 2]);
		if (bytes[k] & 0x80) /* sign bit was set */
			d = -((1 << 24) - d);

		data[i] = d;
	}
}

/**
 convert signed 32 bit integers to 24 bit aligned bytes
	input:	 data contains "num_data" int elements
	output:	bytes contains "3 * num_data" byte elements
 */
void tfa98xx_convert_data2bytes(int num_data, const int data[],
				unsigned char bytes[])
{
	int i; /* index for data */
	int k; /* index for bytes */
	int d;
	/* note: cannot just take the lowest 3 bytes from the 32 bit
	 * integer, because also need to take care of clipping any
	 * value > 2&23 */
	for (i = 0, k = 0; i < num_data; ++i, k += 3) {
		if (data[i] >= 0)
			d = min(data[i], (1 << 23) - 1);
		else {
			/* 2's complement */
			d = (1 << 24) - min(-data[i], 1 << 23);
		}
		bytes[k] = (d >> 16) & 0xFF; /* MSB */
		bytes[k + 1] = (d >> 8) & 0xFF;
		bytes[k + 2] = (d) & 0xFF; /* LSB */
	}
}

/*
 *	DSP RPC message support functions
 *	depending on framework to be up and running
 *	need base i2c of memaccess (tfa1=0x70/tfa2=0x90)
 */

/* write dsp messages in function tfa_dsp_msg_rpc() */
/*	note the 'old' write_parameter() was more efficient because all i2c was in one burst transaction */

/* TODO properly handle bitfields: state should be restored! (now it will change eg dmesg field to xmem) */
enum tfa_error tfa_dsp_msg_write(struct tfa_device *tfa, int length,
				     const char *buffer)
{
	int offset = 0;
	int chunk_size = ROUND_DOWN(tfa->buffer_size, 3); /* XMEM word size */
	int remaining_bytes = length;
	enum tfa_error error = tfa_error_ok;
	uint16_t cfctl;
	int value;

	value = TFA_READ_REG(tfa, DMEM);
	if (value < 0) {
		error = -value;
		return error;
	}
	cfctl = (uint16_t)value;
	/* assume no I2C errors from here */

	TFA_SET_BF_VALUE(tfa, DMEM, (uint16_t)Tfa98xx_DMEM_XMEM,
			 &cfctl); /* set cf ctl to DMEM	*/
	TFA_SET_BF_VALUE(tfa, AIF, 0, &cfctl); /* set to autoincrement */
	TFA_WRITE_REG(tfa, DMEM, cfctl);

	/* xmem[1] is start of message
		*	direct write to register to save cycles avoiding read-modify-write
		*/
	TFA_WRITE_REG(tfa, MADD, 1);

	/* due to autoincrement in cf_ctrl, next write will happen at
	 * the next address */
	while ((error == tfa_error_ok) && (remaining_bytes > 0)) {
		if (remaining_bytes < chunk_size)
			chunk_size = remaining_bytes;
		/* else chunk_size remains at initialize value above */
		error = tfa98xx_write_data(tfa, FAM_TFA98XX_CF_MEM, chunk_size,
					   (const unsigned char *)buffer +
						   offset);
		remaining_bytes -= chunk_size;
		offset += chunk_size;
	}

	/* notify the DSP */
	if (error == tfa_error_ok) {
		/* cf_int=0, cf_aif=0, cf_dmem=XMEM=01, cf_rst_dsp=0 */
		/* set the cf_req1 and cf_int bit */
		TFA_SET_BF_VALUE(tfa, REQCMD, 0x01, &cfctl); /* bit 0 */
		TFA_SET_BF_VALUE(tfa, CFINT, 1, &cfctl);
		error = -TFA_WRITE_REG(tfa, CFINT, cfctl);
	}

	return error;
}

/*
 * status function used by tfa_dsp_msg_rpc() to retrieve command/msg status:
 * return a <0 status of the DSP did not ACK.
 */
enum tfa_error tfa_dsp_msg_status(struct tfa_device *tfa, int *pRpcStatus)
{
	enum tfa_error error = tfa_error_ok;

	error = tfa98xx_wait_result(tfa, 2); /* 2 is only one try */
	if (error == tfa_error_dsp) {
		*pRpcStatus = -1;
		return tfa_error_ok;
	} else if (error != tfa_error_ok)
		return error;

	error = tfa98xx_check_rpc_status(tfa, pRpcStatus);

	return error;
}

const char *tfa98xx_get_i2c_status_id_string(int status)
{
	const char *p_id_str;

	switch (status) {
	case Tfa98xx_DSP_Not_Running:
		p_id_str = "No response from DSP";
		break;
	case Tfa98xx_I2C_Req_Done:
		p_id_str = "Ok";
		break;
	case Tfa98xx_I2C_Req_Busy:
		p_id_str = "Request is being processed";
		break;
	case Tfa98xx_I2C_Req_Invalid_M_ID:
		p_id_str = "Provided M-ID does not fit in valid rang [0..2]";
		break;
	case Tfa98xx_I2C_Req_Invalid_P_ID:
		p_id_str =
			"Provided P-ID is not valid in the given M-ID context";
		break;
	case Tfa98xx_I2C_Req_Invalid_CC:
		p_id_str =
			"Invalid channel configuration bits (SC|DS|DP|DC) combination";
		break;
	case Tfa98xx_I2C_Req_Invalid_Seq:
		p_id_str =
			"Invalid sequence of commands, in case the DSP expects some commands in a specific order";
		break;
	case Tfa98xx_I2C_Req_Invalid_Param:
		p_id_str = "Generic error, invalid parameter";
		break;
	case Tfa98xx_I2C_Req_Buffer_Overflow:
		p_id_str =
			"I2C buffer has overflowed: host has sent too many parameters, memory integrity is not guaranteed";
		break;
	case Tfa98xx_I2C_Req_Calib_Busy:
		p_id_str = "Calibration not completed";
		break;
	case Tfa98xx_I2C_Req_Calib_Failed:
		p_id_str = "Calibration failed";
		break;

	default:
		p_id_str = "Unspecified error";
	}

	return p_id_str;
}

enum tfa_error tfa_dsp_msg_read_rpc(struct tfa_device *tfa, int length,
					unsigned char *bytes)
{
	enum tfa_error error = tfa_error_ok;
	int burst_size; /* number of words per burst size */
	int bytes_per_word = 3;
	int num_bytes;
	int offset = 0;
	unsigned short start_offset = 2; /* msg starts @xmem[2] , [1]=cmd */

	if (length > TFA2_MAX_PARAM_SIZE)
		return tfa_error_bad_param;

	TFA_SET_BF(tfa, DMEM, (uint16_t)Tfa98xx_DMEM_XMEM);
	error = -TFA_WRITE_REG(tfa, MADD, start_offset);
	if (error != tfa_error_ok)
		return error;

	num_bytes = length; /* input param */
	while (num_bytes > 0) {
		burst_size = ROUND_DOWN(tfa->buffer_size, bytes_per_word);
		if (num_bytes < burst_size)
			burst_size = num_bytes;
		error = tfa98xx_read_data(tfa, FAM_TFA98XX_CF_MEM, burst_size,
					  bytes + offset);
		if (error != tfa_error_ok)
			return error;

		num_bytes -= burst_size;
		offset += burst_size;
	}

	return error;
}

enum tfa_error tfa_dsp_msg(struct tfa_device *tfa, int length24,
			       const char *buf24)
{
	enum tfa_error error = tfa_error_ok;
	int lastmessage = 0;
	uint8_t *blob;
	int i;
	int *intbuf = NULL;
	char *buf = (char *)buf24;
	int length = length24;

	if (tfa->convert_dsp32) {
		int idx = 0;

		length = 4 * length24 / 3;
		intbuf = kmem_cache_alloc(tfa->cachep, GFP_KERNEL);
		buf = (char *)intbuf;

		/* convert 24 bit DSP messages to a 32 bit integer */
		for (i = 0; i < length24; i += 3) {
			int tmp = (buf24[i] << 16) + (buf24[i + 1] << 8) +
				  buf24[i + 2];
			/* Sign extend to 32-bit from 24-bit */
			intbuf[idx++] = ((int32_t)tmp << 8) >> 8;
		}
	}

	/* Only create multi-msg when the dsp is cold */
	if (tfa->ext_dsp == 1) {
		/* Creating the multi-msg */
		error = tfa_tib_dsp_msgmulti(tfa, length, buf);
		if (error == tfa_error_fail)
			return tfa_error_fail;

		/* if the buffer is full we need to send the existing message and add the current message */
		if (error == tfa_error_buffer_too_small) {
			int len;

			/* (a) send the existing (full) message */
			blob = kmalloc(64 * 1024,
				       GFP_KERNEL); /* max length is 64k */
			len = tfa_tib_dsp_msgmulti(tfa, -1, (const char *)blob);
			if (tfa->verbose) {
				pr_debug(
					"Multi-message buffer full. Sending multi-message, length=%d\n",
					len);
			}
			if (tfa->has_msg == 0) /* via i2c */ {
				/* Send tot the target selected */
				error = (tfa->dev_ops.tfa_dsp_msg)(
					tfa, len, (const char *)blob);
			} else { /* via msg hal */
				error = tfa98xx_write_dsp(tfa, len,
							  (const char *)blob);
			}
			kfree(blob);

			/* (b) add the current DSP message to a new multi-message */
			error = tfa_tib_dsp_msgmulti(tfa, length, buf);
			if (error == tfa_error_fail) {
				return tfa_error_fail;
			}
		}

		lastmessage = error;

		/* When the lastmessage is done we can send the multi-msg to the target */
		if (lastmessage == 1) {
			/* Get the full multi-msg data */
			blob = kmalloc(64 * 1024,
				       GFP_KERNEL); /* max length is 64k */
			length = tfa_tib_dsp_msgmulti(tfa, -1,
						      (const char *)blob);

			if (tfa->verbose)
				pr_debug(
					"Last message for the multi-message received. Multi-message length=%d\n",
					length);

			if (tfa->has_msg == 0) /* via i2c */ {
				/* Send tot the target selected */
				error = (tfa->dev_ops.tfa_dsp_msg)(
					tfa, length, (const char *)blob);
			} else { /* via msg hal */
				error = tfa98xx_write_dsp(tfa, length,
							  (const char *)blob);
			}

			kfree(blob); /* Free the kmalloc blob */
			lastmessage = 0; /* reset to be able to re-start */
		}
	} else {
		if (tfa->has_msg == 0) /* via i2c */ {
			error = (tfa->dev_ops.tfa_dsp_msg)(tfa, length, buf);
		} else { /* via msg hal */
			error = tfa98xx_write_dsp(tfa, length,
						  (const char *)buf);
		}
	}

	if (error != tfa_error_ok)
		error = (enum tfa_error)(
			error +
			tfa_error_rpc_base); /* Get actual error code from softDSP */

	/* DSP verbose has argument 0x04 */
	if ((tfa->verbose & 0x04) != 0) {
		pr_debug("DSP w [%d]: ", length);
		for (i = 0; i < length; i++)
			pr_debug("0x%02x ", (uint8_t)buf[i]);
		pr_debug("\n");
	}

	if (tfa->convert_dsp32) {
		kmem_cache_free(tfa->cachep, intbuf);
	}

	return error;
}

enum tfa_error tfa_dsp_msg_read(struct tfa_device *tfa, int length24,
				    unsigned char *bytes24)
{
	enum tfa_error error = tfa_error_ok;
	int i;
	int length = length24;
	unsigned char *bytes = bytes24;

	if (tfa->convert_dsp32) {
		length = 4 * length24 / 3;
		bytes = kmem_cache_alloc(tfa->cachep, GFP_KERNEL);
	}

	if (tfa->has_msg == 0) /* via i2c */ {
		error = (tfa->dev_ops.tfa_dsp_msg_read)(tfa, length, bytes);
	} else { /* via msg hal */
		error = tfa98xx_read_dsp(tfa, length, bytes);
	}

	if (error != tfa_error_ok)
		error = (enum tfa_error)(
			error +
			tfa_error_rpc_base); /* Get actual error code from softDSP */

	/* DSP verbose has argument 0x04 */
	if ((tfa->verbose & 0x04) != 0) {
		pr_debug("DSP R [%d]: ", length);
		for (i = 0; i < length; i++)
			pr_debug("0x%02x ", (uint8_t)bytes[i]);
		pr_debug("\n");
	}

	if (tfa->convert_dsp32) {
		int idx = 0;

		/* convert 32 bit LE to 24 bit BE */
		for (i = 0; i < length; i += 4) {
			bytes24[idx++] = bytes[i + 2];
			bytes24[idx++] = bytes[i + 1];
			bytes24[idx++] = bytes[i + 0];
		}

		kmem_cache_free(tfa->cachep, bytes);
	}

	return error;
}

enum tfa_error tfa_reg_read(struct tfa_device *tfa,
				unsigned char subaddress, unsigned short *value)
{
	enum tfa_error error;

	error = (tfa->dev_ops.tfa_reg_read)(tfa, subaddress, value);
	if (error != tfa_error_ok)
		error = (enum tfa_error)(
			error +
			tfa_error_rpc_base); /* Get actual error code from softDSP */

	return error;
}

enum tfa_error tfa_reg_write(struct tfa_device *tfa,
				 unsigned char subaddress, unsigned short value)
{
	enum tfa_error error;

	error = (tfa->dev_ops.tfa_reg_write)(tfa, subaddress, value);
	if (error != tfa_error_ok)
		error = (enum tfa_error)(
			error +
			tfa_error_rpc_base); /* Get actual error code from softDSP */

	return error;
}

enum tfa_error tfa_mem_read(struct tfa_device *tfa,
				unsigned int start_offset, int num_words,
				int *pValues)
{
	enum tfa_error error;

	error = (tfa->dev_ops.tfa_mem_read)(tfa, start_offset, num_words,
					    pValues);
	if (error != tfa_error_ok)
		error = (enum tfa_error)(
			error +
			tfa_error_rpc_base); /* Get actual error code from softDSP */

	return error;
}

enum tfa_error tfa_mem_write(struct tfa_device *tfa, unsigned short address,
				 int value, int memtype)
{
	enum tfa_error error;

	error = (tfa->dev_ops.tfa_mem_write)(tfa, address, value, memtype);
	if (error != tfa_error_ok)
		error = (enum tfa_error)(
			error +
			tfa_error_rpc_base); /* Get actual error code from softDSP */

	return error;
}

/*
 *	write/read raw msg functions :
 *	the buffer is provided in little endian format, each word occupying 3 bytes, length is in bytes.
 *	The functions will return immediately and do not not wait for DSP response.
 */
#define MAX_WORDS (300)
enum tfa_error tfa_dsp_msg_rpc(struct tfa_device *tfa, int length,
				   const char *buf)
{
	enum tfa_error error;
	int tries, rpc_status = Tfa98xx_I2C_Req_Done;

	/* write the message and notify the DSP */
	error = tfa_dsp_msg_write(tfa, length, buf);
	if (error != tfa_error_ok)
		return error;

	/* get the result from the DSP (polling) */
	for (tries = TFA98XX_WAITRESULT_NTRIES; tries > 0; tries--) {
		error = tfa_dsp_msg_status(tfa, &rpc_status);
		if (error == tfa_error_ok &&
		    rpc_status == Tfa98xx_I2C_Req_Done)
			break;
		/* If the rpc status is a specific error we want to know it.
		 * If it is busy or not running it should retry
		 */
		if (rpc_status != Tfa98xx_I2C_Req_Busy &&
		    rpc_status != Tfa98xx_DSP_Not_Running)
			break;
	}

	if (rpc_status != Tfa98xx_I2C_Req_Done) {
		/* DSP RPC call returned an error */
		error = (enum tfa_error)(rpc_status +
					     tfa_error_rpc_base);
		pr_debug("DSP msg status: %d (%s)\n", rpc_status,
			 tfa98xx_get_i2c_status_id_string(rpc_status));
	}
	return error;
}

/* read the return code for the RPC call */
enum tfa_error tfa98xx_check_rpc_status(struct tfa_device *tfa,
							 int *pRpcStatus)
{
	enum tfa_error error = tfa_error_ok;
	/* the value to sent to the * CF_CONTROLS register: cf_req=00000000,
	 * cf_int=0, cf_aif=0, cf_dmem=XMEM=01, cf_rst_dsp=0 */
	unsigned short cf_ctrl = 0x0002;
	/* memory address to be accessed (0: Status, 1: ID, 2: parameters) */
	unsigned short cf_mad = 0x0000;

	if (pRpcStatus == NULL)
		return tfa_error_bad_param;

	/* 1) write DMEM=XMEM to the DSP XMEM */
	{
		/* minimize the number of I2C transactions by making use of the autoincrement in I2C */
		unsigned char buffer[4];
		/* first the data for CF_CONTROLS */
		buffer[0] = (unsigned char)((cf_ctrl >> 8) & 0xFF);
		buffer[1] = (unsigned char)(cf_ctrl & 0xFF);
		/* write the contents of CF_MAD which is the subaddress following CF_CONTROLS */
		buffer[2] = (unsigned char)((cf_mad >> 8) & 0xFF);
		buffer[3] = (unsigned char)(cf_mad & 0xFF);
		error = tfa98xx_write_data(tfa, FAM_TFA98XX_CF_CONTROLS,
					   sizeof(buffer), buffer);
	}
	if (error == tfa_error_ok) {
		/* read 1 word (24 bit) from XMEM */
		error = tfa98xx_dsp_read_mem(tfa, 0, 1, pRpcStatus);
	}

	return error;
}

/***************************** xmem only **********************************/
enum tfa_error tfa98xx_dsp_read_mem(struct tfa_device *tfa,
					unsigned int start_offset,
					int num_words, int *pValues)
{
	enum tfa_error error = tfa_error_ok;
	unsigned char *bytes;
	int burst_size; /* number of words per burst size */
	const int bytes_per_word = 3;
	int dmem;
	int num_bytes;
	int *p;

	bytes = (unsigned char *)kmem_cache_alloc(tfa->cachep, GFP_KERNEL);
	if (bytes == NULL)
		return tfa_error_fail;

	/* If no offset is given, assume XMEM! */
	if (((start_offset >> 16) & 0xf) > 0)
		dmem = (start_offset >> 16) & 0xf;
	else
		dmem = Tfa98xx_DMEM_XMEM;

	/* Remove offset from address */
	start_offset = start_offset & 0xffff;
	num_bytes = num_words * bytes_per_word;
	p = pValues;

	TFA_SET_BF(tfa, DMEM, (uint16_t)dmem);
	error = -TFA_WRITE_REG(tfa, MADD, (unsigned short)start_offset);
	if (error != tfa_error_ok)
		goto tfa98xx_dsp_read_mem_exit;

	for (; num_bytes > 0;) {
		burst_size = ROUND_DOWN(tfa->buffer_size, bytes_per_word);
		if (num_bytes < burst_size)
			burst_size = num_bytes;

		error = tfa98xx_read_data(tfa, FAM_TFA98XX_CF_MEM, burst_size,
					  bytes);
		if (error != tfa_error_ok)
			goto tfa98xx_dsp_read_mem_exit;

		tfa98xx_convert_bytes2data(burst_size, bytes, p);

		num_bytes -= burst_size;
		p += burst_size / bytes_per_word;
	}

tfa98xx_dsp_read_mem_exit:
	kmem_cache_free(tfa->cachep, bytes);

	return error;
}

enum tfa_error tfa98xx_dsp_write_mem_word(struct tfa_device *tfa,
					      unsigned short address, int value,
					      int memtype)
{
	enum tfa_error error = tfa_error_ok;
	unsigned char bytes[3];

	TFA_SET_BF(tfa, DMEM, (uint16_t)memtype);

	error = -TFA_WRITE_REG(tfa, MADD, address);
	if (error != tfa_error_ok)
		return error;

	tfa98xx_convert_data2bytes(1, &value, bytes);
	error = tfa98xx_write_data(tfa, FAM_TFA98XX_CF_MEM, 3, bytes);

	return error;
}

enum tfa_error tfa_cont_write_filterbank(struct tfa_device *tfa,
					     struct TfaFilter *filter)
{
	unsigned char biquad_index;
	enum tfa_error error = tfa_error_ok;

	for (biquad_index = 0; biquad_index < 10; biquad_index++) {
		if (filter[biquad_index].enabled) {
			error = tfa_dsp_cmd_id_write(
				tfa, MODULE_BIQUADFILTERBANK,
				biquad_index + 1, /* start @1 */
				sizeof(filter[biquad_index].biquad.bytes),
				filter[biquad_index].biquad.bytes);
		} else {
			error = Tfa98xx_DspBiquad_Disable(tfa,
							  biquad_index + 1);
		}
		if (error)
			return error;
	}

	return error;
}

enum tfa_error Tfa98xx_DspBiquad_Disable(struct tfa_device *tfa,
					     int biquad_index)
{
	enum tfa_error error = tfa_error_ok;
	int coeff_buffer[BIQUAD_COEFF_SIZE];
	unsigned char bytes[3 + BIQUAD_COEFF_SIZE * 3];
	int nr = 0;

	if (biquad_index > TFA98XX_BIQUAD_NUM)
		return tfa_error_bad_param;
	if (biquad_index < 1)
		return tfa_error_bad_param;

	/* make opcode */
	bytes[nr++] = 0;
	bytes[nr++] = MODULE_BIQUADFILTERBANK + 128;
	bytes[nr++] = (unsigned char)biquad_index;

	/* set in correct order and format for the DSP */
	coeff_buffer[0] = (int)-8388608; /* -1.0f */
	coeff_buffer[1] = 0;
	coeff_buffer[2] = 0;
	coeff_buffer[3] = 0;
	coeff_buffer[4] = 0;
	coeff_buffer[5] = 0;

	/* convert to packed 24 */
	tfa98xx_convert_data2bytes(BIQUAD_COEFF_SIZE, coeff_buffer, &bytes[nr]);
	nr += BIQUAD_COEFF_SIZE * 3;

	error = tfa_dsp_msg(tfa, nr, (char *)bytes);

	return error;
}

/* wrapper for tfa_dsp_msg that adds opcode */
enum tfa_error tfa_dsp_cmd_id_write(struct tfa_device *tfa,
					unsigned char module_id,
					unsigned char param_id, int num_bytes,
					const unsigned char data[])
{
	enum tfa_error error;
	unsigned char *buffer;
	int nr = 0;

	buffer = kmem_cache_alloc(tfa->cachep, GFP_KERNEL);
	if (buffer == NULL)
		return tfa_error_fail;

	buffer[nr++] = tfa->spkr_select;
	buffer[nr++] = module_id + 128;
	buffer[nr++] = param_id;

	memcpy(&buffer[nr], data, num_bytes);
	nr += num_bytes;

	error = tfa_dsp_msg(tfa, nr, (char *)buffer);

	kmem_cache_free(tfa->cachep, buffer);

	return error;
}

/* wrapper for tfa_dsp_msg that adds opcode */
/* this is as the former tfa98xx_dsp_get_param() */
enum tfa_error tfa_dsp_cmd_id_write_read(struct tfa_device *tfa,
					     unsigned char module_id,
					     unsigned char param_id,
					     int num_bytes,
					     unsigned char data[])
{
	enum tfa_error error;
	unsigned char buffer[3];
	int nr = 0;

	if (num_bytes <= 0) {
		pr_debug(
			"Error: The number of READ bytes is smaller or equal to 0!\n");
		return tfa_error_fail;
	}

	if ((tfa->is_probus_device) && (tfa->cnt->ndev == 1) &&
	    (param_id == SB_PARAM_GET_RE25C ||
	     param_id == SB_PARAM_GET_LSMODEL ||
	     param_id == SB_PARAM_GET_ALGO_PARAMS)) {
		/* Modifying the ID for GetRe25C */
		buffer[nr++] = 4;
	} else {
		buffer[nr++] = tfa->spkr_select;
	}
	buffer[nr++] = module_id + 128;
	buffer[nr++] = param_id;

	error = tfa_dsp_msg(tfa, nr, (char *)buffer);
	if (error != tfa_error_ok)
		return error;

	/* read the data from the dsp */
	error = tfa_dsp_msg_read(tfa, num_bytes, data);
	return error;
}

/* wrapper for dsp_msg that adds opcode and 3 bytes required for MBDrcDynamics */
enum tfa_error
tfa_dsp_cmd_id_MBDrc_dynamics(struct tfa_device *tfa, unsigned char module_id,
			      unsigned char param_id, int index_subband,
			      int num_bytes, unsigned char data[])
{
	enum tfa_error error;
	unsigned char buffer[2 * 3];
	int nr = 0;

	buffer[nr++] = tfa->spkr_select;
	buffer[nr++] = module_id + 128;
	buffer[nr++] = param_id;

	buffer[nr++] = 0;
	buffer[nr++] = 0;
	buffer[nr++] = (unsigned char)index_subband;

	error = tfa_dsp_msg(tfa, nr, (char *)buffer);
	if (error != tfa_error_ok)
		return error;

	/* read the data from the dsp */
	error = tfa_dsp_msg_read(tfa, num_bytes, data);

	return error;
}

enum tfa_error tfa98xx_dsp_write_preset(struct tfa_device *tfa, int length,
					    const unsigned char *p_preset_bytes)
{
	enum tfa_error error = tfa_error_ok;

	if (p_preset_bytes != NULL) {
		/* by design: keep the data opaque and no
		 * interpreting/calculation */
		error = tfa_dsp_cmd_id_write(tfa, MODULE_SPEAKERBOOST,
					     SB_PARAM_SET_PRESET, length,
					     p_preset_bytes);
	} else {
		error = tfa_error_bad_param;
	}
	return error;
}

/*
 * get features from MTP
 */
enum tfa_error tfa98xx_dsp_get_hw_feature_bits(struct tfa_device *tfa,
						   int *features)
{
	enum tfa_error error = tfa_error_ok;
	uint32_t value;
	uint16_t mtpbf;

	/* return the cache data if it's valid */
	if (tfa->hw_feature_bits != -1) {
		*features = tfa->hw_feature_bits;
	} else {
		/* for tfa1 check if we have clock */
		mtpbf = 0xf907; /* MTP9 for tfa2, 8 bits */
		value = tfa_read_reg(tfa, mtpbf) & 0xffff;
		*features = tfa->hw_feature_bits = value;
	}

	return error;
}

enum tfa_error tfa98xx_dsp_get_sw_feature_bits(struct tfa_device *tfa,
						   int features[2])
{
	enum tfa_error error = tfa_error_ok;
	const int byte_size = 2 * 3;
	unsigned char bytes[2 * 3];

	/* return the cache data if it's valid */
	if (tfa->sw_feature_bits[0] != -1) {
		features[0] = tfa->sw_feature_bits[0];
		features[1] = tfa->sw_feature_bits[1];
	} else {
		error = tfa_dsp_cmd_id_write_read(tfa, MODULE_FRAMEWORK,
						  FW_PAR_ID_GET_FEATURE_INFO,
						  byte_size, bytes);

		if (error != tfa_error_ok) {
			/* old ROM code may respond with tfa_error_rpc_param_id */
			return error;
		}

		tfa98xx_convert_bytes2data(byte_size, bytes, features);
	}
	return error;
}

enum tfa_error tfa98xx_dsp_support_drc(struct tfa_device *tfa,
					   int *pbSupportDrc)
{
	enum tfa_error error = tfa_error_ok;

	*pbSupportDrc = 0;

	if (tfa->supportDrc != supportNotSet) {
		*pbSupportDrc = (tfa->supportDrc == supportYes);
	} else {
		int featureBits[2];

		error = tfa98xx_dsp_get_sw_feature_bits(tfa, featureBits);
		if (error == tfa_error_ok) {
			/* easy case: new API available */
			/* bit=0 means DRC enabled */
			*pbSupportDrc = (featureBits[0] & FEATURE1_DRC) == 0;
		} else if (error == tfa_error_rpc_param_id) {
			/* older ROM code, doesn't support it */
			*pbSupportDrc = 0;
			error = tfa_error_ok;
		}
		/* else some other error, return transparently */
		/* pbSupportDrc only changed when error == tfa_error_ok */

		if (error == tfa_error_ok) {
			tfa->supportDrc = *pbSupportDrc ? supportYes :
							  supportNo;
		}
	}
	return error;
}

enum tfa_error
tfa98xx_dsp_write_speaker_parameters(struct tfa_device *tfa, int length,
				     const unsigned char *p_speaker_bytes)
{
	enum tfa_error error;
	int bSupportDrc;

	if (p_speaker_bytes != NULL) {
		/* by design: keep the data opaque and no
		 * interpreting/calculation */
		/* Use long WaitResult retry count */
		error = tfa_dsp_cmd_id_write(tfa, MODULE_SPEAKERBOOST,
					     SB_PARAM_SET_LSMODEL, length,
					     p_speaker_bytes);
	} else {
		error = tfa_error_bad_param;
	}

	if (error != tfa_error_ok)
		return error;

	error = tfa98xx_dsp_support_drc(tfa, &bSupportDrc);
	if (error != tfa_error_ok)
		return error;

	if (bSupportDrc) {
		/* Need to set AgcGainInsert back to PRE,
		 * as the SetConfig forces it to POST */
		uint8_t bytes[3] = { 0, 0, 0 };

		error = tfa_dsp_cmd_id_write(tfa, MODULE_SPEAKERBOOST,
					     SB_PARAM_SET_AGCINS, 3, bytes);
	}

	return error;
}

enum tfa_error tfa98xx_dsp_write_config(struct tfa_device *tfa, int length,
					    const unsigned char *p_config_bytes)
{
	enum tfa_error error = tfa_error_ok;
	int bSupportDrc;

	error = tfa_dsp_cmd_id_write(tfa, MODULE_SPEAKERBOOST,
				     SB_PARAM_SET_CONFIG, length,
				     p_config_bytes);
	if (error != tfa_error_ok)
		return error;

	error = tfa98xx_dsp_support_drc(tfa, &bSupportDrc);
	if (error != tfa_error_ok)
		return error;

	if (bSupportDrc) {
		/* Need to set AgcGainInsert back to PRE,
		 * as the SetConfig forces it to POST */
		uint8_t bytes[3] = { 0, 0, 0 };

		error = tfa_dsp_cmd_id_write(tfa, MODULE_SPEAKERBOOST,
					     SB_PARAM_SET_AGCINS, 3, bytes);
	}

	return error;
}

/* load all the parameters for the DRC settings from a file */
enum tfa_error tfa98xx_dsp_write_drc(struct tfa_device *tfa, int length,
					 const unsigned char *p_drc_bytes)
{
	enum tfa_error error = tfa_error_ok;

	if (p_drc_bytes != NULL) {
		error = tfa_dsp_cmd_id_write(tfa, MODULE_SPEAKERBOOST,
					     SB_PARAM_SET_DRC, length,
					     p_drc_bytes);

	} else {
		error = tfa_error_bad_param;
	}
	return error;
}

enum tfa_error tfa98xx_powerdown(struct tfa_device *tfa, int powerdown)
{
	enum tfa_error error = tfa_error_ok;

	error = TFA_SET_BF(tfa, PWDN, (uint16_t)powerdown);

	if (powerdown) {
		/* Workaround for ticket PLMA5337 */
		TFA_SET_BF_VOLATILE(tfa, AMPE, 0);
	}

	return error;
}

enum tfa_error tfa98xx_select_mode(struct tfa_device *tfa,
				       enum Tfa98xx_Mode mode)
{
	enum tfa_error error = tfa_error_ok;

	if (error == tfa_error_ok) {
		switch (mode) {
		default:
			error = tfa_error_bad_param;
		}
	}

	return error;
}

int tfa_set_bf(struct tfa_device *tfa, const uint16_t bf, const uint16_t value)
{
	enum tfa_error err;
	uint16_t regvalue, msk, oldvalue;

	/*
	 * bitfield enum:
	 * - 0..3	: len
	 * - 4..7	: pos
	 * - 8..15 : address
	 */
	uint8_t len = bf & 0x0f;
	uint8_t pos = (bf >> 4) & 0x0f;
	uint8_t address = (bf >> 8) & 0xff;

	err = tfa_reg_read(tfa, address, &regvalue);
	if (err) {
		pr_err("Error getting bf :%d\n", -err);
		return -err;
	}

	oldvalue = regvalue;
	msk = ((1 << (len + 1)) - 1) << pos;
	regvalue &= ~msk;
	regvalue |= value << pos;

	/* Only write when the current register value is not the same as the new value */
	if (oldvalue != regvalue) {
		err = tfa_reg_write(tfa, address, regvalue);
		if (err) {
			pr_err("Error setting bf :%d\n", -err);
			return -err;
		}
	}

	return 0;
}

int tfa_set_bf_volatile(struct tfa_device *tfa, const uint16_t bf,
			const uint16_t value)
{
	enum tfa_error err;
	uint16_t regvalue, msk;

	/*
	 * bitfield enum:
	 * - 0..3	: len
	 * - 4..7	: pos
	 * - 8..15 : address
	 */
	uint8_t len = bf & 0x0f;
	uint8_t pos = (bf >> 4) & 0x0f;
	uint8_t address = (bf >> 8) & 0xff;

	err = tfa_reg_read(tfa, address, &regvalue);
	if (err) {
		pr_err("Error getting bf :%d\n", -err);
		return -err;
	}

	msk = ((1 << (len + 1)) - 1) << pos;
	regvalue &= ~msk;
	regvalue |= value << pos;

	err = tfa_reg_write(tfa, address, regvalue);
	if (err) {
		pr_err("Error setting bf :%d\n", -err);
		return -err;
	}

	return 0;
}

int tfa_get_bf(struct tfa_device *tfa, const uint16_t bf)
{
	enum tfa_error err;
	uint16_t regvalue, msk;
	uint16_t value;

	/*
	 * bitfield enum:
	 * - 0..3	: len
	 * - 4..7	: pos
	 * - 8..15 : address
	 */
	uint8_t len = bf & 0x0f;
	uint8_t pos = (bf >> 4) & 0x0f;
	uint8_t address = (bf >> 8) & 0xff;

	err = tfa_reg_read(tfa, address, &regvalue);
	if (err) {
		pr_err("Error getting bf :%d\n", -err);
		return -err;
	}

	msk = ((1 << (len + 1)) - 1) << pos;
	regvalue &= msk;
	value = regvalue >> pos;

	return value;
}

int tfa_set_bf_value(const uint16_t bf, const uint16_t bf_value,
		     uint16_t *p_reg_value)
{
	uint16_t regvalue, msk;

	/*
	 * bitfield enum:
	 * - 0..3	: len
	 * - 4..7	: pos
	 * - 8..15 : address
	 */
	uint8_t len = bf & 0x0f;
	uint8_t pos = (bf >> 4) & 0x0f;

	regvalue = *p_reg_value;

	msk = ((1 << (len + 1)) - 1) << pos;
	regvalue &= ~msk;
	regvalue |= bf_value << pos;

	*p_reg_value = regvalue;

	return 0;
}

uint16_t tfa_get_bf_value(const uint16_t bf, const uint16_t reg_value)
{
	uint16_t msk, value;

	/*
	 * bitfield enum:
	 * - 0..3	: len
	 * - 4..7	: pos
	 * - 8..15 : address
	 */
	uint8_t len = bf & 0x0f;
	uint8_t pos = (bf >> 4) & 0x0f;

	msk = ((1 << (len + 1)) - 1) << pos;
	value = (reg_value & msk) >> pos;

	return value;
}

int tfa_write_reg(struct tfa_device *tfa, const uint16_t bf,
		  const uint16_t reg_value)
{
	enum tfa_error err;

	/* bitfield enum - 8..15 : address */
	uint8_t address = (bf >> 8) & 0xff;

	err = tfa_reg_write(tfa, address, reg_value);
	if (err)
		return -err;

	return 0;
}

int tfa_read_reg(struct tfa_device *tfa, const uint16_t bf)
{
	enum tfa_error err;
	uint16_t regvalue;

	/* bitfield enum - 8..15 : address */
	uint8_t address = (bf >> 8) & 0xff;

	err = tfa_reg_read(tfa, address, &regvalue);
	if (err)
		return -err;

	return regvalue;
}

/*
 * powerup the coolflux subsystem and wait for it
 */
enum tfa_error tfa_cf_powerup(struct tfa_device *tfa)
{
	enum tfa_error err = tfa_error_ok;
	int tries, status;

	/* power on the sub system */
	TFA_SET_BF_VOLATILE(tfa, PWDN, 0);

/* wait until everything is stable, in case clock has been off */
	if (tfa->verbose)
		pr_info("Waiting for DSP system stable...\n");
	for (tries = CFSTABLE_TRIES; tries > 0; tries--) {
		err = tfa98xx_dsp_system_stable(tfa, &status);
		if (status)
			break;
		else
			msleep_interruptible(
				10); /* wait 10ms to avoid busload */
	}
	if (tries == 0) { /* timedout */
		pr_err("DSP subsystem start timed out\n");
		return tfa_error_timeout;
	}

	return err;
}

/*
 * Print the current state of the hardware manager
 * Device manager status information, man_state from TFA9888_N1B_I2C_regmap_V12
 */
int tfa_is_94_N2_device(struct tfa_device *tfa)
{
	return ((((tfa->rev) & 0xff) == 0x94) &&
		(((tfa->rev >> 8) & 0xff) > 0x1a));
}
enum tfa_error tfa_show_current_state(struct tfa_device *tfa)
{
	enum tfa_error err = tfa_error_ok;
	int manstate = -1;

	if (tfa->verbose) {
		if (tfa_is_94_N2_device(tfa))
			manstate = tfa_get_bf(tfa, TFA9894N2_BF_MANSTATE);
		else if ((tfa->rev & 0xff) == 0x75)
			manstate = tfa_get_bf(tfa, TFA9875_BF_MANSTATE);
		else
			manstate = TFA_GET_BF(tfa, MANSTATE);
		if (manstate < 0)
			return -manstate;

		pr_debug("Current HW manager state: ");

		switch (manstate) {
		case 0:
			pr_debug("power_down_state\n");
			break;
		case 1:
			pr_debug("wait_for_source_settings_state\n");
			break;
		case 2:
			pr_debug("connnect_pll_input_state\n");
			break;
		case 3:
			pr_debug("disconnect_pll_input_state\n");
			break;
		case 4:
			pr_debug("enable_pll_state\n");
			break;
		case 5:
			pr_debug("enable_cgu_state\n");
			break;
		case 6:
			pr_debug("init_cf_state\n");
			break;
		case 7:
			pr_debug("enable_amplifier_state\n");
			break;
		case 8:
			pr_debug("alarm_state\n");
			break;
		case 9:
			pr_debug("operating_state\n");
			break;
		case 10:
			pr_debug("mute_audio_state\n");
			break;
		case 11:
			pr_debug("disable_cgu_pll_state\n");
			break;
		default:
			pr_debug("Unable to find current state\n");
			break;
		}
	}

	return err;
}

enum tfa_error tfaGetFwApiVersion(struct tfa_device *tfa,
				      unsigned char *pFirmwareVersion)
{
	enum tfa_error err = 0;
	char cmd_buf[4];
	int cmd_len, res_len;

	if (tfa == NULL)
		return tfa_error_bad_param;
	if (!tfa->is_probus_device) {
		int buffer;

		err = tfa_mem_read(tfa, FW_VAR_API_VERSION, 1,
				   (int *)(&buffer));
		if (err) {
			pr_debug(
				"%s Error: Unable to get API Version from DSP\n",
				__func__);
			return err;
		}
		pFirmwareVersion[0] = (buffer >> 16) & 0xff;
		pFirmwareVersion[1] = (buffer >> 8) & 0xff;
		if ((pFirmwareVersion[0] != 2) && (pFirmwareVersion[1] >= 33)) {
			pFirmwareVersion[2] = (buffer >> 3) & 0x1F;
			pFirmwareVersion[3] = (buffer) & 0x07;
		} else {
			pFirmwareVersion[2] = (buffer >> 6) & 0x03;
			pFirmwareVersion[3] = (buffer) & 0x3f;
		}
	} else {
		unsigned char buffer[4 * 3] = { 0 };

		cmd_len = 0x03;

		/* GetAPI: Command is 0x00 0x80 0xFE */
		cmd_buf[0] = 0x00;
		cmd_buf[1] = 0x80;
		cmd_buf[2] = 0xFE;

		/* Write the command.*/

		err = tfa98xx_write_dsp(tfa, cmd_len, (const char *)cmd_buf);

		/* Read the API Value.*/
		if (err == 0) {
			res_len = 3;
			err = tfa98xx_read_dsp(tfa, res_len,
					       (unsigned char *)buffer);
		}

		/* Split 3rd byte into two separate ITF version fields (3rd field and 4th field) */
		pFirmwareVersion[0] = (buffer[0]);
		pFirmwareVersion[1] = (buffer[1]);
		if ((pFirmwareVersion[0] != 2) && (pFirmwareVersion[1] >= 33)) {
			pFirmwareVersion[3] = (buffer[2]) & 0x07;
			pFirmwareVersion[2] = (buffer[2] >> 3) & 0x1F;
		} else {
			pFirmwareVersion[3] = (buffer[2]) & 0x3f;
			pFirmwareVersion[2] = (buffer[2] >> 6) & 0x03;
		}
	}

	if (tfa->cnt->ndev == 1) {
		/* Mono configuration */
		/* Workaround for FW 8.9.0 (FW API x.31.y.z) & above.
			Firmware cannot return the 4th field (mono/stereo) of ITF version correctly, as it requires
			certain set of messages to be sent before it can detect itself as a mono/stereo configuration.
			Hence, HostSDK need to handle this at system level */
		if ((pFirmwareVersion[0] == 8) && (pFirmwareVersion[1] >= 31)) {
			pFirmwareVersion[3] = 1;
		}
	}

	return err;
}

/*
 *	start the speakerboost algorithm
 *	this implies a full system startup when the system was not already started
 *
 */
enum tfa_error tfaRunSpeakerBoost(struct tfa_device *tfa, int force,
				      int profile)
{
	enum tfa_error err = tfa_error_ok;
	int value;

	if (force) {
		err = tfaRunColdStartup(tfa, profile);
		if (err)
			return err;
	}

	/* Returns 1 when device is "cold" and 0 when device is warm */
	value = tfa_is_cold(tfa);

	pr_debug("Startup of device [%s] is a %sstart\n",
		 tfaContDeviceName(tfa->cnt, tfa->dev_idx),
		 value ? "cold" : "warm");
	/* cold start and not tap profile */
	if (value) {
		/* Run startup and write all files */
		err = tfaRunSpeakerStartup(tfa, force, profile);
		if (err)
			return err;

		/* Save the current profile and set the vstep to 0 */
		/* This needs to be overwritten even in CF bypass */
		tfa_dev_set_swprof(tfa, (unsigned short)profile);
		tfa_dev_set_swvstep(tfa, 0);
	}

	return err;
}

enum tfa_error tfaRunSpeakerStartup(struct tfa_device *tfa, int force,
					int profile)
{
	enum tfa_error err = tfa_error_ok;

	if (!force) { /* in case of force CF already running */
		err = tfaRunStartup(tfa, profile);
		WARN_ON(err);
		if (err)
			return err;

		/* Startup with CF in bypass then return here */
		if (tfa_cf_enabled(tfa) == 0)
			return err;

		/* respond to external DSP: -1:none, 0:no_dsp, 1:cold, 2:warm */
		if (tfa->ext_dsp == -1) {
			err = tfaRunStartDSP(tfa);
			if (err)
				return err;
		}
	}

	/* Set auto_copy_mtp_to_iic (bit 5 of A3) to 1 */
	tfa->dev_ops.auto_copy_mtp_to_iic(tfa);

	err = tfaGetFwApiVersion(tfa, (unsigned char *)&tfa->fw_itf_ver[0]);
	if (err) {
		pr_debug("[%s] cannot get FWAPI error = %d\n", __func__, err);
		return err;
	}
	/* write all the files from the device list */
	err = tfaContWriteFiles(tfa);
	if (err) {
		pr_debug("[%s] tfaContWriteFiles error = %d\n", __func__, err);
		return err;
	}

	/* write all the files from the profile list (use volumstep 0) */
	err = tfaContWriteFilesProf(tfa, profile, 0);
	if (err) {
		pr_debug("[%s] tfaContWriteFilesProf error = %d\n", __func__,
			 err);
		return err;
	}

	return err;
}

enum tfa_error tfaRunColdboot(struct tfa_device *tfa, int state)
{
#define CF_CONTROL 0x8100
	enum tfa_error err = tfa_error_ok;
	int tries = 10;

	/* repeat set ACS bit until set as requested */
	while (state != TFA_GET_BF(tfa, ACS)) {
		/* set colstarted in CF_CONTROL to force ACS */
		err = tfa_mem_write(tfa, CF_CONTROL, state, Tfa98xx_DMEM_IOMEM);
		WARN_ON(err);

		if (tries-- == 0) {
			pr_debug("coldboot (ACS) did not %s\n",
				 state ? "set" : "clear");
			return tfa_error_other;
		}
	}

	return err;
}

/*
 * load the patch if any
 *	else tell no loaded
 */
static enum tfa_error tfa_run_load_patch(struct tfa_device *tfa)
{
	return tfaContWritePatch(tfa);
}

/*
 *	this will load the patch witch will implicitly start the DSP
 *	if no patch is available the DPS is started immediately
 */
enum tfa_error tfaRunStartDSP(struct tfa_device *tfa)
{
	enum tfa_error err = tfa_error_ok;

	err = tfa_run_load_patch(tfa);
	if (err) { /* patch load is fatal so return immediately*/
		return err;
	}

	/* Clear count_boot, should be reset to 0 before the DSP reset is released */
	err = tfa_mem_write(tfa, 512, 0, Tfa98xx_DMEM_XMEM);
	WARN_ON(err);

	/* Reset DSP once for sure after initializing */
	if (err == tfa_error_ok) {
		err = tfa->dev_ops.dsp_reset(tfa, 0);
		WARN_ON(err);
	}

	/* Sample rate is needed to set the correct tables */
	err = tfa->dev_ops.dsp_write_tables(tfa, TFA_GET_BF(tfa, AUDFS));
	WARN_ON(err);

	return err;
}

/*
 * start the clocks and wait until the AMP is switching
 *	on return the DSP sub system will be ready for loading
 */
enum tfa_error tfaRunStartup(struct tfa_device *tfa, int profile)
{
	enum tfa_error err = tfa_error_ok;
	struct TfaDeviceList *dev = tfaContDevice(tfa->cnt, tfa->dev_idx);
	int i, noinit = 0, audfs = 0, fractdel = 0;

	if (dev == NULL)
		return tfa_error_fail;

	if (dev->bus) /* no i2c device, do nothing */
		return tfa_error_ok;

	/* process the device list to see if the user implemented the noinit */
	for (i = 0; i < dev->length; i++) {
		if (dev->list[i].type == dscNoInit) {
			noinit = 1;
			break;
		}
	}

	if (!noinit) {
		/* Read AUDFS & FRACTDEL prior to (re)init. */
		audfs = TFA_GET_BF(tfa, AUDFS);
		fractdel = TFA_GET_BF(tfa, FRACTDEL);
		/* load the optimal TFA98XX in HW settings */
		err = tfa98xx_init(tfa);
		WARN_ON(err);

		/* Restore audfs & fractdel after coldboot, so we can calibrate with correct fs setting.
		 * in case something else was given in cnt file, profile below will apply this. */
		TFA_SET_BF(tfa, AUDFS, audfs);
		TFA_SET_BF(tfa, FRACTDEL, fractdel);
#ifdef __KERNEL__
		if ((tfa->dynamicTDMmode == 3) &&
		    tfa_dev_set_tdm_bitwidth(tfa, tfa->bitwidth))
			return tfa_error_fail;
#endif
	} else {
		pr_debug(
			"\nWarning: No init keyword found in the cnt file. Init is skipped!\n");
	}

	/* I2S settings to define the audio input properties
	 *	these must be set before the subsys is up */
/* this will run the list until a non-register item is encountered */
	err = tfaContWriteRegsDev(tfa); /* write device register settings */
	WARN_ON(err);
/* also write register the settings from the default profile */
/* NOTE we may still have ACS=1 so we can switch sample rate here */
	err = tfaContWriteRegsProf(tfa, profile);
	WARN_ON(err);

	/* Factory trimming for the Boost converter */
	tfa->dev_ops.factory_trimmer(tfa);
	/* Go to the initCF state */
	tfa_dev_set_state(
		tfa, TFA_STATE_INIT_CF,
		strstr(tfaContProfileName(tfa->cnt, tfa->dev_idx, profile),
		       ".cal") != NULL);

	err = tfa_show_current_state(tfa);

	return err;
}

/*
 * run the startup/init sequence and set ACS bit
 */
enum tfa_error tfaRunColdStartup(struct tfa_device *tfa, int profile)
{
	enum tfa_error err = tfa_error_ok;

	err = tfaRunStartup(tfa, profile);
	WARN_ON(err);
	if (err)
		return err;

	if (!tfa->is_probus_device) {
		/* force cold boot */
		err = tfaRunColdboot(tfa, 1); /* set ACS */
		WARN_ON(err);
		if (err)
			return err;
	}

	/* start */
	err = tfaRunStartDSP(tfa);
	WARN_ON(err);

	return err;
}

/*
 * tfa_dev_start will only do the basics: Going from powerdown to operating or a profile switch.
 * for calibrating or akoustic shock handling use the tfa98xxCalibration function.
 */
enum tfa_error tfa_dev_start(struct tfa_device *tfa, int next_profile,
			     int vstep)
{
	enum tfa_error err = tfa_error_ok;
	int active_profile = -1;

	/* Get currentprofile */
	active_profile = tfa_dev_get_swprof(tfa);
	if (active_profile == 0xff)
		active_profile = -1;

	/* TfaRun_SpeakerBoost implies un-mute */
	pr_debug("Active_profile:%s, next_profile:%s\n",
		 tfaContProfileName(tfa->cnt, tfa->dev_idx, active_profile),
		 tfaContProfileName(tfa->cnt, tfa->dev_idx, next_profile));

	err = tfa_show_current_state(tfa);

	if (tfa->bus != 0) { /* non i2c	*/
#ifndef __KERNEL__
		tfadsp_fw_start(tfa, next_profile, vstep);
#endif /* __KERNEL__ */
	} else {
		/* Check if we need coldstart or ACS is set */
		err = tfaRunSpeakerBoost(tfa, 0, next_profile);
		if (err != tfa_error_ok)
			goto error_exit;

		if (strstr(tfaContProfileName(tfa->cnt, tfa->dev_idx,
					      next_profile),
			   ".standby") != NULL) {
			pr_info("Skip powering on device, in standby profile!\n");
		} else {
			/* Make sure internal oscillator is running for DSP devices (non-dsp and max1 this is no-op) */
			tfa98xx_set_osc_powerdown(tfa, 0);

			/* Go to the Operating state */
			tfa_dev_set_state(
				tfa, TFA_STATE_OPERATING | TFA_STATE_MUTE, 0);
		}
	}
	active_profile = tfa_dev_get_swprof(tfa);

	/* Profile switching */
	if ((next_profile != active_profile && active_profile >= 0)) {
		err = tfaContWriteProfile(tfa, next_profile, vstep);
		if (err != tfa_error_ok)
			goto error_exit;
	}

	/* If the profile contains the .standby suffix go to powerdown
	 * else we should be in operating state
	 */
	if (strstr(tfaContProfileName(tfa->cnt, tfa->dev_idx, next_profile),
		   ".standby") != NULL) {
		tfa_dev_set_swprof(tfa, (unsigned short)next_profile);
		tfa_dev_set_swvstep(tfa, (unsigned short)vstep);

		pr_info("Power down device, by force, in standby profile!\n");
		err = tfa_dev_stop(tfa);
		goto error_exit;
	}

	err = tfa_show_current_state(tfa);

	if ((TFA_GET_BF(tfa, CFE) != 0) && (vstep != tfa->vstep) &&
	    (vstep != -1)) {
		err = tfaContWriteFilesVstep(tfa, next_profile, vstep);
		if (err != tfa_error_ok)
			goto error_exit;
	}

	/* Always search and apply filters after a startup */
	err = tfa_set_filters(tfa, next_profile);
	if (err != tfa_error_ok)
		goto error_exit;

	tfa_dev_set_swprof(tfa, (unsigned short)next_profile);
	tfa_dev_set_swvstep(tfa, (unsigned short)vstep);

	/* PLMA5539: Gives information about current setting of powerswitch */
	if (tfa->verbose) {
		if (!tfa98xx_powerswitch_is_enabled(tfa))
			pr_info("Device start without powerswitch enabled!\n");
	}

error_exit:
	tfa_show_current_state(tfa);

	return err;
}

enum tfa_error tfa_dev_stop(struct tfa_device *tfa)
{
	enum tfa_error err = tfa_error_ok;

	/* Make sure internal oscillator is not running for DSP devices (non-dsp and max1 this is no-op) */
	tfa98xx_set_osc_powerdown(tfa, 1);

	/* powerdown CF */
	err = tfa98xx_powerdown(tfa, 1);
	if (err != tfa_error_ok)
		return err;

	return err;
}

/*
 *	int registers and coldboot dsp
 */
int tfa_reset(struct tfa_device *tfa)
{
	enum tfa_error err = tfa_error_ok;
	int state = -1;
	int retry_cnt = 0;

	/* Check device state. Print warning if reset is done from other state than powerdown (when verbose) */
	state = tfa_dev_get_state(tfa);
	if (tfa->verbose) {
		if ((state != TFA_STATE_POWERDOWN)) {
			pr_info("WARNING: Device reset should be performed in POWERDOWN state\n");
		}
	}

	/* Probus devices needs extra protection to ensure proper reset
			behavior, this step is valid only in state other than powerdown */
	if (tfa->is_probus_device && state != TFA_STATE_POWERDOWN) {
		err = TFA_SET_BF_VOLATILE(tfa, AMPE, 0);
		if (err)
			return err;
		err = tfa98xx_powerdown(tfa, 1);
		if (err)
			return err;
	}

	err = TFA_SET_BF_VOLATILE(tfa, I2CR, 1);
	if (err)
		return err;

	/* Restore MANSCONF to POR state */
	err = TFA_SET_BF_VOLATILE(tfa, MANSCONF, 0);
	if (err)
		return err;

	/* Probus devices HW are already reset here,
			Last step is to send init message to softDSP */
	if (tfa->is_probus_device) {
		if (tfa->ext_dsp > 0) {
			err = tfa_error_not_supported;
			/* ext_dsp status from warm to cold after reset */
			if (tfa->ext_dsp == 2) {
				tfa->ext_dsp = 1;
			}
		}
	} else {
		/* Restore MANCOLD to POR state */
		TFA_SET_BF_VOLATILE(tfa, MANCOLD, 1);

		/* Coolflux has to be powered on to ensure proper ACS
				bit state */

		/* Powerup CF to access CF io */
		err = tfa98xx_powerdown(tfa, 0);
		if (err)
			return err;

		/* For clock */
		err = tfa_cf_powerup(tfa);
		if (err)
			return err;

		/* Force cold boot */
		err = tfaRunColdboot(tfa, 1); /* Set ACS */
		if (err)
			return err;

		/* Set PWDN = 1, this will transfer device into powerdown state */
		err = TFA_SET_BF_VOLATILE(tfa, PWDN, 1);
		if (err)
			return err;

		/* 88 needs SBSL on top of PWDN bit to start transition,
				for 92 and 94 this doesn't matter */
		err = TFA_SET_BF_VOLATILE(tfa, SBSL, 1);
		if (err)
			return err;

		/* Powerdown state should be reached within 1ms */
		for (retry_cnt = 0; retry_cnt < TFA98XX_WAITRESULT_NTRIES;
		     retry_cnt++) {
			if (tfa_is_94_N2_device(tfa))
				state = tfa_get_bf(tfa, TFA9894N2_BF_MANSTATE);
			else if ((tfa->rev & 0xff) == 0x75)
				state = tfa_get_bf(tfa, TFA9875_BF_MANSTATE);
			else
				state = TFA_GET_BF(tfa, MANSTATE);
			if (state < 0) {
				return err;
			}

			/* Check for MANSTATE=Powerdown (0) */
			if (state == 0)
				break;
			msleep_interruptible(2);
		}

		/* Reset all I2C registers to default values,
				now device state is consistent, same as after powerup */
		err = TFA_SET_BF(tfa, I2CR, 1);
	}

	return err;
}

/*
 * Write all the bytes specified by num_bytes and data
 */
enum tfa_error tfa98xx_write_data(struct tfa_device *tfa,
				      unsigned char subaddress, int num_bytes,
				      const unsigned char data[])
{
	enum tfa_error error = tfa_error_ok;
	/* subaddress followed by data */
	const int bytes2write = num_bytes + 1;
	unsigned char *write_data;

	if (num_bytes > TFA2_MAX_PARAM_SIZE)
		return tfa_error_bad_param;

	write_data = (unsigned char *)kmem_cache_alloc(tfa->cachep, GFP_KERNEL);
	if (write_data == NULL)
		return tfa_error_fail;

	write_data[0] = subaddress;
	memcpy(&write_data[1], data, num_bytes);

	error = tfa98xx_write_raw(tfa, bytes2write, write_data);

	kmem_cache_free(tfa->cachep, write_data);
	return error;
}

/* start count from 1, 0 is invalid */
int tfa_dev_get_swprof(struct tfa_device *tfa)
{
	return (tfa->dev_ops.get_swprof)(tfa);
}

int tfa_dev_set_swprof(struct tfa_device *tfa, unsigned short new_value)
{
	return (tfa->dev_ops.set_swprof)(tfa, new_value + 1);
}

int tfa_dev_set_swvstep(struct tfa_device *tfa, unsigned short new_value)
{
	return (tfa->dev_ops.set_swvstep)(tfa, new_value + 1);
}

/*
	function overload for MTPB
 */
int tfa_dev_get_mtpb(struct tfa_device *tfa)
{
	return (tfa->dev_ops.get_mtpb)(tfa);
}

int tfa_is_cold(struct tfa_device *tfa)
{
	int value;

	/*
	 * check for cold boot status
	 */
	if (tfa->is_probus_device) {
		if (tfa->ext_dsp > 0) {
			if (tfa->ext_dsp == 2)
				value = 0; /* warm */
			else /* no dsp or cold */
				value = 1; /* cold */
		} else {
			value = (TFA_GET_BF(tfa, MANSCONF) == 0);
		}
	} else {
		value = TFA_GET_BF(tfa, ACS);
	}

	return value;
}

int tfa_needs_reset(struct tfa_device *tfa)
{
	int value;

	/* checks if the DSP commands SetAlgoParams and SetMBDrc
	 * need a DSP reset (now: at coldstart or during calibration)
	 */
	if (tfa_is_cold(tfa) == 1 || tfa->needs_reset == 1)
		value = 1;
	else
		value = 0;

	return value;
}

int tfa_cf_enabled(struct tfa_device *tfa)
{
	int value;

	/* For 72 there is no CF */
	if (tfa->is_probus_device) {
		value = (tfa->ext_dsp != 0);
	} else {
		value = TFA_GET_BF(tfa, CFE);
	}

	return value;
}

#define NR_COEFFS 6
#define NR_BIQUADS 28
#define BQ_SIZE (3 * NR_COEFFS)
#define DSP_MSG_OVERHEAD 27

#pragma pack(push, 1)
struct dsp_msg_all_coeff {
	uint8_t select_eq[3];
	uint8_t biquad[NR_BIQUADS][NR_COEFFS][3];
};
#pragma pack(pop)

/* number of biquads for each equalizer */
static const int eq_biquads[] = { 10, 10, 2, 2, 2, 2 };

#define NR_EQ ((int)(sizeof(eq_biquads) / sizeof(int)))

enum tfa_error tfa_dsp_partial_coefficients(struct tfa_device *tfa,
						uint8_t *prev, uint8_t *next)
{
	uint8_t bq, eq;
	int eq_offset;
	int new_cost, old_cost;
	uint32_t eq_biquad_mask[NR_EQ];
	enum tfa_error err = tfa_error_ok;
	struct dsp_msg_all_coeff *data1 = (struct dsp_msg_all_coeff *)prev;
	struct dsp_msg_all_coeff *data2 = (struct dsp_msg_all_coeff *)next;

	old_cost = DSP_MSG_OVERHEAD + 3 + sizeof(struct dsp_msg_all_coeff);
	new_cost = 0;

	eq_offset = 0;
	for (eq = 0; eq < NR_EQ; eq++) {
		uint8_t *eq1 = &data1->biquad[eq_offset][0][0];
		uint8_t *eq2 = &data2->biquad[eq_offset][0][0];

		eq_biquad_mask[eq] = 0;

		if (memcmp(eq1, eq2, BQ_SIZE * eq_biquads[eq]) != 0) {
			int nr_bq = 0;
			int bq_sz, eq_sz;

			for (bq = 0; bq < eq_biquads[eq]; bq++) {
				uint8_t *bq1 = &eq1[bq * BQ_SIZE];
				uint8_t *bq2 = &eq2[bq * BQ_SIZE];

				if (memcmp(bq1, bq2, BQ_SIZE) != 0) {
					eq_biquad_mask[eq] |= (1 << bq);
					nr_bq++;
				}
			}

			bq_sz = (2 * 3 + BQ_SIZE) * nr_bq;
			eq_sz = 2 * 3 + BQ_SIZE * eq_biquads[eq];

			/* dsp message i2c transaction overhead */
			bq_sz += DSP_MSG_OVERHEAD * nr_bq;
			eq_sz += DSP_MSG_OVERHEAD;

			if (bq_sz >= eq_sz) {
				eq_biquad_mask[eq] = 0xffffffff;

				new_cost += eq_sz;

			} else {
				new_cost += bq_sz;
			}
		}
		pr_debug("eq_biquad_mask[%d] = 0x%.8x\n", eq,
			 eq_biquad_mask[eq]);

		eq_offset += eq_biquads[eq];
	}

	pr_debug("cost for writing all coefficients	 = %d\n", old_cost);
	pr_debug("cost for writing changed coefficients = %d\n", new_cost);

	if (new_cost >= old_cost) {
		const int buffer_sz = 3 + sizeof(struct dsp_msg_all_coeff);
		uint8_t *buffer;

		buffer = kmalloc(buffer_sz, GFP_KERNEL);
		if (buffer == NULL)
			return tfa_error_fail;

		/* cmd id */
		buffer[0] = 0x00;
		buffer[1] = 0x82;
		buffer[2] = 0x00;

		/* parameters */
		memcpy(&buffer[3], data2, sizeof(struct dsp_msg_all_coeff));

		err = tfa_dsp_msg(tfa, buffer_sz, (const char *)buffer);

		kfree(buffer);
		if (err)
			return err;

	} else {
		eq_offset = 0;
		for (eq = 0; eq < NR_EQ; eq++) {
			uint8_t *eq2 = &data2->biquad[eq_offset][0][0];

			if (eq_biquad_mask[eq] == 0xffffffff) {
				const int msg_sz = 6 + BQ_SIZE * eq_biquads[eq];
				uint8_t *msg;

				msg = kmalloc(msg_sz, GFP_KERNEL);
				if (msg == NULL)
					return tfa_error_fail;

				/* cmd id */
				msg[0] = 0x00;
				msg[1] = 0x82;
				msg[2] = 0x00;

				/* select eq and bq */
				msg[3] = 0x00;
				msg[4] = eq + 1;
				msg[5] = 0x00; /* all biquads */

				/* biquad parameters */
				memcpy(&msg[6], eq2, BQ_SIZE * eq_biquads[eq]);

				err = tfa_dsp_msg(tfa, msg_sz,
						  (const char *)msg);

				kfree(msg);
				if (err)
					return err;

			} else if (eq_biquad_mask[eq] != 0) {
				for (bq = 0; bq < eq_biquads[eq]; bq++) {
					if (eq_biquad_mask[eq] & (1 << bq)) {
						uint8_t *bq2 =
							&eq2[bq * BQ_SIZE];
						const int msg_sz = 6 + BQ_SIZE;
						uint8_t *msg;

						msg = kmem_cache_alloc(
							tfa->cachep,
							GFP_KERNEL);
						if (msg == NULL)
							return tfa_error_fail;

						/* cmd id */
						msg[0] = 0x00;
						msg[1] = 0x82;
						msg[2] = 0x00;

						/* select eq and bq*/
						msg[3] = 0x00;
						msg[4] = eq + 1;
						msg[5] = bq + 1;

						/* biquad parameters */
						memcpy(&msg[6], bq2, BQ_SIZE);

						err = tfa_dsp_msg(
							tfa, msg_sz,
							(const char *)msg);

						kmem_cache_free(tfa->cachep,
								msg);
						if (err)
							return err;
					}
				}
			}
			eq_offset += eq_biquads[eq];
		}
	}

	return err;
}

/* fill context info */
int tfa_dev_probe(int slave, struct tfa_device *tfa)
{
	uint16_t rev;

	tfa->slave_address = (unsigned char)slave;

	/* read revid via low level hal, register 3 */
	if (tfa98xx_read_register16(tfa, 3, &rev) != tfa_error_ok) {
		pr_info("\nError: Unable to read revid from slave:0x%02x\n",
		      slave);
		return -1;
	}

	tfa->rev = rev;
	tfa->dev_idx = -1;
	tfa->state = TFA_STATE_UNKNOWN;
	tfa->p_regInfo = NULL;

	tfa_set_query_info(tfa);

	return 0;
}

enum tfa_error tfa_dev_set_state(struct tfa_device *tfa, enum tfa_state state,
				 int is_calibration)
{
	enum tfa_error err = tfa_error_ok;
	int loop = 50, ready = 0;
	int count;

	/* Base states */
	/* Do not change the order of setting bits as this is important! */
	switch (state & 0x0f) {
	case TFA_STATE_POWERDOWN: /* PLL in powerdown, Algo up */
		break;
	case TFA_STATE_INIT_HW: /* load I2C/PLL hardware setting (~wait2srcsettings) */
		break;
	case TFA_STATE_INIT_CF: /* coolflux HW access possible (~initcf) */
		/* Start with SBSL=0 to stay in initCF state */
		if (!tfa->is_probus_device)
			TFA_SET_BF(tfa, SBSL, 0);

		/* We want to leave Wait4SrcSettings state for max2 */
		TFA_SET_BF(tfa, MANSCONF, 1);

		/* And finally set PWDN to 0 to leave powerdown state */
		TFA_SET_BF(tfa, PWDN, 0);

		/* Make sure the DSP is running! */
		do {
			err = tfa98xx_dsp_system_stable(tfa, &ready);
			if (err != tfa_error_ok)
				return err;
			if (ready)
				break;
		} while (loop--);
		if (((!tfa->is_probus_device) && (is_calibration)) ||
		    ((tfa->rev & 0xff) == 0x13)) {
			/* Enable FAIM when clock is stable, to avoid MTP corruption */
			err = tfa->dev_ops.faim_protect(tfa, 1);
			if (tfa->verbose) {
				pr_debug("FAIM enabled (err:%d).\n", err);
			}
		}
		break;
	case TFA_STATE_INIT_FW: /* DSP framework active (~patch loaded) */
		break;
	case TFA_STATE_OPERATING: /* Amp and Algo running */
		/* Depending on our previous state we need to set 3 bits */
		TFA_SET_BF(tfa, PWDN, 0); /* Coming from state 0 */
		TFA_SET_BF(tfa, MANSCONF, 1); /* Coming from state 1 */
		if (!tfa->is_probus_device)
			TFA_SET_BF(tfa, SBSL, 1); /* Coming from state 6 */
		else
			TFA_SET_BF(
				tfa, AMPE,
				1); /* No SBSL for probus device, we set AMPE to 1	*/

		/*
										* Disable MTP clock to protect memory.
										* However in case of calibration wait for DSP! (This should be case only during calibration).
										*/
		if (TFA_GET_BF(tfa, MTPOTC) == 1) {
			count = MTPEX_WAIT_NTRIES *
				4; /* Calibration takes a lot of time */
			while ((TFA_GET_BF(tfa, MTPEX) != 1) && count) {
				msleep_interruptible(10);
				count--;
			}
		}
		if (((!tfa->is_probus_device) && (is_calibration)) ||
		    ((tfa->rev & 0xff) == 0x13)) {
			err = tfa->dev_ops.faim_protect(tfa, 0);
			if (tfa->verbose) {
				pr_debug("FAIM disabled (err:%d).\n", err);
			}
		}
		/* Synchronize I/V delay on 96/97 at cold start */
		if (tfa->sync_iv_delay) {
			if (tfa->verbose)
				pr_debug("syncing I/V delay for %x\n",
					 (tfa->rev & 0xff));

			/* wait for ACS to be cleared */
			count = 10;
			while ((TFA_GET_BF(tfa, ACS) == 1) && (count-- > 0)) {
				msleep_interruptible(1);
			}

			tfa->dev_ops.dsp_reset(tfa, 1);
			tfa->dev_ops.dsp_reset(tfa, 0);
			tfa->sync_iv_delay = 0;
		}
		break;
	case TFA_STATE_FAULT: /* An alarm or error occurred */
		break;
	case TFA_STATE_RESET: /* I2C reset and ACS set */
		tfa98xx_init(tfa);
		break;
	default:
		if (state & 0x0f)
			return tfa_error_bad_param;
	}

	/* state modifiers */

	if (state & TFA_STATE_MUTE)
		tfa98xx_set_mute(tfa, Tfa98xx_Mute_Amplifier);

	if (state & TFA_STATE_UNMUTE)
		tfa98xx_set_mute(tfa, Tfa98xx_Mute_Off);

	tfa->state = state;

	return tfa_error_ok;
}

enum tfa_state tfa_dev_get_state(struct tfa_device *tfa)
{
	int manstate;

	if (tfa_is_94_N2_device(tfa))
		manstate = tfa_get_bf(tfa, TFA9894N2_BF_MANSTATE);
	else if ((tfa->rev & 0xff) == 0x75)
		manstate = tfa_get_bf(tfa, TFA9875_BF_MANSTATE);
	else
		manstate = TFA_GET_BF(tfa, MANSTATE);
	switch (manstate) {
	case 0:
		tfa->state = TFA_STATE_POWERDOWN;
		break;
	case 8: /* if dsp reset if off assume framework is running */
		tfa->state = TFA_GET_BF(tfa, RST) ? TFA_STATE_INIT_CF :
						    TFA_STATE_INIT_FW;
		break;
	case 9:
		tfa->state = TFA_STATE_OPERATING;
		break;
	default:
		break;
	}

	return tfa->state;
}

int tfa_dev_mtp_get(struct tfa_device *tfa, enum tfa_mtp item)
{
	int value = 0;

	switch (item) {
	case TFA_MTP_OTC:
		value = TFA_GET_BF(tfa, MTPOTC);
		break;
	case TFA_MTP_EX:
		value = TFA_GET_BF(tfa, MTPEX);
		break;
	case TFA_MTP_RE25:
	case TFA_MTP_RE25_PRIM:
		if ((tfa->rev & 0xFF) == 0x88)
			value = TFA_GET_BF(tfa, R25CL);
		else if ((tfa->rev & 0xFF) == 0x13)
			value = tfa_get_bf(tfa, TFA9912_BF_R25C);
		else
			value = TFA_GET_BF(tfa, R25C);
		break;
	case TFA_MTP_RE25_SEC:
		if ((tfa->rev & 0xFF) == 0x88) {
			value = TFA_GET_BF(tfa, R25CR);
		} else {
			pr_debug(
				"Error: Current device has no secondary Re25 channel\n");
		}
		break;
	case TFA_MTP_LOCK:
		break;
	}

	return value;
}

enum tfa_error tfa_dev_mtp_set(struct tfa_device *tfa, enum tfa_mtp item,
			       int value)
{
	enum tfa_error err = tfa_error_ok;

	switch (item) {
	case TFA_MTP_OTC:
		err = tfa98xx_set_mtp(tfa, (uint16_t)value,
				TFA98XX_KEY2_PROTECTED_MTP0_MTPOTC_MSK);
		break;
	case TFA_MTP_EX:
		err = tfa98xx_set_mtp(tfa, (uint16_t)value,
				TFA98XX_KEY2_PROTECTED_MTP0_MTPEX_MSK);
		break;
	case TFA_MTP_RE25:
	case TFA_MTP_RE25_PRIM:
		tfa98xx_key2(tfa, 0); /* unlock */
		if ((tfa->rev & 0xFF) == 0x88)
			TFA_SET_BF(tfa, R25CL, (uint16_t)value);
		else {
			if (tfa->is_probus_device == 1 &&
			    TFA_GET_BF(tfa, MTPOTC) == 1)
				tfa2_manual_mtp_cpy(tfa, 0xF4, value, 2);
			TFA_SET_BF(tfa, R25C, (uint16_t)value);
		}
		tfa98xx_key2(tfa, 1); /* lock */
		break;
	case TFA_MTP_RE25_SEC:
		if ((tfa->rev & 0xFF) == 0x88) {
			TFA_SET_BF(tfa, R25CR, (uint16_t)value);
		} else {
			pr_debug(
				"Error: Current device has no secondary Re25 channel\n");
			err = tfa_error_bad_param;
		}
		break;
	case TFA_MTP_LOCK:
		break;
	}

	return err;
}

int tfa_get_noclk(struct tfa_device *tfa)
{
	return TFA_GET_BF(tfa, NOCLK);
}

enum tfa_error tfa_status(struct tfa_device *tfa)
{
	int value;
	uint16_t val;

	if (tfa->dev_ops.tfa_status != NULL)
		return (tfa->dev_ops.tfa_status(tfa));
	/*
	 * check IC status bits: cold start
	 * and DSP watch dog bit to re init
	 */
	value = TFA_READ_REG(tfa, VDDS); /* STATUSREG */
	if (value < 0)
		return -value;
	val = (uint16_t)value;

	if (TFA_GET_BF_VALUE(tfa, ACS, val) ||
	    TFA_GET_BF_VALUE(tfa, WDS, val)) {
		if (TFA_GET_BF_VALUE(tfa, ACS, val))
			pr_err("ERROR: ACS\n");
		if (TFA_GET_BF_VALUE(tfa, WDS, val))
			pr_err("ERROR: WDS\n");

		return tfa_error_dsp;
	}

	if (TFA_GET_BF_VALUE(tfa, SPKS, val))
		pr_err("ERROR: SPKS\n");
	if (!TFA_GET_BF_VALUE(tfa, SWS, val))
		pr_err("ERROR: SWS\n");

	/* Check secondary errors */
	if (!TFA_GET_BF_VALUE(tfa, CLKS, val) ||
	    !TFA_GET_BF_VALUE(tfa, UVDS, val) ||
	    !TFA_GET_BF_VALUE(tfa, OVDS, val) ||
	    !TFA_GET_BF_VALUE(tfa, OTDS, val) ||
	    !TFA_GET_BF_VALUE(tfa, PLLS, val) ||
	    (!(tfa->daimap & Tfa98xx_DAI_TDM) &&
	     !TFA_GET_BF_VALUE(tfa, VDDS, val)))
		pr_err("Misc errors detected: STATUS_FLAG0 = 0x%x\n", val);

	if (tfa->daimap & Tfa98xx_DAI_TDM) {
		value = TFA_READ_REG(tfa, TDMERR); /* STATUS_FLAGS1 */
		if (value < 0)
			return -value;
		val = (uint16_t)value;
		if (TFA_GET_BF_VALUE(tfa, TDMERR, val) ||
		    TFA_GET_BF_VALUE(tfa, TDMLUTER, val))
			pr_err("TDM related errors: STATUS_FLAG1 = 0x%x\n",
			       val);
	}

	return tfa_error_ok;
}
#ifdef __KERNEL__
void tfa_dev_get_tdm_add(struct tfa_device *tfa, uint16_t *tdme,
			 uint16_t *tnbck, uint16_t *tslln, uint16_t *tsize)
{
	unsigned short revid = tfa->rev;

	switch (revid & 0xff) {
	case 0x72:
		*tdme = TFA9872_BF_TDME;
		*tnbck = TFA9872_BF_TDMNBCK;
		*tslln = TFA9872_BF_TDMSLLN;
		*tsize = TFA9872_BF_TDMSSIZE;
				tfa->bf.swprofil = TFA9872_BF_SWPROFIL;
		tfa->bf.swvstep = TFA9872_BF_SWVSTEP;
		break;
	case 0x73:
		*tdme = TFA9873_BF_TDME;
		*tnbck = TFA9873_BF_TDMNBCK;
		*tslln = TFA9873_BF_TDMSLLN;
		*tsize = TFA9873_BF_TDMSSIZE;
				tfa->bf.swprofil = TFA9873_BF_SWPROFIL;
		tfa->bf.swvstep = TFA9873_BF_SWVSTEP;
		tfa->bf.mtpb = TFA9873_BF_MTPB;
		tfa->bf.clks = TFA9873_BF_CLKS;
		tfa->bf.openmtp = TFA9873_BF_OPENMTP;
		break;
	case 0x74:
		*tdme = TFA9874_BF_TDME;
		*tnbck = TFA9874_BF_TDMNBCK;
		*tslln = TFA9874_BF_TDMSLLN;
		*tsize = TFA9874_BF_TDMSSIZE;
				tfa->bf.swprofil = TFA9874_BF_SWPROFIL;
		tfa->bf.swvstep = TFA9874_BF_SWVSTEP;
		tfa->bf.mtpb = TFA9874_BF_MTPB;
		tfa->bf.clks = TFA9874_BF_CLKS;
		tfa->bf.openmtp = TFA9874_BF_OPENMTP;
		break;
	case 0x78:
		*tdme = TFA9878_BF_TDME;
		*tnbck = TFA9878_BF_TDMNBCK;
		*tslln = TFA9878_BF_TDMSLLN;
		*tsize = TFA9878_BF_TDMSSIZE;
				tfa->bf.swprofil = TFA9878_BF_SWPROFIL;
		tfa->bf.swvstep = TFA9878_BF_SWVSTEP;
		tfa->bf.mtpb = TFA9878_BF_MTPB;
		tfa->bf.clks = TFA9878_BF_CLKS;
		tfa->bf.openmtp = TFA9878_BF_OPENMTP;
		break;
	case 0x13:
		*tdme = TFA9912_BF_TDME;
		*tnbck = TFA9912_BF_TDMNBCK;
		*tslln = TFA9912_BF_TDMSLLN;
		*tsize = TFA9912_BF_TDMSSIZE;
				tfa->bf.swprofil = TFA9912_BF_SWPROFIL;
		tfa->bf.swvstep = TFA9912_BF_SWVSTEP;
		break;
	case 0x94:
		*tdme = TFA9894_BF_TDME;
		*tnbck = TFA9894_BF_TDMNBCK;
		*tslln = TFA9894_BF_TDMSLLN;
		*tsize = TFA9894_BF_TDMSSIZE;
				tfa->bf.swprofil = TFA9894_BF_SWPROFIL;
		tfa->bf.swvstep = TFA9894_BF_SWVSTEP;
		tfa->bf.mtpb = TFA9894_BF_MTPB;
		tfa->bf.clks = TFA9894_BF_CLKS;
		tfa->bf.openmtp = TFA9894_BF_OPENMTP;
		break;

	default:
		pr_err("unsupported device rev:%x\n", revid);
		break;
	}
}
int tfa_dev_set_tdm_bitwidth(struct tfa_device *tfa, int width) /*SACAS-26*/
{
	uint8_t nbck, slotlen, samplesize;

	switch (width) {
	case 16: /* 16-bit sample in 16-bit slot */
		nbck = 0;
		slotlen = 15;
		samplesize = 15;
		break;
	case 24: /* 24-bit sample in 32-bit slot */
		nbck = 2;
		slotlen = 31;
		samplesize = (tfa->is_probus_device == 1) ? 31 : 23;
		break;
	case 32: /* 32-bit sample in 32-bit slot */
		nbck = 2;
		slotlen = 31;
		samplesize = (tfa->is_probus_device == 1) ? 31 : 23;
		break;
	default:
		pr_err("unsupported tdm bitwidth:%d\n", width);
		return -EINVAL;
		break;
	}

	uint16_t tdme, tdmnbck, tdmslln, tdmssize;

	tfa_dev_get_tdm_add(tfa, &tdme, &tdmnbck, &tdmslln,
			    &tdmssize); /*SACAS-26*/
	/* stop tdm */
	tfa_set_bf(tfa, tdme, 0);
	tfa_set_bf(tfa, tdmnbck, nbck);
	tfa_set_bf(tfa, tdmslln, slotlen);
	tfa_set_bf(tfa, tdmssize, samplesize);
	/* enable tdm */
	tfa_set_bf(tfa, tdme, 1);
	return 0;
}
#define NR_OF_BATS 10
void tfa_adapt_noisemode(struct tfa_device *tfa)
{
	int i, avbatt;
	long total_bats = 0;

	if ((tfa_get_bf(tfa, 0x5900) == 0) ||
	    (tfa_get_bf(tfa, TFA9873_BF_LP1) == 1)) {
		if (tfa->verbose)
			pr_debug(
				"Adapting low noise mode is not needed, condition not fulfilled!\n");
		return;
	}
	if (tfa->verbose)
		pr_debug("Adapting low noise mode\n");

	for (i = 0; i < NR_OF_BATS; i++) {
		int bat = TFA_GET_BF(tfa, BATS);

		if (tfa->verbose)
			pr_debug("bats[%d]=%d\n", i, bat);
		total_bats += bat;
		msleep_interruptible(5);
	}

	avbatt = (int)(total_bats / NR_OF_BATS);

	if (avbatt <= MIN_BATT_LEVEL &&
	    !tfa_get_bf(tfa, TFA9873_BF_LNMODE)) {
		tfa_set_bf(tfa, TFA9873_BF_LNMODE, 1);
		pr_debug("\navbatt= %d--Applying high noise gain\n", avbatt);
	} else if (avbatt > MAX_BATT_LEVEL &&
		   tfa_get_bf(tfa, TFA9873_BF_LNMODE)) {
		tfa_set_bf(tfa, TFA9873_BF_LNMODE, 0);
		pr_debug("\navbatt= %d--Applying automatic noise gain\n",
			 avbatt);
	}
}
int tfa_plop_noise_interrupt(struct tfa_device *tfa, int profile, int vstep)
{
	enum tfa_error err;
	int no_clk = 0;

	/* Remove sticky bit by reading it once */
	TFA_GET_BF(tfa, NOCLK);

	/* No clock detected */
	if (tfa_irq_get(tfa, tfa9912_irq_stnoclk)) {
		no_clk = TFA_GET_BF(tfa, NOCLK);

		/* Detect for clock is lost! (clock is not stable) */
		if (no_clk == 1) {
			/* Clock is lost. Set I2CR to remove POP noise */
			pr_info("No clock detected. Resetting the I2CR to avoid pop on 72!\n");
			err = tfa_dev_start(tfa, profile, vstep);
			if (err != tfa_error_ok) {
				pr_err("Error loading i2c registers (tfa_dev_start), err=%d\n",
				       err);
			} else {
				pr_info("Setting i2c registers after I2CR successful\n");
				tfa_dev_set_state(tfa, TFA_STATE_UNMUTE, 0);
			}

			/* Remove sticky bit by reading it once */
			tfa_get_noclk(tfa);

			/* This is only for SAAM on the 72.
				Since the NOCLK interrupt is only enabled for 72 this is the place
				However: Not tested yet! But also does not harm normal flow!
			*/
			if (strstr(tfaContProfileName(tfa->cnt, tfa->dev_idx,
						      profile),
				   ".saam")) {
				pr_info("Powering down from a SAAM profile, workaround PLMA4766 used!\n");
				TFA_SET_BF(tfa, PWDN, 1);
				TFA_SET_BF(tfa, AMPE, 0);
				TFA_SET_BF(tfa, SAMMODE, 0);
			}
		}

		/* If clk is stable set polarity to check for LOW (no clock)*/
		tfa_irq_set_pol(tfa, tfa9912_irq_stnoclk, (no_clk == 0));

		/* clear interrupt */
		tfa_irq_clear(tfa, tfa9912_irq_stnoclk);
	}

	/* return no_clk to know we called tfa_dev_start */
	return no_clk;
}

void tfa_lp_mode_interrupt(struct tfa_device *tfa)
{
	const int irq_stclp0 = 36; /* LP0 interrupt, TFA9872-specific */
	int lp0, lp1;

	if (tfa_irq_get(tfa, irq_stclp0)) {
		lp0 = TFA_GET_BF(tfa, LP0);
		if (lp0 > 0) {
			pr_info("lowpower mode 0 detected\n");
		} else {
			pr_info("lowpower mode 0 not detected\n");
		}

		tfa_irq_set_pol(tfa, irq_stclp0, (lp0 == 0));

		/* clear interrupt */
		tfa_irq_clear(tfa, irq_stclp0);
	}

	if (tfa_irq_get(tfa, tfa9912_irq_stclpr)) {
		lp1 = TFA_GET_BF(tfa, LP1);
		if (lp1 > 0) {
			pr_info("lowpower mode 1 detected\n");
		} else {
			pr_info("lowpower mode 1 not detected\n");
		}

		tfa_irq_set_pol(tfa, tfa9912_irq_stclpr, (lp1 == 0));

		/* clear interrupt */
		tfa_irq_clear(tfa, tfa9912_irq_stclpr);
	}
}
#endif /* __KERNEL__ */
