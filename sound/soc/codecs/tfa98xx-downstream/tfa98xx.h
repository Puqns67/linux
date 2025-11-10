/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2014-2020 NXP Semiconductors, All Rights Reserved.
 * Copyright 2021 GOODIX
 */

#ifndef __TFA98XX_INC__
#define __TFA98XX_INC__

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/list.h>

#include "tfa_device.h"
#include "tfa_container.h"

/* max. length of a alsa mixer control name */
#define MAX_CONTROL_NAME		48

#define TFA98XX_MAX_REGISTER				0xff

#define TFA98XX_FLAG_SKIP_INTERRUPTS	(1 << 0)
#define TFA98XX_FLAG_STEREO_DEVICE	(1 << 2)
#define TFA98XX_FLAG_MULTI_MIC_INPUTS	(1 << 3)
#define TFA98XX_FLAG_CALIBRATION_CTL	(1 << 5)
#define TFA98XX_FLAG_REMOVE_PLOP_NOISE	(1 << 6)
#define TFA98XX_FLAG_LP_MODES			(1 << 7)
#define TFA98XX_FLAG_TDM_DEVICE		 (1 << 8)
#define TFA98XX_FLAG_ADAPT_NOISE_MODE	(1 << 9)

#define TFA98XX_NUM_RATES		9
/* DSP init status */
enum tfa98xx_dsp_init_state {
	TFA98XX_DSP_INIT_STOPPED,	/* DSP not running */
	TFA98XX_DSP_INIT_RECOVER,	/* DSP error detected at runtime */
	TFA98XX_DSP_INIT_FAIL,		/* DSP init failed */
	TFA98XX_DSP_INIT_PENDING,	/* DSP start requested */
	TFA98XX_DSP_INIT_DONE,		/* DSP running */
	TFA98XX_DSP_INIT_INVALIDATED,	/* DSP was running, requires re-init */
};

enum tfa98xx_dsp_fw_state {
		TFA98XX_DSP_FW_NONE = 0,
		TFA98XX_DSP_FW_PENDING,
		TFA98XX_DSP_FW_FAIL,
		TFA98XX_DSP_FW_OK,
};

struct tfa98xx_firmware {
	void			*base;
	struct tfa98xx_device	*dev;
	char			name[9]; /* TODO get length from tfa parameter defs */
};

struct tfa98xx_baseprofile {
	char basename[MAX_CONTROL_NAME];	/* profile basename */
	int len;						       /* profile length */
	int item_id;						   /* profile id */
	int sr_rate_sup[TFA98XX_NUM_RATES]; /* sample rates supported by this profile */
	struct list_head list;				/* list of all profiles */
};
struct tfa98xx {
	struct regmap *regmap;
	struct i2c_client *i2c;
	struct snd_soc_component *codec;
	struct workqueue_struct *tfa98xx_wq;
	struct delayed_work init_work;
	struct delayed_work monitor_work;
	struct delayed_work interrupt_work;
	struct delayed_work nmodeupdate_work;
	struct mutex dsp_lock;
	int dsp_init;
	int dsp_fw_state;
	int sysclk;
	u16 rev;
	int audio_mode;
	struct tfa98xx_firmware fw;
	int rate;
	wait_queue_head_t wq;
	struct device *dev;
	unsigned int init_count;
	int pstream;
	int cstream;

	unsigned int rate_constraint_list[TFA98XX_NUM_RATES];
	struct snd_pcm_hw_constraint_list rate_constraint;

	struct gpio_desc *reset_gpio;
	struct gpio_desc *irq_gpio;
	struct list_head list;
	struct tfa_device *tfa;
	int vstep;
	int profile;
	int prof_vsteps[TFACONT_MAXPROFS]; /* store vstep per profile (single device) */

	u8 reg;
	unsigned int flags;
	bool set_mtp_cal;
	uint16_t cal_data;
};


#endif /* __TFA98XX_INC__ */

