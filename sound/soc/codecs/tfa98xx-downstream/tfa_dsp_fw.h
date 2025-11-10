/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2014-2020 NXP Semiconductors, All Rights Reserved.
 * Copyright 2021 GOODIX
 */

#ifndef TFA98XX_INTERNALS_H
#define TFA98XX_INTERNALS_H

#include "tfa_service.h" /* TODO cleanup for enum Tfa98xx_Status_ID */
/*
 * tfadsp_fw_api.c
 */
/**
 * Return a text version of the firmware status ID code
 * @param status the given status ID code
 * @return the firmware status ID string
 */

/*
 * the order matches the ACK bits order in TFA98XX_CF_STATUS
 */

/* the following type mappings are compiler specific */

/* module Ids */
#define MODULE_FRAMEWORK		0
#define MODULE_SPEAKERBOOST	 1
#define MODULE_BIQUADFILTERBANK 2

/* RPC commands */
/* SET */
#define FW_PAR_ID_SET_MEMORY			0x03
#define FW_PAR_ID_SET_SENSES_DELAY		0x04
/* GET */
#define FW_PAR_ID_GLOBAL_GET_INFO		0x84
#define FW_PAR_ID_GET_FEATURE_INFO		0x85

/* Load a full model into SpeakerBoost. */
/* SET */
#define SB_PARAM_SET_ALGO_PARAMS		0x00
#define SB_PARAM_SET_RE25C				0x05
#define SB_PARAM_SET_LSMODEL			0x06
#define SB_PARAM_SET_MBDRC				0x07
#define SB_PARAM_SET_DRC				0x0F
/* GET */
#define SB_PARAM_GET_ALGO_PARAMS		0x80
#define SB_PARAM_GET_RE25C				0x85
#define SB_PARAM_GET_LSMODEL			0x86

#define SB_PARAM_SET_PRESET			 0x0D	/* Load a preset */
#define SB_PARAM_SET_CONFIG				0x0E	/* Load a config */
#define SB_PARAM_SET_AGCINS			 0x10

/*	SET: TAPTRIGGER */

/* GET: TAPTRIGGER*/

/* sets the speaker calibration impedance (@25 degrees celsius) */

/* for compatibility */

/* RPC Status results */

/* the maximum message length in the communication with the DSP */
#define TFA2_MAX_PARAM_SIZE (507*3) /* TFA2 */

#define ROUND_DOWN(a, n) (((a)/(n))*(n))

/* feature bits */
#define FEATURE1_DRC	0x200 /* bit9 NOT set means DRC expected */

/* DSP firmware xmem defines */

/* note that the following defs rely on the handle variable */
#define TFA2_FW_XMEM_CALIBRATION_DONE	516
#define TFA_FW_XMEM_CALIBRATION_DONE	TFA_FAM_FW(tfa, XMEM_CALIBRATION_DONE)

#define TFA2_FW_ReZ_SCALE	65536

/*
 * Internal functions shared between tfa_dsp.c and tfa_init.c
 */

enum tfa_error tfa98xx_check_rpc_status(struct tfa_device *tfa, int *pRpcStatus);
enum tfa_error tfa98xx_wait_result(struct tfa_device *tfa, int waitRetryCount);

/* per-device ops setup functions (defined in tfa_init.c, called from tfa_dsp.c) */
void tfa9872_ops(struct tfa_device_ops *ops);
void tfa9873_ops(struct tfa_device_ops *ops);
void tfa9874_ops(struct tfa_device_ops *ops);
void tfa9875_ops(struct tfa_device_ops *ops);
void tfa9878_ops(struct tfa_device_ops *ops);
void tfa9912_ops(struct tfa_device_ops *ops);
void tfa9888_ops(struct tfa_device_ops *ops);
void tfa9894_ops(struct tfa_device_ops *ops);

#endif /* TFA98XX_INTERNALS_H */
