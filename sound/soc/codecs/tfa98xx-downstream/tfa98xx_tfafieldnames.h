/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2014-2020 NXP Semiconductors, All Rights Reserved.
 * Copyright 2021 GOODIX
 */

#include "tfa2_tfafieldnames_N1C.h"
/* diffs for specific devices */
#include "tfa9872_tfafieldnames.h"
#include "tfa9912_tfafieldnames.h"
#include "tfa9873_tfafieldnames.h"
#include "tfa9874_tfafieldnames.h"
#include "tfa9878_tfafieldnames.h"
#include "tfa9894_tfafieldnames.h"
#include "tfa9894_tfafieldnames_N2.h"
#include "tfa9875_tfafieldnames.h"
#include "tfa9875_tfafieldnames_A1.h"

/* missing 'common' defs break the build */

/* MTP access uses registers
 *	defs are derived from corresponding bitfield names as used in the BF macros
 */
#define MTPKEY2		MTPK		/* unlock key2 MTPK */
#define MTP0		MTPOTC	/* MTP data */

/* interrupt enable register uses HW name in TFA2 */

/* TFA9872 specific bit field names */
#define TFA2_BF_LP0 TFA9872_BF_LP0
#define TFA2_BF_LP1 TFA9872_BF_LP1
#define TFA2_BF_R25C TFA9872_BF_R25C
#define TFA2_BF_SAMMODE TFA9872_BF_SAMMODE

