/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2014-2020 NXP Semiconductors, All Rights Reserved.
 * Copyright 2021 GOODIX
 */

/*
 * tfa98xx_parameters.h
 *
 *	Created on: Jul 22, 2013
 *		Author: NLV02095
 */

#ifndef TFA98XXPARAMETERS_H_
#define TFA98XXPARAMETERS_H_

#include <linux/types.h>

#include "tfa_service.h"

/*
 * profiles & volumesteps
 *
 */
#define TFA_MAX_VSTEP_MSG_MARKER	(100) /* This marker	is used to indicate if all msgs need to be written to the device */

/*
 * typedef for 24 bit value using 3 bytes
 */
struct uint24 {
	uint8_t b[3];
} __packed;
/*
 * the generic header
 *	all char types are in ASCII
 */
struct TfaHeader {
	uint16_t id;
	char version[2]; /* "V_" : V=version, vv=subversion */
	char subversion[2]; /* "vv" : vv=subversion */
	uint16_t size; /* data size in bytes following CRC */
	uint32_t CRC; /* 32-bits CRC for following data */
	char customer[8]; /* “name of customer” */
	char application[8]; /* “application name” */
	char type[8]; /* “application type name” */
} __packed;

/*
 * coolflux direct memory access
 */
struct TfaDspMem {
	uint8_t	type;		/* 0--3: p, x, y, iomem */
	uint16_t address;	/* target address */
	uint8_t size;		/* data size in words */
	int words[];		/* payload	in signed 32bit integer (two's complement) */
} __packed;

/*
 * the biquad coefficients for the API together with index in filter
 *	the biquad_index is the actual index in the equalizer +1
 */
#define BIQUAD_COEFF_SIZE		6

/*
 * Output fixed point coeffs structure
 */

struct TfaBiquadOld {
	uint8_t bytes[BIQUAD_COEFF_SIZE*sizeof(struct uint24)];
} __packed;

/*
 * EQ filter definitions
 * Note: This is not in line with smartstudio (JV: 12/12/2016)
 */

/*
 * filter parameters for biquad (re-)calculation
 */
struct TfaFilter {
	struct TfaBiquadOld biquad;
	uint8_t enabled;
	uint8_t type; /* (== enum FilterTypes, assure 8bits length) */
	float frequency;
	float Q;
	float gain;
} __packed; /* 8 * float + int32 + byte == 37 */

/*
 * biquad params for calculation
 */

/*
 * Loudspeaker Compensation filter definitions
 */

/*
 * Anti Aliasing Elliptic filter definitions
 */

/**
 * Integrator filter input definitions
 */

struct TfaContAntiAlias {
	int8_t index;	/**< index determines destination type; anti-alias, integrator, eq */
	uint8_t type;
	float cutOffFreq; /* cut off frequency */
	float samplingFreq;
	float rippleDb; /* integrator leakage */
	float rolloff;
	uint8_t bytes[5*3]; /* payload 5*24buts coeffs */
} __packed;

struct TfaContIntegrator {
	int8_t index;	/**< index determines destination type; anti-alias, integrator, eq */
	uint8_t type;
	float cutOffFreq; /* cut off frequency */
	float samplingFreq;
	float leakage; /* integrator leakage */
	float reserved;
	uint8_t bytes[5*3]; /* payload 5*24buts coeffs */
} __packed;

struct TfaContEq {
	int8_t index;
	uint8_t type; /* (== enum FilterTypes, assure 8bits length) */
	float cutOffFreq; /* cut off frequency, // range: [100.0 4000.0] */
	float samplingFreq; /* sampling frequency */
	float Q; /* range: [0.5 5.0] */
	float gainDb; /* range: [-10.0 10.0] */
	uint8_t bytes[5*3]; /* payload 5*24buts coeffs */
} __packed; /* 8 * float + int32 + byte == 37 */

union TfaContBiquad {
	struct TfaContEq eq;
	struct TfaContAntiAlias aa;
	struct TfaContIntegrator in;
} __packed;

#define TFA98XX_MAX_EQ			10

/*
 * files
 */
#define HDR(c1, c2) (c2<<8|c1) /* little endian */
enum TfaHeaderType {
	paramsHdr		= HDR('P', 'M'), /* container file */
	volstepHdr		= HDR('V', 'P'),
	patchHdr		= HDR('P', 'A'),
	speakerHdr		= HDR('S', 'P'),
	presetHdr		= HDR('P', 'R'),
	configHdr		= HDR('C', 'O'),
	equalizerHdr	= HDR('E', 'Q'),
	drcHdr			= HDR('D', 'R'),
	msgHdr			= HDR('M', 'G'),	/* generic message */
	infoHdr			= HDR('I', 'N')
};

/*
 * equalizer file
 */
struct TfaEqualizerFile {
	struct TfaHeader hdr;
	uint8_t samplerate; /* ==enum samplerates, assure 8 bits */
	struct TfaFilter filter[TFA98XX_MAX_EQ]; /* note: API index counts from 1..10 */
} __packed;

/*
 * patch file
 */
struct TfaPatchFile {
	struct TfaHeader hdr;
	uint8_t data[];
} __packed;

/*
 * generic message file
 *	-	the payload of this file includes the opcode and is send straight to the DSP
 */
struct TfaMsgFile {
	struct TfaHeader hdr;
	uint8_t data[];
} __packed;

/*
 * NOTE the tfa98xx API defines the enum Tfa98xx_config_type that defines
 *			the subtypes as describes below.
 *			tfa98xx_dsp_config_parameter_type() can be used to get the
 *			supported type for the active device..
 */
/*
 * config file V1 sub 1
 */

/*
 * config file V1 sub 2
 */

/*
 * config file V1 sub 3
 */

/*
 * config file V1.0
 */
struct TfaConfigFile {
	struct TfaHeader hdr;
	uint8_t data[];
} __packed;

/*
 * preset file
 */
struct TfaPresetFile {
	struct TfaHeader hdr;
	uint8_t data[];
} __packed;

/*
 * drc file
 */
struct TfaDrcFile {
	struct TfaHeader hdr;
	uint8_t data[];
} __packed;

/*
 * drc file
 * for tfa 2 there is also a xml-version
 */
#define TFA_DR3_VERSION	'3'
struct TfaDrcFile2 {
	struct TfaHeader hdr;
	uint8_t version[3];
	uint8_t data[];
} __packed;

/*
 * volume step structures
 */
/* VP01 */

/* VP02 */
struct TfaVolumeStep2 {
	float attenuation; /* IEEE single float */
	uint8_t preset[TFA98XX_PRESET_LENGTH];
	struct TfaFilter filter[TFA98XX_MAX_EQ]; /* note: API index counts from 1..10 */
} __packed;

/*
 * volumestep file
 */
/*
 * volumestep2 file
 */
struct TfaVolumeStep2File {
	struct TfaHeader hdr;
	uint8_t vsteps; /* can also be calculated from size+type */
	uint8_t samplerate; /* ==enum samplerates, assure 8 bits */
	struct TfaVolumeStep2 vstep[]; /* start of variable length contents:N times volsteps */
} __packed;

/*
 * volumestepMax2 file
 */
struct TfaVolumeStepMax2File {
	struct TfaHeader hdr;
	uint8_t version[3];
	uint8_t NrOfVsteps;
	uint8_t vstepsBin[];
} __packed;

/*
 * volumestepMax2 file
 * This volumestep should ONLY be used for the use of bin2hdr!
 * This can only be used to find the messagetype of the vstep (without header)
 */

struct TfaVolumeStepRegisterInfo {
	uint8_t NrOfRegisters;
	uint16_t registerInfo[];
} __packed;

struct TfaVolumeStepMessageInfo {
	uint8_t NrOfMessages;
	uint8_t MessageType;
	struct uint24 MessageLength;
	uint8_t CmdId[3];
	uint8_t ParameterData[];
} __packed;

/*
 * subv 00 volumestep file
 */

/*
 * speaker file header
 */
struct TfaSpkHeader {
	struct TfaHeader hdr;
	char name[8]; /* speaker nick name (e.g. “dumbo”) */
	char vendor[16];
	char type[8];
/* dimensions (mm) */
	uint8_t height;
	uint8_t width;
	uint8_t depth;
	uint16_t ohm;
} __packed;

/*
 * speaker file
 */
struct TfaSpeakerFile {
	struct TfaHeader hdr;
	char name[8]; /* speaker nick name (e.g. “dumbo”) */
	char vendor[16];
	char type[8];
/* dimensions (mm) */
	uint8_t height;
	uint8_t width;
	uint8_t depth;
	uint8_t ohm_primary;
	uint8_t ohm_secondary;
	uint8_t data[]; /* payload TFA98XX_SPEAKERPARAMETER_LENGTH */
} __packed;

struct TfaFWVer {
	uint8_t Major;
	uint8_t minor;
	uint8_t minor_update:6;
	uint8_t Update:2;
} __packed;

/*
 * parameter container file
 */
/*
 * descriptors
 * Note 1: append new DescriptorType at the end
 * Note 2: add new descriptors to dsc_name[] in tfaContUtil.c
 */
enum TfaDescriptorType {
	dscDevice, /* device list */
	dscProfile, /* profile list */
	dscRegister, /* register patch */
	dscString, /* ascii, zero terminated string */
	dscFile, /* filename + file contents */
	dscPatch, /* patch file */
	dscMarker, /* marker to indicate end of a list */
	dscMode,
	dscSetInputSelect,
	dscSetOutputSelect,
	dscSetProgramConfig,
	dscSetLagW,
	dscSetGains,
	dscSetvBatFactors,
	dscSetSensesCal,
	dscSetSensesDelay,
	dscBitfield,
	dscDefault, /* used to reset bitfields to there default values */
	dscLiveData,
	dscLiveDataString,
	dscGroup,
	dscCmd,
	dscSetMBDrc,
	dscFilter,
	dscNoInit,
	dscFeatures,
	dscCfMem, /* coolflux memory x, y, io */
	dscSetFwkUseCase,
	dscSetVddpConfig,
	dsc_last /* trailer */
};

struct TfaDescPtr {
	uint32_t offset:24;
	uint32_t	type:8; /* (== enum TfaDescriptorType, assure 8bits length) */
} __packed;

/*
 * generic file descriptor
 */
struct TfaFileDsc {
	struct TfaDescPtr name;
	uint32_t size; /* file data length in bytes */
	uint8_t data[]; /* payload */
} __packed;

/*
 * device descriptor list
 */
struct TfaDeviceList {
	uint8_t length; /* nr of items in the list */
	uint8_t bus; /* bus */
	uint8_t dev; /* device */
	uint8_t func; /* subfunction or subdevice */
	uint32_t devid; /* device	hw fw id */
	struct TfaDescPtr name; /* device name */
	struct TfaDescPtr list[]; /* items list */
} __packed;

/*
 * profile descriptor list
 */
struct TfaProfileList {
	uint32_t length:8; /* nr of items in the list + name */
	uint32_t group:8; /* profile group number */
	uint32_t ID:16; /* profile ID */
	struct TfaDescPtr name; /* profile name */
	struct TfaDescPtr list[]; /* items list (lenght-1 items) */
} __packed;
#define TFA_PROFID 0x1234

/*
 * livedata descriptor list
 */
struct TfaLiveDataList {
	uint32_t length:8; /* nr of items in the list */
	uint32_t ID:24; /* profile ID */
	struct TfaDescPtr name; /* livedata name */
	struct TfaDescPtr list[]; /* items list */
} __packed;
#define TFA_LIVEDATAID 0x5678

/*
 * Bitfield descriptor
 */
struct TfaBitfield {
	uint16_t	value;
	uint16_t	field; /* ==datasheet defined, 16 bits */
} __packed;

/*
 * Bitfield enumuration bits descriptor
 */
struct TfaBfEnum {
	unsigned int	len:4; /* this is the actual length-1 */
	unsigned int	pos:4;
	unsigned int	address:8;
} __packed;

/*
 * Register patch descriptor
 */
struct TfaRegpatch {
	uint8_t	address; /* register address */
	uint16_t	value; /* value to write */
	uint16_t	mask; /* mask of bits to write */
} __packed;

/*
 * Mode descriptor
 */
struct TfaUseCase {
	int value; /* mode value, maps to enum Tfa98xx_Mode */
} __packed;

/*
 * NoInit descriptor
 */

/*
 * Features descriptor
 */
struct TfaFeatures {
	uint16_t value[3]; /* features value */
} __packed;

/*
 * the container file
 *	- the size field is 32bits long (generic=16)
 *	- all char types are in ASCII
 */
#define TFA_PM_SUBVERSION '1'
struct TfaContainer {
	char id[2]; /* "XX" : XX=type */
	char version[2]; /* "V_" : V=version, vv=subversion */
	char subversion[2]; /* "vv" : vv=subversion */
	uint32_t size; /* data size in bytes following CRC */
	uint32_t CRC; /* 32-bits CRC for following data */
	uint16_t rev; /* "extra chars for rev nr" */
	char customer[8]; /* “name of customer” */
	char application[8]; /* “application name” */
	char type[8]; /* “application type name” */
	uint16_t ndev; /* "nr of device lists" */
	uint16_t nprof; /* "nr of profile lists" */
	uint16_t nliveData; /* "nr of livedata lists" */
	struct TfaDescPtr index[]; /* start of item index table */
} __packed;

#endif /* TFA98XXPARAMETERS_H_ */
