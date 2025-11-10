/* SPDX-License-Identifier: GPL-2.0 */
#ifndef TFA_SERVICE_H
#define TFA_SERVICE_H

#include <linux/types.h>

#include "tfa_device.h"

/*
 * data previously defined in Tfa9888_dsp.h
 */
#define MEMTRACK_MAX_WORDS			150
#define FW_VAR_API_VERSION			(521)

/* following lengths are in bytes */
#define TFA98XX_PRESET_LENGTH			87

/*
 * Type containing all the possible msg returns DSP can give
 *
 * TODO: move to tfa_dsp_fw.h
 */
enum Tfa98xx_Status_ID {
	Tfa98xx_DSP_Not_Running			= -1,	/* No response from DSP */
	Tfa98xx_I2C_Req_Done			= 0,	/* Request executed correctly */
	Tfa98xx_I2C_Req_Busy			= 1,	/* Request is being processed */
	Tfa98xx_I2C_Req_Invalid_M_ID		= 2,	/* Invalid M-ID */
	Tfa98xx_I2C_Req_Invalid_P_ID		= 3,	/* Invalid P-ID */
	Tfa98xx_I2C_Req_Invalid_CC		= 4,	/* Invalid channel config */
	Tfa98xx_I2C_Req_Invalid_Seq		= 5,	/* Invalid command sequence */
	Tfa98xx_I2C_Req_Invalid_Param		= 6,	/* Generic error */
	Tfa98xx_I2C_Req_Buffer_Overflow		= 7,	/* I2C buffer overflowed */
	Tfa98xx_I2C_Req_Calib_Busy		= 8,	/* Calibration not finished */
	Tfa98xx_I2C_Req_Calib_Failed		= 9	/* Calibration failed */
};

/* ---------------------------- Max1 ---------------------------- */
/* Headroom applied to the main input signal */
/* Exponent used for AGC Gain related variables */
/* Exponent used for Gain Correction related variables */
/* -------------------------------------------------------------- */

/* speaker related parameters */

/* vstep related parameters */

/* Maximum number of retries for DSP result
 * Keep this value low!
 * If certain calls require longer wait conditions, the
 * application should poll, not the API
 * The total wait time depends on device settings. Those
 * are application specific.
 */
#define TFA98XX_WAITRESULT_NTRIES		40

/* following lengths are in bytes */

/*
 * Type containing all the possible msg returns DSP can give
 *
 * TODO: move to tfa_dsp_fw.h
 */
/*
 * speaker as microphone
 */
enum Tfa98xx_saam {
	Tfa98xx_saam_none,	/*< SAAM feature not available */
	Tfa98xx_saam		/*< SAAM feature available */
};

/*
 * config file subtypes
 */

/* the number of biquads supported */
#define TFA98XX_BIQUAD_NUM	10

enum Tfa98xx_Mode {
	Tfa98xx_Mode_Normal = 0,
	Tfa98xx_Mode_RCV
};

enum Tfa98xx_Mute {
	Tfa98xx_Mute_Off,
	Tfa98xx_Mute_Digital,
	Tfa98xx_Mute_Amplifier
};

struct TfaMsg {
	uint8_t msg_size;
	unsigned char cmdId[3];
	int data[9];
};

struct Tfa98xx_Memtrack_data {
	int length;
	float mValues[MEMTRACK_MAX_WORDS];
	int mAdresses[MEMTRACK_MAX_WORDS];
	int trackers[MEMTRACK_MAX_WORDS];
	int scalingFactor[MEMTRACK_MAX_WORDS];
};

/* possible memory values for DMEM in CF_CONTROLs */
enum Tfa98xx_DMEM {
	Tfa98xx_DMEM_ERR = -1,
	Tfa98xx_DMEM_PMEM = 0,
	Tfa98xx_DMEM_XMEM = 1,
	Tfa98xx_DMEM_YMEM = 2,
	Tfa98xx_DMEM_IOMEM = 3,
};

/**
 * lookup the device type and return the family type
 */

/**
 *	register definition structure
 */
struct regdef {
	unsigned char offset;			/**< subaddress offset */
	unsigned short pwronDefault;	/**< register contents after poweron */
	unsigned short pwronTestmask;	/**< mask of bits not test */
	char *name;						/**< short register name */
};

enum Tfa98xx_DMEM tfa98xx_filter_mem(struct tfa_device *tfa, int filter_index, unsigned short *address, int channel);

/**
 * Load the default HW settings in the device
 * @param tfa the device struct pointer
 */
enum tfa_error tfa98xx_init(struct tfa_device *tfa);

/**
 * If needed, this function can be used to get a text version of the status ID code
 * @param status the given status ID code
 * @return the I2C status ID string
 */
const char *tfa98xx_get_i2c_status_id_string(int status);

/* control the powerdown bit
 * @param tfa the device struct pointer
 * @param powerdown must be 1 or 0
 */
enum tfa_error tfa98xx_powerdown(struct tfa_device *tfa, int powerdown);

/* indicates on which channel of DATAI2 the gain from the IC is set
 * @param tfa the device struct pointer
 * @param gain_sel, see Tfa98xx_StereoGainSel_t
 */

/**
 * set the mtp with user controllable values
 * @param tfa the device struct pointer
 * @param value to be written
 * @param mask to be applied toi the bits affected
 */
enum tfa_error tfa98xx_set_mtp(struct tfa_device *tfa, uint16_t value, uint16_t mask);
enum tfa_error tfa98xx_get_mtp(struct tfa_device *tfa, uint16_t *value);

/**
 * lock or unlock KEY2
 * lock = 1 will lock
 * lock = 0 will unlock
 * note that on return all the hidden key will be off
 */
void tfa98xx_key2(struct tfa_device *tfa, int lock);

short tfa98xx_get_exttemp(struct tfa_device *tfa);

/* control the volume of the DSP
 * @param vol volume in bit field. It must be between 0 and 255
 */

/* set the input channel to use
 * @param channel see Tfa98xx_Channel_t enumeration
 */

/* set the mode for normal or receiver mode
 * @param mode see Tfa98xx_Mode enumeration
 */
enum tfa_error tfa98xx_select_mode(struct tfa_device *tfa, enum Tfa98xx_Mode mode );

/* mute/unmute the audio
 * @param mute see Tfa98xx_Mute_t enumeration
 */
static enum tfa_error tfa98xx_set_mute(struct tfa_device *tfa,
				       enum Tfa98xx_Mute mute);

/*
 *	returns the number of the supported speaker count
 */

/**
 * Return the tfa revision
 */

/*
 * Return the feature bits from MTP and cnt file for comparison
 */
enum tfa_error tfa98xx_compare_features(struct tfa_device *tfa, int features_from_MTP[3], int features_from_cnt[3]);

/*
 * return feature bits
 */
enum tfa_error tfa98xx_dsp_get_sw_feature_bits(struct tfa_device *tfa, int features[2]);
enum tfa_error tfa98xx_dsp_get_hw_feature_bits(struct tfa_device *tfa, int *features);

/*
 * tfa98xx_supported_saam
 *	returns the speaker as microphone feature
 * @param saam enum pointer
 *	@return error code
 */
enum tfa_error tfa98xx_supported_saam(struct tfa_device *tfa, enum Tfa98xx_saam *saam);

/* load the tables to the DSP
 *	called after patch load is done
 *	@return error code
 */

/* set or clear DSP reset signal
 * @param new state
 * @return error code
 */

/* check the state of the DSP subsystem
 * return ready = 1 when clocks are stable to allow safe DSP subsystem access
 * @param tfa the device struct pointer
 * @param ready pointer to state flag, non-zero if clocks are not stable
 * @return error code
 */
enum tfa_error tfa98xx_dsp_system_stable(struct tfa_device *tfa, int *ready);

/**
 * check the state of the DSP coolflux
 * @param tfa the device struct pointer
 * @return the value of CFE
 */
int tfa_cf_enabled(struct tfa_device *tfa);

/* The following functions can only be called when the DSP is running
 * - I2S clock must be active,
 * - IC must be in operating mode
 */

/**
 * patch the ROM code of the DSP
 * @param tfa the device struct pointer
 * @param patchLength the number of bytes of patchBytes
 * @param patchBytes pointer to the bytes to patch
 */
enum tfa_error tfa_dsp_patch(struct tfa_device *tfa,
				 int patchLength,
				 const unsigned char *patchBytes);

/**
 * load explicitly the speaker parameters in case of free speaker,
 * or when using a saved speaker model
 */
enum tfa_error tfa98xx_dsp_write_speaker_parameters(
				struct tfa_device *tfa,
				int length,
				const unsigned char *pSpeakerBytes);

/**
 * read the speaker parameters as used by the SpeakerBoost processing
 */

/**
 * read the current status of the DSP, typically used for development,
 * not essential to be used in a product
 */

/**
 * Check whether the DSP supports DRC
 * pbSupportDrc=1 when DSP supports DRC,
 * pbSupportDrc=0 when DSP doesn't support it
 */
enum tfa_error tfa98xx_dsp_support_drc(struct tfa_device *tfa,
						int *pbSupportDrc);

/**
 * read the speaker excursion model as used by SpeakerBoost processing
 */

/**
 * load all the parameters for a preset from a file
 */
enum tfa_error tfa98xx_dsp_write_preset(struct tfa_device *tfa,
						int length, const unsigned char
						*pPresetBytes);

/**
 * wrapper for dsp_msg that adds opcode and only writes
 */
enum tfa_error tfa_dsp_cmd_id_write(struct tfa_device *tfa,
				unsigned char module_id,
				unsigned char param_id, int num_bytes,
						      const unsigned char data[]);

/**
 * wrapper for dsp_msg that writes opcode and reads back the data
 */
enum tfa_error tfa_dsp_cmd_id_write_read(struct tfa_device *tfa,
				unsigned char module_id,
				unsigned char param_id, int num_bytes,
						      unsigned char data[]);

/**
 * wrapper for dsp_msg that adds opcode and 3 bytes required for MBDrcDynamics
 */
enum tfa_error tfa_dsp_cmd_id_MBDrc_dynamics(struct tfa_device *tfa,
				unsigned char module_id,
				unsigned char param_id, int index_subband,
				int num_bytes, unsigned char data[]);

/**
 * Disable a certain biquad.
 * @param tfa the device struct pointer
 * @param biquad_index: 1-10 of the biquad that needs to be addressed
 */
enum tfa_error Tfa98xx_DspBiquad_Disable(struct tfa_device *tfa,
									int biquad_index);

/**
 * fill the calibration value as milli ohms in the struct
 * assume that the device has been calibrated
 */

/*
 * return the mohm value
 */

/*
 * return sign extended tap pattern
 */

/**
 * Reads a number of words from dsp memory
 * @param tfa the device struct pointer
 * @param subaddress write address to set in address register
 * @param pValue pointer to read data
 */
enum tfa_error tfa98xx_read_register16(struct tfa_device *tfa,
						unsigned char subaddress,
						unsigned short *pValue);

/**
 * Reads a number of words from dsp memory
 * @param tfa the device struct pointer
 * @param subaddress write address to set in address register
 * @param value value to write int the memory
 */
enum tfa_error tfa98xx_write_register16(struct tfa_device *tfa,
					unsigned char subaddress,
					unsigned short value);

/**
 * Get the status of the external DSP
 * @param tfa the device struct pointer
 * @return status
 */
int tfa98xx_get_dsp_status(struct tfa_device *tfa);

/**
 * Write a command message (RPC) to the dsp
 * @param tfa the device struct pointer
 * @param num_bytes command buffer size in bytes
 * @param command_buffer
 * @return tfa error enum
 */
enum tfa_error tfa98xx_write_dsp(struct tfa_device *tfa,	int num_bytes, const char *command_buffer);

/**
 * Read the result from the last message from the dsp
 * @param tfa the device struct pointer
 * @param num_bytes result buffer size in bytes
 * @param result_buffer
 * @return tfa error enum
 */
enum tfa_error tfa98xx_read_dsp(struct tfa_device *tfa,	int num_bytes, unsigned char *result_buffer);

/**
 * Write a command message (RPC) to the dsp and return the result
 * @param tfa the device struct pointer
 * @param command_length command buffer size in bytes
 * @param command_buffer command buffer
 * @param result_length result buffer size in bytes
 * @param result_buffer result buffer
 * @return tfa error enum
 */
enum tfa_error tfa98xx_writeread_dsp(struct tfa_device *tfa, int command_length, void *command_buffer,
												int result_length, void *result_buffer);

/**
 * Reads a number of words from dsp memory
 * @param tfa the device struct pointer
 * @param start_offset offset from where to start reading
 * @param num_words number of words to read
 * @param pValues pointer to read data
 */
enum tfa_error tfa98xx_dsp_read_mem(struct tfa_device *tfa,
					unsigned int start_offset,
					int num_words, int *pValues);
/**
 * Write a value to dsp memory
 * @param tfa the device struct pointer
 * @param address write address to set in address register
 * @param value value to write int the memory
 * @param memtype type of memory to write to
 */
enum tfa_error tfa98xx_dsp_write_mem_word(struct tfa_device *tfa,
					unsigned short address, int value, int memtype);

/**
 * Read data from dsp memory
 * @param tfa the device struct pointer
 * @param subaddress write address to set in address register
 * @param num_bytes number of bytes to read from dsp
 * @param data the unsigned char buffer to read data into
 */
enum tfa_error tfa98xx_read_data(struct tfa_device *tfa,
				 unsigned char subaddress,
				 int num_bytes, unsigned char data[]);

/**
 * Write all the bytes specified by num_bytes and data to dsp memory
 * @param tfa the device struct pointer
 * @param subaddress the subaddress to write to
 * @param num_bytes number of bytes to write
 * @param data actual data to write
 */
enum tfa_error tfa98xx_write_data(struct tfa_device *tfa,
					unsigned char subaddress,
					int num_bytes,
					const unsigned char data[]);

enum tfa_error tfa98xx_write_raw(struct tfa_device *tfa,
					  int num_bytes,
					  const unsigned char data[]);

/* support for converting error codes into text */
const char *tfa98xx_get_error_string(enum tfa_error error);

/**
 * convert signed 24 bit integers to 32bit aligned bytes
 * input:	data contains "num_bytes/3" int24 elements
 * output:	bytes contains "num_bytes" byte elements
 * @param num_data length of the input data array
 * @param data input data as integer array
 * @param bytes output data as unsigned char array
 */
void tfa98xx_convert_data2bytes(int num_data, const int data[],
					unsigned char bytes[]);

/**
 * convert memory bytes to signed 24 bit integers
 * input:	bytes contains "num_bytes" byte elements
 * output: data contains "num_bytes/3" int24 elements
 * @param num_bytes length of the input data array
 * @param bytes input data as unsigned char array
 * @param data output data as integer array
 */
void tfa98xx_convert_bytes2data(int num_bytes, const unsigned char bytes[],
					int data[]);

/**
 * Read a part of the dsp memory
 * @param tfa the device struct pointer
 * @param memoryType indicator to the memory type
 * @param offset from where to start reading
 * @param length the number of bytes to read
 * @param bytes output data as unsigned char array
 */

/**
 * Write a value to the dsp memory
 * @param tfa the device struct pointer
 * @param memoryType indicator to the memory type
 * @param offset from where to start writing
 * @param length the number of bytes to write
 * @param value the value to write to the dsp
 */

enum tfa_error tfa98xx_dsp_write_config(struct tfa_device *tfa, int length, const unsigned char *p_config_bytes);
enum tfa_error tfa98xx_dsp_write_drc(struct tfa_device *tfa, int length, const unsigned char *p_drc_bytes);

/**
 * write/read raw msg functions :
 * the buffer is provided in little endian format, each word occupying 3 bytes, length is in bytes.
 * The functions will return immediately and do not wait for DSP response.
 * @param tfa the device struct pointer
 * @param length length of the character buffer to write
 * @param buf character buffer to write
 */
enum tfa_error tfa_dsp_msg_rpc(struct tfa_device *tfa, int length, const char *buf);

/**
 * The wrapper functions to call the dsp msg, register and memory function for tfa or probus
 */
enum tfa_error tfa_dsp_msg(struct tfa_device *tfa, int length, const char *buf);
enum tfa_error tfa_dsp_msg_read(struct tfa_device *tfa, int length, unsigned char *bytes);
enum tfa_error tfa_reg_write(struct tfa_device *tfa, unsigned char subaddress, unsigned short value);
enum tfa_error tfa_reg_read(struct tfa_device *tfa, unsigned char subaddress, unsigned short *value);
enum tfa_error tfa_mem_write(struct tfa_device *tfa, unsigned short address, int value, int memtype);
enum tfa_error tfa_mem_read(struct tfa_device *tfa, unsigned int start_offset, int num_words, int *pValues);

enum tfa_error tfa_dsp_partial_coefficients(struct tfa_device *tfa, uint8_t *prev, uint8_t *next);
int tfa_is_94_N2_device(struct tfa_device *tfa);
/**
 * write/read raw msg functions:
 * the buffer is provided in little endian format, each word occupying 3 bytes, length is in bytes.
 * The functions will return immediately and do not wait for DSP response.
 * An ID is added to modify the command-ID
 * @param tfa the device struct pointer
 * @param length length of the character buffer to write
 * @param buf character buffer to write
 * @param cmdid command identifier
 */

/**
 * write raw dsp msg functions
 * @param tfa the device struct pointer
 * @param length length of the character buffer to write
 * @param buffer character buffer to write
 */
enum tfa_error tfa_dsp_msg_write(struct tfa_device *tfa, int length, const char *buffer);

/**
 * write raw dsp msg functions
 * @param tfa the device struct pointer
 * @param length length of the character buffer to write
 * @param buffer character buffer to write
 * @param cmdid command identifier
 */

/**
 * status function used by tfa_dsp_msg() to retrieve command/msg status:
 * return a <0 status of the DSP did not ACK.
 * @param tfa the device struct pointer
 * @param pRpcStatus status for remote processor communication
 */
enum tfa_error tfa_dsp_msg_status(struct tfa_device *tfa, int *pRpcStatus);

/**
 * Read a message from dsp
 * @param tfa the device struct pointer
 * @param length number of bytes of the message
 * @param bytes pointer to unsigned char buffer
 */
enum tfa_error tfa_dsp_msg_read_rpc(struct tfa_device *tfa, int length, unsigned char *bytes);

int tfa_set_bf(struct tfa_device *tfa, const uint16_t bf, const uint16_t value);
int tfa_set_bf_volatile(struct tfa_device *tfa, const uint16_t bf, const uint16_t value);

/**
 * Get the value of a given bitfield
 * @param tfa the device struct pointer
 * @param bf the value indicating which bitfield
 */
int tfa_get_bf(struct tfa_device *tfa, const uint16_t bf);

/**
 * Set the value of a given bitfield
 * @param bf the value indicating which bitfield
 * @param bf_value the value of the bitfield
 * @param p_reg_value a pointer to the register where to write the bitfield value
 */
int tfa_set_bf_value(const uint16_t bf, const uint16_t bf_value, uint16_t *p_reg_value);

uint16_t tfa_get_bf_value(const uint16_t bf, const uint16_t reg_value);
int tfa_read_reg(struct tfa_device *tfa, const uint16_t bf);
int tfa_write_reg(struct tfa_device *tfa, const uint16_t bf, const uint16_t reg_value);

/* bitfield */
/**
 * get the datasheet or bitfield name corresponding to the bitfield number
 * @param num is the number for which to get the bitfield name
 * @param rev is the device type
 */

/**
 * get the datasheet name corresponding to the bitfield number
 * @param num is the number for which to get the bitfield name
 * @param rev is the device type
 */
char *tfaContDsName(uint16_t num, unsigned short rev);

/**
 * get the bitfield name corresponding to the bitfield number
 * @param num is the number for which to get the bitfield name
 * @param rev is the device type
 */
char *tfaContBitName(uint16_t num, unsigned short rev);

/**
 * get the bitfield number corresponding to the bitfield name
 * @param name is the bitfield name for which to get the bitfield number
 * @param rev is the device type
 */

/**
 * get the bitfield number corresponding to the bitfield name, checks for all devices
 * @param name is the bitfield name for which to get the bitfield number
 */

#define TFA_FAM(tfa, fieldname) (TFA2_BF_##fieldname)
#define TFA_FAM_FW(tfa, fwname) (TFA2_FW_##fwname)

/* set/get bit fields to HW register*/
#define TFA_SET_BF(tfa, fieldname, value) tfa_set_bf(tfa, TFA_FAM(tfa, fieldname), value)
#define TFA_SET_BF_VOLATILE(tfa, fieldname, value) tfa_set_bf_volatile(tfa, TFA_FAM(tfa, fieldname), value)
#define TFA_GET_BF(tfa, fieldname) tfa_get_bf(tfa, TFA_FAM(tfa, fieldname))

/* set/get bit field in variable */
#define TFA_SET_BF_VALUE(tfa, fieldname, bf_value, p_reg_value) tfa_set_bf_value(TFA_FAM(tfa, fieldname), bf_value, p_reg_value)
#define TFA_GET_BF_VALUE(tfa, fieldname, reg_value) tfa_get_bf_value(TFA_FAM(tfa, fieldname), reg_value)

/* write/read registers using a bit field name to determine the register address */
#define TFA_READ_REG(tfa, fieldname) tfa_read_reg(tfa, TFA_FAM(tfa, fieldname))
#define TFA_WRITE_REG(tfa, fieldname, value) tfa_write_reg(tfa, TFA_FAM(tfa, fieldname), value)

/* FOR CALIBRATION RETRIES */
#define TFA98XX_API_WAITRESULT_NTRIES 3000 /* defined in API */

/**
 * run the startup/init sequence and set ACS bit
 * @param tfa the device struct pointer
 * @param state the cold start state that is requested
 */
enum tfa_error tfaRunColdboot(struct tfa_device *tfa, int state);

/**
 * wait for calibrateDone
 * @param tfa the device struct pointer
 * @param calibrateDone pointer to status of calibration
 */

/**
 * run the startup/init sequence and set ACS bit
 * @param tfa the device struct pointer
 * @param profile the profile that should be loaded
 */
enum tfa_error tfaRunColdStartup(struct tfa_device *tfa, int profile);

/**
 *	this will load the patch witch will implicitly start the DSP
 *	if no patch is available the DPS is started immediately
 * @param tfa the device struct pointer
 */
enum tfa_error tfaRunStartDSP(struct tfa_device *tfa);

/**
 * start the clocks and wait until the AMP is switching
 * on return the DSP sub system will be ready for loading
 * @param tfa the device struct pointer
 * @param profile the profile that should be loaded on startup
 */
enum tfa_error tfaRunStartup(struct tfa_device *tfa, int profile);

/**
 * start the maximus speakerboost algorithm
 * this implies a full system startup when the system was not already started
 * @param tfa the device struct pointer
 * @param force indicates wether a full system startup should be allowed
 * @param profile the profile that should be loaded
 */
enum tfa_error tfaRunSpeakerBoost(struct tfa_device *tfa, int force, int profile);

/**
 * Startup the device and write all files from device and profile section
 * @param tfa the device struct pointer
 * @param force indicates wether a full system startup should be allowed
 * @param profile the profile that should be loaded on speaker startup
 */
enum tfa_error tfaRunSpeakerStartup(struct tfa_device *tfa, int force, int profile);

/**
 * Run calibration
 * @param tfa the device struct pointer
 */

/**
 * startup all devices. all step until patch loading is handled
 * @param tfa the device struct pointer
 */

/**
 * powerup the coolflux subsystem and wait for it
 * @param tfa the device struct pointer
 */
enum tfa_error tfa_cf_powerup(struct tfa_device *tfa);

/*
 * print the current device manager state
 * @param tfa the device struct pointer
 */
enum tfa_error tfa_show_current_state(struct tfa_device *tfa);

/**
 * Init registers and coldboot dsp
 * @param tfa the device struct pointer
 */
int tfa_reset(struct tfa_device *tfa);

/**
 * Get profile from a register
 * @param tfa the device struct pointer
 */
int tfa_dev_get_swprof(struct tfa_device *tfa);

/**
 * Save profile in a register
 */
int tfa_dev_set_swprof(struct tfa_device *tfa, unsigned short new_value);

int tfa_dev_set_swvstep(struct tfa_device *tfa, unsigned short new_value);

int tfa_needs_reset(struct tfa_device *tfa);

int tfa_is_cold(struct tfa_device *tfa);

void tfa_set_query_info(struct tfa_device *tfa);

int tfa_get_noclk(struct tfa_device *tfa);

/**
 * Status of used for monitoring
 * @param tfa the device struct pointer
 * @return tfa error enum
 */

enum tfa_error tfa_status(struct tfa_device *tfa);

/*
 * function overload for flag_mtp_busy
 */
int tfa_dev_get_mtpb(struct tfa_device *tfa);

enum tfa_error tfaGetFwApiVersion(struct tfa_device *tfa, unsigned char *pFirmwareVersion);
#endif				/* TFA_SERVICE_H */
