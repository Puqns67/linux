// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2016  Texas Instruments Inc.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/pm.h>
#include <linux/i2c.h>
#include <linux/regulator/consumer.h>
#include <linux/firmware.h>
#include <linux/regmap.h>
#include <linux/of.h>
#include <linux/slab.h>
#include <linux/gpio/consumer.h>
#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <linux/uaccess.h>
#include <linux/crc8.h>
#include <sound/core.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>
#include <sound/soc-dapm.h>
#include <sound/initval.h>
#include <sound/tlv.h>

#include "tas2557.h"

struct TBlock {
	unsigned int mnType;
	unsigned char mbPChkSumPresent;
	unsigned char mnPChkSum;
	unsigned int mnCommands;
	unsigned char *mpData;
};

struct TData {
	char mpName[64];
	char *mpDescription;
	unsigned int mnBlocks;
	struct TBlock *mpBlocks;
};

struct TProgram {
	char mpName[64];
	char *mpDescription;
	unsigned char mnAppMode;
	unsigned short mnBoost;
	struct TData mData;
};

struct TPLL {
	char mpName[64];
	char *mpDescription;
	struct TBlock mBlock;
};

struct TConfiguration {
	char mpName[64];
	char *mpDescription;
	unsigned int mnDevices;
	unsigned int mnProgram;
	unsigned int mnPLL;
	unsigned int mnSamplingRate;
	unsigned char mnPLLSrc;
	unsigned int mnPLLSrcRate;
	struct TData mData;
};

struct TCalibration {
	char mpName[64];
	char *mpDescription;
	unsigned int mnProgram;
	unsigned int mnConfiguration;
	struct TData mData;
};

struct TFirmware {
	unsigned int mnFWSize;
	unsigned int mnChecksum;
	unsigned int mnPPCVersion;
	unsigned int mnFWVersion;
	unsigned int mnDriverVersion;
	unsigned int mnTimeStamp;
	char mpDDCName[64];
	char *mpDescription;
	unsigned int mnDeviceFamily;
	unsigned int mnDevice;
	unsigned int mnPLLs;
	struct TPLL *mpPLLs;
	unsigned int mnPrograms;
	struct TProgram *mpPrograms;
	unsigned int mnConfigurations;
	struct TConfiguration *mpConfigurations;
	unsigned int mnCalibrations;
	struct TCalibration *mpCalibrations;
};

enum channel {
	DevA = 0x01,
	DevB = 0x02,
	DevBoth = (DevA | DevB),
};

struct tas2559_priv {
	struct device *dev;
	struct regmap *mpRegmap;
	struct i2c_client *client;
	struct mutex dev_lock;
	struct TFirmware *mpFirmware;
	unsigned int mnCurrentProgram;
	unsigned int mnCurrentSampleRate;
	unsigned int mnCurrentConfiguration;
	unsigned int mnNewConfiguration;
	unsigned int mnCurrentCalibration;
	bool mbPowerUp;
	bool mbLoadConfigurationPrePowerUp;

	/* parameters for tas2559 */
	struct gpio_desc *mnDevAGPIORST;
	unsigned char mnDevAAddr;
	unsigned char mnDevACurrentBook;
	unsigned char mnDevACurrentPage;

	/* parameters for tas2560 */
	struct gpio_desc *mnDevBGPIORST;
	unsigned char mnDevBAddr;
	unsigned char mnDevBCurrentBook;
	unsigned char mnDevBCurrentPage;

	unsigned int mnErrCode;
	unsigned int mnRestart;
	struct mutex codec_lock;
};

static unsigned int p_tas2559_default_data[] = {
	/* enable SAR ADC */
	DevA, TAS2557_SAR_ADC2_REG, 0x05,
	/* clk1:clock hysteresis, 0.34ms; clock halt, 22ms*/
	DevA, TAS2557_CLK_ERR_CTRL2, 0x21,
	/* clk2: rampDown 15dB/us, clock hysteresis, 10.66us; clock halt, 22ms */
	DevA, TAS2557_CLK_ERR_CTRL3, 0x21,
	/* rampDown 15dB/us, clock1 hysteresis, 0.34ms; clock2 hysteresis, 10.6us */
	DevB, TAS2560_CLK_ERR_CTRL2, 0x21,
	DevA, TAS2557_SAFE_GUARD_REG, TAS2557_SAFE_GUARD_PATTERN, /* safe guard */
	DevA, TAS2557_CLK_ERR_CTRL, 0x00, /*enable clock error detection*/
	DevB, TAS2560_CLK_ERR_CTRL, 0x00, /* disable clock error detection */
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
};

static unsigned int p_tas2559_startup_data[] = {
	DevA, TAS2557_GPIO1_PIN_REG, 0x01, /* enable BCLK */
	DevA, TAS2557_GPIO2_PIN_REG, 0x01, /* enable WCLK */
	DevA, TAS2557_POWER_CTRL2_REG, 0xA0, /* Class-D, Boost power up */
	DevA, TAS2557_POWER_CTRL2_REG, 0xA3, /* Class-D, Boost, IV sense power up */
	DevA, TAS2557_POWER_CTRL1_REG, 0xF8, /* PLL, DSP, clock dividers power up */
	DevBoth, TAS2557_UDELAY, 2000, /* delay */
	DevB, TAS2560_DEV_MODE_REG, 0x02,
	DevB, TAS2560_MUTE_REG, 0x41,
	DevBoth, TAS2557_UDELAY, 2000, /* delay */
	DevA, TAS2557_CLK_ERR_CTRL, 0x2B, /* enable clock error detection */
	DevB, TAS2560_CLK_ERR_CTRL, 0x0B, /* disable clock error detection */
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
};

static unsigned int p_tas2559_mute_data[] = {
	DevA, TAS2557_SOFT_MUTE_REG, 0x01, /*soft mute */
	DevB, TAS2560_MUTE_REG, 0x41,
	DevA, TAS2557_MDELAY, 10, /* delay 10ms */
	DevA, TAS2557_MUTE_REG, 0x03, /* mute */
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
};

static unsigned int p_tas2559_unmute_data[] = {
	DevA, TAS2557_MUTE_REG, 0x00, /* unmute */
	DevB, TAS2560_MUTE_REG, 0x40,
	DevA, TAS2557_SOFT_MUTE_REG, 0x00, /* soft unmute */
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
};

static unsigned int p_tas2559_shutdown_data[] = {
	DevA, TAS2557_CLK_ERR_CTRL, 0x00, /* disable clock error detection */
	DevB, TAS2560_CLK_ERR_CTRL, 0x00, /* disable clock error detection */
	DevA, TAS2557_SOFT_MUTE_REG, 0x01, /*soft mute*/
	DevB, TAS2560_MUTE_REG, 0x41,
	DevB, TAS2560_MUTE_REG, 0x01,
	DevBoth, TAS2557_MDELAY, 10, /* delay 10ms */
	DevB, TAS2557_MDELAY, 20, /* delay 20ms */
	DevA, TAS2557_POWER_CTRL1_REG, 0x60, /* DSP power down */
	DevA, TAS2557_MDELAY, 2, /* delay 20ms */
	DevA, TAS2557_MUTE_REG, 0x03, /* mute */
	DevA, TAS2557_POWER_CTRL2_REG, 0x00,/*Class-D, Boost power down*/
	DevA, TAS2557_POWER_CTRL1_REG, 0x00,/*all power down*/
	DevB, TAS2560_DEV_MODE_REG, 0x01,
	DevA, TAS2557_GPIO1_PIN_REG, 0x00,/* disable BCLK */
	DevA, TAS2557_GPIO2_PIN_REG, 0x00,/* disable WCLK */
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
};

static unsigned int p_tas2559_shutdown_DevB_data[] = {
	DevA, TAS2557_CLK_ERR_CTRL, 0x00,/* disable clock error detection */
	DevB, TAS2560_CLK_ERR_CTRL, 0x00,/* disable clock error detection */
	DevB, TAS2560_MUTE_REG, 0x41,
	DevB, TAS2560_MUTE_REG, 0x01,
	DevA, TAS2557_POWER_CTRL1_REG, 0x60, /* DSP power down */
	DevBoth, TAS2557_MDELAY, 30, /* delay 2ms */
	DevB, TAS2560_DEV_MODE_REG, 0x01,
	DevA, TAS2557_POWER_CTRL2_REG, 0x00, /* Class-D, Boost power down */
	DevA, TAS2557_POWER_CTRL1_REG, 0x00, /* all power down */
	DevA, TAS2557_GPIO1_PIN_REG, 0x00, /* disable BCLK */
	DevA, TAS2557_GPIO2_PIN_REG, 0x00, /* disable WCLK */
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
};

static int tas2559_i2c_read_device(struct tas2559_priv *pTAS2557,
				   unsigned char addr,
				   unsigned char reg,
				   unsigned char *p_value)
{
	int nResult = 0;
	unsigned int val = 0;

	pTAS2557->client->addr = addr;
	nResult = regmap_read(pTAS2557->mpRegmap, reg, &val);

	if (nResult < 0)
		dev_err(pTAS2557->dev, "%s[0x%x] Error %d\n",
			__func__, addr, nResult);
	else
		*p_value = (unsigned char)val;

	return nResult;
}

static int tas2559_i2c_write_device(struct tas2559_priv *pTAS2557,
				    unsigned char addr,
				    unsigned char reg,
				    unsigned char value)
{
	int nResult = 0;

	pTAS2557->client->addr = addr;
	nResult = regmap_write(pTAS2557->mpRegmap, reg, value);

	if (nResult < 0)
		dev_err(pTAS2557->dev, "%s[0x%x] Error %d\n",
			__func__, addr, nResult);

	return nResult;
}

static int tas2559_i2c_update_bits(struct tas2559_priv *pTAS2557,
				   unsigned char addr,
				   unsigned char reg,
				   unsigned char mask,
				   unsigned char value)
{
	int nResult = 0;

	pTAS2557->client->addr = addr;
	nResult = regmap_update_bits(pTAS2557->mpRegmap, reg, mask, value);

	if (nResult < 0)
		dev_err(pTAS2557->dev, "%s[0x%x] Error %d\n",
			__func__, addr, nResult);

	return nResult;
}

static int tas2559_i2c_bulkwrite_device(struct tas2559_priv *pTAS2557,
					unsigned char addr,
					unsigned char reg,
					unsigned char *pBuf,
					unsigned int len)
{
	int nResult = 0;

	pTAS2557->client->addr = addr;
	nResult = regmap_bulk_write(pTAS2557->mpRegmap, reg, pBuf, len);

	if (nResult < 0)
		dev_err(pTAS2557->dev, "%s[0x%x] Error %d\n",
			__func__, addr, nResult);

	return nResult;
}

static int tas2559_change_book_page(struct tas2559_priv *pTAS2557,
				    enum channel chn,
				    unsigned char nBook,
				    unsigned char nPage)
{
	int nResult = 0;

	if (chn & DevA) {
		if (pTAS2557->mnDevACurrentBook == nBook) {
			if (pTAS2557->mnDevACurrentPage != nPage) {
				nResult = tas2559_i2c_write_device(pTAS2557,
								   pTAS2557->mnDevAAddr,
								   TAS2557_BOOKCTL_PAGE,
								   nPage);

				if (nResult >= 0)
					pTAS2557->mnDevACurrentPage = nPage;
			}
		} else {
			nResult = tas2559_i2c_write_device(pTAS2557,
							   pTAS2557->mnDevAAddr,
							   TAS2557_BOOKCTL_PAGE, 0);

			if (nResult >= 0) {
				pTAS2557->mnDevACurrentPage = 0;
				nResult = tas2559_i2c_write_device(pTAS2557,
								   pTAS2557->mnDevAAddr,
								   TAS2557_BOOKCTL_REG,
								   nBook);
				pTAS2557->mnDevACurrentBook = nBook;

				if (nPage != 0) {
					nResult = tas2559_i2c_write_device(pTAS2557,
									   pTAS2557->mnDevAAddr,
									   TAS2557_BOOKCTL_PAGE,
									   nPage);
					pTAS2557->mnDevACurrentPage = nPage;
				}
			}
		}
	}

	if (chn & DevB) {
		if (pTAS2557->mnDevBCurrentBook == nBook) {
			if (pTAS2557->mnDevBCurrentPage != nPage) {
				nResult = tas2559_i2c_write_device(pTAS2557,
								   pTAS2557->mnDevBAddr,
								   TAS2557_BOOKCTL_PAGE,
								   nPage);

				if (nResult >= 0)
					pTAS2557->mnDevBCurrentPage = nPage;
			}
		} else {
			nResult = tas2559_i2c_write_device(pTAS2557,
							   pTAS2557->mnDevBAddr,
							   TAS2557_BOOKCTL_PAGE, 0);

			if (nResult >= 0) {
				pTAS2557->mnDevBCurrentPage = 0;
				nResult = tas2559_i2c_write_device(pTAS2557,
								   pTAS2557->mnDevBAddr,
								   TAS2557_BOOKCTL_REG,
								   nBook);
				pTAS2557->mnDevBCurrentBook = nBook;

				if (nPage != 0) {
					tas2559_i2c_write_device(pTAS2557,
								 pTAS2557->mnDevBAddr,
								 TAS2557_BOOKCTL_PAGE,
								 nPage);
					pTAS2557->mnDevBCurrentPage = nPage;
				}
			}
		}
	}

	return nResult;
}

static int tas2559_dev_read(struct tas2559_priv *pTAS2557,
			    enum channel chn,
			    unsigned int nRegister,
			    unsigned int *pValue)
{
	int nResult = 0;
	unsigned char Value = 0;

	mutex_lock(&pTAS2557->dev_lock);

	nResult = tas2559_change_book_page(pTAS2557, chn,
					   TAS2557_BOOK_ID(nRegister),
					   TAS2557_PAGE_ID(nRegister));

	if (nResult >= 0) {
		if (chn == DevA)
			nResult = tas2559_i2c_read_device(pTAS2557,
							  pTAS2557->mnDevAAddr,
							  TAS2557_PAGE_REG(nRegister),
							  &Value);
		else
			if (chn == DevB)
				nResult = tas2559_i2c_read_device(pTAS2557,
								  pTAS2557->mnDevBAddr,
								  TAS2557_PAGE_REG(nRegister),
								  &Value);
			else {
				dev_err(pTAS2557->dev,
					"read chn ERROR %d\n",
					chn);
				nResult = -EINVAL;
			}

		if (nResult >= 0)
			*pValue = Value;
	}

	mutex_unlock(&pTAS2557->dev_lock);
	return nResult;
}

static int tas2559_dev_write(struct tas2559_priv *pTAS2557,
			     enum channel chn,
			     unsigned int nRegister,
			     unsigned int nValue)
{
	int nResult = 0;

	mutex_lock(&pTAS2557->dev_lock);

	nResult = tas2559_change_book_page(pTAS2557,
					   chn,
					   TAS2557_BOOK_ID(nRegister),
					   TAS2557_PAGE_ID(nRegister));

	if (nResult < 0)
		goto end;

	if (chn & DevA)
		nResult = tas2559_i2c_write_device(pTAS2557,
						   pTAS2557->mnDevAAddr,
						   TAS2557_PAGE_REG(nRegister), nValue);

	if (chn & DevB)
		nResult = tas2559_i2c_write_device(pTAS2557,
						   pTAS2557->mnDevBAddr,
						   TAS2557_PAGE_REG(nRegister), nValue);

end:
	mutex_unlock(&pTAS2557->dev_lock);
	return nResult;
}

static int tas2559_dev_bulk_write(struct tas2559_priv *pTAS2557,
				  enum channel chn,
				  unsigned int nRegister,
				  unsigned char *pData,
				  unsigned int nLength)
{
	int nResult = 0;
	unsigned char reg = 0;

	mutex_lock(&pTAS2557->dev_lock);

	nResult = tas2559_change_book_page(pTAS2557, chn,
					   TAS2557_BOOK_ID(nRegister),
					   TAS2557_PAGE_ID(nRegister));

	if (nResult < 0)
		goto end;

	reg = TAS2557_PAGE_REG(nRegister);

	if (chn & DevA)
		nResult = tas2559_i2c_bulkwrite_device(pTAS2557,
						       pTAS2557->mnDevAAddr,
						       reg, pData, nLength);

	if (chn & DevB)
		nResult = tas2559_i2c_bulkwrite_device(pTAS2557,
						       pTAS2557->mnDevBAddr,
						       reg, pData, nLength);

end:
	mutex_unlock(&pTAS2557->dev_lock);
	return nResult;
}

static int tas2559_dev_update_bits(
	struct tas2559_priv *pTAS2557,
	enum channel chn,
	unsigned int nRegister,
	unsigned int nMask,
	unsigned int nValue)
{
	int nResult = 0;

	mutex_lock(&pTAS2557->dev_lock);

	nResult = tas2559_change_book_page(pTAS2557,
					   chn,
					   TAS2557_BOOK_ID(nRegister),
					   TAS2557_PAGE_ID(nRegister));

	if (nResult < 0)
		goto end;

	if (chn & DevA)
		nResult = tas2559_i2c_update_bits(pTAS2557,
						  pTAS2557->mnDevAAddr,
						  TAS2557_PAGE_REG(nRegister),
						  nMask, nValue);

	if (chn & DevB)
		nResult = tas2559_i2c_update_bits(pTAS2557,
						  pTAS2557->mnDevBAddr,
						  TAS2557_PAGE_REG(nRegister),
						  nMask, nValue);

end:
	mutex_unlock(&pTAS2557->dev_lock);
	return nResult;
}

static void tas2559_hw_reset(struct tas2559_priv *pTAS2557)
{
	gpiod_set_value_cansleep(pTAS2557->mnDevAGPIORST, 0);
	msleep(20); /* was 5 */
	gpiod_set_value_cansleep(pTAS2557->mnDevAGPIORST, 1);
	msleep(20); /* was 2 */

	gpiod_set_value_cansleep(pTAS2557->mnDevBGPIORST, 0);
	msleep(20); /* was 5 */
	gpiod_set_value_cansleep(pTAS2557->mnDevBGPIORST, 1);
	msleep(20); /* was 2 */

	pTAS2557->mnDevACurrentBook = -1;
	pTAS2557->mnDevACurrentPage = -1;
	pTAS2557->mnDevBCurrentBook = -1;
	pTAS2557->mnDevBCurrentPage = -1;

	if (pTAS2557->mnErrCode)
		dev_info(pTAS2557->dev, "before reset, ErrCode=0x%x\n",
			 pTAS2557->mnErrCode);

	pTAS2557->mnErrCode = 0;
}

static int tas2559_dev_load_data(struct tas2559_priv *pTAS2557,
				 enum channel dev, unsigned int *pData)
{
	int ret = 0;
	unsigned int n = 0;
	unsigned int nRegister;
	unsigned int nData;
	enum channel chl;

	do {
		chl = pData[n * 3];

		if (chl == 0xffffffff)
			break;

		if (dev & chl) {
			nRegister = pData[n * 3 + 1];
			nData = pData[n * 3 + 2];

			if (nRegister == TAS2557_UDELAY) {
				udelay(nData);
			} else if (nRegister == TAS2557_MDELAY) {
				mdelay(nData);
			} else if (nRegister != 0xFFFFFFFF) {
				ret = tas2559_dev_write(pTAS2557, chl, nRegister, nData);
				if (ret < 0)
					break;
			}
		}

		n++;
	} while (nRegister != 0xFFFFFFFF);

	return ret;
}

static int tas2559_DevStartup(struct tas2559_priv *pTAS2557,
			      unsigned int dev)
{
	int nResult = 0;
	enum channel chl = dev;

	if (dev == DevB)
		chl = DevBoth;

	dev_dbg(pTAS2557->dev, "%s, chl=%d\n", __func__, chl);
	nResult = tas2559_dev_load_data(pTAS2557, chl, p_tas2559_startup_data);

	return nResult;
}

static int tas2559_DevShutdown(struct tas2559_priv *pTAS2557,
			       unsigned int dev)
{
	int nResult = 0;

	dev_dbg(pTAS2557->dev, "%s, dev=%d\n", __func__, dev);

	if (dev == DevB)
		nResult = tas2559_dev_load_data(pTAS2557, dev, p_tas2559_shutdown_DevB_data);
	else
		nResult = tas2559_dev_load_data(pTAS2557, dev, p_tas2559_shutdown_data);

	return nResult;
}

int tas2559_set_DAC_gain(struct tas2559_priv *pTAS2557,
			 enum channel chl, unsigned int nGain)
{
	int nResult = 0;
	int gain = (nGain & 0x0f);

	dev_dbg(pTAS2557->dev, "%s, nGain: %d", __func__, nGain);

	if (chl & DevA) {
		nResult = tas2559_dev_update_bits(pTAS2557, DevA,
						TAS2557_SPK_CTRL_REG, 0x78, (gain << 3));

		if (nResult < 0)
			goto end;
	}

	if (chl & DevB)
		nResult = tas2559_dev_update_bits(pTAS2557, DevB,
						TAS2560_SPK_CTRL_REG, 0x0f, gain);

end:

	return nResult;
}

int tas2559_get_DAC_gain(struct tas2559_priv *pTAS2557,
			 enum channel chl, unsigned char *pnGain)
{
	int nResult = 0;
	int nGain;

	if (chl == DevA) {
		nResult = tas2559_dev_read(pTAS2557, DevA, TAS2557_SPK_CTRL_REG, &nGain);

		if (nResult >= 0)
			*pnGain = ((nGain >> 3) & 0x0f);
	} else
		if (chl == DevB) {
			nResult = tas2559_dev_read(pTAS2557, DevB, TAS2560_SPK_CTRL_REG, &nGain);

			if (nResult >= 0)
				*pnGain = (nGain & 0x0f);
		}

	return nResult;
}

int tas2559_DevMute(struct tas2559_priv *pTAS2557, enum channel dev, bool mute)
{
	int nResult = 0;

	dev_dbg(pTAS2557->dev, "%s, dev=%d, mute=%d\n", __func__, dev, mute);

	if (mute)
		nResult = tas2559_dev_load_data(pTAS2557, dev, p_tas2559_mute_data);
	else
		nResult = tas2559_dev_load_data(pTAS2557, dev, p_tas2559_unmute_data);

	return nResult;
}

int tas2559_load_default(struct tas2559_priv *pTAS2557)
{
	int nResult = 0;

	nResult = tas2559_dev_load_data(pTAS2557, DevBoth, p_tas2559_default_data);
	if (nResult < 0)
		goto end;

	// Set default bit rate of 16 for DevA
	nResult = tas2559_dev_update_bits(pTAS2557, DevA,
					  TAS2557_ASI1_DAC_FORMAT_REG, 0x18, 0);
	if (nResult < 0)
		goto end;

	// Set default bit rate of 16 for DevB
	nResult = tas2559_dev_update_bits(pTAS2557, DevB,
					  TAS2560_DAI_FMT, 0x03, 0);
	if (nResult < 0)
		goto end;

	/* enable DOUT tri-state for extra BCLKs */
	nResult = tas2559_dev_update_bits(pTAS2557, DevA,
					  TAS2557_ASI1_DAC_FORMAT_REG, 0x01, 0x01);
	if (nResult < 0)
		goto end;

	nResult = tas2559_dev_update_bits(pTAS2557, DevB,
					  TAS2560_ASI_CFG_1, 0x02, 0x02);
	if (nResult < 0)
		goto end;

	/* Interrupt pin, low-highZ, high active driven */
	nResult = tas2559_dev_update_bits(pTAS2557, DevA,
					  TAS2557_GPIO_HIZ_CTRL2_REG, 0x30, 0x30);

end:
	return nResult;
}


void tas2559_clear_firmware(struct TFirmware *pFirmware)
{
	unsigned int n, nn;

	if (!pFirmware)
		return;

	kfree(pFirmware->mpDescription);

	if (pFirmware->mpPLLs != NULL) {
		for (n = 0; n < pFirmware->mnPLLs; n++) {
			kfree(pFirmware->mpPLLs[n].mpDescription);
			kfree(pFirmware->mpPLLs[n].mBlock.mpData);
		}

		kfree(pFirmware->mpPLLs);
	}

	if (pFirmware->mpPrograms != NULL) {
		for (n = 0; n < pFirmware->mnPrograms; n++) {
			kfree(pFirmware->mpPrograms[n].mpDescription);
			kfree(pFirmware->mpPrograms[n].mData.mpDescription);

			for (nn = 0; nn < pFirmware->mpPrograms[n].mData.mnBlocks; nn++)
				kfree(pFirmware->mpPrograms[n].mData.mpBlocks[nn].mpData);

			kfree(pFirmware->mpPrograms[n].mData.mpBlocks);
		}

		kfree(pFirmware->mpPrograms);
	}

	if (pFirmware->mpConfigurations != NULL) {
		for (n = 0; n < pFirmware->mnConfigurations; n++) {
			kfree(pFirmware->mpConfigurations[n].mpDescription);
			kfree(pFirmware->mpConfigurations[n].mData.mpDescription);

			for (nn = 0; nn < pFirmware->mpConfigurations[n].mData.mnBlocks; nn++)
				kfree(pFirmware->mpConfigurations[n].mData.mpBlocks[nn].mpData);

			kfree(pFirmware->mpConfigurations[n].mData.mpBlocks);
		}

		kfree(pFirmware->mpConfigurations);
	}

	if (pFirmware->mpCalibrations != NULL) {
		for (n = 0; n < pFirmware->mnCalibrations; n++) {
			kfree(pFirmware->mpCalibrations[n].mpDescription);
			kfree(pFirmware->mpCalibrations[n].mData.mpDescription);

			for (nn = 0; nn < pFirmware->mpCalibrations[n].mData.mnBlocks; nn++)
				kfree(pFirmware->mpCalibrations[n].mData.mpBlocks[nn].mpData);

			kfree(pFirmware->mpCalibrations[n].mData.mpBlocks);
		}

		kfree(pFirmware->mpCalibrations);
	}

	memset(pFirmware, 0x00, sizeof(struct TFirmware));
}

static int tas2559_load_block(struct tas2559_priv *pTAS2557, struct TBlock *pBlock)
{
	int nResult = 0;
	unsigned int nCommand = 0;
	unsigned char nBook;
	unsigned char nPage;
	unsigned char nOffset;
	unsigned char nData;
	unsigned int nValue1;
	unsigned int nLength;
	unsigned int nSleep;
	enum channel chl;
	unsigned char *pData = pBlock->mpData;

	dev_dbg(pTAS2557->dev, "TAS255x load block: Type = %d, commands = %d\n",
		pBlock->mnType, pBlock->mnCommands);

	if (pBlock->mnType == TAS2557_BLOCK_PLL) {
		chl = DevA;
	} else if ((pBlock->mnType == TAS2557_BLOCK_PGM_DEV_A)
		    || (pBlock->mnType == TAS2557_BLOCK_CFG_COEFF_DEV_A)
		    || (pBlock->mnType == TAS2557_BLOCK_CFG_PRE_DEV_A)) {
		chl = DevA;
	} else if ((pBlock->mnType == TAS2557_BLOCK_PGM_DEV_B)
		    || (pBlock->mnType == TAS2559_BLOCK_PST_POWERUP_DEV_B)
		    || (pBlock->mnType == TAS2557_BLOCK_CFG_PRE_DEV_B)) {
		chl = DevB;
	} else {
		dev_err(pTAS2557->dev, "block type error %d\n", pBlock->mnType);
		nResult = -EINVAL;
		goto end;
	}

	if (pBlock->mbPChkSumPresent) {
		if (chl == DevA) {
			nResult = tas2559_dev_write(pTAS2557, DevA, TAS2557_CRC_RESET_REG, 1);
			if (nResult < 0)
				goto end;
		} else {
			nResult = tas2559_dev_write(pTAS2557, DevB, TAS2560_CRC_CHK_REG, 1);
			if (nResult < 0)
				goto end;
		}
	}

	nCommand = 0;

	while (nCommand < pBlock->mnCommands) {
		pData = pBlock->mpData + nCommand * 4;

		nBook = pData[0];
		nPage = pData[1];
		nOffset = pData[2];
		nData = pData[3];

		nCommand++;

		if (nOffset <= 0x7F) {
			nResult = tas2559_dev_write(pTAS2557,
						    chl, TAS2557_REG(nBook, nPage, nOffset),
						    nData);
			if (nResult < 0)
				goto end;

		} else if (nOffset == 0x81) {
			nSleep = (nBook << 8) + nPage;
			msleep(nSleep);
		} else if (nOffset == 0x85) {
			pData += 4;
			nLength = (nBook << 8) + nPage;
			nBook = pData[0];
			nPage = pData[1];
			nOffset = pData[2];

			if (nLength > 1) {
				nResult = tas2559_dev_bulk_write(pTAS2557,
							chl, TAS2557_REG(nBook, nPage, nOffset),
							pData + 3, nLength);
				if (nResult < 0)
					goto end;
			} else {
				nResult = tas2559_dev_write(pTAS2557,
							chl, TAS2557_REG(nBook, nPage, nOffset),
							pData[3]);
				if (nResult < 0)
					goto end;
			}

			nCommand++;
			if (nLength >= 2)
				nCommand += ((nLength - 2) / 4) + 1;
		}
	}

	if (pBlock->mbPChkSumPresent) {
		if (chl == DevA)
			nResult = tas2559_dev_read(pTAS2557, DevA,
						TAS2557_CRC_CHECKSUM_REG, &nValue1);
		else
			nResult = tas2559_dev_read(pTAS2557, DevB,
						TAS2560_CRC_CHK_REG, &nValue1);

		if (nResult < 0)
			goto end;

		if (nValue1 != pBlock->mnPChkSum) {
			dev_err(pTAS2557->dev, "Block PChkSum Error: FW = 0x%x, Reg = 0x%x\n",
				pBlock->mnPChkSum, (nValue1 & 0xff));
			nResult = -EAGAIN;
			pTAS2557->mnErrCode |= ERROR_PRAM_CRCCHK;
		}
	}

end:
	if (nResult < 0)
		dev_err(pTAS2557->dev, "Block (%d) load error\n",
			pBlock->mnType);

	return nResult;
}

static int tas2559_load_data(struct tas2559_priv *pTAS2557,
			     struct TData *pData,
			     unsigned int nType)
{
	int nResult = 0;
	unsigned int nBlock;
	struct TBlock *pBlock;

	dev_dbg(pTAS2557->dev,
		"TAS2557 load data: %s, Blocks = %d, Block Type = %d\n",
		pData->mpName, pData->mnBlocks, nType);

	for (nBlock = 0; nBlock < pData->mnBlocks; nBlock++) {
		pBlock = &(pData->mpBlocks[nBlock]);

		if (pBlock->mnType == nType) {
			nResult = tas2559_load_block(pTAS2557, pBlock);

			if (nResult < 0)
				break;
		}
	}

	return nResult;
}

static void failsafe(struct tas2559_priv *pTAS2557)
{
	int ret;

	pTAS2557->mnErrCode |= ERROR_FAILSAFE;

	tas2559_DevShutdown(pTAS2557, DevBoth);
	pTAS2557->mbPowerUp = false;
	tas2559_hw_reset(pTAS2557);
	ret = tas2559_dev_write(pTAS2557, DevBoth, TAS2557_SW_RESET_REG, 0x01);
	if (ret < 0)
		dev_dbg(pTAS2557->dev, "failed sw reset\n");

	msleep(20); /* was 1 */
	ret = tas2559_dev_write(pTAS2557, DevA, TAS2557_SPK_CTRL_REG, 0x04);
	if (ret < 0)
		dev_dbg(pTAS2557->dev, "failed in spk ctrl\n");

	ret = tas2559_dev_write(pTAS2557, DevB, TAS2560_SPK_CTRL_REG, 0x50);
	if (ret < 0)
		dev_dbg(pTAS2557->dev, "failed in spk ctrl\n");

	if (pTAS2557->mpFirmware != NULL)
		tas2559_clear_firmware(pTAS2557->mpFirmware);
}

static int tas2559_load_coefficient(struct tas2559_priv *pTAS2557,
				    int nPrevConfig, int nNewConfig, bool bPowerOn)
{
	int nResult = 0;
	struct TPLL *pPLL;
	struct TProgram *pProgram = NULL;
	struct TConfiguration *pPrevConfiguration;
	struct TConfiguration *pNewConfiguration;
	enum channel chl;
	bool bRestorePower = false;

	dev_dbg(pTAS2557->dev, "%s, Prev=%d, new=%d, Pow=%d\n",
		__func__, nPrevConfig, nNewConfig, bPowerOn);

	if (!pTAS2557->mpFirmware->mnConfigurations) {
		dev_err(pTAS2557->dev, "%s, firmware not loaded\n", __func__);
		goto end;
	}

	if (nNewConfig >= pTAS2557->mpFirmware->mnConfigurations) {
		dev_err(pTAS2557->dev, "%s, invalid configuration New=%d, total=%d\n",
			__func__, nNewConfig, pTAS2557->mpFirmware->mnConfigurations);
		goto end;
	}

	if (nPrevConfig < 0) {
		pPrevConfiguration = NULL;
		chl = DevBoth;
	} else
		if (nPrevConfig == nNewConfig) {
			dev_dbg(pTAS2557->dev, "%d configuration is already loaded\n",
					nNewConfig);
			goto end;
		} else {
			pPrevConfiguration = &(pTAS2557->mpFirmware->mpConfigurations[nPrevConfig]);
			chl = pPrevConfiguration->mnDevices;
		}

	pNewConfiguration = &(pTAS2557->mpFirmware->mpConfigurations[nNewConfig]);
	pTAS2557->mnCurrentConfiguration = nNewConfig;

	if (pPrevConfiguration) {
		if ((pPrevConfiguration->mnPLL == pNewConfiguration->mnPLL)
		    && (pPrevConfiguration->mnDevices == pNewConfiguration->mnDevices)) {
			dev_dbg(pTAS2557->dev, "%s, PLL and device same\n", __func__);
			goto prog_coefficient;
		}
	}

	pProgram = &(pTAS2557->mpFirmware->mpPrograms[pTAS2557->mnCurrentProgram]);

	if (bPowerOn) {
		dev_dbg(pTAS2557->dev, "%s, power down to load new PLL\n", __func__);

		nResult = tas2559_DevShutdown(pTAS2557, chl);
		if (nResult < 0)
			goto end;

		bRestorePower = true;
	}

	/* load PLL */
	pPLL = &(pTAS2557->mpFirmware->mpPLLs[pNewConfiguration->mnPLL]);
	dev_dbg(pTAS2557->dev, "load PLL: %s block for Configuration %s\n",
		pPLL->mpName, pNewConfiguration->mpName);
	nResult = tas2559_load_block(pTAS2557, &(pPLL->mBlock));

	if (nResult < 0)
		goto end;

	pTAS2557->mnCurrentSampleRate = pNewConfiguration->mnSamplingRate;

	dev_dbg(pTAS2557->dev, "load configuration %s conefficient pre block\n",
		pNewConfiguration->mpName);

	if (pNewConfiguration->mnDevices & DevA) {
		nResult = tas2559_load_data(pTAS2557,
					    &pNewConfiguration->mData,
					    TAS2557_BLOCK_CFG_PRE_DEV_A);

		if (nResult < 0)
			goto end;
	}

	if (pNewConfiguration->mnDevices & DevB) {
		nResult = tas2559_load_data(pTAS2557,
					    &pNewConfiguration->mData,
					    TAS2557_BLOCK_CFG_PRE_DEV_B);

		if (nResult < 0)
			goto end;
	}

prog_coefficient:
	dev_dbg(pTAS2557->dev, "load new configuration: %s, coeff block data\n",
		pNewConfiguration->mpName);

	if (pNewConfiguration->mnDevices & DevA) {
		nResult = tas2559_load_data(pTAS2557,
					    &pNewConfiguration->mData,
					    TAS2557_BLOCK_CFG_COEFF_DEV_A);
		if (nResult < 0)
			goto end;
	}

	if (pNewConfiguration->mnDevices & DevB) {
		nResult = tas2559_load_data(pTAS2557,
					    &pNewConfiguration->mData,
					    TAS2557_BLOCK_CFG_COEFF_DEV_B);
		if (nResult < 0)
			goto end;
	}

	if (bRestorePower) {
		nResult = tas2559_DevStartup(pTAS2557, pNewConfiguration->mnDevices);
		if (nResult < 0)
			goto end;

		if (pNewConfiguration->mnDevices & DevB) {
			nResult = tas2559_load_data(pTAS2557,
						    &pNewConfiguration->mData,
						    TAS2559_BLOCK_PST_POWERUP_DEV_B);

			if (nResult < 0)
				goto end;
		}

		dev_dbg(pTAS2557->dev,
			"device powered up, load unmute\n");
		nResult = tas2559_DevMute(pTAS2557, pNewConfiguration->mnDevices, false);
		if (nResult < 0)
			goto end;
	}

end:

	if (nResult < 0)
		dev_err(pTAS2557->dev, "%s, load new conf %s error\n",
			__func__, pNewConfiguration->mpName);

	pTAS2557->mnNewConfiguration = pTAS2557->mnCurrentConfiguration;
	return nResult;
}

static int tas2559_load_configuration(struct tas2559_priv *pTAS2557,
				      unsigned int nConfiguration, bool bLoadSame)
{
	int nResult = 0;
	struct TConfiguration *pCurrentConfiguration = NULL;
	struct TConfiguration *pNewConfiguration = NULL;

	dev_dbg(pTAS2557->dev, "%s: %d\n", __func__, nConfiguration);

	if ((!pTAS2557->mpFirmware->mpPrograms) ||
	    (!pTAS2557->mpFirmware->mpConfigurations)) {
		dev_err(pTAS2557->dev, "Firmware not loaded\n");
		nResult = 0;
		goto end;
	}

	if (nConfiguration >= pTAS2557->mpFirmware->mnConfigurations) {
		dev_err(pTAS2557->dev, "Configuration %d doesn't exist\n",
			nConfiguration);
		nResult = 0;
		goto end;
	}

	if ((!pTAS2557->mbLoadConfigurationPrePowerUp) &&
	    (nConfiguration == pTAS2557->mnCurrentConfiguration) &&
	    (!bLoadSame)) {
		dev_info(pTAS2557->dev, "Configuration %d is already loaded\n",
			 nConfiguration);
		nResult = 0;
		goto end;
	}

	pCurrentConfiguration =
		&(pTAS2557->mpFirmware->mpConfigurations[pTAS2557->mnCurrentConfiguration]);
	pNewConfiguration =
		&(pTAS2557->mpFirmware->mpConfigurations[nConfiguration]);

	if (pNewConfiguration->mnProgram != pCurrentConfiguration->mnProgram) {
		dev_err(pTAS2557->dev,
			"Configuration %d, %s doesn't share the same program as current %d\n",
			nConfiguration,
			pNewConfiguration->mpName,
			pCurrentConfiguration->mnProgram);
		nResult = 0;
		goto end;
	}

	if (pNewConfiguration->mnPLL >= pTAS2557->mpFirmware->mnPLLs) {
		dev_err(pTAS2557->dev,
			"Configuration %d, %s doesn't have a valid PLL index %d\n",
			nConfiguration, pNewConfiguration->mpName,
			pNewConfiguration->mnPLL);
		nResult = 0;
		goto end;
	}

	if (pTAS2557->mbPowerUp) {
		dev_err(pTAS2557->dev, "%s, device power on, load new conf[%d] %s\n", __func__,
			nConfiguration, pNewConfiguration->mpName);
		nResult = tas2559_load_coefficient(pTAS2557,
						   pTAS2557->mnCurrentConfiguration,
						   nConfiguration, true);
		pTAS2557->mbLoadConfigurationPrePowerUp = false;
	} else {
		dev_dbg(pTAS2557->dev,
			"TAS2557 was powered down, will load coefficient when power up\n");
		pTAS2557->mbLoadConfigurationPrePowerUp = true;
		pTAS2557->mnNewConfiguration = nConfiguration;
	}

end:

	if (nResult < 0) {
		if (pTAS2557->mnErrCode &
		    (ERROR_DEVA_I2C_COMM | ERROR_DEVB_I2C_COMM |
		     ERROR_PRAM_CRCCHK | ERROR_YRAM_CRCCHK))
			failsafe(pTAS2557);
	}

	return nResult;
}

int tas2559_set_program(struct tas2559_priv *pTAS2557,
			unsigned int nProgram, int nConfig)
{
	struct TProgram *pProgram;
	struct TConfiguration *pConfiguration;
	unsigned int nConfiguration = 0;
	unsigned int nSampleRate = 0;
	bool bFound = false;
	int nResult = 0;

	if ((!pTAS2557->mpFirmware->mpPrograms) ||
	    (!pTAS2557->mpFirmware->mpConfigurations)) {
		dev_err(pTAS2557->dev, "Firmware not loaded\n");
		nResult = 0;
		goto end;
	}

	if (nProgram >= pTAS2557->mpFirmware->mnPrograms) {
		dev_err(pTAS2557->dev, "TAS2557: Program %d doesn't exist\n",
			nProgram);
		nResult = 0;
		goto end;
	}

	if (nProgram == 1)
		pTAS2557->mnCurrentSampleRate = 96000;
	else
		pTAS2557->mnCurrentSampleRate = 48000;

	if (nConfig < 0) {
		nConfiguration = 0;
		nSampleRate = pTAS2557->mnCurrentSampleRate;
		dev_err(pTAS2557->dev, "nSampleRate: %d\n", nSampleRate);

		while (!bFound && (nConfiguration < pTAS2557->mpFirmware->mnConfigurations)) {
			dev_err(pTAS2557->dev, "mpConfigurations SampleRate: %d\n",
				pTAS2557->mpFirmware->mpConfigurations[nConfiguration].mnSamplingRate);
			if (pTAS2557->mpFirmware->mpConfigurations[nConfiguration].mnProgram ==
			    nProgram) {
				if (nSampleRate == 0) {
					bFound = true;
					dev_info(pTAS2557->dev,
						 "find default configuration %d\n",
						 nConfiguration);
				} else if (nSampleRate ==
					   pTAS2557->mpFirmware->mpConfigurations[nConfiguration].mnSamplingRate) {
					bFound = true;
					dev_info(pTAS2557->dev,
						 "find matching configuration %d\n",
						 nConfiguration);
				} else {
					nConfiguration++;
				}
			} else {
				nConfiguration++;
			}
		}

		if (!bFound) {
			dev_err(pTAS2557->dev,
				"Program %d, no valid configuration found for sample rate %d, ignore\n",
				nProgram, nSampleRate);
			nResult = 0;
			goto end;
		}
	} else {
		if (pTAS2557->mpFirmware->mpConfigurations[nConfig].mnProgram != nProgram) {
			dev_err(pTAS2557->dev,
				"%s, configuration program doesn't match\n", __func__);
			nResult = 0;
			goto end;
		}

		nConfiguration = nConfig;
	}

	pProgram = &(pTAS2557->mpFirmware->mpPrograms[nProgram]);
	if (pTAS2557->mbPowerUp) {
		dev_info(pTAS2557->dev,
			 "device powered up, power down to load program %d (%s)\n",
			 nProgram, pProgram->mpName);

		nResult = tas2559_DevShutdown(pTAS2557, DevBoth);

		if (nResult < 0)
			goto end;
	}

	tas2559_hw_reset(pTAS2557);
	nResult = tas2559_dev_write(pTAS2557, DevBoth, TAS2557_SW_RESET_REG, 0x01);
	if (nResult < 0)
		goto end;

	msleep(1);
	nResult = tas2559_load_default(pTAS2557);
	if (nResult < 0)
		goto end;

	dev_info(pTAS2557->dev, "load program %d (%s)\n", nProgram, pProgram->mpName);
	nResult = tas2559_load_data(pTAS2557, &(pProgram->mData), TAS2557_BLOCK_PGM_DEV_A);
	if (nResult < 0)
		goto end;

	nResult = tas2559_load_data(pTAS2557, &(pProgram->mData), TAS2557_BLOCK_PGM_DEV_B);
	if (nResult < 0)
		goto end;

	pTAS2557->mnCurrentProgram = nProgram;

	nResult = tas2559_load_coefficient(pTAS2557, -1, nConfiguration, false);
	if (nResult < 0)
		goto end;

	if (pTAS2557->mbPowerUp) {
		pConfiguration = &(pTAS2557->mpFirmware->mpConfigurations[pTAS2557->mnCurrentConfiguration]);
		nResult = tas2559_DevStartup(pTAS2557, pConfiguration->mnDevices);
		if (nResult < 0)
			goto end;

		if (pConfiguration->mnDevices & DevB) {
			nResult = tas2559_load_data(pTAS2557, &(pConfiguration->mData),
						    TAS2559_BLOCK_PST_POWERUP_DEV_B);
			if (nResult < 0)
				goto end;
		}

		nResult = tas2559_DevMute(pTAS2557, pConfiguration->mnDevices, false);
		if (nResult < 0)
			goto end;
	}

end:

	if (nResult < 0) {
		if (pTAS2557->mnErrCode &
		    (ERROR_DEVA_I2C_COMM | ERROR_DEVB_I2C_COMM |
		     ERROR_PRAM_CRCCHK | ERROR_YRAM_CRCCHK))
			failsafe(pTAS2557);
	}

	return nResult;
}

static void fw_print_header(struct tas2559_priv *pTAS2557, struct TFirmware *pFirmware)
{
	dev_info(pTAS2557->dev, "FW Size       = %d", pFirmware->mnFWSize);
	dev_info(pTAS2557->dev, "Checksum      = 0x%04X", pFirmware->mnChecksum);
	dev_info(pTAS2557->dev, "PPC Version   = 0x%04X", pFirmware->mnPPCVersion);
	dev_info(pTAS2557->dev, "FW  Version    = 0x%04X", pFirmware->mnFWVersion);
	dev_info(pTAS2557->dev, "Driver Version= 0x%04X", pFirmware->mnDriverVersion);
	dev_info(pTAS2557->dev, "Timestamp     = %d", pFirmware->mnTimeStamp);
	dev_info(pTAS2557->dev, "DDC Name      = %s", pFirmware->mpDDCName);
	dev_info(pTAS2557->dev, "Description   = %s", pFirmware->mpDescription);
}

static inline unsigned int fw_convert_number(unsigned char *pData)
{
	return pData[3] + (pData[2] << 8) + (pData[1] << 16) + (pData[0] << 24);
}

static int fw_parse_header(struct tas2559_priv *pTAS2557,
			   struct TFirmware *pFirmware,
			   unsigned char *pData,
			   unsigned int nSize)
{
	unsigned char *pDataStart = pData;
	unsigned int n;
	unsigned char pMagicNumber[] = { 0x35, 0x35, 0x35, 0x32 };

	if (nSize < 104) {
		dev_err(pTAS2557->dev, "Firmware: Header too short");
		return -EINVAL;
	}

	if (memcmp(pData, pMagicNumber, 4)) {
		dev_err(pTAS2557->dev, "Firmware: Magic number doesn't match");
		return -EINVAL;
	}

	pData += 4;

	pFirmware->mnFWSize = fw_convert_number(pData);
	pData += 4;

	pFirmware->mnChecksum = fw_convert_number(pData);
	pData += 4;

	pFirmware->mnPPCVersion = fw_convert_number(pData);
	pData += 4;

	pFirmware->mnFWVersion = fw_convert_number(pData);
	pData += 4;

	pFirmware->mnDriverVersion = fw_convert_number(pData);
	dev_err(pTAS2557->dev, "Firmware driver: 0x%x", pFirmware->mnDriverVersion);
	pData += 4;

	pFirmware->mnTimeStamp = fw_convert_number(pData);
	pData += 4;

	memcpy(pFirmware->mpDDCName, pData, 64);
	pData += 64;

	n = strlen(pData);
	pFirmware->mpDescription = kmemdup(pData, n + 1, GFP_KERNEL);
	pData += n + 1;

	if ((pData - pDataStart) >= nSize) {
		dev_err(pTAS2557->dev, "Firmware: Header too short after DDC description");
		return -EINVAL;
	}

	pFirmware->mnDeviceFamily = fw_convert_number(pData);
	pData += 4;

	if (pFirmware->mnDeviceFamily != 0) {
		dev_err(pTAS2557->dev,
			"deviceFamily %d, not TAS device", pFirmware->mnDeviceFamily);
		return -EINVAL;
	}

	pFirmware->mnDevice = fw_convert_number(pData);
	pData += 4;

	if (pFirmware->mnDevice != 4) {
		dev_err(pTAS2557->dev,
			"device %d, not TAS2559", pFirmware->mnDevice);
		return -EINVAL;
	}

	fw_print_header(pTAS2557, pFirmware);

	return pData - pDataStart;
}

static int fw_parse_block_data(struct tas2559_priv *pTAS2557, struct TFirmware *pFirmware,
			       struct TBlock *pBlock, unsigned char *pData)
{
	unsigned char *pDataStart = pData;
	unsigned int n;

	pBlock->mnType = fw_convert_number(pData);
	pData += 4;

	if (pFirmware->mnDriverVersion >= PPC_DRIVER_CRCCHK) {
		pBlock->mbPChkSumPresent = pData[0];
		pData++;

		pBlock->mnPChkSum = pData[0];
		pData++;

		// skip YRAM checksum data for simplicity
		pData += 2;
	} else {
		pBlock->mbPChkSumPresent = 0;
	}

	pBlock->mnCommands = fw_convert_number(pData);
	pData += 4;

	n = pBlock->mnCommands * 4;
	pBlock->mpData = kmemdup(pData, n, GFP_KERNEL);
	pData += n;

	return pData - pDataStart;
}

static int fw_parse_data(struct tas2559_priv *pTAS2557, struct TFirmware *pFirmware,
			 struct TData *pImageData, unsigned char *pData)
{
	unsigned char *pDataStart = pData;
	unsigned int nBlock;
	unsigned int n;

	memcpy(pImageData->mpName, pData, 64);
	pData += 64;

	n = strlen(pData);
	pImageData->mpDescription = kmemdup(pData, n + 1, GFP_KERNEL);
	pData += n + 1;

	pImageData->mnBlocks = (pData[0] << 8) + pData[1];
	pData += 2;

	pImageData->mpBlocks =
		kmalloc(sizeof(struct TBlock) * pImageData->mnBlocks, GFP_KERNEL);

	for (nBlock = 0; nBlock < pImageData->mnBlocks; nBlock++) {
		n = fw_parse_block_data(pTAS2557, pFirmware,
					&(pImageData->mpBlocks[nBlock]), pData);
		pData += n;
	}

	return pData - pDataStart;
}

static int fw_parse_pll_data(struct tas2559_priv *pTAS2557,
			     struct TFirmware *pFirmware, unsigned char *pData)
{
	unsigned char *pDataStart = pData;
	unsigned int n;
	unsigned int nPLL;
	struct TPLL *pPLL;

	pFirmware->mnPLLs = (pData[0] << 8) + pData[1];
	pData += 2;

	if (pFirmware->mnPLLs == 0)
		goto end;

	pFirmware->mpPLLs = kmalloc_array(pFirmware->mnPLLs, sizeof(struct TPLL), GFP_KERNEL);

	for (nPLL = 0; nPLL < pFirmware->mnPLLs; nPLL++) {
		pPLL = &(pFirmware->mpPLLs[nPLL]);

		memcpy(pPLL->mpName, pData, 64);
		pData += 64;

		n = strlen(pData);
		pPLL->mpDescription = kmemdup(pData, n + 1, GFP_KERNEL);
		pData += n + 1;

		n = fw_parse_block_data(pTAS2557, pFirmware, &(pPLL->mBlock), pData);
		pData += n;
	}

end:
	return pData - pDataStart;
}

static int fw_parse_program_data(struct tas2559_priv *pTAS2557,
				 struct TFirmware *pFirmware, unsigned char *pData)
{
	unsigned char *pDataStart = pData;
	unsigned int n;
	unsigned int nProgram;
	struct TProgram *pProgram;

	pFirmware->mnPrograms = (pData[0] << 8) + pData[1];
	pData += 2;

	if (pFirmware->mnPrograms == 0)
		goto end;

	pFirmware->mpPrograms =
		kmalloc(sizeof(struct TProgram) * pFirmware->mnPrograms, GFP_KERNEL);
	if (!pFirmware->mpPrograms) {
		dev_dbg(pTAS2557->dev, "failed malloc program mem\n");
	}

	for (nProgram = 0; nProgram < pFirmware->mnPrograms; nProgram++) {
		pProgram = &(pFirmware->mpPrograms[nProgram]);
		memcpy(pProgram->mpName, pData, 64);
		pData += 64;

		n = strlen(pData);
		pProgram->mpDescription = kmemdup(pData, n + 1, GFP_KERNEL);
		pData += n + 1;

		pProgram->mnAppMode = pData[0];
		pData++;

		pProgram->mnBoost = (pData[0] << 8) + pData[1];
		pData += 2;

		n = fw_parse_data(pTAS2557, pFirmware, &(pProgram->mData), pData);
		pData += n;
	}

end:

	return pData - pDataStart;
}

static int fw_parse_configuration_data(struct tas2559_priv *pTAS2557,
				       struct TFirmware *pFirmware, unsigned char *pData)
{
	unsigned char *pDataStart = pData;
	unsigned int n;
	unsigned int nConfiguration;
	struct TConfiguration *pConfiguration;

	pFirmware->mnConfigurations = (pData[0] << 8) + pData[1];
	pData += 2;

	if (pFirmware->mnConfigurations == 0)
		goto end;

	pFirmware->mpConfigurations =
		kmalloc(sizeof(struct TConfiguration) * pFirmware->mnConfigurations,
			GFP_KERNEL);
	if (!pFirmware->mpConfigurations) {
		dev_dbg(pTAS2557->dev, "failed malloc configuration mem\n");
		/* return */
	}

	for (nConfiguration = 0; nConfiguration < pFirmware->mnConfigurations;
	     nConfiguration++) {
		pConfiguration = &(pFirmware->mpConfigurations[nConfiguration]);
		memcpy(pConfiguration->mpName, pData, 64);
		pData += 64;

		n = strlen(pData);
		pConfiguration->mpDescription = kmemdup(pData, n + 1, GFP_KERNEL);
		pData += n + 1;

		if ((pFirmware->mnDriverVersion >= PPC_DRIVER_CONFDEV)
		    || ((pFirmware->mnDriverVersion >= PPC_DRIVER_CFGDEV_NONCRC)
			&& (pFirmware->mnDriverVersion < PPC_DRIVER_CRCCHK))) {
			pConfiguration->mnDevices = (pData[0] << 8) + pData[1];
			pData += 2;
		} else
			pConfiguration->mnDevices = DevBoth;

		pConfiguration->mnProgram = pData[0];
		pData++;

		pConfiguration->mnPLL = pData[0];
		pData++;

		pConfiguration->mnSamplingRate = fw_convert_number(pData);
		pData += 4;

		if (pFirmware->mnDriverVersion >= PPC_DRIVER_MTPLLSRC) {
			pConfiguration->mnPLLSrc = pData[0];
			pData++;

			pConfiguration->mnPLLSrcRate = fw_convert_number(pData);
			pData += 4;
			dev_err(pTAS2557->dev, "line:%d, pData: 0x%x, 0x%x, 0x%x, 0x%x",
				__LINE__, pData[0], pData[1], pData[2], pData[3]);
		}

		n = fw_parse_data(pTAS2557, pFirmware, &(pConfiguration->mData), pData);
		pData += n;
	}

end:

	return pData - pDataStart;
}

static int fw_parse_calibration_data(struct tas2559_priv *pTAS2557,
			      struct TFirmware *pFirmware, unsigned char *pData)
{
	unsigned char *pDataStart = pData;
	unsigned int n;
	unsigned int nCalibration;
	struct TCalibration *pCalibration;

	pFirmware->mnCalibrations = (pData[0] << 8) + pData[1];
	pData += 2;

	if (pFirmware->mnCalibrations == 0)
		goto end;

	pFirmware->mpCalibrations =
		kmalloc(sizeof(struct TCalibration) * pFirmware->mnCalibrations, GFP_KERNEL);
	if (!pFirmware->mpCalibrations) {
	}

	for (nCalibration = 0;
	     nCalibration < pFirmware->mnCalibrations;
	     nCalibration++) {
		pCalibration = &(pFirmware->mpCalibrations[nCalibration]);
		memcpy(pCalibration->mpName, pData, 64);
		pData += 64;

		n = strlen(pData);
		pCalibration->mpDescription = kmemdup(pData, n + 1, GFP_KERNEL);
		pData += n + 1;

		pCalibration->mnProgram = pData[0];
		pData++;

		pCalibration->mnConfiguration = pData[0];
		pData++;

		n = fw_parse_data(pTAS2557, pFirmware, &(pCalibration->mData), pData);
		pData += n;
	}

end:

	return pData - pDataStart;
}

static int fw_parse(struct tas2559_priv *pTAS2557,
		    struct TFirmware *pFirmware, unsigned char *pData,
		    unsigned int nSize)
{
	int nPosition = 0;

	nPosition = fw_parse_header(pTAS2557, pFirmware, pData, nSize);
	if (nPosition < 0) {
		dev_err(pTAS2557->dev, "Firmware: Wrong Header");
		return -EINVAL;
	}

	if (nPosition >= nSize) {
		dev_err(pTAS2557->dev, "Firmware: Too short");
		return -EINVAL;
	}

	pData += nPosition;
	nSize -= nPosition;
	nPosition = 0;

	nPosition = fw_parse_pll_data(pTAS2557, pFirmware, pData);

	pData += nPosition;
	nSize -= nPosition;
	nPosition = 0;

	nPosition = fw_parse_program_data(pTAS2557, pFirmware, pData);

	pData += nPosition;
	nSize -= nPosition;
	nPosition = 0;

	nPosition = fw_parse_configuration_data(pTAS2557, pFirmware, pData);

	pData += nPosition;
	nSize -= nPosition;
	nPosition = 0;

	if (nSize > 64)
		nPosition = fw_parse_calibration_data(pTAS2557, pFirmware, pData);

	return 0;
}

void tas2559_fw_ready(const struct firmware *pFW, void *pContext)
{
	struct tas2559_priv *pTAS2557 = (struct tas2559_priv *) pContext;
	int nResult;
	unsigned int nProgram = 0;
	unsigned int nSampleRate = 0;

	mutex_lock(&pTAS2557->codec_lock);

	if (unlikely(!pFW) || unlikely(!pFW->data)) {
		dev_err(pTAS2557->dev, "%s firmware is not loaded.\n",
			TAS2559_FW_NAME);
		goto end;
	}

	if (pTAS2557->mpFirmware->mpConfigurations) {
		nProgram = pTAS2557->mnCurrentProgram;
		nSampleRate = pTAS2557->mnCurrentSampleRate;
		dev_dbg(pTAS2557->dev, "clear current firmware\n");
		tas2559_clear_firmware(pTAS2557->mpFirmware);
	}

	nResult = fw_parse(pTAS2557, pTAS2557->mpFirmware,
			   (unsigned char *)(pFW->data), pFW->size);
	release_firmware(pFW);
	if (nResult < 0) {
		dev_err(pTAS2557->dev, "firmware is corrupt\n");
		goto end;
	}

	if (!pTAS2557->mpFirmware->mnPrograms) {
		dev_err(pTAS2557->dev, "firmware contains no programs\n");
		nResult = -EINVAL;
		goto end;
	}

	if (!pTAS2557->mpFirmware->mnConfigurations) {
		dev_err(pTAS2557->dev, "firmware contains no configurations\n");
		nResult = -EINVAL;
		goto end;
	}

	if (nProgram >= pTAS2557->mpFirmware->mnPrograms) {
		dev_info(pTAS2557->dev,
			 "no previous program, set to default\n");
		nProgram = 0;
	}

	pTAS2557->mnCurrentSampleRate = nSampleRate;
	nResult = tas2559_set_program(pTAS2557, nProgram, -1);

end:
	mutex_unlock(&pTAS2557->codec_lock);
}

int tas2559_enable(struct tas2559_priv *pTAS2557, bool bEnable)
{
	int nResult = 0;
	struct TProgram *pProgram;
	struct TConfiguration *pConfiguration;
	unsigned int nValue;

	dev_dbg(pTAS2557->dev, "%s: %s\n", __func__, bEnable ? "On" : "Off");

	if ((pTAS2557->mpFirmware->mnPrograms == 0)
	    || (pTAS2557->mpFirmware->mnConfigurations == 0)) {
		dev_dbg(pTAS2557->dev, "%s, firmware not loaded\n", __func__);

		nResult = request_firmware_nowait(THIS_MODULE, 1, TAS2559_FW_NAME,
						  pTAS2557->dev, GFP_KERNEL,
						  pTAS2557, tas2559_fw_ready);
		if (nResult < 0) {
			dev_err(pTAS2557->dev, "%s, firmware is loaded\n", __func__);
			goto end;
		}
	}

	/* check safe guard */
	nResult = tas2559_dev_read(pTAS2557, DevA, TAS2557_SAFE_GUARD_REG, &nValue);
	if (nResult < 0)
		goto end;
	if ((nValue & 0xff) != TAS2557_SAFE_GUARD_PATTERN) {
		dev_err(pTAS2557->dev, "ERROR DevA safe guard (0x%x) failure!\n", nValue);
		nResult = -EPIPE;
		pTAS2557->mnErrCode = ERROR_SAFE_GUARD;
		pTAS2557->mbPowerUp = true;
		goto end;
	}

	pProgram = &(pTAS2557->mpFirmware->mpPrograms[pTAS2557->mnCurrentProgram]);
	if (bEnable) {
		if (pTAS2557->mbPowerUp) {
			nResult = 0;
			goto end;
		}

		if (pTAS2557->mbLoadConfigurationPrePowerUp) {
			pTAS2557->mbLoadConfigurationPrePowerUp = false;
			nResult = tas2559_load_coefficient(pTAS2557,
							   pTAS2557->mnCurrentConfiguration,
							   pTAS2557->mnNewConfiguration,
							   false);
			if (nResult < 0)
				goto end;
		}

		pConfiguration =
		  &(pTAS2557->mpFirmware->mpConfigurations[pTAS2557->mnCurrentConfiguration]);
		nResult = tas2559_DevStartup(pTAS2557, pConfiguration->mnDevices);
		if (nResult < 0)
			goto end;

		if (pConfiguration->mnDevices & DevB) {
			nResult = tas2559_load_data(pTAS2557, &(pConfiguration->mData),
						    TAS2559_BLOCK_PST_POWERUP_DEV_B);
			if (nResult < 0)
				goto end;
		}

		nResult = tas2559_DevMute(pTAS2557, pConfiguration->mnDevices, false);
		if (nResult < 0)
			goto end;

		pTAS2557->mbPowerUp = true;
		pTAS2557->mnRestart = 0;
	} else {
		if (!pTAS2557->mbPowerUp) {
			nResult = 0;
			goto end;
		}

		pConfiguration =
			&(pTAS2557->mpFirmware->mpConfigurations[pTAS2557->mnCurrentConfiguration]);

		nResult = tas2559_DevShutdown(pTAS2557, pConfiguration->mnDevices);
		if (nResult < 0)
			goto end;

		pTAS2557->mbPowerUp = false;
		pTAS2557->mnRestart = 0;
	}

	nResult = 0;

end:

	if (nResult < 0) {
		if (pTAS2557->mnErrCode &
		    (ERROR_DEVA_I2C_COMM | ERROR_DEVB_I2C_COMM |
		     ERROR_PRAM_CRCCHK | ERROR_YRAM_CRCCHK | ERROR_SAFE_GUARD))
			failsafe(pTAS2557);
	}

	return nResult;
}

int tas2559_set_sampling_rate(struct tas2559_priv *pTAS2557, unsigned int nSamplingRate)
{
	int nResult = 0;
	struct TConfiguration *pConfiguration;
	unsigned int nConfiguration;

	dev_dbg(pTAS2557->dev, "%s: nSamplingRate = %d [Hz]\n", __func__,
		nSamplingRate);

	if ((!pTAS2557->mpFirmware->mpPrograms) ||
	    (!pTAS2557->mpFirmware->mpConfigurations)) {
		dev_err(pTAS2557->dev, "Firmware not loaded\n");
		nResult = -EINVAL;
		goto end;
	}

	pConfiguration =
		&(pTAS2557->mpFirmware->mpConfigurations[pTAS2557->mnCurrentConfiguration]);

	if (pConfiguration->mnSamplingRate == nSamplingRate) {
		dev_info(pTAS2557->dev, "Sampling rate for current configuration matches: %d\n",
			 nSamplingRate);
		nResult = 0;
		goto end;
	}

	for (nConfiguration = 0;
	     nConfiguration < pTAS2557->mpFirmware->mnConfigurations;
	     nConfiguration++) {
		pConfiguration =
			&(pTAS2557->mpFirmware->mpConfigurations[nConfiguration]);

		if ((pConfiguration->mnSamplingRate == nSamplingRate)
		    && (pConfiguration->mnProgram == pTAS2557->mnCurrentProgram)) {
			dev_info(pTAS2557->dev,
				 "Found configuration: %s, with compatible sampling rate %d\n",
				 pConfiguration->mpName, nSamplingRate);
			nResult = tas2559_load_configuration(pTAS2557, nConfiguration, false);
			goto end;
		}
	}

	dev_err(pTAS2557->dev, "Cannot find a configuration that supports sampling rate: %d\n",
		nSamplingRate);

end:

	return nResult;
}

int tas2559_set_config(struct tas2559_priv *pTAS2557, int config)
{
	struct TConfiguration *pConfiguration;
	struct TProgram *pProgram;
	unsigned int nProgram = pTAS2557->mnCurrentProgram;
	unsigned int nConfiguration = config;
	int nResult = 0;

	if ((!pTAS2557->mpFirmware->mpPrograms) ||
	    (!pTAS2557->mpFirmware->mpConfigurations)) {
		dev_err(pTAS2557->dev, "Firmware not loaded\n");
		nResult = -EINVAL;
		goto end;
	}

	if (nConfiguration >= pTAS2557->mpFirmware->mnConfigurations) {
		dev_err(pTAS2557->dev, "Configuration %d doesn't exist\n",
			nConfiguration);
		nResult = -EINVAL;
		goto end;
	}

	pConfiguration = &(pTAS2557->mpFirmware->mpConfigurations[nConfiguration]);
	pProgram = &(pTAS2557->mpFirmware->mpPrograms[nProgram]);

	if (nProgram != pConfiguration->mnProgram) {
		dev_err(pTAS2557->dev,
			"Configuration %d, %s with Program %d isn't compatible with existing Program %d, %s\n",
			nConfiguration, pConfiguration->mpName, pConfiguration->mnProgram,
			nProgram, pProgram->mpName);
		nResult = -EINVAL;
		goto end;
	}

	dev_dbg(pTAS2557->dev, "%s, load new conf %s\n", __func__, pConfiguration->mpName);
	nResult = tas2559_load_configuration(pTAS2557, nConfiguration, false);

end:

	return nResult;
}

int tas2559_parse_dt(struct device *dev, struct tas2559_priv *pTAS2557)
{
	struct device_node *np = dev->of_node;
	int rc = 0, ret = 0;
	unsigned int value;

	pTAS2557->mnDevAGPIORST = devm_gpiod_get(dev, "ti,tas2559-reset", GPIOD_OUT_LOW);
	if (IS_ERR(pTAS2557->mnDevAGPIORST)) {
		ret = PTR_ERR(pTAS2557->mnDevAGPIORST);
		dev_err(dev, "Failed to request reset gpio, error %d\n", ret);
		return ret;
	}

	dev_dbg(pTAS2557->dev, "%s, tas2559 reset gpio\n", __func__);

	pTAS2557->mnDevBGPIORST = devm_gpiod_get(dev, "ti,tas2560-reset", GPIOD_OUT_LOW);
	if (IS_ERR(pTAS2557->mnDevBGPIORST)) {
		ret = PTR_ERR(pTAS2557->mnDevBGPIORST);
		dev_err(dev, "Failed to request reset gpio, error %d\n", ret);
		return ret;
	}

	dev_dbg(pTAS2557->dev, "%s, tas2560 reset gpio\n", __func__);

	rc = of_property_read_u32(np, "ti,tas2559-addr", &value);
	if (rc) {
		dev_err(pTAS2557->dev, "Looking up %s property in node %s failed %d\n",
			"ti,tas2559-addr", np->full_name, rc);
		ret = -EINVAL;
		goto end;
	}

	pTAS2557->mnDevAAddr = value;
	dev_dbg(pTAS2557->dev, "ti,tas2559 addr=0x%x\n", pTAS2557->mnDevAAddr);

	rc = of_property_read_u32(np, "ti,tas2560-addr", &value);
	if (rc) {
		dev_err(pTAS2557->dev, "Looking up %s property in node %s failed %d\n",
			"ti,tas2560-addr", np->full_name, rc);
		ret = -EINVAL;
		goto end;
	}

	pTAS2557->mnDevBAddr = value;
	dev_dbg(pTAS2557->dev, "ti,tas2560-addr=0x%x\n", pTAS2557->mnDevBAddr);

end:
	return ret;
}

// Codec related

static const struct snd_soc_dapm_widget tas2559_dapm_widgets[] = {
	SND_SOC_DAPM_AIF_IN("ASI1", "ASI1 Playback", 0, SND_SOC_NOPM, 0, 0),
	SND_SOC_DAPM_AIF_IN("ASI2", "ASI2 Playback", 0, SND_SOC_NOPM, 0, 0),
	SND_SOC_DAPM_AIF_IN("ASIM", "ASIM Playback", 0, SND_SOC_NOPM, 0, 0),
	SND_SOC_DAPM_DAC("DAC", NULL, SND_SOC_NOPM, 0, 0),
	SND_SOC_DAPM_OUT_DRV("ClassD", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_SUPPLY("PLL", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_SUPPLY("NDivider", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_OUTPUT("OUT")
};

static const struct snd_soc_dapm_route tas2559_audio_map[] = {
	{"DAC", NULL, "ASI1"},
	{"DAC", NULL, "ASI2"},
	{"DAC", NULL, "ASIM"},
	{"ClassD", NULL, "DAC"},
	{"OUT", NULL, "ClassD"},
	{"DAC", NULL, "PLL"},
	{"DAC", NULL, "NDivider"},
};

static int tas2559_mute(struct snd_soc_dai *dai, int mute, int direction)
{
	struct snd_soc_component *codec = dai->component;
	struct tas2559_priv *pTAS2557 = snd_soc_component_get_drvdata(codec);

	mutex_lock(&pTAS2557->codec_lock);

	tas2559_enable(pTAS2557, !mute);

	mutex_unlock(&pTAS2557->codec_lock);
	return 0;
}

static int tas2559_hw_params(struct snd_pcm_substream *pSubstream,
			     struct snd_pcm_hw_params *pParams, struct snd_soc_dai *pDAI)
{
	struct snd_soc_component *pCodec = pDAI->component;
	struct tas2559_priv *pTAS2557 = snd_soc_component_get_drvdata(pCodec);

	mutex_lock(&pTAS2557->codec_lock);

	tas2559_set_sampling_rate(pTAS2557, params_rate(pParams));

	mutex_unlock(&pTAS2557->codec_lock);
	return 0;
}

static int tas2559_configuration_get(struct snd_kcontrol *pKcontrol,
				     struct snd_ctl_elem_value *pValue)
{
	struct snd_soc_component *codec = snd_kcontrol_chip(pKcontrol);
	struct tas2559_priv *pTAS2557 = snd_soc_component_get_drvdata(codec);

	mutex_lock(&pTAS2557->codec_lock);

	pValue->value.integer.value[0] = pTAS2557->mnCurrentConfiguration;
	dev_dbg(pTAS2557->dev, "%s = %d\n", __func__,
		pTAS2557->mnCurrentConfiguration);

	mutex_unlock(&pTAS2557->codec_lock);
	return 0;
}

static int tas2559_configuration_put(struct snd_kcontrol *pKcontrol,
				     struct snd_ctl_elem_value *pValue)
{
	struct snd_soc_component *codec = snd_kcontrol_chip(pKcontrol);
	struct tas2559_priv *pTAS2557 = snd_soc_component_get_drvdata(codec);
	unsigned int nConfiguration = pValue->value.integer.value[0];
	int ret = 0;

	mutex_lock(&pTAS2557->codec_lock);

	dev_info(pTAS2557->dev, "%s = %d\n", __func__, nConfiguration);
	ret = tas2559_set_config(pTAS2557, nConfiguration);

	mutex_unlock(&pTAS2557->codec_lock);
	return ret;
}

static int tas2559_ldac_gain_get(struct snd_kcontrol *pKcontrol,
				 struct snd_ctl_elem_value *pValue)
{
	struct snd_soc_component *codec = snd_kcontrol_chip(pKcontrol);
	struct tas2559_priv *pTAS2557 = snd_soc_component_get_drvdata(codec);
	unsigned char nGain = 0;
	int ret = -1;

	mutex_lock(&pTAS2557->codec_lock);

	ret = tas2559_get_DAC_gain(pTAS2557, DevA, &nGain);

	if (ret >= 0)
		pValue->value.integer.value[0] = nGain;

	dev_dbg(pTAS2557->dev, "%s, ret = %d, %d\n", __func__, ret, nGain);

	mutex_unlock(&pTAS2557->codec_lock);
	return ret;
}

static int tas2559_ldac_gain_put(struct snd_kcontrol *pKcontrol,
				 struct snd_ctl_elem_value *pValue)
{
	struct snd_soc_component *codec = snd_kcontrol_chip(pKcontrol);
	struct tas2559_priv *pTAS2557 = snd_soc_component_get_drvdata(codec);
	unsigned int nGain = pValue->value.integer.value[0];
	int ret = 0;

	mutex_lock(&pTAS2557->codec_lock);

	ret = tas2559_set_DAC_gain(pTAS2557, DevA, nGain);

	mutex_unlock(&pTAS2557->codec_lock);
	return ret;
}

static int tas2559_rdac_gain_get(struct snd_kcontrol *pKcontrol,
				 struct snd_ctl_elem_value *pValue)
{
	struct snd_soc_component *codec = snd_kcontrol_chip(pKcontrol);
	struct tas2559_priv *pTAS2557 = snd_soc_component_get_drvdata(codec);
	unsigned char nGain = 0;
	int ret = -1;

	mutex_lock(&pTAS2557->codec_lock);

	ret = tas2559_get_DAC_gain(pTAS2557, DevB, &nGain);

	if (ret >= 0)
		pValue->value.integer.value[0] = nGain;

	dev_dbg(pTAS2557->dev, "%s, ret = %d, %d\n", __func__, ret, nGain);

	mutex_unlock(&pTAS2557->codec_lock);

	return ret;
}

static int tas2559_rdac_gain_put(struct snd_kcontrol *pKcontrol,
				 struct snd_ctl_elem_value *pValue)
{
	struct snd_soc_component *codec = snd_kcontrol_chip(pKcontrol);
	struct tas2559_priv *pTAS2557 = snd_soc_component_get_drvdata(codec);
	unsigned int nGain = pValue->value.integer.value[0];
	int ret = 0;

	mutex_lock(&pTAS2557->codec_lock);

	ret = tas2559_set_DAC_gain(pTAS2557, DevB, nGain);

	mutex_unlock(&pTAS2557->codec_lock);
	return ret;
}

static const struct snd_kcontrol_new tas2559_snd_controls[] = {
	SOC_SINGLE_EXT("TAS2557 DAC Playback Volume", SND_SOC_NOPM, 0, 0x0f, 0,
		tas2559_ldac_gain_get, tas2559_ldac_gain_put),
	SOC_SINGLE_EXT("TAS2560 DAC Playback Volume", SND_SOC_NOPM, 0, 0x0f, 0,
		tas2559_rdac_gain_get, tas2559_rdac_gain_put),
	SOC_SINGLE_EXT("Configuration", SND_SOC_NOPM, 0, 0x00FF, 0,
		tas2559_configuration_get, tas2559_configuration_put),
};

static const struct snd_soc_component_driver soc_codec_driver_tas2559 = {
	.idle_bias_on = false,
	.controls = tas2559_snd_controls,
	.num_controls = ARRAY_SIZE(tas2559_snd_controls),
	.dapm_widgets = tas2559_dapm_widgets,
	.num_dapm_widgets = ARRAY_SIZE(tas2559_dapm_widgets),
	.dapm_routes = tas2559_audio_map,
	.num_dapm_routes = ARRAY_SIZE(tas2559_audio_map),
	.legacy_dai_naming	= 1,
};

static const struct snd_soc_dai_ops tas2559_dai_ops = {
	.mute_stream = tas2559_mute,
	.hw_params = tas2559_hw_params,
};

#define TAS2557_FORMATS (SNDRV_PCM_FMTBIT_S16_LE | SNDRV_PCM_FMTBIT_S20_3LE |\
			SNDRV_PCM_FMTBIT_S24_LE | SNDRV_PCM_FMTBIT_S32_LE)
static struct snd_soc_dai_driver tas2559_dai_driver[] = {
	{
		.name = "tas2559 ASI1",
		.id = 0,
		.playback = {
			.stream_name = "ASI1 Playback",
			.channels_min = 2,
			.channels_max = 2,
			.rates = SNDRV_PCM_RATE_8000_192000,
			.formats = TAS2557_FORMATS,
		},
		.ops = &tas2559_dai_ops,
		.symmetric_rate = 1,
	},
	{
		.name = "tas2559 ASI2",
		.id = 1,
		.playback = {
			.stream_name = "ASI2 Playback",
			.channels_min = 2,
			.channels_max = 2,
			.rates = SNDRV_PCM_RATE_8000_192000,
			.formats = TAS2557_FORMATS,
		},
		.ops = &tas2559_dai_ops,
		.symmetric_rate = 1,
	},
	{
		.name = "tas2559 ASIM",
		.id = 2,
		.playback = {
			.stream_name = "ASIM Playback",
			.channels_min = 2,
			.channels_max = 2,
			.rates = SNDRV_PCM_RATE_8000_192000,
			.formats = TAS2557_FORMATS,
		},
		.ops = &tas2559_dai_ops,
		.symmetric_rate = 1,
	},
};

int tas2559_register_codec(struct tas2559_priv *pTAS2557)
{
	int nResult = 0;

	dev_info(pTAS2557->dev, "%s, enter\n", __func__);
	nResult = devm_snd_soc_register_component(pTAS2557->dev,
					 &soc_codec_driver_tas2559,
					 tas2559_dai_driver, ARRAY_SIZE(tas2559_dai_driver));
	return nResult;
}

int tas255x_deregister_codec(struct tas2559_priv *pTAS255X)
{
	snd_soc_unregister_component(pTAS255X->dev);
	return 0;
}

static bool tas2559_volatile(struct device *pDev, unsigned int nRegister)
{
	return true;
}

static bool tas2559_writeable(struct device *pDev, unsigned int nRegister)
{
	return true;
}

static const struct regmap_config tas2559_i2c_regmap = {
	.reg_bits = 8,
	.val_bits = 8,
	.writeable_reg = tas2559_writeable,
	.volatile_reg = tas2559_volatile,
	.cache_type = REGCACHE_NONE,
	.max_register = 128,
};

static int tas2559_i2c_probe(struct i2c_client *pClient)
{
	struct tas2559_priv *pTAS2557;
	int nResult;

	pTAS2557 = devm_kzalloc(&pClient->dev, sizeof(struct tas2559_priv), GFP_KERNEL);

	if (!pTAS2557) {
		nResult = -ENOMEM;
		goto err;
	}

	pTAS2557->client = pClient;
	pTAS2557->dev = &pClient->dev;
	i2c_set_clientdata(pClient, pTAS2557);
	dev_set_drvdata(&pClient->dev, pTAS2557);

	pTAS2557->mpRegmap = devm_regmap_init_i2c(pClient, &tas2559_i2c_regmap);

	if (IS_ERR(pTAS2557->mpRegmap)) {
		nResult = PTR_ERR(pTAS2557->mpRegmap);
		dev_err(&pClient->dev, "Failed to allocate register map: %d\n",
			nResult);
		goto err;
	}

	if (pClient->dev.of_node)
		tas2559_parse_dt(&pClient->dev, pTAS2557);

	tas2559_hw_reset(pTAS2557);

	pTAS2557->mnRestart = 0;

	mutex_init(&pTAS2557->dev_lock);

	/* Reset the chip */
	nResult = tas2559_dev_write(pTAS2557, DevBoth, TAS2557_SW_RESET_REG, 1);
	if (nResult < 0) {
		dev_err(&pClient->dev, "I2c fail, %d\n", nResult);
		goto err;
	}
	msleep(20); // was 1

	pTAS2557->mpFirmware = devm_kzalloc(&pClient->dev, sizeof(struct TFirmware), GFP_KERNEL);

	if (!pTAS2557->mpFirmware) {
		nResult = -ENOMEM;
		goto err;
	}

	mutex_init(&pTAS2557->codec_lock);
	tas2559_register_codec(pTAS2557);

	nResult = request_firmware_nowait(THIS_MODULE, 1, TAS2557_FW_NAME,
					  pTAS2557->dev, GFP_KERNEL, pTAS2557, tas2559_fw_ready);

err:

	return nResult;
}

static void tas2559_i2c_remove(struct i2c_client *pClient)
{
	struct tas2559_priv *pTAS2557 = i2c_get_clientdata(pClient);

	tas255x_deregister_codec(pTAS2557);
	mutex_destroy(&pTAS2557->codec_lock);

	mutex_destroy(&pTAS2557->dev_lock);
}

static const struct i2c_device_id tas255x_i2c_id[] = {
	{"tas2559", 0},
	{}
};

MODULE_DEVICE_TABLE(i2c, tas255x_i2c_id);

static const struct of_device_id tas255x_of_match[] = {
	{.compatible = "ti,tas2559"},
	{},
};

MODULE_DEVICE_TABLE(of, tas255x_of_match);

static struct i2c_driver tas2559_i2c_driver = {
	.driver = {
		.name = "tas2559",
		.owner = THIS_MODULE,
		.of_match_table = of_match_ptr(tas255x_of_match),
	},
	.probe = tas2559_i2c_probe,
	.remove = tas2559_i2c_remove,
	.id_table = tas255x_i2c_id,
};

module_i2c_driver(tas2559_i2c_driver);

MODULE_AUTHOR("Texas Instruments Inc.");
MODULE_DESCRIPTION("TAS255x ALSA SOC Smart Amplifier Stereo driver");
MODULE_LICENSE("GPL");
