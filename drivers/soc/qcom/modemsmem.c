// SPDX-License-Identifier: GPL-2.0-only
/*
 * SoC information for the modem on Google Pixel phones, published over SMEM.
 *
 * Copyright 2022-2024, Richard Acayan.
 */

#include <linux/err.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/soc/qcom/smem.h>
#include <linux/soc/qcom/socinfo.h>

/* First vendor-reserved SMEM item; Google's modem firmware reads it at boot */
#define SMEM_ID_VENDOR0		134

#define MODEM_SMEM_VERSION	0

#define PLAT_VER_TO_MAJOR_ID(v)	(((v) >> 16) & 0xff)
#define PLAT_VER_TO_MINOR_ID(v)	((v) & 0xff)

struct modem_smem_info {
	__le32 version;
	__le32 modem_flag;
	__le32 major_id;
	__le32 minor_id;
	__le32 subtype;
	__le32 platform;
	__le32 efs_magic;
	__le32 ftm_magic;
};

static int modemsmem_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct modem_smem_info *info;
	struct socinfo *socinfo;
	u32 plat_ver;
	int ret;

	socinfo = qcom_smem_get(QCOM_SMEM_HOST_ANY, SMEM_HW_SW_BUILD_ID, NULL);
	if (IS_ERR(socinfo))
		return dev_err_probe(dev, PTR_ERR(socinfo), "Could not get socinfo\n");

	/* hw_plat_subtype was added in socinfo format 0.6 */
	if (le32_to_cpu(socinfo->fmt) < SOCINFO_VERSION(0, 6))
		return dev_err_probe(dev, -EOPNOTSUPP, "socinfo format too old\n");

	/* -EEXIST: the item survived an earlier probe or module load */
	ret = qcom_smem_alloc(QCOM_SMEM_HOST_ANY, SMEM_ID_VENDOR0, sizeof(*info));
	if (ret && ret != -EEXIST)
		return dev_err_probe(dev, ret, "Could not allocate modem smem\n");

	info = qcom_smem_get(QCOM_SMEM_HOST_ANY, SMEM_ID_VENDOR0, NULL);
	if (IS_ERR(info))
		return dev_err_probe(dev, PTR_ERR(info), "Could not get modem smem\n");

	plat_ver = le32_to_cpu(socinfo->plat_ver);

	/* Unnamed fields (modem_flag, efs_magic, ftm_magic) are zeroed */
	*info = (struct modem_smem_info) {
		.version = cpu_to_le32(MODEM_SMEM_VERSION),
		.major_id = cpu_to_le32(PLAT_VER_TO_MAJOR_ID(plat_ver)),
		.minor_id = cpu_to_le32(PLAT_VER_TO_MINOR_ID(plat_ver)),
		.subtype = socinfo->hw_plat_subtype,
		.platform = socinfo->hw_plat,
	};

	return 0;
}

static struct platform_driver modemsmem_driver = {
	.probe = modemsmem_probe,
	.driver = {
		.name = "google-modemsmem",
	},
};

/*
 * The item layout is a contract between Google's downstream kernel and the
 * modem firmware, not hardware, so there is no device tree node to bind to.
 */
static const struct of_device_id modemsmem_machines[] = {
	{ .compatible = "google,blueline" },
	{ .compatible = "google,bonito" },
	{ .compatible = "google,crosshatch" },
	{ .compatible = "google,sargo" },
	{ }
};

static struct platform_device *modemsmem_pdev;

static int __init modemsmem_init(void)
{
	int ret;

	if (!of_machine_device_match(modemsmem_machines))
		return -ENODEV;

	ret = platform_driver_register(&modemsmem_driver);
	if (ret)
		return ret;

	/* A device of our own lets the probe defer until SMEM is available */
	modemsmem_pdev = platform_device_register_simple("google-modemsmem",
							 PLATFORM_DEVID_NONE,
							 NULL, 0);
	if (IS_ERR(modemsmem_pdev)) {
		platform_driver_unregister(&modemsmem_driver);
		return PTR_ERR(modemsmem_pdev);
	}

	return 0;
}
module_init(modemsmem_init);

static void __exit modemsmem_exit(void)
{
	platform_device_unregister(modemsmem_pdev);
	platform_driver_unregister(&modemsmem_driver);
}
module_exit(modemsmem_exit);

MODULE_AUTHOR("Richard Acayan <mailingradian@gmail.com>");
MODULE_DESCRIPTION("SoC information over SMEM for Google Pixel modems");
MODULE_LICENSE("GPL");
