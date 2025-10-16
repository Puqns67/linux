// SPDX-License-Identifier: GPL-2.0
/*
 * SpacemiT K1 PCIe host driver
 *
 * Copyright (C) 2025 by RISCstar Solutions Corporation.  All rights reserved.
 * Copyright (c) 2023, spacemit Corporation.
 */

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/mfd/syscon.h>
#include <linux/mod_devicetable.h>
#include <linux/phy/phy.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/reset.h>
#include <linux/types.h>

#include "pcie-designware.h"

#define PCI_VENDOR_ID_SPACEMIT		0x201f
#define PCI_DEVICE_ID_SPACEMIT_K1	0x0001

/* Offsets and field definitions for link management registers */

#define K1_PHY_AHB_IRQ_EN			0x0000
#define PCIE_INTERRUPT_EN		BIT(0)

#define K1_PHY_AHB_LINK_STS			0x0004
#define SMLH_LINK_UP			BIT(1)
#define RDLH_LINK_UP			BIT(12)

#define INTR_ENABLE				0x0014
#define MSI_CTRL_INT			BIT(11)

/* Some controls require APMU regmap access */
#define SYSCON_APMU			"spacemit,apmu"

/* Offsets and field definitions for APMU registers */

#define PCIE_CLK_RESET_CONTROL			0x0000
#define LTSSM_EN			BIT(6)
#define PCIE_AUX_PWR_DET		BIT(9)
#define PCIE_RC_PERST			BIT(12)	/* 1: assert PERST# */
#define APP_HOLD_PHY_RST		BIT(30)
#define DEVICE_TYPE_RC			BIT(31)	/* 0: endpoint; 1: RC */

#define PCIE_CONTROL_LOGIC			0x0004
#define PCIE_SOFT_RESET			BIT(0)

struct k1_pcie {
	struct dw_pcie pci;
	struct phy *phy;
	void __iomem *link;
	struct regmap *pmu;	/* Errors ignored; MMIO-backed regmap */
	u32 pmu_off;
};

#define to_k1_pcie(dw_pcie) \
		platform_get_drvdata(to_platform_device((dw_pcie)->dev))

static void k1_pcie_toggle_soft_reset(struct k1_pcie *k1)
{
	u32 offset;
	u32 val;

	/*
	 * Write, then read back to guarantee it has reached the device
	 * before we start the delay.
	 */
	offset = k1->pmu_off + PCIE_CONTROL_LOGIC;
	regmap_set_bits(k1->pmu, offset, PCIE_SOFT_RESET);
	regmap_read(k1->pmu, offset, &val);

	mdelay(2);

	regmap_clear_bits(k1->pmu, offset, PCIE_SOFT_RESET);
}

/* Enable app clocks, deassert resets */
static int k1_pcie_activate(struct k1_pcie *k1)
{
	struct dw_pcie *pci = &k1->pci;
	int ret;

	ret = clk_bulk_prepare_enable(ARRAY_SIZE(pci->app_clks), pci->app_clks);
	if (ret)
		return ret;

	ret = reset_control_bulk_deassert(ARRAY_SIZE(pci->app_rsts),
					  pci->app_rsts);
	if (ret)
		goto err_disable_clks;

	ret = reset_control_bulk_deassert(ARRAY_SIZE(pci->core_rsts),
					  pci->core_rsts);
	if (ret)
		goto err_assert_resets;

	return 0;

err_assert_resets:
	reset_control_bulk_assert(ARRAY_SIZE(pci->app_rsts), pci->app_rsts);
err_disable_clks:
	clk_bulk_disable_unprepare(ARRAY_SIZE(pci->app_clks), pci->app_clks);

	return ret;
}

/* Assert resets, disable app clocks */
static void k1_pcie_deactivate(struct k1_pcie *k1)
{
	struct dw_pcie *pci = &k1->pci;

	reset_control_bulk_assert(ARRAY_SIZE(pci->core_rsts), pci->core_rsts);
	reset_control_bulk_assert(ARRAY_SIZE(pci->app_rsts), pci->app_rsts);
	clk_bulk_disable_unprepare(ARRAY_SIZE(pci->app_clks), pci->app_clks);
}

static int k1_pcie_init(struct dw_pcie_rp *pp)
{
	struct dw_pcie *pci = to_dw_pcie_from_pp(pp);
	struct k1_pcie *k1 = to_k1_pcie(pci);
	u32 offset;
	u32 mask;
	u32 val;
	int ret;

	k1_pcie_toggle_soft_reset(k1);

	ret = k1_pcie_activate(k1);
	if (ret)
		return ret;

	ret = phy_init(k1->phy);
	if (ret) {
		k1_pcie_deactivate(k1);

		return ret;
	}

	/* Set the PCI vendor and device ID */
	dw_pcie_dbi_ro_wr_en(pci);
	dw_pcie_writew_dbi(pci, PCI_VENDOR_ID, PCI_VENDOR_ID_SPACEMIT);
	dw_pcie_writew_dbi(pci, PCI_DEVICE_ID, PCI_DEVICE_ID_SPACEMIT_K1);
	dw_pcie_dbi_ro_wr_dis(pci);

	/*
	 * Assert fundamental reset (drive PERST# low).  Put the port in
	 * root complex mode, and indicate that Vaux (3.3v) is present.
	 */
	mask = PCIE_RC_PERST;
	mask |= DEVICE_TYPE_RC | PCIE_AUX_PWR_DET;

	/*
	 * Write, then read back to guarantee it has reached the device
	 * before we start the delay.
	 */
	offset = k1->pmu_off + PCIE_CLK_RESET_CONTROL;
	regmap_set_bits(k1->pmu, offset, mask);
	regmap_read(k1->pmu, offset, &val);

	mdelay(PCIE_T_PVPERL_MS);

	/* Deassert fundamental reset (drive PERST# high) */
	regmap_clear_bits(k1->pmu, offset, PCIE_RC_PERST);

	return 0;
}

static void k1_pcie_deinit(struct dw_pcie_rp *pp)
{
	struct dw_pcie *pci = to_dw_pcie_from_pp(pp);
	struct k1_pcie *k1 = to_k1_pcie(pci);

	/* Assert fundamental reset (drive PERST# low) */
	regmap_set_bits(k1->pmu, k1->pmu_off + PCIE_CLK_RESET_CONTROL,
			PCIE_RC_PERST);

	phy_exit(k1->phy);

	k1_pcie_deactivate(k1);
}

static const struct dw_pcie_host_ops k1_pcie_host_ops = {
	.init		= k1_pcie_init,
	.deinit		= k1_pcie_deinit,
};

static bool k1_pcie_link_up(struct dw_pcie *pci)
{
	struct k1_pcie *k1 = to_k1_pcie(pci);
	u32 val;

	val = readl_relaxed(k1->link + K1_PHY_AHB_LINK_STS);

	return (val & RDLH_LINK_UP) && (val & SMLH_LINK_UP);
}

static int k1_pcie_start_link(struct dw_pcie *pci)
{
	struct k1_pcie *k1 = to_k1_pcie(pci);
	u32 val;

	/* Stop holding the PHY in reset, and enable link training */
	regmap_update_bits(k1->pmu, k1->pmu_off + PCIE_CLK_RESET_CONTROL,
			   APP_HOLD_PHY_RST | LTSSM_EN, LTSSM_EN);

	/* Enable the MSI interrupt */
	writel_relaxed(MSI_CTRL_INT, k1->link + INTR_ENABLE);

	/* Top-level interrupt enable */
	val = readl_relaxed(k1->link + K1_PHY_AHB_IRQ_EN);
	val |= PCIE_INTERRUPT_EN;
	writel_relaxed(val, k1->link + K1_PHY_AHB_IRQ_EN);

	return 0;
}

static void k1_pcie_stop_link(struct dw_pcie *pci)
{
	struct k1_pcie *k1 = to_k1_pcie(pci);
	u32 val;

	/* Disable interrupts */
	val = readl_relaxed(k1->link + K1_PHY_AHB_IRQ_EN);
	val &= ~PCIE_INTERRUPT_EN;
	writel_relaxed(val, k1->link + K1_PHY_AHB_IRQ_EN);

	writel_relaxed(0, k1->link + INTR_ENABLE);

	/* Disable the link and hold the PHY in reset */
	regmap_update_bits(k1->pmu, k1->pmu_off + PCIE_CLK_RESET_CONTROL,
			   APP_HOLD_PHY_RST | LTSSM_EN, APP_HOLD_PHY_RST);
}

static const struct dw_pcie_ops k1_pcie_ops = {
	.link_up	= k1_pcie_link_up,
	.start_link	= k1_pcie_start_link,
	.stop_link	= k1_pcie_stop_link,
};

static int k1_pcie_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct k1_pcie *k1;
	int ret;

	k1 = devm_kzalloc(dev, sizeof(*k1), GFP_KERNEL);
	if (!k1)
		return -ENOMEM;

	k1->pmu = syscon_regmap_lookup_by_phandle_args(dev_of_node(dev),
						       SYSCON_APMU, 1,
						       &k1->pmu_off);
	if (IS_ERR(k1->pmu))
		return dev_err_probe(dev, PTR_ERR(k1->pmu),
				     "failed to lookup PMU registers\n");

	k1->link = devm_platform_ioremap_resource_byname(pdev, "link");
	if (!k1->link)
		return dev_err_probe(dev, -ENOMEM,
				     "failed to map \"link\" registers\n");

	ret = devm_regulator_get_enable(dev, "vpcie3v3-supply");
	if (ret)
		return dev_err_probe(dev, ret,
				     "failed to get \"vpcie3v3\" supply\n");

	/* Hold the PHY in reset until we start the link */
	regmap_set_bits(k1->pmu, k1->pmu_off + PCIE_CLK_RESET_CONTROL,
			APP_HOLD_PHY_RST);

	k1->phy = devm_phy_get(dev, NULL);
	if (IS_ERR(k1->phy))
		return dev_err_probe(dev, PTR_ERR(k1->phy),
				     "failed to get PHY\n");

	k1->pci.dev = dev;
	k1->pci.ops = &k1_pcie_ops;
	dw_pcie_cap_set(&k1->pci, REQ_RES);

	k1->pci.pp.ops = &k1_pcie_host_ops;
	k1->pci.pp.num_vectors = MAX_MSI_IRQS;

	platform_set_drvdata(pdev, k1);

	ret = dw_pcie_host_init(&k1->pci.pp);
	if (ret)
		return dev_err_probe(dev, ret, "failed to initialize host\n");

	return 0;
}

static void k1_pcie_remove(struct platform_device *pdev)
{
	struct k1_pcie *k1 = platform_get_drvdata(pdev);

	dw_pcie_host_deinit(&k1->pci.pp);
}

static const struct of_device_id k1_pcie_of_match_table[] = {
	{ .compatible = "spacemit,k1-pcie", },
	{ },
};

static struct platform_driver k1_pcie_driver = {
	.probe	= k1_pcie_probe,
	.remove	= k1_pcie_remove,
	.driver = {
		.name			= "spacemit-k1-pcie",
		.of_match_table		= k1_pcie_of_match_table,
		.probe_type		= PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_platform_driver(k1_pcie_driver);
