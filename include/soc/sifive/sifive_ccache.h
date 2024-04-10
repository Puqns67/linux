/* SPDX-License-Identifier: GPL-2.0 */
/*
 * SiFive Composable Cache Controller header file
 *
 */

#ifndef __SOC_SIFIVE_CCACHE_H
#define __SOC_SIFIVE_CCACHE_H

#include <linux/auxiliary_bus.h>

struct sifive_ccache {
	void __iomem		*base;
	struct auxiliary_device	edac_dev;
	struct auxiliary_device	pmu_dev;
};

extern int register_sifive_ccache_error_notifier(struct notifier_block *nb);
extern int unregister_sifive_ccache_error_notifier(struct notifier_block *nb);

#define SIFIVE_CCACHE_ERR_TYPE_CE 0
#define SIFIVE_CCACHE_ERR_TYPE_UE 1

#endif /* __SOC_SIFIVE_CCACHE_H */
