/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 SpacemiT Co., Ltd.
 */

#ifndef DPU_K1_H
#define DPU_K1_H

#include "dpu_saturn.h"

/* K1 Saturn DPU description, selected by the "spacemit,k1-saturn-dpu" match. */
extern const struct spacemit_hw_device k1_saturn_dpu;
extern const struct dpu_core_ops dpu_k1_ops;

int k1_parse_dt_clocks(struct device *dev, struct dpu_clk_context *clk_ctx);

#endif /* DPU_K1_H */
