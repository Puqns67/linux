// SPDX-License-Identifier: GPL-2.0-only
/*
 * DRM driver for the Samsung EA8074 display driver IC and associated panel.
 *
 * Copyright David Heidelberg.
 */

#include <linux/backlight.h>
#include <linux/delay.h>
#include <linux/gpio/consumer.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/regulator/consumer.h>

#include <video/mipi_display.h>

#include <drm/drm_mipi_dsi.h>
#include <drm/drm_modes.h>
#include <drm/drm_panel.h>
#include <drm/drm_probe_helper.h>

struct samsung_ea8074_panel_desc {
	const struct drm_display_mode *mode;
	int (*init_sequence)(struct mipi_dsi_multi_context *dsi_ctx);
};

struct samsung_ea8074 {
	struct drm_panel panel;
	struct mipi_dsi_device *dsi;
	struct regulator_bulk_data *supplies;
	struct gpio_desc *reset_gpio;
	const struct samsung_ea8074_panel_desc *desc;
};

static const struct regulator_bulk_data ea8074_supplies[] = {
	{ .supply = "vddio",
	  .init_load_uA = 62000 },
	{ .supply = "elvdd",
	  .init_load_uA = 100000 },
	{ .supply = "elvss",
	  .init_load_uA = 100000 },
};

static inline
struct samsung_ea8074 *to_samsung_ea8074(struct drm_panel *panel)
{
	return container_of(panel, struct samsung_ea8074, panel);
}

#define ea8074_test_key_on_lvl2(ctx) \
	mipi_dsi_dcs_write_seq_multi(ctx, 0xf0, 0x5a, 0x5a)
#define ea8074_test_key_off_lvl2(ctx) \
	mipi_dsi_dcs_write_seq_multi(ctx, 0xf0, 0xa5, 0xa5)
#define ea8074_test_key_on_lvl3(ctx) \
	mipi_dsi_dcs_write_seq_multi(ctx, 0xfc, 0x5a, 0x5a)
#define ea8074_test_key_off_lvl3(ctx) \
	mipi_dsi_dcs_write_seq_multi(ctx, 0xfc, 0xa5, 0xa5)

static void samsung_ea8074_reset(struct samsung_ea8074 *ctx)
{
	gpiod_set_value_cansleep(ctx->reset_gpio, 0);
	usleep_range(1000, 2000);
	gpiod_set_value_cansleep(ctx->reset_gpio, 1);
	usleep_range(1000, 2000);
	gpiod_set_value_cansleep(ctx->reset_gpio, 0);
	usleep_range(10000, 11000);
}

static int l590nt06_init_sequence(struct mipi_dsi_multi_context *dsi_ctx)
{
	mipi_dsi_dcs_exit_sleep_mode_multi(dsi_ctx);
	mipi_dsi_usleep_range(dsi_ctx, 10000, 11000);

	mipi_dsi_dcs_set_column_address_multi(dsi_ctx, 0x0000, 0x0437);
	mipi_dsi_usleep_range(dsi_ctx, 10000, 11000);

	mipi_dsi_dcs_set_page_address_multi(dsi_ctx, 0x0000, 0x0800 | 0x006f);
	mipi_dsi_usleep_range(dsi_ctx, 10000, 11000);

	mipi_dsi_dcs_set_tear_on_multi(dsi_ctx, MIPI_DSI_DCS_TEAR_MODE_VBLANK);
	mipi_dsi_usleep_range(dsi_ctx, 10000, 11000);

	mipi_dsi_dcs_write_seq_multi(dsi_ctx, MIPI_DCS_WRITE_CONTROL_DISPLAY,
				     0x20);
	mipi_dsi_usleep_range(dsi_ctx, 10000, 11000);

	mipi_dsi_dcs_write_seq_multi(dsi_ctx, MIPI_DCS_SET_DISPLAY_BRIGHTNESS,
				     0x00, 0x00);
	mipi_dsi_usleep_range(dsi_ctx, 10000, 11000);

	mipi_dsi_dcs_write_seq_multi(dsi_ctx, MIPI_DCS_WRITE_POWER_SAVE, 0x00);
	mipi_dsi_usleep_range(dsi_ctx, 10000, 11000);

	/* Unlock Samsung vendor registers */
	ea8074_test_key_on_lvl2(dsi_ctx);
	mipi_dsi_usleep_range(dsi_ctx, 10000, 11000);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb0, 0x06);
	mipi_dsi_usleep_range(dsi_ctx, 10000, 11000);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xef, 0x35);
	mipi_dsi_usleep_range(dsi_ctx, 10000, 11000);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xcc, 0x55, 0x12);
	mipi_dsi_usleep_range(dsi_ctx, 10000, 11000);

	ea8074_test_key_on_lvl3(dsi_ctx);
	mipi_dsi_usleep_range(dsi_ctx, 10000, 11000);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb0, 0x01);
	mipi_dsi_usleep_range(dsi_ctx, 10000, 11000);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xd2, 0x20);
	mipi_dsi_usleep_range(dsi_ctx, 10000, 11000);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb0, 0x05);
	mipi_dsi_usleep_range(dsi_ctx, 10000, 11000);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xd2, 0x40);
	mipi_dsi_usleep_range(dsi_ctx, 10000, 11000);
	ea8074_test_key_off_lvl3(dsi_ctx);
	mipi_dsi_usleep_range(dsi_ctx, 10000, 11000);

	ea8074_test_key_off_lvl2(dsi_ctx);
	mipi_dsi_msleep(dsi_ctx, 110);

	mipi_dsi_dcs_write_seq_multi(dsi_ctx, MIPI_DCS_WRITE_MEMORY_START);
	mipi_dsi_usleep_range(dsi_ctx, 10000, 11000);

	mipi_dsi_dcs_set_display_on_multi(dsi_ctx);
	mipi_dsi_usleep_range(dsi_ctx, 10000, 11000);

	/* Post display-on vendor configuration */
	ea8074_test_key_on_lvl2(dsi_ctx);
	mipi_dsi_usleep_range(dsi_ctx, 10000, 11000);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb0, 0x05);
	mipi_dsi_usleep_range(dsi_ctx, 10000, 11000);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb1, 0x40);
	mipi_dsi_usleep_range(dsi_ctx, 10000, 11000);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb0, 0x03);
	mipi_dsi_usleep_range(dsi_ctx, 10000, 11000);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb6, 0xa2);
	mipi_dsi_usleep_range(dsi_ctx, 10000, 11000);
	ea8074_test_key_off_lvl2(dsi_ctx);
	mipi_dsi_usleep_range(dsi_ctx, 10000, 11000);

	return dsi_ctx->accum_err;
}

static int ams621rc_init_sequence(struct mipi_dsi_multi_context *dsi_ctx)
{
	mipi_dsi_dcs_exit_sleep_mode_multi(dsi_ctx);
	mipi_dsi_usleep_range(dsi_ctx, 10000, 11000);

	mipi_dsi_dcs_set_page_address_multi(dsi_ctx, 0x0000, 0x0800 | 0x00c7);
	mipi_dsi_usleep_range(dsi_ctx, 10000, 11000);

	ea8074_test_key_on_lvl2(dsi_ctx);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xef, 0xf0, 0x31, 0x00, 0x33, 0x31, 0x14, 0x35);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb0, 0x01);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xbb, 0x03);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb0, 0x4f);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xcb, 0x00);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb0, 0x6b);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xcb, 0x00);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xf7, 0x03);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb0, 0x05);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb1, 0x10);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb0, 0x02);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xd5, 0x02, 0x17, 0x54, 0x14);
	ea8074_test_key_off_lvl2(dsi_ctx);

	ea8074_test_key_on_lvl2(dsi_ctx);
	ea8074_test_key_on_lvl3(dsi_ctx);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xd2, 0x9f, 0xf0);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb0, 0x0e);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xd2, 0x70);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xb0, 0x04);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, 0xd2, 0x20);
	ea8074_test_key_off_lvl2(dsi_ctx);
	ea8074_test_key_off_lvl3(dsi_ctx);

	mipi_dsi_dcs_set_tear_on_multi(dsi_ctx, MIPI_DSI_DCS_TEAR_MODE_VBLANK);

	mipi_dsi_dcs_write_seq_multi(dsi_ctx, MIPI_DCS_WRITE_CONTROL_DISPLAY, 0x20);
	mipi_dsi_dcs_write_seq_multi(dsi_ctx, MIPI_DCS_WRITE_POWER_SAVE, 0x00);
	mipi_dsi_msleep(dsi_ctx, 110);

	return dsi_ctx->accum_err;
}

static int samsung_ea8074_enable(struct drm_panel *panel)
{
	struct samsung_ea8074 *ctx = to_samsung_ea8074(panel);
	struct mipi_dsi_multi_context dsi_ctx = { .dsi = ctx->dsi };

	mipi_dsi_dcs_set_display_on_multi(&dsi_ctx);
	mipi_dsi_msleep(&dsi_ctx, 120);

	return dsi_ctx.accum_err;
}

static int samsung_ea8074_disable(struct drm_panel *panel)
{
	struct samsung_ea8074 *ctx = to_samsung_ea8074(panel);
	struct mipi_dsi_multi_context dsi_ctx = { .dsi = ctx->dsi };

	mipi_dsi_dcs_set_display_off_multi(&dsi_ctx);
	mipi_dsi_usleep_range(&dsi_ctx, 17000, 18000);

	mipi_dsi_dcs_enter_sleep_mode_multi(&dsi_ctx);
	mipi_dsi_msleep(&dsi_ctx, 120);

	return dsi_ctx.accum_err;
}

static int samsung_ea8074_prepare(struct drm_panel *panel)
{
	struct samsung_ea8074 *ctx = to_samsung_ea8074(panel);
	struct mipi_dsi_multi_context dsi_ctx = { .dsi = ctx->dsi };
	int ret;

	ret = regulator_bulk_enable(ARRAY_SIZE(ea8074_supplies), ctx->supplies);
	if (ret < 0)
		return ret;

	samsung_ea8074_reset(ctx);

	ret = ctx->desc->init_sequence(&dsi_ctx);
	if (ret < 0) {
		gpiod_set_value_cansleep(ctx->reset_gpio, 1);
		regulator_bulk_disable(ARRAY_SIZE(ea8074_supplies), ctx->supplies);
		return ret;
	}

	return 0;
}

static int samsung_ea8074_unprepare(struct drm_panel *panel)
{
	struct samsung_ea8074 *ctx = to_samsung_ea8074(panel);

	gpiod_set_value_cansleep(ctx->reset_gpio, 1);
	regulator_bulk_disable(ARRAY_SIZE(ea8074_supplies), ctx->supplies);

	return 0;
}

static int samsung_ea8074_get_modes(struct drm_panel *panel,
					 struct drm_connector *connector)
{
	struct samsung_ea8074 *ctx = to_samsung_ea8074(panel);

	return drm_connector_helper_get_modes_fixed(connector, ctx->desc->mode);
}

static const struct drm_panel_funcs samsung_ea8074_panel_funcs = {
	.enable = samsung_ea8074_enable,
	.prepare = samsung_ea8074_prepare,
	.disable = samsung_ea8074_disable,
	.unprepare = samsung_ea8074_unprepare,
	.get_modes = samsung_ea8074_get_modes,
};

static int samsung_ea8074_bl_update_status(struct backlight_device *bl)
{
	struct mipi_dsi_device *dsi = bl_get_data(bl);
	u16 brightness = backlight_get_brightness(bl);
	int err;

	dsi->mode_flags &= ~MIPI_DSI_MODE_LPM;

	err = mipi_dsi_dcs_set_display_brightness_large(dsi, brightness);
	if (err < 0)
		return err;

	dsi->mode_flags |= MIPI_DSI_MODE_LPM;

	return 0;
}

static const struct backlight_ops samsung_ea8074_bl_ops = {
	.update_status = samsung_ea8074_bl_update_status,
};

static struct backlight_device *
samsung_ea8074_create_backlight(struct mipi_dsi_device *dsi)
{
	struct device *dev = &dsi->dev;
	const struct backlight_properties props = {
		.type = BACKLIGHT_RAW,
		.brightness = 512,
		.max_brightness = 1023,
	};

	return devm_backlight_device_register(dev, dev_name(dev), dev, dsi,
					      &samsung_ea8074_bl_ops, &props);
}

static int samsung_ea8074_probe(struct mipi_dsi_device *dsi)
{
	struct device *dev = &dsi->dev;
	struct samsung_ea8074 *ctx;
	int ret;

	ctx = devm_drm_panel_alloc(dev, struct samsung_ea8074, panel,
				   &samsung_ea8074_panel_funcs,
				   DRM_MODE_CONNECTOR_DSI);
	if (IS_ERR(ctx))
		return PTR_ERR(ctx);

	ret = devm_regulator_bulk_get_const(dev,
					    ARRAY_SIZE(ea8074_supplies),
					    ea8074_supplies,
					    &ctx->supplies);
	if (ret < 0)
		return dev_err_probe(dev, ret, "Failed to get regulators\n");

	ctx->reset_gpio = devm_gpiod_get(dev, "reset", GPIOD_OUT_LOW);
	if (IS_ERR(ctx->reset_gpio))
		return dev_err_probe(dev, PTR_ERR(ctx->reset_gpio),
				     "Failed to get reset-gpios\n");

	mipi_dsi_set_drvdata(dsi, ctx);

	ctx->dsi = dsi;
	ctx->desc = of_device_get_match_data(dev);

	dsi->lanes = 4;
	dsi->format = MIPI_DSI_FMT_RGB888;
	dsi->mode_flags = MIPI_DSI_CLOCK_NON_CONTINUOUS | MIPI_DSI_MODE_LPM;

	ctx->panel.prepare_prev_first = true;

	ctx->panel.backlight = samsung_ea8074_create_backlight(dsi);
	if (IS_ERR(ctx->panel.backlight))
		return dev_err_probe(dev, PTR_ERR(ctx->panel.backlight),
				     "Failed to create backlight\n");

	drm_panel_add(&ctx->panel);

	ret = mipi_dsi_attach(dsi);
	if (ret < 0) {
		dev_err(dev, "Failed to attach to DSI host: %d\n", ret);
		drm_panel_remove(&ctx->panel);
		return ret;
	}

	return 0;
}

static void samsung_ea8074_remove(struct mipi_dsi_device *dsi)
{
	struct samsung_ea8074 *ctx = mipi_dsi_get_drvdata(dsi);
	int ret;

	ret = mipi_dsi_detach(dsi);
	if (ret < 0)
		dev_err(&dsi->dev, "Failed to detach from DSI host: %d\n", ret);

	drm_panel_remove(&ctx->panel);
}

static const struct drm_display_mode l590nt06_mode = {
	.clock = (1080 + 48 + 16 + 48) * (2160 + 20 + 12 + 28) * 60 / 1000,
	.hdisplay = 1080,
	.hsync_start = 1080 + 48,
	.hsync_end = 1080 + 48 + 16,
	.htotal = 1080 + 48 + 16 + 48,
	.vdisplay = 2160,
	.vsync_start = 2160 + 20,
	.vsync_end = 2160 + 20 + 12,
	.vtotal = 2160 + 20 + 12 + 28,
	.width_mm = 68,
	.height_mm = 137,
	.type = DRM_MODE_TYPE_DRIVER | DRM_MODE_TYPE_PREFERRED,
};

static const struct drm_display_mode ams621rc_mode = {
	.clock = (1080 + 56 + 18 + 56) * (2248 + 26 + 12 + 24) * 60 / 1000,
	.hdisplay = 1080,
	.hsync_start = 1080 + 56,
	.hsync_end = 1080 + 56 + 18,
	.htotal = 1080 + 56 + 18 + 56,
	.vdisplay = 2248,
	.vsync_start = 2248 + 26,
	.vsync_end = 2248 + 26 + 12,
	.vtotal = 2248 + 26 + 12 + 24,
	.width_mm = 68,
	.height_mm = 142,
	.type = DRM_MODE_TYPE_DRIVER | DRM_MODE_TYPE_PREFERRED,
};

const struct samsung_ea8074_panel_desc l590nt06_display_desc = {
	.mode = &l590nt06_mode,
	.init_sequence = l590nt06_init_sequence,
};

const struct samsung_ea8074_panel_desc ams621rc_display_desc = {
	.mode = &ams621rc_mode,
	.init_sequence = ams621rc_init_sequence,
};

static const struct of_device_id samsung_ea8074_of_match[] = {
	/* Comma three */
	{ .compatible = "samsung,ea8074-l590nt06", .data = &l590nt06_display_desc },
	 /* Huawei Mate 10 Pro */
	{ .compatible = "samsung,ea8074-ams601nt01", .data = &l590nt06_display_desc },
	/* Xiaomi Mi 8 */
	{ .compatible = "samsung,ea8074-ams621rc", .data = &ams621rc_display_desc },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, samsung_ea8074_of_match);

static struct mipi_dsi_driver samsung_ea8074_driver = {
	.probe = samsung_ea8074_probe,
	.remove = samsung_ea8074_remove,
	.driver = {
		.name = "panel-samsung-ea8074",
		.of_match_table = samsung_ea8074_of_match,
	},
};
module_mipi_dsi_driver(samsung_ea8074_driver);

MODULE_AUTHOR("David Heidelberg <david@ixit.cz>");
MODULE_DESCRIPTION("DRM driver for the Samsung EA8074 panel");
MODULE_LICENSE("GPL");
