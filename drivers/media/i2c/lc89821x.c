// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright Vasiliy Doylov <nekocwd@altlinux.org>

#include <linux/bits.h>
#include <linux/delay.h>
#include <linux/i2c.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/pm_runtime.h>
#include <linux/regulator/consumer.h>
#include <media/v4l2-cci.h>
#include <media/v4l2-ctrls.h>
#include <media/v4l2-subdev.h>

#define LC89821X_FOCUS_STEPS 1
#define LC89821X_DAC_ADDR CCI_REG16(0x84)

/* Wake up sequence of the models equipped with an EEPROM */
#define LC89821X_ID_ADDR CCI_REG8(0xf0)
#define LC89821X_ID_VAL 0xa5
#define LC89821X_STANDBY_ADDR CCI_REG8(0x81)
#define LC89821X_STANDBY_RELEASE 0x80
#define LC89821X_DOWNLOAD_ADDR CCI_REG8(0xe0)
#define LC89821X_DOWNLOAD_START 0x01
#define LC89821X_STATUS_ADDR CCI_REG8(0xb3)
#define LC89821X_STATUS_BUSY GENMASK(7, 5)
#define LC89821X_DOWNLOAD_RETRIES 10

/*
 * The LC89821x are closed loop auto focus controllers: the value written to
 * LC89821X_DAC_ADDR is a target hall sensor position, so the usable range
 * follows the width of the built in A/D converter and differs per model.
 */
struct lc89821x_chip {
	u16 focus_pos_max;
	/* Position is a two's complement offset from the centre of the range */
	bool signed_pos;
	/* Calibration data has to be loaded from the EEPROM after power on */
	bool needs_wakeup;
};

static const char *const lc89821x_supply_names[] = {
	"vdd",
};

struct lc89821x {
	struct device *dev;
	const struct lc89821x_chip *chip;
	struct regulator_bulk_data supplies[ARRAY_SIZE(lc89821x_supply_names)];
	struct v4l2_ctrl_handler ctrls;
	struct v4l2_subdev sd;
	struct regmap *regmap;
};

static inline struct lc89821x *sd_to_lc89821x(struct v4l2_subdev *subdev)
{
	return container_of(subdev, struct lc89821x, sd);
}

static int lc89821x_set_dac(struct lc89821x *lc89821x, u16 val)
{
	const struct lc89821x_chip *chip = lc89821x->chip;
	int ret;

	/*
	 * Positive targets move the lens towards macro, like
	 * V4L2_CID_FOCUS_ABSOLUTE, so map the control range straight onto
	 * the two's complement offset from the centre. The usable window is
	 * a per module calibration matter left to userspace, as for the
	 * other chip.
	 */
	if (chip->signed_pos)
		val = (val - (chip->focus_pos_max + 1) / 2) & chip->focus_pos_max;

	ret = cci_write(lc89821x->regmap, LC89821X_DAC_ADDR, val, NULL);
	if (ret)
		dev_err(lc89821x->dev, "failed to set DAC: %d\n", ret);

	return ret;
}

/*
 * Load the calibration data from the on chip EEPROM into RAM. The vendor
 * driver additionally enables lens temperature correction here, but only
 * after seeding the reference temperature registers from a live reading,
 * scaled by gain bits stored on a second I2C address. That is not
 * implemented, so the correction is left disabled.
 */
static int lc89821x_wakeup(struct lc89821x *lc89821x)
{
	unsigned int i;
	int ret = 0;
	u64 val;

	ret = cci_read(lc89821x->regmap, LC89821X_ID_ADDR, &val, NULL);
	if (ret)
		return ret;

	if (val != LC89821X_ID_VAL) {
		dev_err(lc89821x->dev, "unexpected chip id 0x%llx\n", val);
		return -ENODEV;
	}

	fsleep(1000);

	cci_write(lc89821x->regmap, LC89821X_STANDBY_ADDR,
		  LC89821X_STANDBY_RELEASE, &ret);
	fsleep(1000);
	cci_write(lc89821x->regmap, LC89821X_DOWNLOAD_ADDR,
		  LC89821X_DOWNLOAD_START, &ret);
	if (ret)
		return ret;

	fsleep(8000);

	for (i = 0; i < LC89821X_DOWNLOAD_RETRIES; i++) {
		ret = cci_read(lc89821x->regmap, LC89821X_STATUS_ADDR, &val,
			       NULL);
		if (ret)
			return ret;

		if (!(val & LC89821X_STATUS_BUSY))
			return 0;

		fsleep(1000);
	}

	dev_err(lc89821x->dev, "timed out loading the calibration data\n");

	return -ETIMEDOUT;
}

static int lc89821x_power_off(struct lc89821x *lc89821x)
{
	regulator_bulk_disable(ARRAY_SIZE(lc89821x_supply_names),
			       lc89821x->supplies);
	return 0;
}

static int lc89821x_power_on(struct lc89821x *lc89821x)
{
	int ret;

	ret = regulator_bulk_enable(ARRAY_SIZE(lc89821x_supply_names),
				    lc89821x->supplies);
	if (ret < 0)
		return ret;

	fsleep(10000);

	if (lc89821x->chip->needs_wakeup) {
		ret = lc89821x_wakeup(lc89821x);
		if (ret) {
			lc89821x_power_off(lc89821x);
			return ret;
		}
	}

	return 0;
}

static int __maybe_unused lc89821x_runtime_suspend(struct device *dev)
{
	struct v4l2_subdev *sd = dev_get_drvdata(dev);
	struct lc89821x *lc89821x = sd_to_lc89821x(sd);

	lc89821x_power_off(lc89821x);
	return 0;
}

static int __maybe_unused lc89821x_runtime_resume(struct device *dev)
{
	struct v4l2_subdev *sd = dev_get_drvdata(dev);
	struct lc89821x *lc89821x = sd_to_lc89821x(sd);
	int ret;

	ret = lc89821x_power_on(lc89821x);
	if (ret < 0) {
		dev_err(dev, "failed to enable regulators\n");
		return ret;
	}

	__v4l2_ctrl_handler_setup(&lc89821x->ctrls);

	return ret;
}

static int lc89821x_set_ctrl(struct v4l2_ctrl *ctrl)
{
	struct lc89821x *lc89821x =
		container_of(ctrl->handler, struct lc89821x, ctrls);

	if (ctrl->id == V4L2_CID_FOCUS_ABSOLUTE)
		return lc89821x_set_dac(lc89821x, ctrl->val);

	return 0;
}

static const struct v4l2_ctrl_ops lc89821x_ctrl_ops = {
	.s_ctrl = lc89821x_set_ctrl,
};

static int lc89821x_open(struct v4l2_subdev *sd, struct v4l2_subdev_fh *fh)
{
	return pm_runtime_resume_and_get(sd->dev);
}

static int lc89821x_close(struct v4l2_subdev *sd, struct v4l2_subdev_fh *fh)
{
	pm_runtime_put_autosuspend(sd->dev);

	return 0;
}

static const struct v4l2_subdev_internal_ops lc89821x_int_ops = {
	.open = lc89821x_open,
	.close = lc89821x_close,
};

static const struct v4l2_subdev_core_ops lc89821x_core_ops = {
	.log_status = v4l2_ctrl_subdev_log_status,
};

static const struct v4l2_subdev_ops lc89821x_ops = {
	.core = &lc89821x_core_ops,
};

static int lc89821x_init_controls(struct lc89821x *lc89821x)
{
	struct v4l2_ctrl_handler *hdl = &lc89821x->ctrls;
	const struct v4l2_ctrl_ops *ops = &lc89821x_ctrl_ops;

	v4l2_ctrl_handler_init(hdl, 1);

	/*
	 * A closed loop controller drives full current at an unreachable
	 * target, so rest the signed chips mid stroke rather than against
	 * the infinity stop.
	 */
	v4l2_ctrl_new_std(hdl, ops, V4L2_CID_FOCUS_ABSOLUTE, 0,
			  lc89821x->chip->focus_pos_max, LC89821X_FOCUS_STEPS,
			  lc89821x->chip->signed_pos ?
			  (lc89821x->chip->focus_pos_max + 1) / 2 : 0);

	if (hdl->error)
		return hdl->error;

	lc89821x->sd.ctrl_handler = hdl;

	return 0;
}

static int lc89821x_probe(struct i2c_client *client)
{
	struct lc89821x *lc89821x;
	unsigned int i;
	int ret;

	lc89821x = devm_kzalloc(&client->dev, sizeof(*lc89821x), GFP_KERNEL);
	if (!lc89821x)
		return -ENOMEM;

	lc89821x->dev = &client->dev;

	lc89821x->chip = i2c_get_match_data(client);
	if (!lc89821x->chip)
		return -ENODEV;

	lc89821x->regmap = devm_cci_regmap_init_i2c(client, 8);
	if (IS_ERR(lc89821x->regmap))
		return dev_err_probe(lc89821x->dev, PTR_ERR(lc89821x->regmap),
				     "failed to initialize CCI\n");

	/* Initialize subdev */
	v4l2_i2c_subdev_init(&lc89821x->sd, client, &lc89821x_ops);

	for (i = 0; i < ARRAY_SIZE(lc89821x_supply_names); i++)
		lc89821x->supplies[i].supply = lc89821x_supply_names[i];

	ret = devm_regulator_bulk_get(lc89821x->dev,
				      ARRAY_SIZE(lc89821x_supply_names),
				      lc89821x->supplies);
	if (ret)
		return dev_err_probe(lc89821x->dev, ret,
				     "failed to get regulators\n");

	ret = lc89821x_init_controls(lc89821x);
	if (ret) {
		dev_err_probe(lc89821x->dev, ret,
			      "failed to init v4l2 controls\n");
		goto err_free_handler;
	}

	/* Initialize subdev */
	lc89821x->sd.flags |= V4L2_SUBDEV_FL_HAS_DEVNODE;
	lc89821x->sd.internal_ops = &lc89821x_int_ops;

	ret = media_entity_pads_init(&lc89821x->sd.entity, 0, NULL);
	if (ret < 0) {
		dev_err_probe(lc89821x->dev, ret,
			      "failed to init media entity pads");
		goto err_free_handler;
	}

	lc89821x->sd.entity.function = MEDIA_ENT_F_LENS;

	pm_runtime_enable(lc89821x->dev);

	ret = v4l2_async_register_subdev(&lc89821x->sd);
	if (ret < 0) {
		dev_err_probe(lc89821x->dev, ret,
			      "failed to register V4L2 subdev\n");
		goto err_pm;
	}

	pm_runtime_idle(lc89821x->dev);

	return 0;

err_pm:
	pm_runtime_disable(lc89821x->dev);
	media_entity_cleanup(&lc89821x->sd.entity);
err_free_handler:
	v4l2_ctrl_handler_free(&lc89821x->ctrls);

	return ret;
}

static void lc89821x_remove(struct i2c_client *client)
{
	struct v4l2_subdev *sd = i2c_get_clientdata(client);
	struct lc89821x *lc89821x = sd_to_lc89821x(sd);
	struct device *dev = &client->dev;

	v4l2_async_unregister_subdev(&lc89821x->sd);
	v4l2_ctrl_handler_free(&lc89821x->ctrls);
	media_entity_cleanup(&lc89821x->sd.entity);

	/*
	 * Disable runtime PM. In case runtime PM is disabled in the kernel,
	 * make sure to turn power off manually.
	 */
	pm_runtime_disable(dev);
	if (!pm_runtime_status_suspended(dev))
		lc89821x_power_off(lc89821x);
	pm_runtime_set_suspended(dev);
}

static const struct lc89821x_chip lc898217xc_chip = {
	/* 11 bit A/D converter */
	.focus_pos_max = 2047,
};

static const struct lc89821x_chip lc898219xi_chip = {
	/* 12 bit A/D converter */
	.focus_pos_max = 4095,
	.signed_pos = true,
	.needs_wakeup = true,
};

static const struct of_device_id lc89821x_of_table[] = {
	{ .compatible = "onnn,lc898217xc", .data = &lc898217xc_chip },
	{ .compatible = "onnn,lc898219xi", .data = &lc898219xi_chip },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, lc89821x_of_table);

static const struct dev_pm_ops lc89821x_pm_ops = {
	SET_RUNTIME_PM_OPS(lc89821x_runtime_suspend, lc89821x_runtime_resume,
			   NULL)
};

static struct i2c_driver lc89821x_i2c_driver = {
	.driver = {
		.name = "lc89821x",
		.pm = &lc89821x_pm_ops,
		.of_match_table = lc89821x_of_table,
	},
	.probe = lc89821x_probe,
	.remove = lc89821x_remove,
};
module_i2c_driver(lc89821x_i2c_driver);

MODULE_AUTHOR("Vasiliy Doylov <nekocwd@mainlining.org>");
MODULE_AUTHOR("Frieder Hannenheim <git@fhannenheim.net>");
MODULE_DESCRIPTION("Onsemi LC89821X VCM driver");
MODULE_LICENSE("GPL");
