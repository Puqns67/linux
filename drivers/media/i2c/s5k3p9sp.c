// SPDX-License-Identifier: GPL-2.0-only
// Copyright David Heidelberg

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/gpio/consumer.h>
#include <linux/i2c.h>
#include <linux/module.h>
#include <linux/pm_runtime.h>
#include <linux/regulator/consumer.h>
#include <linux/units.h>
#include <media/v4l2-cci.h>
#include <media/v4l2-ctrls.h>
#include <media/v4l2-device.h>
#include <media/v4l2-fwnode.h>

#include "ccs/ccs-regs.h"
#include "s5k3p9sp_regs.h"

#define S5K3P9SP_LINK_FREQ_700MHZ	(700ULL * HZ_PER_MHZ)
#define S5K3P9SP_MCLK_FREQ_24MHZ	(24 * HZ_PER_MHZ)
#define S5K3P9SP_DATA_LANES		4

/* Register map follows the MIPI CCS compliant camera sensor layout */
#define S5K3P9SP_CHIP_ID		0x3109

#define S5K3P9SP_EXPOSURE_MIN		3
#define S5K3P9SP_EXPOSURE_STEP		1
#define S5K3P9SP_EXPOSURE_MARGIN	3

#define S5K3P9SP_AGAIN_MIN		1
#define S5K3P9SP_AGAIN_MAX		16
#define S5K3P9SP_AGAIN_STEP		1
#define S5K3P9SP_AGAIN_DEFAULT		6
#define S5K3P9SP_AGAIN_SHIFT		5

#define S5K3P9SP_VTS_MAX		0xffff

#define to_s5k3p9sp(_sd)		container_of(_sd, struct s5k3p9sp, sd)

static const s64 s5k3p9sp_link_freq_menu[] = {
	S5K3P9SP_LINK_FREQ_700MHZ,
};

/* Supported formats to cover horizontal and vertical flip controls */
static const u32 s5k3p9sp_mbus_formats[] = {
	MEDIA_BUS_FMT_SGRBG10_1X10,	MEDIA_BUS_FMT_SRGGB10_1X10,
	MEDIA_BUS_FMT_SBGGR10_1X10,	MEDIA_BUS_FMT_SGBRG10_1X10,
};

struct s5k3p9sp_reg_list {
	const struct cci_reg_sequence *regs;
	unsigned int num_regs;
};

struct s5k3p9sp_mode {
	u32 width;			/* Frame width in pixels */
	u32 height;			/* Frame height in pixels */
	u32 hts;			/* Horizontal timing size */
	u32 vts;			/* Default vertical timing size */
	u32 exposure;			/* Default exposure value */

	const struct s5k3p9sp_reg_list reg_list;	/* Sensor register setting */
};

static const struct s5k3p9sp_mode s5k3p9sp_supported_modes[] = {
	{
		.width = 4608,
		.height = 3456,
		.hts = 5088,
		.vts = 3668,
		.exposure = S5K3P9SP_MODE_DEFAULT_EXPOSURE,
		.reg_list = {
			.regs = s5k3p9sp_mode_4608x3456_settings,
			.num_regs = ARRAY_SIZE(s5k3p9sp_mode_4608x3456_settings),
		},
	},
	{
		.width = 2304,
		.height = 1728,
		.hts = 10036,
		.vts = 1859,
		.exposure = S5K3P9SP_MODE_DEFAULT_EXPOSURE,
		.reg_list = {
			.regs = s5k3p9sp_mode_2304x1728_settings,
			.num_regs = ARRAY_SIZE(s5k3p9sp_mode_2304x1728_settings),
		},
	},
};

static const char * const s5k3p9sp_test_pattern_menu[] = {
	"Disabled",
	"Solid colour",
	"Colour bars",
	"Fade to grey colour bars",
	"PN9",
};

static const char * const s5k3p9sp_supply_names[] = {
	"vana",		/* Analog power */
	"vdig",		/* Digital core power */
	"vio",		/* Digital I/O power */
};

#define S5K3P9SP_NUM_SUPPLIES	ARRAY_SIZE(s5k3p9sp_supply_names)

struct s5k3p9sp {
	struct device *dev;
	struct regmap *regmap;
	struct clk *mclk;
	struct gpio_desc *reset_gpio;
	struct regulator_bulk_data supplies[S5K3P9SP_NUM_SUPPLIES];

	struct v4l2_subdev sd;
	struct media_pad pad;

	struct v4l2_ctrl_handler ctrl_handler;
	struct v4l2_ctrl *link_freq;
	struct v4l2_ctrl *pixel_rate;
	struct v4l2_ctrl *hblank;
	struct v4l2_ctrl *vblank;
	struct v4l2_ctrl *exposure;
	struct v4l2_ctrl *vflip;
	struct v4l2_ctrl *hflip;

	const struct s5k3p9sp_mode *mode;
};

static int s5k3p9sp_set_ctrl(struct v4l2_ctrl *ctrl)
{
	struct s5k3p9sp *s5k3p9sp = container_of(ctrl->handler, struct s5k3p9sp,
						 ctrl_handler);
	const struct s5k3p9sp_mode *mode = s5k3p9sp->mode;
	s64 exposure_max;
	int ret;

	/* Propagate change of current control to all related controls */
	switch (ctrl->id) {
	case V4L2_CID_VBLANK:
		/* Update max exposure while meeting expected vblanking */
		exposure_max = mode->height + ctrl->val - S5K3P9SP_EXPOSURE_MARGIN;
		__v4l2_ctrl_modify_range(s5k3p9sp->exposure,
					 s5k3p9sp->exposure->minimum,
					 exposure_max,
					 s5k3p9sp->exposure->step,
					 s5k3p9sp->exposure->default_value);
		break;
	}

	/* V4L2 controls are applied, when sensor is powered up for streaming */
	if (!pm_runtime_get_if_active(s5k3p9sp->dev))
		return 0;

	switch (ctrl->id) {
	case V4L2_CID_ANALOGUE_GAIN:
		ret = cci_write(s5k3p9sp->regmap, CCS_R_ANALOG_GAIN_CODE_GLOBAL,
				ctrl->val << S5K3P9SP_AGAIN_SHIFT, NULL);
		break;
	case V4L2_CID_EXPOSURE:
		ret = cci_write(s5k3p9sp->regmap, CCS_R_COARSE_INTEGRATION_TIME,
				ctrl->val, NULL);
		break;
	case V4L2_CID_VBLANK:
		ret = cci_write(s5k3p9sp->regmap, CCS_R_FRAME_LENGTH_LINES,
				ctrl->val + mode->height, NULL);
		break;
	case V4L2_CID_VFLIP:
	case V4L2_CID_HFLIP:
		ret = cci_write(s5k3p9sp->regmap, CCS_R_IMAGE_ORIENTATION,
				(s5k3p9sp->vflip->val ?
				 CCS_IMAGE_ORIENTATION_VERTICAL_FLIP : 0) |
				(s5k3p9sp->hflip->val ?
				 CCS_IMAGE_ORIENTATION_HORIZONTAL_MIRROR : 0),
				NULL);
		break;
	case V4L2_CID_TEST_PATTERN:
		ret = cci_write(s5k3p9sp->regmap, CCS_R_TEST_PATTERN_MODE,
				ctrl->val, NULL);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	pm_runtime_put(s5k3p9sp->dev);

	return ret;
}

static const struct v4l2_ctrl_ops s5k3p9sp_ctrl_ops = {
	.s_ctrl = s5k3p9sp_set_ctrl,
};

static inline u64 s5k3p9sp_freq_to_pixel_rate(const u64 freq)
{
	return div_u64(freq * 2 * S5K3P9SP_DATA_LANES, 10);
}

static int s5k3p9sp_init_controls(struct s5k3p9sp *s5k3p9sp)
{
	struct v4l2_ctrl_handler *ctrl_hdlr = &s5k3p9sp->ctrl_handler;
	const struct s5k3p9sp_mode *mode = s5k3p9sp->mode;
	s64 pixel_rate, hblank, vblank, exposure_max;
	struct v4l2_fwnode_device_properties props;
	int ret;

	v4l2_ctrl_handler_init(ctrl_hdlr, 9);

	s5k3p9sp->link_freq = v4l2_ctrl_new_int_menu(ctrl_hdlr,
					&s5k3p9sp_ctrl_ops,
					V4L2_CID_LINK_FREQ,
					ARRAY_SIZE(s5k3p9sp_link_freq_menu) - 1,
					0, s5k3p9sp_link_freq_menu);
	if (s5k3p9sp->link_freq)
		s5k3p9sp->link_freq->flags |= V4L2_CTRL_FLAG_READ_ONLY;

	pixel_rate = s5k3p9sp_freq_to_pixel_rate(s5k3p9sp_link_freq_menu[0]);
	s5k3p9sp->pixel_rate = v4l2_ctrl_new_std(ctrl_hdlr, &s5k3p9sp_ctrl_ops,
					       V4L2_CID_PIXEL_RATE,
					       0, pixel_rate, 1, pixel_rate);

	hblank = mode->hts - mode->width;
	s5k3p9sp->hblank = v4l2_ctrl_new_std(ctrl_hdlr, &s5k3p9sp_ctrl_ops,
					   V4L2_CID_HBLANK, hblank,
					   hblank, 1, hblank);
	if (s5k3p9sp->hblank)
		s5k3p9sp->hblank->flags |= V4L2_CTRL_FLAG_READ_ONLY;

	vblank = mode->vts - mode->height;
	s5k3p9sp->vblank = v4l2_ctrl_new_std(ctrl_hdlr, &s5k3p9sp_ctrl_ops,
					   V4L2_CID_VBLANK, vblank,
					   S5K3P9SP_VTS_MAX - mode->height, 1,
					   vblank);

	v4l2_ctrl_new_std(ctrl_hdlr, &s5k3p9sp_ctrl_ops, V4L2_CID_ANALOGUE_GAIN,
			  S5K3P9SP_AGAIN_MIN, S5K3P9SP_AGAIN_MAX,
			  S5K3P9SP_AGAIN_STEP, S5K3P9SP_AGAIN_DEFAULT);

	exposure_max = mode->vts - S5K3P9SP_EXPOSURE_MARGIN;
	s5k3p9sp->exposure = v4l2_ctrl_new_std(ctrl_hdlr, &s5k3p9sp_ctrl_ops,
					     V4L2_CID_EXPOSURE,
					     S5K3P9SP_EXPOSURE_MIN,
					     exposure_max,
					     S5K3P9SP_EXPOSURE_STEP,
					     mode->exposure);

	v4l2_ctrl_new_std_menu_items(ctrl_hdlr, &s5k3p9sp_ctrl_ops,
				     V4L2_CID_TEST_PATTERN,
				     ARRAY_SIZE(s5k3p9sp_test_pattern_menu) - 1,
				     0, 0, s5k3p9sp_test_pattern_menu);

	s5k3p9sp->hflip = v4l2_ctrl_new_std(ctrl_hdlr, &s5k3p9sp_ctrl_ops,
					  V4L2_CID_HFLIP, 0, 1, 1, 0);
	if (s5k3p9sp->hflip)
		s5k3p9sp->hflip->flags |= V4L2_CTRL_FLAG_MODIFY_LAYOUT;

	s5k3p9sp->vflip = v4l2_ctrl_new_std(ctrl_hdlr, &s5k3p9sp_ctrl_ops,
					  V4L2_CID_VFLIP, 0, 1, 1, 0);
	if (s5k3p9sp->vflip)
		s5k3p9sp->vflip->flags |= V4L2_CTRL_FLAG_MODIFY_LAYOUT;

	ret = v4l2_fwnode_device_parse(s5k3p9sp->dev, &props);
	if (ret)
		goto error_free_hdlr;

	ret = v4l2_ctrl_new_fwnode_properties(ctrl_hdlr, &s5k3p9sp_ctrl_ops,
					      &props);
	if (ret)
		goto error_free_hdlr;

	s5k3p9sp->sd.ctrl_handler = ctrl_hdlr;

	return 0;

error_free_hdlr:
	v4l2_ctrl_handler_free(ctrl_hdlr);

	return ret;
}

static int s5k3p9sp_enable_streams(struct v4l2_subdev *sd,
				 struct v4l2_subdev_state *state, u32 pad,
				 u64 streams_mask)
{
	struct s5k3p9sp *s5k3p9sp = to_s5k3p9sp(sd);
	const struct s5k3p9sp_reg_list *reg_list = &s5k3p9sp->mode->reg_list;
	int ret;

	ret = pm_runtime_resume_and_get(s5k3p9sp->dev);
	if (ret)
		return ret;

	/* Software reset, the sensor needs a few ms before accepting I2C */
	cci_write(s5k3p9sp->regmap, CCI_REG16(0x6028), 0x4000, &ret);
	cci_write(s5k3p9sp->regmap, CCI_REG16(0x6010), 0x0001, &ret);
	if (ret)
		goto error;

	usleep_range(5 * USEC_PER_MSEC, 6 * USEC_PER_MSEC);

	/* Sensor init settings (firmware upload and calibration) */
	cci_multi_reg_write(s5k3p9sp->regmap, s5k3p9sp_init_settings,
			    ARRAY_SIZE(s5k3p9sp_init_settings), &ret);

	/* Resolution specific settings */
	cci_multi_reg_write(s5k3p9sp->regmap, reg_list->regs,
			    reg_list->num_regs, &ret);
	if (ret)
		goto error;

	ret = __v4l2_ctrl_handler_setup(s5k3p9sp->sd.ctrl_handler);

	cci_write(s5k3p9sp->regmap, CCS_R_MODE_SELECT,
		  CCS_MODE_SELECT_STREAMING, &ret);
	if (ret)
		goto error;

	return 0;

error:
	dev_err(s5k3p9sp->dev, "failed to start streaming: %d\n", ret);
	pm_runtime_put_autosuspend(s5k3p9sp->dev);

	return ret;
}

static int s5k3p9sp_disable_streams(struct v4l2_subdev *sd,
				  struct v4l2_subdev_state *state, u32 pad,
				  u64 streams_mask)
{
	struct s5k3p9sp *s5k3p9sp = to_s5k3p9sp(sd);
	int ret;

	ret = cci_write(s5k3p9sp->regmap, CCS_R_MODE_SELECT,
			CCS_MODE_SELECT_SOFTWARE_STANDBY, NULL);
	if (ret)
		dev_err(s5k3p9sp->dev, "failed to stop streaming: %d\n", ret);

	pm_runtime_put_autosuspend(s5k3p9sp->dev);

	return ret;
}

static u32 s5k3p9sp_get_format_code(struct s5k3p9sp *s5k3p9sp)
{
	unsigned int i;

	i = (s5k3p9sp->vflip->val ? 2 : 0) | (s5k3p9sp->hflip->val ? 1 : 0);

	return s5k3p9sp_mbus_formats[i];
}

static void s5k3p9sp_update_pad_format(struct s5k3p9sp *s5k3p9sp,
				     const struct s5k3p9sp_mode *mode,
				     struct v4l2_mbus_framefmt *fmt)
{
	fmt->code = s5k3p9sp_get_format_code(s5k3p9sp);
	fmt->width = mode->width;
	fmt->height = mode->height;
	fmt->field = V4L2_FIELD_NONE;
	fmt->colorspace = V4L2_COLORSPACE_SRGB;
	fmt->ycbcr_enc = V4L2_YCBCR_ENC_DEFAULT;
	fmt->quantization = V4L2_QUANTIZATION_FULL_RANGE;
	fmt->xfer_func = V4L2_XFER_FUNC_NONE;
}

static int s5k3p9sp_set_pad_format(struct v4l2_subdev *sd,
				 struct v4l2_subdev_state *state,
				 struct v4l2_subdev_format *fmt)
{
	struct s5k3p9sp *s5k3p9sp = to_s5k3p9sp(sd);
	s64 hblank, vblank, exposure_max;
	const struct s5k3p9sp_mode *mode;

	mode = v4l2_find_nearest_size(s5k3p9sp_supported_modes,
				      ARRAY_SIZE(s5k3p9sp_supported_modes),
				      width, height,
				      fmt->format.width, fmt->format.height);

	s5k3p9sp_update_pad_format(s5k3p9sp, mode, &fmt->format);

	/* Format code could be updated with respect to flip controls */
	if (fmt->which == V4L2_SUBDEV_FORMAT_TRY || s5k3p9sp->mode == mode)
		goto set_format;

	/* Update limits and set FPS and exposure to default values */
	hblank = mode->hts - mode->width;
	__v4l2_ctrl_modify_range(s5k3p9sp->hblank, hblank, hblank, 1, hblank);

	vblank = mode->vts - mode->height;
	__v4l2_ctrl_modify_range(s5k3p9sp->vblank, vblank,
				 S5K3P9SP_VTS_MAX - mode->height, 1, vblank);
	__v4l2_ctrl_s_ctrl(s5k3p9sp->vblank, vblank);

	exposure_max = mode->vts - S5K3P9SP_EXPOSURE_MARGIN;
	__v4l2_ctrl_modify_range(s5k3p9sp->exposure, S5K3P9SP_EXPOSURE_MIN,
				 exposure_max, S5K3P9SP_EXPOSURE_STEP,
				 mode->exposure);
	__v4l2_ctrl_s_ctrl(s5k3p9sp->exposure, mode->exposure);

	if (s5k3p9sp->sd.ctrl_handler->error)
		return s5k3p9sp->sd.ctrl_handler->error;

	s5k3p9sp->mode = mode;

set_format:
	*v4l2_subdev_state_get_format(state, 0) = fmt->format;

	return 0;
}

static int s5k3p9sp_enum_mbus_code(struct v4l2_subdev *sd,
				 struct v4l2_subdev_state *sd_state,
				 struct v4l2_subdev_mbus_code_enum *code)
{
	struct s5k3p9sp *s5k3p9sp = to_s5k3p9sp(sd);

	/* Media bus code index is constant, but code formats are not */
	if (code->index > 0)
		return -EINVAL;

	code->code = s5k3p9sp_get_format_code(s5k3p9sp);

	return 0;
}

static int s5k3p9sp_enum_frame_size(struct v4l2_subdev *sd,
				  struct v4l2_subdev_state *sd_state,
				  struct v4l2_subdev_frame_size_enum *fse)
{
	struct s5k3p9sp *s5k3p9sp = to_s5k3p9sp(sd);

	if (fse->index >= ARRAY_SIZE(s5k3p9sp_supported_modes))
		return -EINVAL;

	if (fse->code != s5k3p9sp_get_format_code(s5k3p9sp))
		return -EINVAL;

	fse->min_width = s5k3p9sp_supported_modes[fse->index].width;
	fse->max_width = fse->min_width;
	fse->min_height = s5k3p9sp_supported_modes[fse->index].height;
	fse->max_height = fse->min_height;

	return 0;
}

static int s5k3p9sp_get_selection(struct v4l2_subdev *sd,
				struct v4l2_subdev_state *sd_state,
				struct v4l2_subdev_selection *sel)
{
	struct s5k3p9sp *s5k3p9sp = to_s5k3p9sp(sd);

	switch (sel->target) {
	case V4L2_SEL_TGT_CROP:
	case V4L2_SEL_TGT_CROP_BOUNDS:
	case V4L2_SEL_TGT_CROP_DEFAULT:
	case V4L2_SEL_TGT_NATIVE_SIZE:
		sel->r.left = 0;
		sel->r.top = 0;
		sel->r.width = s5k3p9sp->mode->width;
		sel->r.height = s5k3p9sp->mode->height;
		return 0;
	default:
		return -EINVAL;
	}
}

static int s5k3p9sp_init_state(struct v4l2_subdev *sd,
			     struct v4l2_subdev_state *state)
{
	struct s5k3p9sp *s5k3p9sp = to_s5k3p9sp(sd);
	struct v4l2_subdev_format fmt = {
		.which = V4L2_SUBDEV_FORMAT_TRY,
		.pad = 0,
		.format = {
			/* Media bus code depends on current flip controls */
			.width = s5k3p9sp->mode->width,
			.height = s5k3p9sp->mode->height,
		},
	};

	s5k3p9sp_set_pad_format(sd, state, &fmt);

	return 0;
}

static const struct v4l2_subdev_video_ops s5k3p9sp_video_ops = {
	.s_stream = v4l2_subdev_s_stream_helper,
};

static const struct v4l2_subdev_pad_ops s5k3p9sp_pad_ops = {
	.set_fmt = s5k3p9sp_set_pad_format,
	.get_fmt = v4l2_subdev_get_fmt,
	.get_selection = s5k3p9sp_get_selection,
	.enum_mbus_code = s5k3p9sp_enum_mbus_code,
	.enum_frame_size = s5k3p9sp_enum_frame_size,
	.enable_streams = s5k3p9sp_enable_streams,
	.disable_streams = s5k3p9sp_disable_streams,
};

static const struct v4l2_subdev_ops s5k3p9sp_subdev_ops = {
	.video = &s5k3p9sp_video_ops,
	.pad = &s5k3p9sp_pad_ops,
};

static const struct v4l2_subdev_internal_ops s5k3p9sp_internal_ops = {
	.init_state = s5k3p9sp_init_state,
};

static const struct media_entity_operations s5k3p9sp_subdev_entity_ops = {
	.link_validate = v4l2_subdev_link_validate,
};

static int s5k3p9sp_identify_sensor(struct s5k3p9sp *s5k3p9sp)
{
	u64 val;
	int ret;

	ret = cci_read(s5k3p9sp->regmap, CCS_R_MODULE_MODEL_ID, &val, NULL);
	if (ret) {
		dev_err(s5k3p9sp->dev, "failed to read chip id: %d\n", ret);
		return ret;
	}

	if (val != S5K3P9SP_CHIP_ID) {
		dev_err(s5k3p9sp->dev, "chip id mismatch: %x!=%llx\n",
			S5K3P9SP_CHIP_ID, val);
		return -ENODEV;
	}

	return 0;
}

static int s5k3p9sp_check_hwcfg(struct s5k3p9sp *s5k3p9sp)
{
	struct fwnode_handle *fwnode = dev_fwnode(s5k3p9sp->dev), *ep;
	struct v4l2_fwnode_endpoint bus_cfg = {
		.bus = {
			.mipi_csi2 = {
				.num_data_lanes = S5K3P9SP_DATA_LANES,
			},
		},
		.bus_type = V4L2_MBUS_CSI2_DPHY,
	};
	unsigned long freq_bitmap;
	int ret;

	if (!fwnode)
		return -ENODEV;

	ep = fwnode_graph_get_next_endpoint(fwnode, NULL);
	if (!ep)
		return -EINVAL;

	ret = v4l2_fwnode_endpoint_alloc_parse(ep, &bus_cfg);
	fwnode_handle_put(ep);
	if (ret)
		return ret;

	if (bus_cfg.bus.mipi_csi2.num_data_lanes != S5K3P9SP_DATA_LANES) {
		dev_err(s5k3p9sp->dev, "Invalid number of data lanes: %u\n",
			bus_cfg.bus.mipi_csi2.num_data_lanes);
		ret = -EINVAL;
		goto endpoint_free;
	}

	ret = v4l2_link_freq_to_bitmap(s5k3p9sp->dev, bus_cfg.link_frequencies,
				       bus_cfg.nr_of_link_frequencies,
				       s5k3p9sp_link_freq_menu,
				       ARRAY_SIZE(s5k3p9sp_link_freq_menu),
				       &freq_bitmap);

endpoint_free:
	v4l2_fwnode_endpoint_free(&bus_cfg);

	return ret;
}

static int s5k3p9sp_power_on(struct device *dev)
{
	struct v4l2_subdev *sd = dev_get_drvdata(dev);
	struct s5k3p9sp *s5k3p9sp = to_s5k3p9sp(sd);
	int ret;

	/* Hold the sensor in reset while powering up the supplies */
	gpiod_set_value_cansleep(s5k3p9sp->reset_gpio, 1);

	ret = regulator_bulk_enable(S5K3P9SP_NUM_SUPPLIES, s5k3p9sp->supplies);
	if (ret)
		goto assert_reset;

	ret = clk_prepare_enable(s5k3p9sp->mclk);
	if (ret)
		goto disable_regulators;

	/*
	 * The sensor requires a minimum of 18 ms after the release of
	 * the reset signal before the I2C interface can be accessed.
	 */
	gpiod_set_value_cansleep(s5k3p9sp->reset_gpio, 0);
	usleep_range(18000, 22000);

	return 0;

disable_regulators:
	regulator_bulk_disable(S5K3P9SP_NUM_SUPPLIES, s5k3p9sp->supplies);

assert_reset:
	gpiod_set_value_cansleep(s5k3p9sp->reset_gpio, 1);

	return ret;
}

static int s5k3p9sp_power_off(struct device *dev)
{
	struct v4l2_subdev *sd = dev_get_drvdata(dev);
	struct s5k3p9sp *s5k3p9sp = to_s5k3p9sp(sd);

	gpiod_set_value_cansleep(s5k3p9sp->reset_gpio, 1);

	clk_disable_unprepare(s5k3p9sp->mclk);

	regulator_bulk_disable(S5K3P9SP_NUM_SUPPLIES, s5k3p9sp->supplies);

	return 0;
}

static int s5k3p9sp_probe(struct i2c_client *client)
{
	struct s5k3p9sp *s5k3p9sp;
	unsigned long freq;
	unsigned int i;
	int ret;

	s5k3p9sp = devm_kzalloc(&client->dev, sizeof(*s5k3p9sp), GFP_KERNEL);
	if (!s5k3p9sp)
		return -ENOMEM;

	s5k3p9sp->dev = &client->dev;
	v4l2_i2c_subdev_init(&s5k3p9sp->sd, client, &s5k3p9sp_subdev_ops);

	s5k3p9sp->regmap = devm_cci_regmap_init_i2c(client, 16);
	if (IS_ERR(s5k3p9sp->regmap))
		return dev_err_probe(s5k3p9sp->dev, PTR_ERR(s5k3p9sp->regmap),
				     "failed to init CCI\n");

	s5k3p9sp->mclk = devm_v4l2_sensor_clk_get(s5k3p9sp->dev, NULL);
	if (IS_ERR(s5k3p9sp->mclk))
		return dev_err_probe(s5k3p9sp->dev, PTR_ERR(s5k3p9sp->mclk),
				     "failed to get MCLK clock\n");

	freq = clk_get_rate(s5k3p9sp->mclk);
	if (freq != S5K3P9SP_MCLK_FREQ_24MHZ)
		return dev_err_probe(s5k3p9sp->dev, -EINVAL,
				     "MCLK clock frequency %lu is not supported\n",
				     freq);

	ret = s5k3p9sp_check_hwcfg(s5k3p9sp);
	if (ret)
		return dev_err_probe(s5k3p9sp->dev, ret,
				     "failed to check HW configuration\n");

	s5k3p9sp->reset_gpio = devm_gpiod_get_optional(s5k3p9sp->dev, "reset",
						     GPIOD_OUT_HIGH);
	if (IS_ERR(s5k3p9sp->reset_gpio))
		return dev_err_probe(s5k3p9sp->dev, PTR_ERR(s5k3p9sp->reset_gpio),
				     "cannot get reset GPIO\n");

	for (i = 0; i < S5K3P9SP_NUM_SUPPLIES; i++)
		s5k3p9sp->supplies[i].supply = s5k3p9sp_supply_names[i];

	ret = devm_regulator_bulk_get(s5k3p9sp->dev, S5K3P9SP_NUM_SUPPLIES,
				      s5k3p9sp->supplies);
	if (ret)
		return dev_err_probe(s5k3p9sp->dev, ret,
				     "failed to get supply regulators\n");

	/* The sensor must be powered on to read the CHIP_ID register */
	ret = s5k3p9sp_power_on(s5k3p9sp->dev);
	if (ret)
		return ret;

	ret = s5k3p9sp_identify_sensor(s5k3p9sp);
	if (ret) {
		dev_err_probe(s5k3p9sp->dev, ret, "failed to find sensor\n");
		goto power_off;
	}

	s5k3p9sp->mode = &s5k3p9sp_supported_modes[0];
	ret = s5k3p9sp_init_controls(s5k3p9sp);
	if (ret) {
		dev_err_probe(s5k3p9sp->dev, ret, "failed to init controls\n");
		goto power_off;
	}

	s5k3p9sp->sd.state_lock = s5k3p9sp->ctrl_handler.lock;
	s5k3p9sp->sd.internal_ops = &s5k3p9sp_internal_ops;
	s5k3p9sp->sd.flags |= V4L2_SUBDEV_FL_HAS_DEVNODE;
	s5k3p9sp->sd.entity.ops = &s5k3p9sp_subdev_entity_ops;
	s5k3p9sp->sd.entity.function = MEDIA_ENT_F_CAM_SENSOR;
	s5k3p9sp->pad.flags = MEDIA_PAD_FL_SOURCE;

	ret = media_entity_pads_init(&s5k3p9sp->sd.entity, 1, &s5k3p9sp->pad);
	if (ret) {
		dev_err_probe(s5k3p9sp->dev, ret,
			      "failed to init media entity pads\n");
		goto v4l2_ctrl_handler_free;
	}

	ret = v4l2_subdev_init_finalize(&s5k3p9sp->sd);
	if (ret < 0) {
		dev_err_probe(s5k3p9sp->dev, ret,
			      "failed to init media entity pads\n");
		goto media_entity_cleanup;
	}

	pm_runtime_set_active(s5k3p9sp->dev);
	pm_runtime_enable(s5k3p9sp->dev);

	ret = v4l2_async_register_subdev_sensor(&s5k3p9sp->sd);
	if (ret < 0) {
		dev_err_probe(s5k3p9sp->dev, ret,
			      "failed to register V4L2 subdev\n");
		goto subdev_cleanup;
	}

	pm_runtime_set_autosuspend_delay(s5k3p9sp->dev, 1000);
	pm_runtime_use_autosuspend(s5k3p9sp->dev);
	pm_runtime_idle(s5k3p9sp->dev);

	return 0;

subdev_cleanup:
	v4l2_subdev_cleanup(&s5k3p9sp->sd);
	pm_runtime_disable(s5k3p9sp->dev);
	pm_runtime_set_suspended(s5k3p9sp->dev);

media_entity_cleanup:
	media_entity_cleanup(&s5k3p9sp->sd.entity);

v4l2_ctrl_handler_free:
	v4l2_ctrl_handler_free(s5k3p9sp->sd.ctrl_handler);

power_off:
	s5k3p9sp_power_off(s5k3p9sp->dev);

	return ret;
}

static void s5k3p9sp_remove(struct i2c_client *client)
{
	struct v4l2_subdev *sd = i2c_get_clientdata(client);
	struct s5k3p9sp *s5k3p9sp = to_s5k3p9sp(sd);

	v4l2_async_unregister_subdev(sd);
	v4l2_subdev_cleanup(sd);
	media_entity_cleanup(&sd->entity);
	v4l2_ctrl_handler_free(sd->ctrl_handler);
	pm_runtime_disable(s5k3p9sp->dev);

	if (!pm_runtime_status_suspended(s5k3p9sp->dev)) {
		s5k3p9sp_power_off(s5k3p9sp->dev);
		pm_runtime_set_suspended(s5k3p9sp->dev);
	}
}

static const struct dev_pm_ops s5k3p9sp_pm_ops = {
	SET_RUNTIME_PM_OPS(s5k3p9sp_power_off, s5k3p9sp_power_on, NULL)
};

static const struct of_device_id s5k3p9sp_of_match[] = {
	{ .compatible = "samsung,s5k3p9sp" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, s5k3p9sp_of_match);

static struct i2c_driver s5k3p9sp_i2c_driver = {
	.driver = {
		.name = "s5k3p9sp",
		.pm = &s5k3p9sp_pm_ops,
		.of_match_table = s5k3p9sp_of_match,
	},
	.probe = s5k3p9sp_probe,
	.remove = s5k3p9sp_remove,
};

module_i2c_driver(s5k3p9sp_i2c_driver);

MODULE_DESCRIPTION("Samsung S5K3P9SP image sensor driver");
MODULE_LICENSE("GPL");
