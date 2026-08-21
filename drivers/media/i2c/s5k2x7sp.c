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
#include "s5k2x7sp_regs.h"

#define S5K2X7SP_LINK_FREQ_1150MHZ	(1150000000ULL)
#define S5K2X7SP_MCLK_FREQ_24MHZ	(24 * HZ_PER_MHZ)
#define S5K2X7SP_DATA_LANES		4

/* Register map follows the MIPI CCS compliant camera sensor layout */
#define S5K2X7SP_CHIP_ID		0x2187

#define S5K2X7SP_EXPOSURE_MIN		8
#define S5K2X7SP_EXPOSURE_STEP		1
#define S5K2X7SP_EXPOSURE_MARGIN	16

#define S5K2X7SP_AGAIN_MIN		1
#define S5K2X7SP_AGAIN_MAX		16
#define S5K2X7SP_AGAIN_STEP		1
#define S5K2X7SP_AGAIN_DEFAULT		1
#define S5K2X7SP_AGAIN_SHIFT		5

#define S5K2X7SP_VTS_MAX		0xffff

#define to_s5k2x7sp(_sd)			container_of(_sd, struct s5k2x7sp, sd)

static const s64 s5k2x7sp_link_freq_menu[] = {
	S5K2X7SP_LINK_FREQ_1150MHZ,
};

/* Supported formats to cover horizontal and vertical flip controls */
static const u32 s5k2x7sp_mbus_formats[] = {
	MEDIA_BUS_FMT_SGRBG10_1X10,	MEDIA_BUS_FMT_SRGGB10_1X10,
	MEDIA_BUS_FMT_SBGGR10_1X10,	MEDIA_BUS_FMT_SGBRG10_1X10,
};

struct s5k2x7sp_reg_list {
	const struct cci_reg_sequence *regs;
	unsigned int num_regs;
};

struct s5k2x7sp_mode {
	u32 width;			/* Frame width in pixels */
	u32 height;			/* Frame height in pixels */
	u32 hts;			/* Horizontal timing size */
	u32 vts;			/* Default vertical timing size */
	u32 exposure;			/* Default exposure value */

	const struct s5k2x7sp_reg_list reg_list;	/* Sensor register setting */
};

static const struct s5k2x7sp_mode s5k2x7sp_supported_modes[] = {
	{
		.width = 2832,
		.height = 2128,
		.hts = 8448,
		.vts = 3630,
		.exposure = S5K2X7SP_MODE_DEFAULT_EXPOSURE,
		.reg_list = {
			.regs = s5k2x7sp_mode_settings,
			.num_regs = ARRAY_SIZE(s5k2x7sp_mode_settings),
		},
	},
};

static const char * const s5k2x7sp_test_pattern_menu[] = {
	"Disabled",
	"Solid colour",
	"Colour bars",
	"Fade to grey colour bars",
	"PN9",
};

static const char * const s5k2x7sp_supply_names[] = {
	"vana",		/* Analog power */
	"vdig",		/* Digital core power */
	"vio",		/* Digital I/O power */
};

#define S5K2X7SP_NUM_SUPPLIES	ARRAY_SIZE(s5k2x7sp_supply_names)

struct s5k2x7sp {
	struct device *dev;
	struct regmap *regmap;
	struct clk *mclk;
	struct gpio_desc *reset_gpio;
	struct regulator_bulk_data supplies[S5K2X7SP_NUM_SUPPLIES];

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

	const struct s5k2x7sp_mode *mode;
};

static const struct cci_reg_sequence s5k2x7sp_init_burst[] = {
	{ CCI_REG16(0x6028), 0x4000 },
	{ CCI_REG16(0x6214), 0x7971 },
	{ CCI_REG16(0x6218), 0x7150 },
};

static int s5k2x7sp_set_ctrl(struct v4l2_ctrl *ctrl)
{
	struct s5k2x7sp *s5k2x7sp = container_of(ctrl->handler, struct s5k2x7sp,
						  ctrl_handler);
	const struct s5k2x7sp_mode *mode = s5k2x7sp->mode;
	s64 exposure_max;
	int ret;

	/* Propagate change of current control to all related controls */
	switch (ctrl->id) {
	case V4L2_CID_HFLIP:
	case V4L2_CID_VFLIP:
		/* The orientation settings are applied along with streaming */
		return 0;
	case V4L2_CID_VBLANK:
		/* Update max exposure while meeting expected vblanking */
		exposure_max = mode->height + ctrl->val - S5K2X7SP_EXPOSURE_MARGIN;
		__v4l2_ctrl_modify_range(s5k2x7sp->exposure,
					 s5k2x7sp->exposure->minimum,
					 exposure_max,
					 s5k2x7sp->exposure->step,
					 s5k2x7sp->exposure->default_value);
		break;
	}

	/* V4L2 controls are applied, when sensor is powered up for streaming */
	if (!pm_runtime_get_if_active(s5k2x7sp->dev))
		return 0;

	switch (ctrl->id) {
	case V4L2_CID_ANALOGUE_GAIN:
		ret = cci_write(s5k2x7sp->regmap, CCS_R_ANALOG_GAIN_CODE_GLOBAL,
				ctrl->val << S5K2X7SP_AGAIN_SHIFT, NULL);
		break;
	case V4L2_CID_EXPOSURE:
		ret = cci_write(s5k2x7sp->regmap, CCS_R_COARSE_INTEGRATION_TIME,
				ctrl->val, NULL);
		break;
	case V4L2_CID_VBLANK:
		ret = cci_write(s5k2x7sp->regmap, CCS_R_FRAME_LENGTH_LINES,
				ctrl->val + mode->height, NULL);
		break;
	case V4L2_CID_TEST_PATTERN:
		ret = cci_write(s5k2x7sp->regmap, CCS_R_TEST_PATTERN_MODE,
				ctrl->val, NULL);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	pm_runtime_put(s5k2x7sp->dev);

	return ret;
}

static const struct v4l2_ctrl_ops s5k2x7sp_ctrl_ops = {
	.s_ctrl = s5k2x7sp_set_ctrl,
};

static inline u64 s5k2x7sp_freq_to_pixel_rate(const u64 freq)
{
	return div_u64(freq * 2 * S5K2X7SP_DATA_LANES, 10);
}

static int s5k2x7sp_init_controls(struct s5k2x7sp *s5k2x7sp)
{
	struct v4l2_ctrl_handler *ctrl_hdlr = &s5k2x7sp->ctrl_handler;
	const struct s5k2x7sp_mode *mode = s5k2x7sp->mode;
	s64 pixel_rate, hblank, vblank, exposure_max;
	struct v4l2_fwnode_device_properties props;
	int ret;

	v4l2_ctrl_handler_init(ctrl_hdlr, 9);

	s5k2x7sp->link_freq = v4l2_ctrl_new_int_menu(ctrl_hdlr,
					&s5k2x7sp_ctrl_ops,
					V4L2_CID_LINK_FREQ,
					ARRAY_SIZE(s5k2x7sp_link_freq_menu) - 1,
					0, s5k2x7sp_link_freq_menu);
	if (s5k2x7sp->link_freq)
		s5k2x7sp->link_freq->flags |= V4L2_CTRL_FLAG_READ_ONLY;

	pixel_rate = s5k2x7sp_freq_to_pixel_rate(s5k2x7sp_link_freq_menu[0]);
	s5k2x7sp->pixel_rate = v4l2_ctrl_new_std(ctrl_hdlr, &s5k2x7sp_ctrl_ops,
					       V4L2_CID_PIXEL_RATE,
					       0, pixel_rate, 1, pixel_rate);

	hblank = mode->hts - mode->width;
	s5k2x7sp->hblank = v4l2_ctrl_new_std(ctrl_hdlr, &s5k2x7sp_ctrl_ops,
					   V4L2_CID_HBLANK, hblank,
					   hblank, 1, hblank);
	if (s5k2x7sp->hblank)
		s5k2x7sp->hblank->flags |= V4L2_CTRL_FLAG_READ_ONLY;

	vblank = mode->vts - mode->height;
	s5k2x7sp->vblank = v4l2_ctrl_new_std(ctrl_hdlr, &s5k2x7sp_ctrl_ops,
					   V4L2_CID_VBLANK, vblank,
					   S5K2X7SP_VTS_MAX - mode->height, 1,
					   vblank);

	v4l2_ctrl_new_std(ctrl_hdlr, &s5k2x7sp_ctrl_ops, V4L2_CID_ANALOGUE_GAIN,
			  S5K2X7SP_AGAIN_MIN, S5K2X7SP_AGAIN_MAX,
			  S5K2X7SP_AGAIN_STEP, S5K2X7SP_AGAIN_DEFAULT);

	exposure_max = mode->vts - S5K2X7SP_EXPOSURE_MARGIN;
	s5k2x7sp->exposure = v4l2_ctrl_new_std(ctrl_hdlr, &s5k2x7sp_ctrl_ops,
					     V4L2_CID_EXPOSURE,
					     S5K2X7SP_EXPOSURE_MIN,
					     exposure_max,
					     S5K2X7SP_EXPOSURE_STEP,
					     mode->exposure);

	v4l2_ctrl_new_std_menu_items(ctrl_hdlr, &s5k2x7sp_ctrl_ops,
				     V4L2_CID_TEST_PATTERN,
				     ARRAY_SIZE(s5k2x7sp_test_pattern_menu) - 1,
				     0, 0, s5k2x7sp_test_pattern_menu);

	s5k2x7sp->hflip = v4l2_ctrl_new_std(ctrl_hdlr, &s5k2x7sp_ctrl_ops,
					  V4L2_CID_HFLIP, 0, 1, 1, 0);
	if (s5k2x7sp->hflip)
		s5k2x7sp->hflip->flags |= V4L2_CTRL_FLAG_MODIFY_LAYOUT;

	s5k2x7sp->vflip = v4l2_ctrl_new_std(ctrl_hdlr, &s5k2x7sp_ctrl_ops,
					  V4L2_CID_VFLIP, 0, 1, 1, 0);
	if (s5k2x7sp->vflip)
		s5k2x7sp->vflip->flags |= V4L2_CTRL_FLAG_MODIFY_LAYOUT;

	ret = v4l2_fwnode_device_parse(s5k2x7sp->dev, &props);
	if (ret)
		goto error_free_hdlr;

	ret = v4l2_ctrl_new_fwnode_properties(ctrl_hdlr, &s5k2x7sp_ctrl_ops,
					      &props);
	if (ret)
		goto error_free_hdlr;

	s5k2x7sp->sd.ctrl_handler = ctrl_hdlr;

	return 0;

error_free_hdlr:
	v4l2_ctrl_handler_free(ctrl_hdlr);

	return ret;
}
static int s5k2x7sp_enable_streams(struct v4l2_subdev *sd,
				 struct v4l2_subdev_state *state, u32 pad,
				 u64 streams_mask)
{
	struct s5k2x7sp *s5k2x7sp = to_s5k2x7sp(sd);
	const struct s5k2x7sp_reg_list *reg_list = &s5k2x7sp->mode->reg_list;
	int ret;

	ret = pm_runtime_resume_and_get(s5k2x7sp->dev);
	if (ret)
		return ret;

	/* Page pointer and SRAM access configuration */
	cci_multi_reg_write(s5k2x7sp->regmap, s5k2x7sp_init_burst,
			    ARRAY_SIZE(s5k2x7sp_init_burst), &ret);

	/* Sensor init settings (firmware upload and calibration) */
	cci_multi_reg_write(s5k2x7sp->regmap, s5k2x7sp_init_settings,
			    ARRAY_SIZE(s5k2x7sp_init_settings), &ret);

	/* Resolution specific settings */
	cci_multi_reg_write(s5k2x7sp->regmap, reg_list->regs,
			    reg_list->num_regs, &ret);
	if (ret)
		goto error;

	ret = __v4l2_ctrl_handler_setup(s5k2x7sp->sd.ctrl_handler);

	cci_write(s5k2x7sp->regmap, CCS_R_IMAGE_ORIENTATION,
		  (s5k2x7sp->vflip->val ? CCS_IMAGE_ORIENTATION_VERTICAL_FLIP : 0) |
		  (s5k2x7sp->hflip->val ? CCS_IMAGE_ORIENTATION_HORIZONTAL_MIRROR : 0),
		  &ret);
	cci_write(s5k2x7sp->regmap, CCS_R_MODE_SELECT,
		  CCS_MODE_SELECT_STREAMING, &ret);
	if (ret)
		goto error;

	return 0;

error:
	dev_err(s5k2x7sp->dev, "failed to start streaming: %d\n", ret);
	pm_runtime_put_autosuspend(s5k2x7sp->dev);

	return ret;
}

static int s5k2x7sp_disable_streams(struct v4l2_subdev *sd,
				  struct v4l2_subdev_state *state, u32 pad,
				  u64 streams_mask)
{
	struct s5k2x7sp *s5k2x7sp = to_s5k2x7sp(sd);
	int ret;

	ret = cci_write(s5k2x7sp->regmap, CCS_R_MODE_SELECT,
			CCS_MODE_SELECT_SOFTWARE_STANDBY, NULL);
	if (ret)
		dev_err(s5k2x7sp->dev, "failed to stop streaming: %d\n", ret);

	pm_runtime_put_autosuspend(s5k2x7sp->dev);

	return ret;
}

static u32 s5k2x7sp_get_format_code(struct s5k2x7sp *s5k2x7sp)
{
	unsigned int i;

	i = (s5k2x7sp->vflip->val ? 2 : 0) | (s5k2x7sp->hflip->val ? 1 : 0);

	return s5k2x7sp_mbus_formats[i];
}

static void s5k2x7sp_update_pad_format(struct s5k2x7sp *s5k2x7sp,
				     const struct s5k2x7sp_mode *mode,
				     struct v4l2_mbus_framefmt *fmt)
{
	fmt->code = s5k2x7sp_get_format_code(s5k2x7sp);
	fmt->width = mode->width;
	fmt->height = mode->height;
	fmt->field = V4L2_FIELD_NONE;
	fmt->colorspace = V4L2_COLORSPACE_SRGB;
	fmt->ycbcr_enc = V4L2_YCBCR_ENC_DEFAULT;
	fmt->quantization = V4L2_QUANTIZATION_FULL_RANGE;
	fmt->xfer_func = V4L2_XFER_FUNC_NONE;
}

static int s5k2x7sp_set_pad_format(struct v4l2_subdev *sd,
				 struct v4l2_subdev_state *state,
				 struct v4l2_subdev_format *fmt)
{
	struct s5k2x7sp *s5k2x7sp = to_s5k2x7sp(sd);
	s64 hblank, vblank, exposure_max;
	const struct s5k2x7sp_mode *mode;

	mode = v4l2_find_nearest_size(s5k2x7sp_supported_modes,
				      ARRAY_SIZE(s5k2x7sp_supported_modes),
				      width, height,
				      fmt->format.width, fmt->format.height);

	s5k2x7sp_update_pad_format(s5k2x7sp, mode, &fmt->format);

	/* Format code could be updated with respect to flip controls */
	if (fmt->which == V4L2_SUBDEV_FORMAT_TRY || s5k2x7sp->mode == mode)
		goto set_format;

	/* Update limits and set FPS and exposure to default values */
	hblank = mode->hts - mode->width;
	__v4l2_ctrl_modify_range(s5k2x7sp->hblank, hblank, hblank, 1, hblank);

	vblank = mode->vts - mode->height;
	__v4l2_ctrl_modify_range(s5k2x7sp->vblank, vblank,
				 S5K2X7SP_VTS_MAX - mode->height, 1, vblank);
	__v4l2_ctrl_s_ctrl(s5k2x7sp->vblank, vblank);

	exposure_max = mode->vts - S5K2X7SP_EXPOSURE_MARGIN;
	__v4l2_ctrl_modify_range(s5k2x7sp->exposure, S5K2X7SP_EXPOSURE_MIN,
				 exposure_max, S5K2X7SP_EXPOSURE_STEP,
				 mode->exposure);
	__v4l2_ctrl_s_ctrl(s5k2x7sp->exposure, mode->exposure);

	if (s5k2x7sp->sd.ctrl_handler->error)
		return s5k2x7sp->sd.ctrl_handler->error;

	s5k2x7sp->mode = mode;

set_format:
	*v4l2_subdev_state_get_format(state, 0) = fmt->format;

	return 0;
}

static int s5k2x7sp_enum_mbus_code(struct v4l2_subdev *sd,
				 struct v4l2_subdev_state *sd_state,
				 struct v4l2_subdev_mbus_code_enum *code)
{
	struct s5k2x7sp *s5k2x7sp = to_s5k2x7sp(sd);

	/* Media bus code index is constant, but code formats are not */
	if (code->index > 0)
		return -EINVAL;

	code->code = s5k2x7sp_get_format_code(s5k2x7sp);

	return 0;
}

static int s5k2x7sp_enum_frame_size(struct v4l2_subdev *sd,
				  struct v4l2_subdev_state *sd_state,
				  struct v4l2_subdev_frame_size_enum *fse)
{
	struct s5k2x7sp *s5k2x7sp = to_s5k2x7sp(sd);

	if (fse->index >= ARRAY_SIZE(s5k2x7sp_supported_modes))
		return -EINVAL;

	if (fse->code != s5k2x7sp_get_format_code(s5k2x7sp))
		return -EINVAL;

	fse->min_width = s5k2x7sp_supported_modes[fse->index].width;
	fse->max_width = fse->min_width;
	fse->min_height = s5k2x7sp_supported_modes[fse->index].height;
	fse->max_height = fse->min_height;

	return 0;
}

static int s5k2x7sp_get_selection(struct v4l2_subdev *sd,
				struct v4l2_subdev_state *sd_state,
				struct v4l2_subdev_selection *sel)
{
	struct s5k2x7sp *s5k2x7sp = to_s5k2x7sp(sd);

	switch (sel->target) {
	case V4L2_SEL_TGT_CROP:
	case V4L2_SEL_TGT_CROP_BOUNDS:
	case V4L2_SEL_TGT_CROP_DEFAULT:
	case V4L2_SEL_TGT_NATIVE_SIZE:
		sel->r.left = 0;
		sel->r.top = 0;
		sel->r.width = s5k2x7sp->mode->width;
		sel->r.height = s5k2x7sp->mode->height;
		return 0;
	default:
		return -EINVAL;
	}
}

static int s5k2x7sp_init_state(struct v4l2_subdev *sd,
			     struct v4l2_subdev_state *state)
{
	struct s5k2x7sp *s5k2x7sp = to_s5k2x7sp(sd);
	struct v4l2_subdev_format fmt = {
		.which = V4L2_SUBDEV_FORMAT_TRY,
		.pad = 0,
		.format = {
			/* Media bus code depends on current flip controls */
			.width = s5k2x7sp->mode->width,
			.height = s5k2x7sp->mode->height,
		},
	};

	s5k2x7sp_set_pad_format(sd, state, &fmt);

	return 0;
}

static const struct v4l2_subdev_video_ops s5k2x7sp_video_ops = {
	.s_stream = v4l2_subdev_s_stream_helper,
};

static const struct v4l2_subdev_pad_ops s5k2x7sp_pad_ops = {
	.set_fmt = s5k2x7sp_set_pad_format,
	.get_fmt = v4l2_subdev_get_fmt,
	.get_selection = s5k2x7sp_get_selection,
	.enum_mbus_code = s5k2x7sp_enum_mbus_code,
	.enum_frame_size = s5k2x7sp_enum_frame_size,
	.enable_streams = s5k2x7sp_enable_streams,
	.disable_streams = s5k2x7sp_disable_streams,
};

static const struct v4l2_subdev_ops s5k2x7sp_subdev_ops = {
	.video = &s5k2x7sp_video_ops,
	.pad = &s5k2x7sp_pad_ops,
};

static const struct v4l2_subdev_internal_ops s5k2x7sp_internal_ops = {
	.init_state = s5k2x7sp_init_state,
};

static const struct media_entity_operations s5k2x7sp_subdev_entity_ops = {
	.link_validate = v4l2_subdev_link_validate,
};

static int s5k2x7sp_identify_sensor(struct s5k2x7sp *s5k2x7sp)
{
	u64 val;
	int ret;

	ret = cci_read(s5k2x7sp->regmap, CCS_R_MODULE_MODEL_ID, &val, NULL);
	if (ret) {
		dev_err(s5k2x7sp->dev, "failed to read chip id: %d\n", ret);
		return ret;
	}

	if (val != S5K2X7SP_CHIP_ID) {
		dev_err(s5k2x7sp->dev, "chip id mismatch: %x!=%llx\n",
			S5K2X7SP_CHIP_ID, val);
		return -ENODEV;
	}

	return 0;
}

static int s5k2x7sp_check_hwcfg(struct s5k2x7sp *s5k2x7sp)
{
	struct fwnode_handle *fwnode = dev_fwnode(s5k2x7sp->dev), *ep;
	struct v4l2_fwnode_endpoint bus_cfg = {
		.bus = {
			.mipi_csi2 = {
				.num_data_lanes = S5K2X7SP_DATA_LANES,
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

	if (bus_cfg.bus.mipi_csi2.num_data_lanes != S5K2X7SP_DATA_LANES) {
		dev_err(s5k2x7sp->dev, "Invalid number of data lanes: %u\n",
			bus_cfg.bus.mipi_csi2.num_data_lanes);
		ret = -EINVAL;
		goto endpoint_free;
	}

	ret = v4l2_link_freq_to_bitmap(s5k2x7sp->dev, bus_cfg.link_frequencies,
				       bus_cfg.nr_of_link_frequencies,
				       s5k2x7sp_link_freq_menu,
				       ARRAY_SIZE(s5k2x7sp_link_freq_menu),
				       &freq_bitmap);

endpoint_free:
	v4l2_fwnode_endpoint_free(&bus_cfg);

	return ret;
}

static int s5k2x7sp_power_on(struct device *dev)
{
	struct v4l2_subdev *sd = dev_get_drvdata(dev);
	struct s5k2x7sp *s5k2x7sp = to_s5k2x7sp(sd);
	int ret;

	/* Hold the sensor in reset while powering up the supplies */
	if (s5k2x7sp->reset_gpio)
		gpiod_set_value_cansleep(s5k2x7sp->reset_gpio, 1);

	ret = regulator_bulk_enable(S5K2X7SP_NUM_SUPPLIES, s5k2x7sp->supplies);
	if (ret)
		goto assert_reset;

	ret = clk_prepare_enable(s5k2x7sp->mclk);
	if (ret)
		goto disable_regulators;

	/* Release the reset signal once the supplies and clock are stable */
	if (s5k2x7sp->reset_gpio) {
		usleep_range(10 * USEC_PER_MSEC, 15 * USEC_PER_MSEC);
		gpiod_set_value_cansleep(s5k2x7sp->reset_gpio, 0);
	}
	usleep_range(10 * USEC_PER_MSEC, 15 * USEC_PER_MSEC);

	return 0;

disable_regulators:
	regulator_bulk_disable(S5K2X7SP_NUM_SUPPLIES, s5k2x7sp->supplies);

assert_reset:
	if (s5k2x7sp->reset_gpio)
		gpiod_set_value_cansleep(s5k2x7sp->reset_gpio, 1);

	return ret;
}

static int s5k2x7sp_power_off(struct device *dev)
{
	struct v4l2_subdev *sd = dev_get_drvdata(dev);
	struct s5k2x7sp *s5k2x7sp = to_s5k2x7sp(sd);

	if (s5k2x7sp->reset_gpio)
		gpiod_set_value_cansleep(s5k2x7sp->reset_gpio, 1);

	clk_disable_unprepare(s5k2x7sp->mclk);

	regulator_bulk_disable(S5K2X7SP_NUM_SUPPLIES, s5k2x7sp->supplies);

	return 0;
}

static int s5k2x7sp_probe(struct i2c_client *client)
{
	struct s5k2x7sp *s5k2x7sp;
	unsigned long freq;
	unsigned int i;
	int ret;

	s5k2x7sp = devm_kzalloc(&client->dev, sizeof(*s5k2x7sp), GFP_KERNEL);
	if (!s5k2x7sp)
		return -ENOMEM;

	s5k2x7sp->dev = &client->dev;
	v4l2_i2c_subdev_init(&s5k2x7sp->sd, client, &s5k2x7sp_subdev_ops);

	s5k2x7sp->regmap = devm_cci_regmap_init_i2c(client, 16);
	if (IS_ERR(s5k2x7sp->regmap))
		return dev_err_probe(s5k2x7sp->dev, PTR_ERR(s5k2x7sp->regmap),
				     "failed to init CCI\n");

	s5k2x7sp->mclk = devm_v4l2_sensor_clk_get(s5k2x7sp->dev, NULL);
	if (IS_ERR(s5k2x7sp->mclk))
		return dev_err_probe(s5k2x7sp->dev, PTR_ERR(s5k2x7sp->mclk),
				     "failed to get MCLK clock\n");

	freq = clk_get_rate(s5k2x7sp->mclk);
	if (freq != S5K2X7SP_MCLK_FREQ_24MHZ)
		return dev_err_probe(s5k2x7sp->dev, -EINVAL,
				     "MCLK clock frequency %lu is not supported\n",
				     freq);

	ret = s5k2x7sp_check_hwcfg(s5k2x7sp);
	if (ret)
		return dev_err_probe(s5k2x7sp->dev, ret,
				     "failed to check HW configuration\n");

	s5k2x7sp->reset_gpio = devm_gpiod_get_optional(s5k2x7sp->dev, "reset",
						     GPIOD_OUT_HIGH);
	if (IS_ERR(s5k2x7sp->reset_gpio))
		return dev_err_probe(s5k2x7sp->dev, PTR_ERR(s5k2x7sp->reset_gpio),
				     "cannot get reset GPIO\n");

	for (i = 0; i < S5K2X7SP_NUM_SUPPLIES; i++)
		s5k2x7sp->supplies[i].supply = s5k2x7sp_supply_names[i];

	ret = devm_regulator_bulk_get(s5k2x7sp->dev, S5K2X7SP_NUM_SUPPLIES,
				      s5k2x7sp->supplies);
	if (ret)
		return dev_err_probe(s5k2x7sp->dev, ret,
				     "failed to get supply regulators\n");

	/* The sensor must be powered on to read the CHIP_ID register */
	ret = s5k2x7sp_power_on(s5k2x7sp->dev);
	if (ret)
		return ret;

	ret = s5k2x7sp_identify_sensor(s5k2x7sp);
	if (ret) {
		dev_err_probe(s5k2x7sp->dev, ret, "failed to find sensor\n");
		goto power_off;
	}

	s5k2x7sp->mode = &s5k2x7sp_supported_modes[0];
	ret = s5k2x7sp_init_controls(s5k2x7sp);
	if (ret) {
		dev_err_probe(s5k2x7sp->dev, ret, "failed to init controls\n");
		goto power_off;
	}

	s5k2x7sp->sd.state_lock = s5k2x7sp->ctrl_handler.lock;
	s5k2x7sp->sd.internal_ops = &s5k2x7sp_internal_ops;
	s5k2x7sp->sd.flags |= V4L2_SUBDEV_FL_HAS_DEVNODE;
	s5k2x7sp->sd.entity.ops = &s5k2x7sp_subdev_entity_ops;
	s5k2x7sp->sd.entity.function = MEDIA_ENT_F_CAM_SENSOR;
	s5k2x7sp->pad.flags = MEDIA_PAD_FL_SOURCE;

	ret = media_entity_pads_init(&s5k2x7sp->sd.entity, 1, &s5k2x7sp->pad);
	if (ret) {
		dev_err_probe(s5k2x7sp->dev, ret,
			      "failed to init media entity pads\n");
		goto v4l2_ctrl_handler_free;
	}

	ret = v4l2_subdev_init_finalize(&s5k2x7sp->sd);
	if (ret < 0) {
		dev_err_probe(s5k2x7sp->dev, ret,
			      "failed to init media entity pads\n");
		goto media_entity_cleanup;
	}

	pm_runtime_set_active(s5k2x7sp->dev);
	pm_runtime_enable(s5k2x7sp->dev);

	ret = v4l2_async_register_subdev_sensor(&s5k2x7sp->sd);
	if (ret < 0) {
		dev_err_probe(s5k2x7sp->dev, ret,
			      "failed to register V4L2 subdev\n");
		goto subdev_cleanup;
	}

	pm_runtime_set_autosuspend_delay(s5k2x7sp->dev, 1000);
	pm_runtime_use_autosuspend(s5k2x7sp->dev);
	pm_runtime_idle(s5k2x7sp->dev);

	return 0;

subdev_cleanup:
	v4l2_subdev_cleanup(&s5k2x7sp->sd);
	pm_runtime_disable(s5k2x7sp->dev);
	pm_runtime_set_suspended(s5k2x7sp->dev);

media_entity_cleanup:
	media_entity_cleanup(&s5k2x7sp->sd.entity);

v4l2_ctrl_handler_free:
	v4l2_ctrl_handler_free(s5k2x7sp->sd.ctrl_handler);

power_off:
	s5k2x7sp_power_off(s5k2x7sp->dev);

	return ret;
}

static void s5k2x7sp_remove(struct i2c_client *client)
{
	struct v4l2_subdev *sd = i2c_get_clientdata(client);
	struct s5k2x7sp *s5k2x7sp = to_s5k2x7sp(sd);

	v4l2_async_unregister_subdev(sd);
	v4l2_subdev_cleanup(sd);
	media_entity_cleanup(&sd->entity);
	v4l2_ctrl_handler_free(sd->ctrl_handler);
	pm_runtime_disable(s5k2x7sp->dev);

	if (!pm_runtime_status_suspended(s5k2x7sp->dev)) {
		s5k2x7sp_power_off(s5k2x7sp->dev);
		pm_runtime_set_suspended(s5k2x7sp->dev);
	}
}

static const struct dev_pm_ops s5k2x7sp_pm_ops = {
	SET_RUNTIME_PM_OPS(s5k2x7sp_power_off, s5k2x7sp_power_on, NULL)
};

static const struct of_device_id s5k2x7sp_of_match[] = {
	{ .compatible = "samsung,s5k2x7sp" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, s5k2x7sp_of_match);

static struct i2c_driver s5k2x7sp_i2c_driver = {
	.driver = {
		.name = "s5k2x7sp",
		.pm = &s5k2x7sp_pm_ops,
		.of_match_table = s5k2x7sp_of_match,
	},
	.probe = s5k2x7sp_probe,
	.remove = s5k2x7sp_remove,
};

module_i2c_driver(s5k2x7sp_i2c_driver);

MODULE_DESCRIPTION("Samsung S5K2X7SP image sensor driver");
MODULE_LICENSE("GPL");
