// SPDX-License-Identifier: GPL-2.0+ OR MIT
/*
 *  Driver for LGE / SiliconWorks SW49410 touchscreen over SPI
 *
 *  Copyright (c) 2025 Paul Sajna
 */

#include <linux/types.h>

#include <linux/kernel.h>

#include <linux/spinlock.h>
#include <linux/delay.h>
#include <linux/gpio/consumer.h>
#include <linux/input.h>
#include <linux/input/touchscreen.h>
#include <linux/input/mt.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spi/spi.h>
#include <linux/unaligned.h>
#include <linux/of.h>
#include <linux/of_irq.h>

#include <drm/drm_panel.h>

#define SW49410_PACKET_SIZE	132
#define SW49410_MAX_FINGER	10
#define SW49410_MAX_PRESSURE	255
#define SW49410_MAX_WIDTH	15
#define SW49410_MAX_ORIENTATION 90

#define SPI_BUS_RX_HDR_SZ 6
#define SPI_BUS_TX_HDR_SZ 2
#define TC_IC_STATUS 0x200

#define REG_ADDR_SPI		0xFE4
#define REG_ADDR_I2C		0xFE5
#define REG_ADDR_SET		0xFF3
#define REG_TC_DEVICE_CTL	0xC00
#define REG_TC_INTERRUPT_CTL    0xC01
#define REG_TC_INTERRUPT_STS    0xC02
#define REG_TC_DRIVE_CTL	0xC03

#define TC_DRIVE_CTL_START     1
#define TC_DRIVE_CTL_STOP      2
#define TC_DRIVE_CTL_DISP_U0   (0 << 7)
#define TC_DRIVE_CTL_DISP_U2   (2 << 7)
#define TC_DRIVE_CTL_DISP_U3   (3 << 7)
#define TC_DRIVE_CTL_PARTIAL   (1 << 9)
#define TC_DRIVE_CTL_QCOVER    (1 << 10)
#define TC_DRIVE_CTL_MODE_VB   (0 << 2)
#define TC_DRIVE_CTL_MODE_6LHB (1 << 2)
#define TC_DRIVE_CTL_MODE_MIK  (1 << 3)

enum {
	TOUCHSTS_IDLE = 0,
	TOUCHSTS_DOWN,
	TOUCHSTS_MOVE,
	TOUCHSTS_UP,
};

struct sw49410_touch_data {
	u8 tool_type:4;
	u8 event:4;
	u8 track_id;
	u16 x;
	u16 y;
	u8 pressure;
	u8 angle;
	u16 width_major;
	u16 width_minor;
} __packed;

struct sw49410_touch_info {
	u32 ic_status;
	u32 device_status;
	u32 wakeup_type:8;
	u32 touch_cnt:5;
	u32 button_cnt:3;
	u32 palm_bit:16;
	struct sw49410_touch_data data[SW49410_MAX_FINGER];
} __packed;

struct sw49410_ts_spi {
	struct spi_device *spi;
	struct gpio_desc *gpiod_rst;
	struct input_dev *input;
	struct touchscreen_properties props;
	struct drm_panel_follower panel_follower;

	u8 *packet;
	u8 tx_buf[10];

	bool irq_enabled;
	int irq;
};

static spinlock_t irq_lock;

static int sw49410_ts_spi_reg_read(struct sw49410_ts_spi *ts, u16 addr, void *data, int size)
{
	struct spi_device *spi = ts->spi;
	struct spi_message msg;
	struct spi_transfer xfer;

	xfer.rx_buf = data;

	ts->tx_buf[0] = ((size > 4) ? 0x20 : 0x00);
	ts->tx_buf[0] |= ((addr >> 8) & 0x0f);
	ts->tx_buf[1] = (addr & 0xff);

	xfer.tx_buf = ts->tx_buf;
	xfer.len = SPI_BUS_RX_HDR_SZ + size;
	xfer.bits_per_word = 8;
	xfer.speed_hz = spi->max_speed_hz;

	spi_message_init(&msg);
	spi_message_add_tail(&xfer, &msg);
	return spi_sync(spi, &msg);
}

static int sw49410_ts_spi_reg_write(struct sw49410_ts_spi *ts, u16 addr, void *data, int size)
{
	struct spi_device *spi = ts->spi;
	struct spi_message msg;
	struct spi_transfer xfer;

	ts->tx_buf[0] = 0x60;
	ts->tx_buf[0] |= ((addr >> 8) & 0x0f);
	ts->tx_buf[1] = (addr & 0xff);

	memcpy(&ts->tx_buf[SPI_BUS_TX_HDR_SZ], data, SPI_BUS_TX_HDR_SZ + size);

	xfer.tx_buf = ts->tx_buf;
	xfer.len = SPI_BUS_TX_HDR_SZ + size;
	xfer.bits_per_word = 8;
	xfer.speed_hz = spi->max_speed_hz;

	spi_message_init(&msg);
	spi_message_add_tail(&xfer, &msg);
	return spi_sync(spi, &msg);
}

inline int sw49410_ts_spi_reg_write_value(struct sw49410_ts_spi *ts, u16 addr, uint32_t value)
{
	return sw49410_ts_spi_reg_write(ts, addr, &value, sizeof(value));
}

static int sw49410_ts_spi_init(struct sw49410_ts_spi *ts)
{
	int error = 0;

	struct reg_value_pair {
		u16 reg;
		u32 value;
	};

	static struct reg_value_pair init_sequence[8] = {
		{REG_ADDR_SPI,		1},
		{REG_ADDR_I2C,		0},
		{REG_ADDR_SET,		0x03},
		{REG_ADDR_SET,		0x03},
		{REG_ADDR_SET,		0x03},
		{REG_TC_DEVICE_CTL,	1},
		{REG_TC_INTERRUPT_CTL,  1},
		{REG_TC_DRIVE_CTL,	TC_DRIVE_CTL_START |
					TC_DRIVE_CTL_DISP_U3 |
					TC_DRIVE_CTL_MODE_6LHB}
	};

	for (int i = 0; i < 8; i++) {
		error = sw49410_ts_spi_reg_write_value(ts, init_sequence[i].reg,
						       init_sequence[i].value);
		if (error) {
			dev_err(&ts->spi->dev, "%s failed %d\n", __func__, error);
			return error;
		}
		msleep(100);
	}
	return 0;
}

static void sw49410_ts_spi_process_touch(struct sw49410_ts_spi *ts)
{
	struct input_dev *input = ts->input;
	struct device *dev = &ts->spi->dev;
	struct sw49410_touch_info *tdata = NULL;
	int slot;

	if (!input) {
		dev_err(dev, "Input device has not been set up yet\n");
		return;
	}

	tdata = (struct sw49410_touch_info *)&ts->packet[SPI_BUS_RX_HDR_SZ];

	for (int i = 0; i < SW49410_MAX_FINGER; i++) {
		slot = input_mt_get_slot_by_key(ts->input, tdata->data[i].track_id);
		if (slot < 0) {
			dev_warn(dev, "Skipping slot\n");
			continue;
		}

		if (tdata->data[i].event == TOUCHSTS_DOWN ||
		    tdata->data[i].event == TOUCHSTS_MOVE) {
			input_mt_slot(ts->input, slot);
			input_mt_report_slot_state(ts->input, MT_TOOL_FINGER, true);
			touchscreen_report_pos(ts->input, &ts->props, tdata->data[i].x,
					       tdata->data[i].y, true);
			input_report_abs(ts->input, ABS_MT_WIDTH_MAJOR,
					 tdata->data[i].width_major);
			input_report_abs(ts->input, ABS_MT_WIDTH_MINOR,
					 tdata->data[i].width_minor);
			input_report_abs(ts->input, ABS_MT_PRESSURE, tdata->data[i].pressure);
			input_report_abs(ts->input, ABS_MT_ORIENTATION, tdata->data[i].angle);
		}

		if (tdata->data[i].event == TOUCHSTS_UP) {
			input_mt_slot(ts->input, slot);
			input_report_abs(ts->input, ABS_MT_TRACKING_ID, -1);
			input_report_key(ts->input, BTN_TOUCH, 0);
			input_report_key(ts->input, BTN_TOOL_FINGER, 0);
		}
	}

	input_mt_sync_frame(ts->input);
	input_sync(ts->input);
}

static void sw49410_ts_spi_disable_irq(struct sw49410_ts_spi *ts)
{
	unsigned long flags = 0;

	spin_lock_irqsave(&irq_lock, flags);
	if (ts->irq_enabled) {
		disable_irq(ts->irq);
		ts->irq_enabled = false;
	}
	spin_unlock_irqrestore(&irq_lock, flags);
}

static void sw49410_ts_spi_enable_irq(struct sw49410_ts_spi *ts)
{
	unsigned long flags = 0;

	spin_lock_irqsave(&irq_lock, flags);
	if (!(ts->irq_enabled)) {
		enable_irq(ts->irq);
		ts->irq_enabled = true;
	}
	spin_unlock_irqrestore(&irq_lock, flags);
}

static irqreturn_t sw49410_ts_spi_irq_handler(int irq, void *dev_id)
{
	struct sw49410_ts_spi *ts = dev_id;

	sw49410_ts_spi_reg_read(ts, TC_IC_STATUS, ts->packet, SW49410_PACKET_SIZE);

	sw49410_ts_spi_process_touch(ts);

	return IRQ_HANDLED;
}

static int sw49410_ts_spi_reset(struct sw49410_ts_spi *ts)
{
	int error;

	error = gpiod_set_value(ts->gpiod_rst, false);
	msleep(90);
	error = gpiod_set_value(ts->gpiod_rst, true);
	msleep(90);
	error = gpiod_set_value(ts->gpiod_rst, false);
	msleep(90);

	return error;
}

/**
 * sw49410_ts_spi_get_gpio_config - Get GPIO config from DT
 *
 * @ts: sw49410_ts_spi pointer
 */
static int sw49410_ts_spi_get_gpio_config(struct sw49410_ts_spi *ts)
{
	struct device *dev;

	dev = &ts->spi->dev;

	ts->gpiod_rst = devm_gpiod_get_optional(dev, "reset", GPIOD_OUT_LOW);

	if (IS_ERR(ts->gpiod_rst))
		return dev_err_probe(dev, PTR_ERR(ts->gpiod_rst),
				     "unable to get reset-gpio\n");

	return 0;
}

static int sw49410_ts_spi_create_touch_input(struct sw49410_ts_spi *ts)
{
	struct input_dev *input;
	int error;

	input = devm_input_allocate_device(&ts->spi->dev);
	if (!input) {
		dev_err(&ts->spi->dev, "failed to allocate input device\n");
		return -ENOMEM;
	}

	ts->input = input;

	input_set_capability(input, EV_ABS, ABS_MT_POSITION_X);
	input_set_capability(input, EV_ABS, ABS_MT_POSITION_Y);
	input_set_capability(input, EV_ABS, ABS_MT_PRESSURE);
	input_set_capability(input, EV_ABS, ABS_MT_WIDTH_MAJOR);
	input_set_capability(input, EV_ABS, ABS_MT_WIDTH_MINOR);
	input_set_capability(input, EV_ABS, ABS_MT_ORIENTATION);

	input_set_abs_params(input, ABS_MT_POSITION_X, 0, 65535, 0, 0);
	input_set_abs_params(input, ABS_MT_POSITION_Y, 0, 65535, 0, 0);
	input_set_abs_params(input, ABS_MT_PRESSURE, 0,
			     SW49410_MAX_PRESSURE, 0, 0);
	input_set_abs_params(input, ABS_MT_WIDTH_MAJOR, 0,
			     SW49410_MAX_WIDTH, 0, 0);
	input_set_abs_params(input, ABS_MT_WIDTH_MINOR, 0,
			     SW49410_MAX_WIDTH, 0, 0);
	input_set_abs_params(input, ABS_MT_ORIENTATION, 0,
			     SW49410_MAX_ORIENTATION, 0, 0);

	touchscreen_parse_properties(input, true, &ts->props);
	input_abs_set_fuzz(input, ABS_MT_POSITION_X, 0);
	input_abs_set_fuzz(input, ABS_MT_POSITION_Y, 0);

	error = input_mt_init_slots(input, SW49410_MAX_FINGER,
				    INPUT_MT_DIRECT | INPUT_MT_DROP_UNUSED);

	if (error) {
		dev_err(&ts->spi->dev, "failed to create input slots %d\n", error);
		return error;
	}

	input->name = "SiW SW49410 SPI Touchscreen";
	input->phys = "input/ts";
	input->id.bustype = BUS_SPI;

	return 0;
}

static int sw49410_ts_spi_suspend(struct device *dev)
{
	struct spi_device *spi = to_spi_device(dev);
	struct sw49410_ts_spi *ts = spi_get_drvdata(spi);

	sw49410_ts_spi_disable_irq(ts);
	gpiod_set_value(ts->gpiod_rst, true);

	return 0;
}

static int sw49410_ts_spi_resume(struct device *dev)
{
	int error;
	struct spi_device *spi = to_spi_device(dev);
	struct sw49410_ts_spi *ts = spi_get_drvdata(spi);

	error = sw49410_ts_spi_reset(ts);
	if (error) {
		dev_err(dev, "resume reset failed %d\n", error);
		return error;
	}

	error = sw49410_ts_spi_init(ts);
	if (error) {
		dev_err(dev, "resume init failed %d\n", error);
		return error;
	}

	sw49410_ts_spi_enable_irq(ts);

	return error;
}

static int sw49410_panel_prepared(struct drm_panel_follower *follower)
{
	struct sw49410_ts_spi *ts = container_of(follower, struct sw49410_ts_spi, panel_follower);

	return sw49410_ts_spi_resume(&ts->spi->dev);
}

static int sw49410_panel_unpreparing(struct drm_panel_follower *follower)
{
	struct sw49410_ts_spi *ts = container_of(follower, struct sw49410_ts_spi, panel_follower);

	return sw49410_ts_spi_suspend(&ts->spi->dev);
}

static const struct drm_panel_follower_funcs sw49410_ts_spi_panel_follower_funcs = {
	.panel_prepared = sw49410_panel_prepared,
	.panel_unpreparing = sw49410_panel_unpreparing,
};

static int sw49410_ts_spi_probe(struct spi_device *spi)
{
	int irq;
	struct sw49410_ts_spi *ts;
	int error;
	u8 *packet;

	spi->bits_per_word = 8;
	spi->mode = SPI_MODE_0;
	error = spi_setup(spi);
	if (error) {
		dev_err(&spi->dev, "failed to setup spi %d\n", error);
		return error;
	}

	ts = devm_kzalloc(&spi->dev, sizeof(*ts), GFP_KERNEL);
	if (!ts)
		return -ENOMEM;

	ts->spi = spi;
	spi_set_drvdata(spi, ts);

	packet = devm_kzalloc(&spi->dev, SW49410_PACKET_SIZE, GFP_KERNEL);
	if (!packet)
		return -ENOMEM;
	ts->packet = packet;

	error = sw49410_ts_spi_get_gpio_config(ts);
	if (error) {
		dev_err(&spi->dev, "failed to acquire reset pin\n");
		return error;
	}

	error = sw49410_ts_spi_reset(ts);
	if (error) {
		dev_err(&spi->dev, "reset failed: %d\n", error);
		return error;
	}

	error = sw49410_ts_spi_create_touch_input(ts);
	if (error) {
		dev_err(&spi->dev, "failed to create input device %d\n", error);
		return error;
	}

	error = input_register_device(ts->input);
	if (error) {
		dev_err(&spi->dev, "failed to register input device: %d\n", error);
		return error;
	}

	ts->panel_follower.funcs = &sw49410_ts_spi_panel_follower_funcs;
	error = drm_panel_add_follower(&spi->dev, &ts->panel_follower);
	if (error) {
		dev_err(&spi->dev, "failed to add drm follower %d\n", error);
		return error;
	}

	spin_lock_init(&irq_lock);
	irq = of_irq_get((&spi->dev)->of_node, 0);
	if (irq < 0) {
		dev_err(&spi->dev, "failed to get IRQ: %d\n", irq);
		return irq;
	}
	ts->irq = irq;

	error = devm_request_threaded_irq(&spi->dev, ts->irq,
					  NULL, sw49410_ts_spi_irq_handler,
					  IRQF_ONESHOT | IRQF_TRIGGER_FALLING,
					  "sw49410-ts-spi", ts);
	if (error) {
		dev_err(&spi->dev, "failed to request irq %d\n", error);
		return error;
	}

	error = sw49410_ts_spi_init(ts);
	if (error) {
		dev_err(&spi->dev, "init sequence failed to send %d\n", error);
		return error;
	}

	dev_info(&spi->dev, "SW49410 probe successful\n");
	return 0;
}

static void sw49410_ts_spi_remove(struct spi_device *spi)
{
	struct sw49410_ts_spi *ts = spi_get_drvdata(spi);

	drm_panel_remove_follower(&ts->panel_follower);
	if (ts->input)
		input_unregister_device(ts->input);
	sw49410_ts_spi_disable_irq(ts);
	free_irq(ts->irq, (void *)ts);
}

#ifdef CONFIG_OF
static const struct of_device_id sw49410_of_match[] = {
	{.compatible = "siw,sw49410-ts-spi"},
	{ }
};
MODULE_DEVICE_TABLE(of, sw49410_of_match);
#endif

static DEFINE_SIMPLE_DEV_PM_OPS(sw49410_ts_spi_pm_ops,
				sw49410_ts_spi_suspend,
				sw49410_ts_spi_resume);

static struct spi_driver sw49410_ts_spi_driver = {
	.driver = {
		.name	= "sw49410-ts-spi",
		.pm = pm_sleep_ptr(&sw49410_ts_spi_pm_ops),
		.of_match_table = sw49410_of_match,
	},
	.probe = sw49410_ts_spi_probe,
	.remove = sw49410_ts_spi_remove,
};

module_spi_driver(sw49410_ts_spi_driver);

MODULE_AUTHOR("Paul Sajna <sajattack@postmarketos.org>");
MODULE_DESCRIPTION("LG/SiliconWorks SW49410 touchscreen driver for SPI");
MODULE_LICENSE("Dual MIT/GPL");
