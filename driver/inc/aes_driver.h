#ifndef AES_DRIVER_H
#define AES_DRIVER_H

#include <linux/device.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/printk.h>
#include <linux/regmap.h>
#include <linux/slab.h>
#include <linux/sysfs.h>

#define DRIVER_NAME "AES"

#define SYSFS_BUFFER_LEN 10

/* Macros for read-only and read-write attributes */
#define DEVICE_ATTR_RW(_name)                                                  \
  struct device_attribute dev_attr_##_name = __ATTR_RW(_name)

#define DEVICE_ATTR_R(_name)                                                   \
  struct device_attribute dev_attr_##_name = __ATTR_RO(_name)

/* Register offsets */
#define enable_reg 0x0000
#define enable_reg_RST 0x0000
#define aes_key_choice_reg 0x0004
#define aes_key_choice_reg_RST 0x0000
#define plaintext_reg0 0x0008
#define plaintext_reg0_RST 0x0000
#define plaintext_reg1 0x000C
#define plaintext_reg1_RST 0x0000
#define plaintext_reg2 0x0010
#define plaintext_reg2_RST 0x0000
#define plaintext_reg3 0x0014
#define plaintext_reg3_RST 0x0000
#define key_reg0 0x0018
#define key_reg0_RST 0x0000
#define key_reg1 0x001C
#define key_reg1_RST 0x0000
#define key_reg2 0x0020
#define key_reg2_RST 0x0000
#define key_reg3 0x0024
#define key_reg3_RST 0x0000
#define key_reg4 0x0028
#define key_reg4_RST 0x0000
#define key_reg5 0x002C
#define key_reg5_RST 0x0000
#define key_reg6 0x0030
#define key_reg6_RST 0x0000
#define key_reg7 0x0034
#define key_reg7_RST 0x0000
#define done_reg 0x0048
#define comp_state_reg 0x004C
#define ciphertext_reg0 0x0050
#define ciphertext_reg1 0x0054
#define ciphertext_reg2 0x0058
#define ciphertext_reg3 0x005C

/* Bitfields */
#define AES_ENABLE_BIT BIT(0)
#define AES_KEY_CHOICE_MASK GENMASK(1, 0)
#define AES_KEY_CHOICE_BIT_OFFSET 0
#define DONE_BIT BIT(0)
#define COMP_STATE_MASK GENMASK(1, 0)
#define COMP_STATE_BIT_OFFSET 0

#endif // AES_DRIVER_H
