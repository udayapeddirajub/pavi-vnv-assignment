/*  AES.c
 *	 Linux platform device driver for IP read/write.
 *   Interfaces via AXI
 *	 Utilizes regmap for register access and sysfs for exposing to userspace
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.

 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "aes_driver.h"

struct pixxel_AES_config {
  const struct regmap_config *reg_map_config;
};

struct pixxel_AES_dev {
  unsigned int dummy;
};

static const struct regmap_range AES_wr_range[] = {
    {.range_min = enable_reg, .range_max = enable_reg},
    {.range_min = aes_key_choice_reg, .range_max = aes_key_choice_reg},
    {.range_min = plaintext_reg0, .range_max = plaintext_reg0},
    {.range_min = plaintext_reg1, .range_max = plaintext_reg1},
    {.range_min = plaintext_reg2, .range_max = plaintext_reg2},
    {.range_min = plaintext_reg3, .range_max = plaintext_reg3},
    {.range_min = key_reg0, .range_max = key_reg0},
    {.range_min = key_reg1, .range_max = key_reg1},
    {.range_min = key_reg2, .range_max = key_reg2},
    {.range_min = key_reg3, .range_max = key_reg3},
    {.range_min = key_reg4, .range_max = key_reg4},
    {.range_min = key_reg5, .range_max = key_reg5},
    {.range_min = key_reg6, .range_max = key_reg6},
    {.range_min = key_reg7, .range_max = key_reg7},

};

/* All registers readable by default */
static const struct regmap_range AES_rd_range[] = {
    {.range_min = enable_reg, .range_max = enable_reg},
    {.range_min = aes_key_choice_reg, .range_max = aes_key_choice_reg},
    {.range_min = plaintext_reg0, .range_max = plaintext_reg0},
    {.range_min = plaintext_reg1, .range_max = plaintext_reg1},
    {.range_min = plaintext_reg2, .range_max = plaintext_reg2},
    {.range_min = plaintext_reg3, .range_max = plaintext_reg3},
    {.range_min = key_reg0, .range_max = key_reg0},
    {.range_min = key_reg1, .range_max = key_reg1},
    {.range_min = key_reg2, .range_max = key_reg2},
    {.range_min = key_reg3, .range_max = key_reg3},
    {.range_min = key_reg4, .range_max = key_reg4},
    {.range_min = key_reg5, .range_max = key_reg5},
    {.range_min = key_reg6, .range_max = key_reg6},
    {.range_min = key_reg7, .range_max = key_reg7},
    {.range_min = done_reg, .range_max = done_reg},
    {.range_min = comp_state_reg, .range_max = comp_state_reg},
    {.range_min = ciphertext_reg0, .range_max = ciphertext_reg0},
    {.range_min = ciphertext_reg1, .range_max = ciphertext_reg1},
    {.range_min = ciphertext_reg2, .range_max = ciphertext_reg2},
    {.range_min = ciphertext_reg3, .range_max = ciphertext_reg3},
};

static const struct regmap_access_table AES_wr_table = {
    .yes_ranges = AES_wr_range,
    .n_yes_ranges = ARRAY_SIZE(AES_wr_range),
};

static const struct regmap_access_table AES_rd_table = {
    .yes_ranges = AES_rd_range,
    .n_yes_ranges = ARRAY_SIZE(AES_rd_range),
};

static const struct regmap_config AES_regmap_config = {
    .reg_bits = 32,
    .val_bits = 32,
    .reg_stride = 4,
    .cache_type = REGCACHE_NONE,
    .wr_table = &AES_wr_table,
    .rd_table = &AES_rd_table,
};

static const struct pixxel_AES_config AES_config = {
    .reg_map_config = &AES_regmap_config,
    //.reg_map_irq_chip = &AES_regmap_irq_chip,
};

static struct of_device_id AES_of_match_ids[] = {
    {
        .compatible = "xlnx,AES_v1.0",
        .data = &AES_config,
    },
    {/* end of list */},
};

MODULE_DEVICE_TABLE(of, AES_of_match_ids);

/*--------------------------------------------------------- SYSFS ATTRIBUTES
 * ---------------------------------------------------------*/

static ssize_t aes_enable_show(struct device *dev,
                               struct device_attribute *attr, char *buf) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int val;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  ret = regmap_read(AES_regmap, enable_reg, &val);
  if (ret) {
    dev_err(dev, "AES: Failed to read enable_reg.\n");
    return ret;
  }

  return scnprintf(buf, PAGE_SIZE, "%u\n", !!(val & AES_ENABLE_BIT));
}

static ssize_t aes_enable_store(struct device *dev,
                                struct device_attribute *attr, const char *buf,
                                size_t count) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int data;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  if (kstrtouint(buf, SYSFS_BUFFER_LEN, &data)) {
    dev_err(dev, "AES: Unable to store aes_enable data.\n");
    return -EIO;
  }

  ret = regmap_update_bits(AES_regmap, enable_reg, AES_ENABLE_BIT,
                           data ? AES_ENABLE_BIT : 0);

  if (ret) {
    dev_err(dev, "AES: Failed to write to aes_enable.\n");
    return ret;
  }

  dev_info(dev, "AES: Wrote value %u to aes_enable.\n", data);
  return count;
}

static ssize_t aes_key_choice_show(struct device *dev,
                                   struct device_attribute *attr, char *buf) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int val;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  ret = regmap_read(AES_regmap, aes_key_choice_reg, &val);
  if (ret) {
    dev_err(dev, "AES: Failed to read aes_key_choice_reg.\n");
    return ret;
  }

  return scnprintf(buf, PAGE_SIZE, "%lu\n",
                   (val & AES_KEY_CHOICE_MASK) >> AES_KEY_CHOICE_BIT_OFFSET);
}

static ssize_t aes_key_choice_store(struct device *dev,
                                    struct device_attribute *attr,
                                    const char *buf, size_t count) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int data;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  if (kstrtouint(buf, SYSFS_BUFFER_LEN, &data)) {
    dev_err(dev, "AES: Unable to store aes_key_choice data.\n");
    return -EIO;
  }

  data = (data >> AES_KEY_CHOICE_BIT_OFFSET);
  data &= AES_KEY_CHOICE_MASK;
  ret = regmap_update_bits(AES_regmap, aes_key_choice_reg, AES_KEY_CHOICE_MASK,
                           data);

  if (ret) {
    dev_err(dev, "AES: Failed to write to aes_key_choice.\n");
    return ret;
  }

  dev_info(dev, "AES: Wrote value %u to aes_key_choice.\n", data);
  return count;
}

static ssize_t plain_text0_show(struct device *dev,
                                struct device_attribute *attr, char *buf) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int val;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  ret = regmap_read(AES_regmap, plaintext_reg0, &val);
  if (ret) {
    dev_err(dev, "AES: Failed to read plaintext_reg0.\n");
    return ret;
  }

  return scnprintf(buf, PAGE_SIZE, "%u\n", val);
}

static ssize_t plain_text0_store(struct device *dev,
                                 struct device_attribute *attr, const char *buf,
                                 size_t count) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int data;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  if (kstrtouint(buf, SYSFS_BUFFER_LEN, &data)) {
    dev_err(dev, "AES: Unable to store plain_text0 data.\n");
    return -EIO;
  }

  ret = regmap_write(AES_regmap, plaintext_reg0, data);
  if (ret) {
    dev_err(dev, "AES: Failed to write to plain_text0.\n");
    return ret;
  }

  dev_info(dev, "AES: Wrote value %u to plain_text0.\n", data);
  return count;
}

static ssize_t plain_text1_show(struct device *dev,
                                struct device_attribute *attr, char *buf) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int val;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  ret = regmap_read(AES_regmap, plaintext_reg1, &val);
  if (ret) {
    dev_err(dev, "AES: Failed to read plaintext_reg1.\n");
    return ret;
  }

  return scnprintf(buf, PAGE_SIZE, "%u\n", val);
}

static ssize_t plain_text1_store(struct device *dev,
                                 struct device_attribute *attr, const char *buf,
                                 size_t count) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int data;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  if (kstrtouint(buf, SYSFS_BUFFER_LEN, &data)) {
    dev_err(dev, "AES: Unable to store plain_text1 data.\n");
    return -EIO;
  }

  ret = regmap_write(AES_regmap, plaintext_reg1, data);
  if (ret) {
    dev_err(dev, "AES: Failed to write to plain_text1.\n");
    return ret;
  }

  dev_info(dev, "AES: Wrote value %u to plain_text1.\n", data);
  return count;
}

static ssize_t plain_text2_show(struct device *dev,
                                struct device_attribute *attr, char *buf) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int val;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  ret = regmap_read(AES_regmap, plaintext_reg2, &val);
  if (ret) {
    dev_err(dev, "AES: Failed to read plaintext_reg2.\n");
    return ret;
  }

  return scnprintf(buf, PAGE_SIZE, "%u\n", val);
}

static ssize_t plain_text2_store(struct device *dev,
                                 struct device_attribute *attr, const char *buf,
                                 size_t count) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int data;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  if (kstrtouint(buf, SYSFS_BUFFER_LEN, &data)) {
    dev_err(dev, "AES: Unable to store plain_text2 data.\n");
    return -EIO;
  }

  ret = regmap_write(AES_regmap, plaintext_reg2, data);
  if (ret) {
    dev_err(dev, "AES: Failed to write to plain_text2.\n");
    return ret;
  }

  dev_info(dev, "AES: Wrote value %u to plain_text2.\n", data);
  return count;
}

static ssize_t plain_text3_show(struct device *dev,
                                struct device_attribute *attr, char *buf) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int val;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  ret = regmap_read(AES_regmap, plaintext_reg3, &val);
  if (ret) {
    dev_err(dev, "AES: Failed to read plaintext_reg3.\n");
    return ret;
  }

  return scnprintf(buf, PAGE_SIZE, "%u\n", val);
}

static ssize_t plain_text3_store(struct device *dev,
                                 struct device_attribute *attr, const char *buf,
                                 size_t count) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int data;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  if (kstrtouint(buf, SYSFS_BUFFER_LEN, &data)) {
    dev_err(dev, "AES: Unable to store plain_text3 data.\n");
    return -EIO;
  }

  ret = regmap_write(AES_regmap, plaintext_reg3, data);
  if (ret) {
    dev_err(dev, "AES: Failed to write to plain_text3.\n");
    return ret;
  }

  dev_info(dev, "AES: Wrote value %u to plain_text3.\n", data);
  return count;
}

static ssize_t key0_show(struct device *dev, struct device_attribute *attr,
                         char *buf) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int val;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  ret = regmap_read(AES_regmap, key_reg0, &val);
  if (ret) {
    dev_err(dev, "AES: Failed to read key_reg0.\n");
    return ret;
  }

  return scnprintf(buf, PAGE_SIZE, "%u\n", val);
}

static ssize_t key0_store(struct device *dev, struct device_attribute *attr,
                          const char *buf, size_t count) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int data;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  if (kstrtouint(buf, SYSFS_BUFFER_LEN, &data)) {
    dev_err(dev, "AES: Unable to store key0 data.\n");
    return -EIO;
  }

  ret = regmap_write(AES_regmap, key_reg0, data);
  if (ret) {
    dev_err(dev, "AES: Failed to write to key0.\n");
    return ret;
  }

  dev_info(dev, "AES: Wrote value %u to key0.\n", data);
  return count;
}

static ssize_t key1_show(struct device *dev, struct device_attribute *attr,
                         char *buf) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int val;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  ret = regmap_read(AES_regmap, key_reg1, &val);
  if (ret) {
    dev_err(dev, "AES: Failed to read key_reg1.\n");
    return ret;
  }

  return scnprintf(buf, PAGE_SIZE, "%u\n", val);
}

static ssize_t key1_store(struct device *dev, struct device_attribute *attr,
                          const char *buf, size_t count) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int data;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  if (kstrtouint(buf, SYSFS_BUFFER_LEN, &data)) {
    dev_err(dev, "AES: Unable to store key1 data.\n");
    return -EIO;
  }

  ret = regmap_write(AES_regmap, key_reg1, data);
  if (ret) {
    dev_err(dev, "AES: Failed to write to key1.\n");
    return ret;
  }

  dev_info(dev, "AES: Wrote value %u to key1.\n", data);
  return count;
}

static ssize_t key2_show(struct device *dev, struct device_attribute *attr,
                         char *buf) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int val;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  ret = regmap_read(AES_regmap, key_reg2, &val);
  if (ret) {
    dev_err(dev, "AES: Failed to read key_reg2.\n");
    return ret;
  }

  return scnprintf(buf, PAGE_SIZE, "%u\n", val);
}

static ssize_t key2_store(struct device *dev, struct device_attribute *attr,
                          const char *buf, size_t count) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int data;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  if (kstrtouint(buf, SYSFS_BUFFER_LEN, &data)) {
    dev_err(dev, "AES: Unable to store key2 data.\n");
    return -EIO;
  }

  ret = regmap_write(AES_regmap, key_reg2, data);
  if (ret) {
    dev_err(dev, "AES: Failed to write to key2.\n");
    return ret;
  }

  dev_info(dev, "AES: Wrote value %u to key2.\n", data);
  return count;
}

static ssize_t key3_show(struct device *dev, struct device_attribute *attr,
                         char *buf) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int val;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  ret = regmap_read(AES_regmap, key_reg3, &val);
  if (ret) {
    dev_err(dev, "AES: Failed to read key_reg3.\n");
    return ret;
  }

  return scnprintf(buf, PAGE_SIZE, "%u\n", val);
}

static ssize_t key3_store(struct device *dev, struct device_attribute *attr,
                          const char *buf, size_t count) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int data;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  if (kstrtouint(buf, SYSFS_BUFFER_LEN, &data)) {
    dev_err(dev, "AES: Unable to store key3 data.\n");
    return -EIO;
  }

  ret = regmap_write(AES_regmap, key_reg3, data);
  if (ret) {
    dev_err(dev, "AES: Failed to write to key3.\n");
    return ret;
  }

  dev_info(dev, "AES: Wrote value %u to key3.\n", data);
  return count;
}

static ssize_t key4_show(struct device *dev, struct device_attribute *attr,
                         char *buf) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int val;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  ret = regmap_read(AES_regmap, key_reg4, &val);
  if (ret) {
    dev_err(dev, "AES: Failed to read key_reg4.\n");
    return ret;
  }

  return scnprintf(buf, PAGE_SIZE, "%u\n", val);
}

static ssize_t key4_store(struct device *dev, struct device_attribute *attr,
                          const char *buf, size_t count) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int data;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  if (kstrtouint(buf, SYSFS_BUFFER_LEN, &data)) {
    dev_err(dev, "AES: Unable to store key4 data.\n");
    return -EIO;
  }

  ret = regmap_write(AES_regmap, key_reg4, data);
  if (ret) {
    dev_err(dev, "AES: Failed to write to key4.\n");
    return ret;
  }

  dev_info(dev, "AES: Wrote value %u to key4.\n", data);
  return count;
}

static ssize_t key5_show(struct device *dev, struct device_attribute *attr,
                         char *buf) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int val;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  ret = regmap_read(AES_regmap, key_reg5, &val);
  if (ret) {
    dev_err(dev, "AES: Failed to read key_reg5.\n");
    return ret;
  }

  return scnprintf(buf, PAGE_SIZE, "%u\n", val);
}

static ssize_t key5_store(struct device *dev, struct device_attribute *attr,
                          const char *buf, size_t count) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int data;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  if (kstrtouint(buf, SYSFS_BUFFER_LEN, &data)) {
    dev_err(dev, "AES: Unable to store key5 data.\n");
    return -EIO;
  }

  ret = regmap_write(AES_regmap, key_reg5, data);
  if (ret) {
    dev_err(dev, "AES: Failed to write to key5.\n");
    return ret;
  }

  dev_info(dev, "AES: Wrote value %u to key5.\n", data);
  return count;
}

static ssize_t key6_show(struct device *dev, struct device_attribute *attr,
                         char *buf) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int val;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  ret = regmap_read(AES_regmap, key_reg6, &val);
  if (ret) {
    dev_err(dev, "AES: Failed to read key_reg6.\n");
    return ret;
  }

  return scnprintf(buf, PAGE_SIZE, "%u\n", val);
}

static ssize_t key6_store(struct device *dev, struct device_attribute *attr,
                          const char *buf, size_t count) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int data;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  if (kstrtouint(buf, SYSFS_BUFFER_LEN, &data)) {
    dev_err(dev, "AES: Unable to store key6 data.\n");
    return -EIO;
  }

  ret = regmap_write(AES_regmap, key_reg6, data);
  if (ret) {
    dev_err(dev, "AES: Failed to write to key6.\n");
    return ret;
  }

  dev_info(dev, "AES: Wrote value %u to key6.\n", data);
  return count;
}

static ssize_t key7_show(struct device *dev, struct device_attribute *attr,
                         char *buf) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int val;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  ret = regmap_read(AES_regmap, key_reg7, &val);
  if (ret) {
    dev_err(dev, "AES: Failed to read key_reg7.\n");
    return ret;
  }

  return scnprintf(buf, PAGE_SIZE, "%u\n", val);
}

static ssize_t key7_store(struct device *dev, struct device_attribute *attr,
                          const char *buf, size_t count) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int data;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  if (kstrtouint(buf, SYSFS_BUFFER_LEN, &data)) {
    dev_err(dev, "AES: Unable to store key7 data.\n");
    return -EIO;
  }

  ret = regmap_write(AES_regmap, key_reg7, data);
  if (ret) {
    dev_err(dev, "AES: Failed to write to key7.\n");
    return ret;
  }

  dev_info(dev, "AES: Wrote value %u to key7.\n", data);
  return count;
}

static ssize_t done_show(struct device *dev, struct device_attribute *attr,
                         char *buf) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int val;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  ret = regmap_read(AES_regmap, done_reg, &val);
  if (ret) {
    dev_err(dev, "AES: Failed to read done_reg.\n");
    return ret;
  }

  return scnprintf(buf, PAGE_SIZE, "%u\n", !!(val & DONE_BIT));
}

static ssize_t comp_state_show(struct device *dev,
                               struct device_attribute *attr, char *buf) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int val;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  ret = regmap_read(AES_regmap, comp_state_reg, &val);
  if (ret) {
    dev_err(dev, "AES: Failed to read comp_state_reg.\n");
    return ret;
  }

  return scnprintf(buf, PAGE_SIZE, "%lu\n",
                   (val & COMP_STATE_MASK) >> COMP_STATE_BIT_OFFSET);
}

static ssize_t cipher_text0_show(struct device *dev,
                                 struct device_attribute *attr, char *buf) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int val;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  ret = regmap_read(AES_regmap, ciphertext_reg0, &val);
  if (ret) {
    dev_err(dev, "AES: Failed to read ciphertext_reg0.\n");
    return ret;
  }

  return scnprintf(buf, PAGE_SIZE, "%u\n", val);
}

static ssize_t cipher_text1_show(struct device *dev,
                                 struct device_attribute *attr, char *buf) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int val;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  ret = regmap_read(AES_regmap, ciphertext_reg1, &val);
  if (ret) {
    dev_err(dev, "AES: Failed to read ciphertext_reg1.\n");
    return ret;
  }

  return scnprintf(buf, PAGE_SIZE, "%u\n", val);
}

static ssize_t cipher_text2_show(struct device *dev,
                                 struct device_attribute *attr, char *buf) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int val;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  ret = regmap_read(AES_regmap, ciphertext_reg2, &val);
  if (ret) {
    dev_err(dev, "AES: Failed to read ciphertext_reg2.\n");
    return ret;
  }

  return scnprintf(buf, PAGE_SIZE, "%u\n", val);
}

static ssize_t cipher_text3_show(struct device *dev,
                                 struct device_attribute *attr, char *buf) {
  struct regmap *AES_regmap = dev_get_regmap(dev, NULL);
  unsigned int val;
  int ret;

  if (!AES_regmap) {
    dev_err(dev, "AES: Failed to get regmap.\n");
    return -ENODEV;
  }

  ret = regmap_read(AES_regmap, ciphertext_reg3, &val);
  if (ret) {
    dev_err(dev, "AES: Failed to read ciphertext_reg3.\n");
    return ret;
  }

  return scnprintf(buf, PAGE_SIZE, "%u\n", val);
}

DEVICE_ATTR_RW(aes_enable);
DEVICE_ATTR_RW(aes_key_choice);
DEVICE_ATTR_RW(plain_text0);
DEVICE_ATTR_RW(plain_text1);
DEVICE_ATTR_RW(plain_text2);
DEVICE_ATTR_RW(plain_text3);
DEVICE_ATTR_RW(key0);
DEVICE_ATTR_RW(key1);
DEVICE_ATTR_RW(key2);
DEVICE_ATTR_RW(key3);
DEVICE_ATTR_RW(key4);
DEVICE_ATTR_RW(key5);
DEVICE_ATTR_RW(key6);
DEVICE_ATTR_RW(key7);
DEVICE_ATTR_R(done);
DEVICE_ATTR_R(comp_state);
DEVICE_ATTR_R(cipher_text0);
DEVICE_ATTR_R(cipher_text1);
DEVICE_ATTR_R(cipher_text2);
DEVICE_ATTR_R(cipher_text3);

static struct attribute *AES_attrs[] = {&dev_attr_aes_enable.attr,
                                        &dev_attr_aes_key_choice.attr,
                                        &dev_attr_plain_text0.attr,
                                        &dev_attr_plain_text1.attr,
                                        &dev_attr_plain_text2.attr,
                                        &dev_attr_plain_text3.attr,
                                        &dev_attr_key0.attr,
                                        &dev_attr_key1.attr,
                                        &dev_attr_key2.attr,
                                        &dev_attr_key3.attr,
                                        &dev_attr_key4.attr,
                                        &dev_attr_key5.attr,
                                        &dev_attr_key6.attr,
                                        &dev_attr_key7.attr,
                                        &dev_attr_done.attr,
                                        &dev_attr_comp_state.attr,
                                        &dev_attr_cipher_text0.attr,
                                        &dev_attr_cipher_text1.attr,
                                        &dev_attr_cipher_text2.attr,
                                        &dev_attr_cipher_text3.attr,
                                        NULL};

ATTRIBUTE_GROUPS(AES);

/*--------------------------------------------------------- PROBE AND REMOVE
 * ---------------------------------------------------------*/

static int AES_probe(struct platform_device *pdev) {
  struct resource *r_mem; /* IO mem resources */
  void __iomem *base_addr;
  //struct device_node *node = pdev->dev.of_node; //unused variable
  const struct of_device_id *match;
  struct pixxel_AES_config *AES_config;
  struct regmap *AES_regmap;
  struct pixxel_AES_dev *AES_dev;
  dev_info(&pdev->dev, "Probing Device Tree\n");

  /* Get the memory resource */
  r_mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
  if (!r_mem) {
    dev_err(&pdev->dev, "Failed to get memory resource. Invalid address.\n");
    return -ENODEV;
  }

  /* Map physical memory region to virtual address */
  base_addr = devm_ioremap_resource(&pdev->dev, r_mem);
  if (IS_ERR(base_addr)) {
    dev_err(&pdev->dev, "Failed to map memory region\n");
    return PTR_ERR(base_addr);
  }

  /* Setup regmap */
  match = of_match_node(AES_of_match_ids, pdev->dev.of_node);
  if (!match) {
    dev_err(&pdev->dev, "Could not find a matching OF ID\n");
    return -ENODEV;
  }
  if (!match->data) {
    dev_err(&pdev->dev, "Device %s has no data\n", match->name);
    return -ENODATA;
  }
  AES_config = (struct pixxel_AES_config *)match->data;
  AES_regmap =
      devm_regmap_init_mmio(&pdev->dev, base_addr, AES_config->reg_map_config);
  if (IS_ERR(AES_regmap)) {
    dev_err(&pdev->dev, "Could not initialize regmap");
    return PTR_ERR(AES_regmap);
  }

  /* Set device data */
  AES_dev = devm_kzalloc(&pdev->dev, sizeof(*AES_dev), GFP_KERNEL);
  platform_set_drvdata(pdev, AES_dev);

  dev_info(&pdev->dev,
           "AES at physical addr: 0x%llx mapped to virtual address: %p \n",
           (unsigned long long)r_mem->start, base_addr);
  return 0;
}

static void AES_remove(struct platform_device *pdev) {
  dev_set_drvdata(&pdev->dev, NULL);
  return;
}

static struct platform_driver AES_driver = {
    .driver =
        {
            .name = DRIVER_NAME,
            .owner = THIS_MODULE,
            .of_match_table = AES_of_match_ids,
            .dev_groups = AES_groups,
        },
    .probe = AES_probe,
    .remove = AES_remove,
};

module_platform_driver(AES_driver) MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arya Pathak");
MODULE_AUTHOR("Ashish Kumar");
MODULE_DESCRIPTION("AXI IP driver for AES");
