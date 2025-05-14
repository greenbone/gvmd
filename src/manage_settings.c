/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file manage_filter_utils.c
 * @brief GVM management layer: Filter utilities.
 *
 * Filter parser and handling utilities code for the GVM management layer.
 */

#include <assert.h>
#include "manage_settings.h"

/**
 * @brief Internal function for getting a setting value as a string.
 *
 * Should be set by init_manage_settings_funcs.
 */
static setting_value_func setting_value_internal;

/**
 * @brief Internal function for getting a setting value as an integer.
 *
 * Should be set by init_manage_settings_funcs.
 */
static setting_value_int_func setting_value_int_internal;

/**
 * @brief Get the value of a setting as a string.
 *
 * @param[in]   uuid   UUID of setting.
 * @param[out]  value  Freshly allocated value.
 *
 * @return 0 success, -1 error.
 */
int
setting_value (const char *uuid, char **value)
{
  assert (setting_value_internal);
  return setting_value_internal (uuid, value);
}

/**
 * @brief Get the value of a setting.
 *
 * @param[in]   uuid   UUID of setting.
 * @param[out]  value  Value.
 *
 * @return 0 success, -1 error.
 */
int
setting_value_int (const char *uuid, int *value)
{
  assert (setting_value_int_internal);
  return setting_value_int_internal (uuid, value);
}

/**
 * @brief Initialize functions of the manage_settings submodule.
 * 
 * @param[in] setting_value_f      Function for getting setting string values.
 * @param[in] setting_value_int_f  Function for getting setting int values.
 */
void
init_manage_settings_funcs (setting_value_func setting_value_f,
                            setting_value_int_func setting_value_int_f)
{
  setting_value_internal = setting_value_f;
  setting_value_int_internal = setting_value_int_f;
}