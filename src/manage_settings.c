/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Filter utilities.
 *
 * Filter parser and handling utilities code for the GVM management layer.
 */

#include <assert.h>
#include "manage_settings.h"
#include "manage.h" // for current_credentials

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"


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

/**
 * @brief Return the Note/Override Excerpt Size user setting as an int.
 *
 * @return The excerpt size.
 */
int
setting_excerpt_size_int ()
{
  if (current_credentials.excerpt_size <= 0)
    return EXCERPT_SIZE_DEFAULT;
  return current_credentials.excerpt_size;
}

/**
 * @brief Check whether a setting is the Default CA Cert setting.
 *
 * @param[in]  uuid  UUID of setting.
 *
 * @return 1 if Default CA Cert, else 0.
 */
int
setting_is_default_ca_cert (const gchar *uuid)
{
  return strcmp (uuid, SETTING_UUID_DEFAULT_CA_CERT) == 0;
}

/**
 * @brief Return max, adjusted according to maximum allowed rows.
 *
 * @param[in]  max  Max.
 * @param[in]  ignore_max_rows_per_page  Whether to ignore "Max Rows Per Page"
 *
 * @return Adjusted max.
 */
int
manage_max_rows (int max, int ignore_max_rows_per_page)
{
  int max_rows;

  if (current_credentials.uuid == NULL
      || ignore_max_rows_per_page
      || setting_value_int (SETTING_UUID_MAX_ROWS_PER_PAGE, &max_rows))
    return max;

  if (max_rows && (max < 0 || max > max_rows))
    return max_rows;
  return max;
}
