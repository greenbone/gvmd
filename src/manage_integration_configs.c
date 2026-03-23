/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Integration configuration management in GVMD.
 *
 * This file contains the logic for modifying and getting integration
 * configurations.
 */

#include "manage_integration_configs.h"

#include "utils.h"

#include <assert.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Allocate and initialize integration configuration data.
 *
 * @return Newly allocated integration configuration data, or NULL on failure.
 */
integration_config_data_t
integration_config_data_new (void)
{
  integration_config_data_t data;

  data = g_malloc0 (sizeof (*data));
  if (data == NULL)
    return NULL;

  data->creation_time = 0;
  data->modification_time = 0;

  return data;
}

/**
 * @brief Free an integration configuration data object.
 *
 * @param[in] data  Integration configuration data to free.
 */
void
integration_config_data_free (integration_config_data_t data)
{
  if (data == NULL)
    return;

  g_free (data->uuid);
  g_free (data->name);
  g_free (data->comment);
  g_free (data->service_url);
  g_free (data->service_cacert);
  g_free (data->oidc_url);
  g_free (data->oidc_client_id);
  g_free (data->oidc_client_secret);

  g_free (data);
}