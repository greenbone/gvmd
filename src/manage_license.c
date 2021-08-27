/* Copyright (C) 2020-2021 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file manage_license.c
 * @brief GVM management layer: License information.
 *
 * Non-SQL license information code for the GVM management layer.
 */

#include "manage_acl.h"
#include "manage_license.h"
#include "utils.h"

/* Data types */

/**
 * @brief Allocates a new license metadata struct
 *
 * @return Newly allocated license metadata. Free with license_meta_free.
 */
license_meta_t *
license_meta_new ()
{
  return g_malloc0 (sizeof (license_meta_t));
}

/**
 * @brief Frees a license metadata struct and its fields.
 *
 * @param[in]  data  The data struct to free.
 */
void
license_meta_free (license_meta_t *data)
{
  if (data == NULL)
    return;

  free (data->id);
  free (data->version);
  free (data->title);
  free (data->type);
  free (data->customer);

  g_free (data);
}

/**
 * @brief Allocates a new license appliance data struct
 *
 * @return Newly allocated license appliance data. Free with license_meta_free.
 */
license_appliance_t *
license_appliance_new ()
{
  return g_malloc0 (sizeof (license_appliance_t));
}

/**
 * @brief Frees a license appliance data struct and its fields.
 *
 * @param[in]  data  The data struct to free.
 */
void
license_appliance_free (license_appliance_t *data)
{
  if (data == NULL)
    return;

  free (data->model);
  free (data->model_type);

  g_free (data);
}

/**
 * @brief Allocates a new license data struct
 *
 * @return Newly allocated license data. Free with license_meta_free.
 */
license_data_t *
license_data_new ()
{
  license_data_t *data = g_malloc0 (sizeof (license_data_t));

  data->meta = license_meta_new ();
  data->appliance = license_appliance_new ();

  data->keys = g_tree_new_full ((GCompareDataFunc) g_ascii_strcasecmp,
                                NULL, g_free, g_free);

  data->signatures = g_tree_new_full ((GCompareDataFunc) g_ascii_strcasecmp,
                                      NULL, g_free, g_free);

  return data;
}

/**
 * @brief Frees a license data struct and its fields.
 *
 * @param[in]  data  The data struct to free.
 */
void
license_data_free (license_data_t *data)
{
  if (data == NULL)
    return;

  license_meta_free (data->meta);
  license_appliance_free (data->appliance);
  g_tree_destroy (data->keys);
  g_tree_destroy (data->signatures);

  g_free (data);
}

/* Actions */

/**
 * @brief Update the license file by replacing it with the given one.
 *
 * @param[in]  new_license  The content of the new license.
 *
 * @return 0 success, 99 permission denied.
 */
int
manage_update_license_file (const char *new_license)
{
  if (! acl_user_may ("modify_license"))
    return 99;

  g_message ("%s: Uploaded new license file (%lu bytes)",
             __func__, strlen (new_license));

  return 0;
}

/**
 * @brief Get the current license information.
 *
 * @param[out] status       The validation status (e.g. "valid", "expired").
 * @param[out] license_data The content of the license organized in a struct.
 *
 * @return 0 success, 1 service unavailable, 99 permission denied.
 */
int
manage_get_license (gchar **status,
                    license_data_t **license_data)
{
  if (! acl_user_may ("get_license"))
    return 99;

  if (status)
    *status = g_strdup ("active");

  if (license_data)
    {
      *license_data = license_data_new ();
      license_meta_t *license_meta = (*license_data)->meta;
      license_appliance_t *license_appliance = (*license_data)->appliance;

      // TODO : replace dummy data with data from license service
      license_meta->id = g_strdup ("4711");
      license_meta->version = g_strdup_printf("1.0.0");
      license_meta->title = g_strdup ("Test License");
      license_meta->type = g_strdup ("trial");
      license_meta->customer = g_strdup ("Jane Doe");
      license_meta->created = time (NULL) - 3600;
      license_meta->begins = time (NULL);
      license_meta->expires = time (NULL) + 3600 * 24 * 8;

      license_appliance->model = g_strdup ("trial");
      license_appliance->model_type = g_strdup ("virtual");
      license_appliance->sensor = FALSE;

      g_tree_replace ((*license_data)->keys,
                      g_strdup ("feed"),
                      g_strdup ("*base64 GSF key*"));

      g_tree_replace ((*license_data)->signatures,
                      g_strdup ("license"),
                      g_strdup ("*base64 signature*"));
    }

  return 0;
}
