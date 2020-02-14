/* Copyright (C) 2019 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * @file
 * @brief GVM manage layer: GET utils.
 */

#include "manage_get.h"

/**
 * @brief Reset command data.
 *
 * @param[in]  data  Command data.
 */
void
get_data_reset (get_data_t *data)
{
  free (data->id);
  free (data->filt_id);
  free (data->filter);
  free (data->filter_replace);
  free (data->filter_replacement);
  free (data->subtype);
  free (data->type);
  if (data->extra_params)
    g_hash_table_destroy (data->extra_params);

  memset (data, 0, sizeof (get_data_t));
}

/**
 * @brief Retrieves a type-specific extra parameter from a get_data_t.
 *
 * @param[in]  data   The get data to add the parameter to.
 * @param[in]  name   Name of the parameter to add.
 *
 * @return  Value of the parameter or NULL if not set.
 */
const char *
get_data_get_extra (const get_data_t *data, const char *name)
{
  if (data->extra_params == NULL)
    return NULL;
  else
    return g_hash_table_lookup (data->extra_params, name);
}
