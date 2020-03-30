/* Copyright (C) 2019 Greenbone Networks GmbH
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
 * @file
 * @brief GVM manage layer: GET utils.
 */

#include "manage_get.h"
#include "manage_sql.h"
#include "sql.h"

#include <stdlib.h>
#include <string.h>

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

/**
 * @brief Sets a type-specific extra parameter in a get_data_t.
 *
 * The names and values will be duplicated.
 *
 * @param[in]  data   The get data to add the parameter to.
 * @param[in]  name   Name of the parameter to add.
 * @param[in]  value  Value of the parameter to add.
 */
void
get_data_set_extra (get_data_t *data, const char *name, const char *value)
{
  if (name == NULL)
    return;

  if (data->extra_params == NULL)
    {
      if (value == NULL)
        return;

      data->extra_params
        = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    }

  if (value)
    g_hash_table_insert (data->extra_params,
                         g_strdup (name),
                         g_strdup (value));
  else
    g_hash_table_remove (data->extra_params, name);
}


/* GET iterators. */

/**
 * @brief Get the resource from a GET iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Resource.
 */
resource_t
get_iterator_resource (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return iterator_int64 (iterator, 0);
}

/**
 * @brief Get the UUID of the resource from a GET iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return UUID of the resource or NULL if iteration is complete.
 */
DEF_ACCESS (get_iterator_uuid, 1);

/**
 * @brief Get the name of the resource from a GET iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name of the resource or NULL if iteration is complete.
 */
DEF_ACCESS (get_iterator_name, 2);

/**
 * @brief Get the comment from a GET iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Comment.
 */
const char*
get_iterator_comment (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return "";
  ret = iterator_string (iterator, 3);
  return ret ? ret : "";
}

/**
 * @brief Get the creation time of the resource from a GET iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Creation time of the resource or NULL if iteration is complete.
 */
DEF_ACCESS (get_iterator_creation_time, 4);

/**
 * @brief Get the modification time of the resource from a GET iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Modification time of the resource or NULL if iteration is complete.
 */
DEF_ACCESS (get_iterator_modification_time, 5);

/**
 * @brief Get the owner name of the resource from a GET iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Owner name of the resource or NULL if iteration is complete.
 */
DEF_ACCESS (get_iterator_owner_name, 8);

/**
 * @brief Get the owner from a GET iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Owner.
 */
user_t
get_iterator_owner (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return iterator_int64 (iterator, 9);
}
