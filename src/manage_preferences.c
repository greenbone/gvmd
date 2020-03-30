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
 * @brief GVM manage layer: Preference utils.
 */

#include "manage_preferences.h"

#include <stdlib.h>

/**
 * @brief Create a new preference.
 *
 * @param[in]  id        ID of preference.
 * @param[in]  name      Name of preference.
 * @param[in]  type      Type of preference.
 * @param[in]  value     Value of preference.
 * @param[in]  nvt_name  Name of NVT of preference.
 * @param[in]  nvt_oid   OID of NVT of preference.
 * @param[in]  alts      Array of gchar's.  Alternative values for type radio.
 * @param[in]  default_value   Default value of preference.
 * @param[in]  hr_name   Extended, more human-readable name of the preference.
 * @param[in]  free_strings Whether string fields are freed by preference_free.
 *
 * @return Newly allocated preference.
 */
gpointer
preference_new (char *id, char *name, char *type, char *value, char *nvt_name,
                char *nvt_oid, array_t *alts, char* default_value,
                char *hr_name, int free_strings)
{
  preference_t *preference;

  preference = (preference_t*) g_malloc0 (sizeof (preference_t));
  preference->id = id;
  preference->name = name;
  preference->type = type;
  preference->value = value;
  preference->nvt_name = nvt_name;
  preference->nvt_oid = nvt_oid;
  preference->alts = alts;
  preference->default_value = default_value;
  preference->hr_name = hr_name;
  preference->free_strings = free_strings;

  return preference;
}

/**
 * @brief Frees a preference including its assigned values.
 *
 * @param[in]  preference  The preference to free.
 */
void
preference_free (preference_t *preference)
{
  if (preference == NULL)
    return;

  if (preference->alts)
    g_ptr_array_free (preference->alts, TRUE);
  if (preference->free_strings)
    {
      free (preference->id);
      free (preference->name);
      free (preference->type);
      free (preference->value);
      free (preference->nvt_name);
      free (preference->nvt_oid);
      free (preference->default_value);
      free (preference->hr_name);
    }

  g_free (preference);
}

/**
 * @brief Cleanup preferences array.
 *
 * @param[in]  import_preferences  Import preferences.
 */
void
cleanup_import_preferences (array_t *import_preferences)
{
  if (import_preferences)
    {
      guint index;

      for (index = 0; index < import_preferences->len; index++)
        {
          preference_t *pref;
          pref = (preference_t*) g_ptr_array_index (import_preferences,
                                                    index);
          if (pref)
            preference_free (pref);
        }
      g_ptr_array_free (import_preferences, TRUE);
    }
}
