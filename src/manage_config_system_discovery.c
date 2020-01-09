/* Copyright (C) 2013-2018 Greenbone Networks GmbH
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
 * @file  manage_config_system_discovery.c
 * @brief GVM management layer: Predefined config: System Discovery
 *
 * This file contains the creation of the predefined config System Discovery.
 */

#include "manage.h"
#include "manage_sql.h"
#include "sql.h"

#include <assert.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md   main"

/**
 * @brief Ensure the Discovery config is up to date.
 *
 * @param[in]  uuid  UUID of config.
 *
 * @return 0 success, -1 error.
 */
int
check_config_system_discovery (const char *uuid)
{
  int update;

  update = 0;

  /* Check new NVT. */

  if (sql_int ("SELECT count (*) FROM nvt_selectors"
               " WHERE name = (SELECT nvt_selector FROM configs"
               "               WHERE uuid = '%s')"
               "       AND family_or_nvt = '1.3.6.1.4.1.25623.1.0.51662';",
               uuid)
      == 0)
    {
      sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
           " VALUES ((SELECT nvt_selector FROM configs WHERE uuid = '%s'), 0,"
           "         " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
           "         '1.3.6.1.4.1.25623.1.0.51662', 'General');",
           uuid);
      update = 1;
    }

  if (sql_int ("SELECT count (*) FROM nvt_selectors"
               " WHERE name = (SELECT nvt_selector FROM configs"
               "               WHERE uuid = '%s')"
               "       AND family_or_nvt = '1.3.6.1.4.1.25623.1.0.105937';",
               uuid)
      == 0)
    {
      sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
           " VALUES ((SELECT nvt_selector FROM configs WHERE uuid = '%s'), 0,"
           "         " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
           "         '1.3.6.1.4.1.25623.1.0.105937', 'Product detection');",
           uuid);
      update = 1;
    }

  if (update)
    update_config_cache_init (uuid);

  /* Check preferences. */

  update_config_preference (uuid,
                            "PLUGINS_PREFS",
                            OID_PING_HOST ":5:checkbox:"
                            "Mark unrechable Hosts as dead (not scanning)",
                            "yes",
                            TRUE);

  return 0;
}
