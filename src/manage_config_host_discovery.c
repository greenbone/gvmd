/* OpenVAS Manager
 * $Id$
 * Description: Manage library: NVTs for "Host Discovery" scan configuration.
 *
 * Authors:
 * Hani Benhabiles <hani.benhabiles@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2013 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
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

#include "manage.h"
#include "manage_sql.h"
#include "sql.h"

#include <assert.h>

/**
 * @brief Make Host Discovery Scan Config.
 *
 * Caller must lock the db.
 *
 * @param[in]  uuid           UUID for new scan config.
 * @param[in]  selector_name  Name of NVT selector to use.
 */
void
make_config_host_discovery (char *const uuid, char *const selector_name)
{
  config_t config;

  sql ("BEGIN EXCLUSIVE;");

  /* Create the Host Discovery config. */

  sql ("INSERT into configs (uuid, name, owner, nvt_selector, comment,"
       " family_count, nvt_count, nvts_growing, families_growing,"
       " creation_time, modification_time)"
       " VALUES ('%s', 'Host Discovery', NULL,"
       "         '%s', 'Network Host Discovery scan configuration.',"
       "         0, 0, 0, 0, now (), now ());",
       uuid,
       selector_name);

  config = sqlite3_last_insert_rowid (task_db);

  /* Add the Ping Host NVT to the config. */

  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.100315', 'Port scanners');",
       selector_name);

  /* Update number of families and nvts. */

  sql ("UPDATE configs"
       " SET family_count = %i, nvt_count = %i,"
       "     modification_time = now ()"
       " WHERE ROWID = %llu;",
       nvt_selector_family_count (selector_name, 0),
       nvt_selector_nvt_count (selector_name, NULL, 0),
       config);

  /* Add preferences for "ping host" nvt. */

  sql ("INSERT INTO config_preferences (config, type, name, value)"
       " VALUES (%llu,"
       "         'PLUGINS_PREFS',"
       "         'Ping Host[checkbox]:Mark unrechable Hosts as dead (not scanning)',"
       "         'yes');",
       config);

  sql ("INSERT INTO config_preferences (config, type, name, value)"
       " VALUES (%llu,"
       "         'PLUGINS_PREFS',"
       "         'Ping Host[checkbox]:Report about reachable Hosts',"
       "         'yes');",
       config);

  sql ("INSERT INTO config_preferences (config, type, name, value)"
       " VALUES (%llu,"
       "         'PLUGINS_PREFS',"
       "         'Ping Host[checkbox]:Report about unrechable Hosts',"
       "         'no');",
       config);

  sql ("COMMIT;");
}

/**
 * @brief Preference name.
 */
#define NAME "Global variable settings[checkbox]:Strictly unauthenticated"

/**
 * @brief Ensure the Host Discovery config is up to date.
 *
 * @param[in]  uuid  UUID of config.
 *
 * @return 0 success, -1 error.
 */
int
check_config_host_discovery (char *const uuid)
{
  int update;

  sql ("BEGIN EXCLUSIVE;");

  update = 0;

  /* Check new preference. */

  if (sql_int (0, 0,
               "SELECT count (*) FROM config_preferences"
               " WHERE config = (SELECT ROWID FROM configs WHERE uuid = '%s')"
               "       AND type = 'PLUGINS_PREFS'"
               "       AND name = '" NAME "';",
               uuid)
      == 0)
    {
      sql ("INSERT INTO config_preferences (config, type, name, value)"
           " VALUES ((SELECT ROWID FROM configs WHERE uuid = '%s'),"
           "         'PLUGINS_PREFS',"
           "         '" NAME "',"
           "         'yes');",
           uuid);
      update = 1;
    }

  /* Check new NVT. */

  if (sql_int (0, 0,
               "SELECT count (*) FROM nvt_selectors"
               " WHERE name = (SELECT nvt_selector FROM configs"
               "               WHERE uuid = '%s')"
               "       AND family_or_nvt = '1.3.6.1.4.1.25623.1.0.12288';",
               uuid)
      == 0)
    {
      sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
           " VALUES ((SELECT nvt_selector FROM configs WHERE uuid = '%s'), 0,"
           "         " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
           "         '1.3.6.1.4.1.25623.1.0.12288', 'Settings');",
           uuid);
      update = 1;
    }

  if (update)
    update_config_cache_init (uuid);

  sql ("COMMIT;");

  return 0;
}
