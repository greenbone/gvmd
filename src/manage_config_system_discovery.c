/* OpenVAS Manager
 * $Id$
 * Description: Manage library: NVTs for "System Discovery" scan configuration.
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
 * @brief Make System Discovery Scan Config.
 *
 * Caller must lock the db.
 *
 * @param[in]  uuid           UUID for new scan config.
 * @param[in]  selector_name  Name of NVT selector to use.
 */
void
make_config_system_discovery (char *const uuid, char *const selector_name)
{
  config_t config;

  sql ("BEGIN EXCLUSIVE;");

  /* Create the System Discovery config. */

  sql ("INSERT into configs (uuid, name, owner, nvt_selector, comment,"
       " family_count, nvt_count, nvts_growing, families_growing,"
       " creation_time, modification_time)"
       " VALUES ('%s', 'System Discovery', NULL,"
       "         '%s', 'Network System Discovery scan configuration.',"
       "         0, 0, 0, 0, now (), now ());",
       uuid,
       selector_name);

  config = sqlite3_last_insert_rowid (task_db);

  /* Add NVTs to the config. */

  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.100315', 'Port scanners');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.14259', 'Port scanners');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.50282', 'General');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.96207', 'Windows');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.103621', 'Windows');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.103220', 'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.102002', 'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.103633', 'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.103804', 'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.96200', 'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.103675', 'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.103817', 'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.103628', 'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.803719', 'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.103799', 'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.103685', 'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.103809', 'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.103707', 'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.103418', 'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.10267', 'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.103417', 'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.103648', 'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.103779', 'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.103997', 'Service detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.10884', 'Service detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.102011', 'Service detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.101013', 'Service detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.103416', 'SNMP');",
       selector_name);

  /* Update number of families and nvts. */

  sql ("UPDATE configs"
       " SET family_count = %i, nvt_count = %i,"
       "     modification_time = now ()"
       " WHERE ROWID = %llu;",
       nvt_selector_family_count (selector_name, 0),
       nvt_selector_nvt_count (selector_name, NULL, 0),
       config);

  sql ("COMMIT;");
}
