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
 * @file  manage_config_host_discovery.c
 * @brief GVM management layer: Predefined config: "Base"
 *
 * This file contains the creation of the predefined config "Base".
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
 * @brief Make Base Scan Config.
 *
 * Caller must lock the db.
 *
 * @param[in]  uuid           UUID for new scan config.
 * @param[in]  selector_name  Name of NVT selector to use.
 */
void
make_config_base (char *const uuid, char *const selector_name)
{
  config_t config;

  /* Create the Base config. */

  sql ("INSERT into configs (uuid, name, owner, nvt_selector, comment,"
       " family_count, nvt_count, nvts_growing, families_growing,"
       " type, creation_time, modification_time, usage_type)"
       " VALUES ('%s', 'Base', NULL,"
       "         '%s', '%s',"
       "         0, 0, 0, 0, 0, m_now (), m_now (), 'scan');",
       uuid,
       selector_name,
       "Basic configuration template with a minimum set of NVTs"
       " required for a scan.");

  config = sql_last_insert_id ();

  /* Add the NVTs to the config */

  // Ping host
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '" OID_PING_HOST "', 'Port scanners');",
       selector_name);

  // Nmap (NASL wrapper)
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.14259', 'Port scanners');",
       selector_name);

  // Host details
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.103997', 'Service detection');",
       selector_name);

  /* Update number of families and nvts. */

  sql ("UPDATE configs"
       " SET family_count = %i, nvt_count = %i,"
       "     modification_time = m_now ()"
       " WHERE id = %llu;",
       nvt_selector_family_count (selector_name, 0),
       nvt_selector_nvt_count (selector_name, NULL, 0),
       config);

  /* Add preferences. */

  sql ("INSERT INTO config_preferences (config, type, name, value)"
       " VALUES (%llu,"
       "         'SERVER_PREFS',"
       "         'auto_enable_dependencies',"
       "         'yes');",
       config);
}
