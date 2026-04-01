/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Greenbone Vulnerability Manager scanner relays SQL.
 */

#include "manage_scanner_relays.h"
#include "manage_sql.h"

#include <glib/gstdio.h>
#include <gvm/util/json.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain used for messages from this module.
 */
#define G_LOG_DOMAIN "md   manage"

/**
 * @brief Get the time the scanner relays were last updated in the database.
 *
 * @return The time in the "scanner_relays_update_time" meta table entry.
 */
time_t
get_scanner_relays_db_update_time ()
{
  long long db_update_time = 0;
  sql_int64_ps (&db_update_time,
                "SELECT value FROM meta"
                " WHERE name = 'scanner_relays_update_time'",
                NULL);
  return db_update_time;
}

/**
 * @brief Sets a scanner relays update time in the meta table.
 *
 * @param[in]  new_time  The new time to set.
 */
void
set_scanner_relays_update_time (time_t new_time)
{
  sql_ps ("INSERT INTO meta (name, value)"
          " VALUES ('scanner_relays_update_time', $1)"
          " ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value;",
          SQL_RESOURCE_PARAM (new_time),
          NULL);
}

/**
 * @brief Perform actions at the start of updating all scanner relays.
 *
 * The relay hosts and ports for all scanners are reset.
 */
void
update_all_scanner_relays_start ()
{
  sql_ps ("UPDATE scanners SET relay_host = NULL, relay_port = NULL", NULL);
}

/**
 * @brief Update all affected scanners according a relays list item
 *
 * @param[in]  item  Relays list item describing the scanner(s) and relay
 * @param[out] updated_scanner_uuids  Hashtable insert updated scanners into
 *
 * @return 0 success, -1 error
 */
int
update_all_scanner_relays_from_item (relays_list_item_t *item,
                                     GHashTable *updated_scanner_uuids)
{
  iterator_t iterator;

  if (item->protocol && strcmp (item->protocol, ""))
    {
      scanner_type_t sc_type;
      if (strcasecmp (item->protocol, "agent-control") == 0)
        sc_type = SCANNER_TYPE_AGENT_CONTROLLER_SENSOR;
      else if (strcasecmp (item->protocol, "openvasd") == 0)
        sc_type = SCANNER_TYPE_OPENVASD_SENSOR;
      else if (strcasecmp (item->protocol, "osp") == 0)
        sc_type = SCANNER_TYPE_OSP_SENSOR;
      else
        {
          g_warning ("%s: relay with unknown protocol '%s'",
                     __func__, item->protocol);
          return 0;
        }

      init_ps_iterator (&iterator,
                        "UPDATE scanners SET relay_host = $1, relay_port = $2"
                        " WHERE type = $3 AND host = $4 AND ($5 = 0 OR port = $5)"
                        " RETURNING uuid",
                        SQL_STR_PARAM (item->relay_host),
                        SQL_INT_PARAM (item->relay_port),
                        SQL_INT_PARAM (sc_type),
                        SQL_STR_PARAM (item->original_host),
                        SQL_INT_PARAM (item->original_port),
                        NULL);
    }
  else
    {
      init_ps_iterator (&iterator,
                        "UPDATE scanners SET relay_host = $1, relay_port = $2"
                        " WHERE host = $3 AND ($4 = 0 OR port = $4)"
                        " RETURNING uuid",
                        SQL_STR_PARAM (item->relay_host),
                        SQL_INT_PARAM (item->relay_port),
                        SQL_STR_PARAM (item->original_host),
                        SQL_INT_PARAM (item->original_port),
                        NULL);
    }

  if (updated_scanner_uuids)
    {
      while (next (&iterator))
        {
          gchar *updated_uuid = g_strdup (iterator_string (&iterator, 0));
          g_hash_table_add (updated_scanner_uuids, updated_uuid);
        }
    }

  cleanup_iterator (&iterator);

  return 0;
}

/**
 * @brief Perform actions at the end of updating all scanner relays
 *
 * The scanner relays update time in the DB is set to the file timestamp
 *
 * @param[in]  file_mod_time  File modification time to set in the DB
 */
void
update_all_scanner_relays_end (time_t file_mod_time)
{
  set_scanner_relays_update_time (file_mod_time);
}
