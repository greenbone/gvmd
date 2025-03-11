/* Copyright (C) 2010-2025 Greenbone AG
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
 * @file manage_sql_nvts_osp.c
 * @brief GVM management layer: OSP NVT logic
 *
 * NVT logic specific to OSP in the GVM management layer.
 */

#include "manage.h"
#include "manage_sql.h"
#include "manage_sql_configs.h"
#include "manage_sql_nvts_osp.h"
#include "sql.h"

#include <gvm/osp/osp.h>

/**
 * @brief Get the VTs feed version from an OSP scanner.
 *
 * @param[in]  update_socket  Socket to use to contact ospd-openvas scanner.
 *
 * @return The feed version or NULL on error.
 */
char *
osp_scanner_feed_version (const gchar *update_socket)
{
  osp_connection_t *connection;
  gchar *error;
  gchar *scanner_feed_version;

  scanner_feed_version = NULL;

  connection = osp_connection_new (update_socket, 0, NULL, NULL, NULL);
  if (!connection)
    {
      g_warning ("%s: failed to connect to %s", __func__, update_socket);
      return NULL;
    }

  error = NULL;
  if (osp_get_vts_version (connection, &scanner_feed_version, &error))
    {
      if (error && strcmp (error, "OSPd OpenVAS is still starting") == 0)
        g_info ("%s: No feed version available yet. %s",
                __func__, error);
      else
        g_warning ("%s: failed to get scanner_feed_version. %s",
                   __func__, error ? : "");
      g_free (error);
      osp_connection_close (connection);
      return NULL;
    }

  osp_connection_close (connection);

  return scanner_feed_version;
}

/**
 * @brief Check VTs feed version status via OSP, optionally get versions.
 *
 * @param[in]  update_socket  Socket to use to contact ospd-openvas scanner.
 * @param[out] db_feed_version_out       Output of database feed version.
 * @param[out] scanner_feed_version_out  Output of scanner feed version.
 *
 * @return 0 VTs feed current, -1 error, 1 VT update needed.
 */
int
nvts_feed_version_status_internal_osp (const gchar *update_socket,
                                   gchar **db_feed_version_out,
                                   gchar **scanner_feed_version_out)
{
  gchar *db_feed_version = NULL;
  gchar *scanner_feed_version = NULL;

  if (db_feed_version_out)
    *db_feed_version_out = NULL;
  if (scanner_feed_version_out)
    *scanner_feed_version_out = NULL;

  db_feed_version = nvts_feed_version ();
  g_debug ("%s: db_feed_version: %s", __func__, db_feed_version);
  if (db_feed_version_out && db_feed_version)
    *db_feed_version_out = g_strdup (db_feed_version);

  scanner_feed_version = osp_scanner_feed_version (update_socket);

  g_debug ("%s: scanner_feed_version: %s", __func__, scanner_feed_version);
  if (scanner_feed_version == NULL) {
      g_free (db_feed_version);
      return -1;
  }

  if (scanner_feed_version_out && scanner_feed_version)
    *scanner_feed_version_out = g_strdup (scanner_feed_version);

  if ((db_feed_version == NULL)
      || strcmp (scanner_feed_version, db_feed_version))
    {
      g_free (db_feed_version);
      g_free (scanner_feed_version);
      return 1;
    }

  g_free (db_feed_version);
  g_free (scanner_feed_version);
  return 0;
}

/**
 * @brief Update VTs via OSP.
 *
 * @param[in]  osp_uuid         UUID of ospd-openvas to connect to.
 * @param[in]  db_feed_version       Feed version from meta table.
 * @param[in]  scanner_feed_version  Feed version from scanner.
 * @param[in]  rebuild               Whether to rebuild the NVT tables from scratch.
 *
 * @return 0 success, 1 VT integrity check failed, -1 error.
 */
int
update_nvt_cache_osp (const gchar *update_socket, gchar *db_feed_version,
                      gchar *scanner_feed_version, int rebuild)
{
  osp_connection_t *connection;
  GSList *scanner_prefs;
  element_t vts;
  osp_get_vts_opts_t get_vts_opts;
  time_t old_nvts_last_modified;
  int ret;
  char *str;

  if (rebuild
      || db_feed_version == NULL
      || strcmp (db_feed_version, "") == 0
      || strcmp (db_feed_version, "0") == 0)
    old_nvts_last_modified = 0;
  else
    old_nvts_last_modified
      = (time_t) sql_int64_0 ("SELECT max(modification_time) FROM nvts");

  /* Update NVTs. */

  connection = osp_connection_new (update_socket, 0, NULL, NULL, NULL);
  if (!connection)
    {
      g_warning ("%s: failed to connect to %s (2)", __func__,
                 update_socket);
      return -1;
    }

  get_vts_opts = osp_get_vts_opts_default;
  if (db_feed_version)
    get_vts_opts.filter = g_strdup_printf ("modification_time>%s", db_feed_version);
  else
    get_vts_opts.filter = NULL;

  if (osp_get_vts_ext_str (connection, get_vts_opts, &str))
    {
      g_warning ("%s: failed to get VTs", __func__);
      g_free (get_vts_opts.filter);
      g_free (str);
      return -1;
    }

  g_free (get_vts_opts.filter);

  if (parse_element (str, &vts))
    {
      g_warning ("%s: failed to parse VTs", __func__);
      g_free (str);
      return -1;
    }

  osp_connection_close (connection);
  ret = update_nvts_from_vts (&vts, scanner_feed_version, rebuild);
  element_free (vts);
  g_free (str);
  if (ret)
    return ret;

  /* Update scanner preferences */

  connection = osp_connection_new (update_socket, 0, NULL, NULL, NULL);
  if (!connection)
    {
      g_warning ("%s: failed to connect to %s (3)",
                __func__, update_socket);
      return -1;
    }

  scanner_prefs = NULL;
  if (osp_get_scanner_details (connection, NULL, &scanner_prefs))
    {
      g_warning ("%s: failed to get scanner preferences", __func__);
      osp_connection_close (connection);
      return -1;
    }
  else
    {
      GString *prefs_sql;
      GSList *point;
      int first;

      point = scanner_prefs;
      first = 1;

      osp_connection_close (connection);
      prefs_sql = g_string_new ("INSERT INTO nvt_preferences (name, value)"
                                " VALUES");
      while (point)
        {
          osp_param_t *param;
          gchar *quoted_name, *quoted_value;

          param = point->data;
          quoted_name = sql_quote (osp_param_id (param));
          quoted_value = sql_quote (osp_param_default (param));

          g_string_append_printf (prefs_sql,
                                  "%s ('%s', '%s')",
                                  first ? "" : ",",
                                  quoted_name,
                                  quoted_value);
          first = 0;
          point = g_slist_next (point);
          g_free (quoted_name);
          g_free (quoted_value);
        }
      g_string_append (prefs_sql,
                       " ON CONFLICT (name)"
                       " DO UPDATE SET value = EXCLUDED.value;");

      if (first == 0)
        {
          sql ("%s", prefs_sql->str);
        }

      g_string_free (prefs_sql, TRUE);
    }

  /* Update the cache of report counts. */

  reports_clear_count_cache_dynamic ();

  /* Tell the main process to update its NVTi cache. */
  sql ("UPDATE %s.meta SET value = 1 WHERE name = 'update_nvti_cache';",
       sql_schema ());

  g_info ("Updating VTs in database ... done (%i VTs).",
          sql_int ("SELECT count (*) FROM nvts;"));

  if (sql_int ("SELECT coalesce ((SELECT CAST (value AS INTEGER)"
               "                  FROM meta"
               "                  WHERE name = 'checked_preferences'),"
               "                 0);")
      == 0)
    {
      check_old_preference_names ("config_preferences");
      check_old_preference_names ("config_preferences_trash");

      /* Force update of names in new format in case hard-coded names
       * used by migrators are outdated */
      old_nvts_last_modified = 0;

      sql ("INSERT INTO meta (name, value)"
           " VALUES ('checked_preferences', 1)"
           " ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value;");
    }

  check_preference_names (0, old_nvts_last_modified);
  check_preference_names (1, old_nvts_last_modified);

  check_whole_only_in_configs ();

  return 0;
}

/**
 * @brief Update or rebuild NVT db.
 *
 * Caller must get the lock.
 *
 * @param[in]  update  0 rebuild, else update.
 *
 * @return 0 success, -1 error, -1 no osp update socket, -2 could not connect
 *         to osp update socket, -3 failed to get scanner version
 */
int
update_or_rebuild_nvts_osp (int update)
{
  gchar *db_feed_version = NULL;
  gchar *scanner_feed_version = NULL;

  const char *osp_update_socket;
  osp_connection_t *connection;
  int ret;
  gchar *error;

  if (check_osp_vt_update_socket ())
    {
      g_warning ("No OSP VT update socket found."
               " Use --osp-vt-update or change the 'OpenVAS Default'"
               " scanner to use the main ospd-openvas socket.");
      return -1;
    }

  osp_update_socket = get_osp_vt_update_socket ();
  if (osp_update_socket == NULL)
    {
      g_warning ("No OSP VT update socket set.");
      return -1;
    }

  db_feed_version = nvts_feed_version ();
  g_debug ("%s: db_feed_version: %s", __func__, db_feed_version);

  connection = osp_connection_new (osp_update_socket, 0, NULL, NULL, NULL);
  if (!connection)
    {
      g_warning ("Failed to connect to %s.", osp_update_socket);
      return -2;
    }

  error = NULL;
  if (osp_get_vts_version (connection, &scanner_feed_version, &error))
    {
      g_warning ("Failed to get scanner_version. %s", error ? : "");
      g_free (error);
      return -3;
    }
  g_debug ("%s: scanner_feed_version: %s", __func__, scanner_feed_version);

  osp_connection_close (connection);

  if (update == 0)
    set_nvts_feed_version ("0");

  ret = update_nvt_cache_osp(osp_update_socket, NULL, scanner_feed_version, update == 0);
  if (ret)
    {
      return -1;
    }
  return 0;
}

/**
 * @brief Update VTs via OSP.
 *
 * Expect to be called in the child after a fork.
 *
 * @param[in]  update_socket  Socket to use to contact ospd-openvas scanner.
 *
 * @return 0 success, -1 error, 1 VT integrity check failed.
 */
int
manage_update_nvt_cache_osp (const gchar *update_socket)
{
  gchar *db_feed_version, *scanner_feed_version;
  int ret;

  /* Re-open DB after fork. */

  reinit_manage_process ();
  manage_session_init (current_credentials.uuid);

  /* Try update VTs. */

  ret = nvts_feed_version_status_internal_osp (update_socket,
                                           &db_feed_version,
                                           &scanner_feed_version);
  if (ret == 1)
    {
      g_info ("OSP service has different VT status (version %s)"
              " from database (version %s, %i VTs). Starting update ...",
              scanner_feed_version, db_feed_version,
              sql_int ("SELECT count (*) FROM nvts;"));

      ret = update_nvt_cache_osp (update_socket, db_feed_version,
                                  scanner_feed_version, 0);
      g_free (db_feed_version);
      g_free (scanner_feed_version);
      return ret;
    }

  return ret;
}
