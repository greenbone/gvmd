/* Copyright (C) 2020 Greenbone Networks GmbH
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
 * @file manage_sql_port_lists.c
 * @brief GVM management layer: Port list SQL
 *
 * The Port List SQL for the GVM management layer.
 */

#include "manage_port_lists.h"
#include "manage.h"
#include "manage_sql_port_lists.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"


/* Feed port lists. */

/**
 * @brief Get path to port lists in feed.
 *
 * @return Path to port lists in feed.
 */
static const gchar *
feed_dir_port_lists ()
{
  static gchar *path = NULL;
  if (path == NULL)
    path = g_build_filename (GVMD_FEED_DIR, "port_lists", NULL);
  return path;
}

/**
 * @brief Sync a single port_list with the feed.
 *
 * @param[in]  path  Path to port_list XML in feed.
 */
static void
sync_port_list_with_feed (const gchar *path)
{
  gchar **split, *full_path, *uuid;
//  port_list_t port_list;

  g_debug ("%s: considering %s", __func__, path);

  split = g_regex_split_simple
           (/* All-TCP--daba56c8-73ec-11df-a475-002264764cea.xml */
            "^.*([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12}).xml$",
            path, 0, 0);

  if (split == NULL || g_strv_length (split) != 7)
    {
      g_strfreev (split);
      g_warning ("%s: path not in required format: %s", __func__, path);
      return;
    }

  full_path = g_build_filename (feed_dir_port_lists (), path, NULL);

  uuid = g_strdup_printf ("%s-%s-%s-%s-%s",
                          split[1], split[2], split[3], split[4], split[5]);
  g_strfreev (split);
#if 0
  if (find_port_list_no_acl (uuid, &port_list) == 0
      && port_list)
    {
      g_free (uuid);

      g_debug ("%s: considering %s for update", __func__, path);

// TODO
#if 0
      if (port_list_updated_in_feed (port_list, full_path))
        {
          g_debug ("%s: updating %s", __func__, path);
          update_port_list_from_file (port_list, full_path);
        }
#endif

      g_free (full_path);
      return;
    }
#endif

#if 0
  if (find_trash_port_list_no_acl (uuid, &port_list) == 0
      && port_list)
    {
      g_warning ("%s: ignoring port list '%s', as it is in the trashcan",
                 __func__, uuid);
      g_free (uuid);
      return;
    }
#endif

  g_free (uuid);

  g_debug ("%s: adding %s", __func__, path);

  //create_port_list_from_file (full_path);

  g_free (full_path);
}

/**
 * @brief Sync all port lists with the feed.
 *
 * Create port lists that exists in the feed but not in the db.
 * Update port lists in the db that have changed on the feed.
 * Do nothing to db port lists that have been removed from the feed.
 *
 * @return 0 success, -1 error.
 */
int
sync_port_lists_with_feed ()
{
  GError *error;
  GDir *dir;
  const gchar *port_list_path;

  /* Setup owner. */

  setting_value (SETTING_UUID_FEED_IMPORT_OWNER, &current_credentials.uuid);

  if (current_credentials.uuid == NULL
      || strlen (current_credentials.uuid) == 0)
    {
      /* Sync is disabled by having no "Feed Import Owner". */
      g_debug ("%s: no Feed Import Owner so not syncing from feed", __func__);
      return 0;
    }

  current_credentials.username = user_name (current_credentials.uuid);
  if (current_credentials.username == NULL)
    {
      g_debug ("%s: unknown Feed Import Owner so not syncing from feed", __func__);
      return 0;
    }

  /* Open feed import directory. */

  error = NULL;
  dir = g_dir_open (feed_dir_port_lists (), 0, &error);
  if (dir == NULL)
    {
      g_warning ("%s: Failed to open directory '%s': %s",
                 __func__, feed_dir_port_lists (), error->message);
      g_error_free (error);
      g_free (current_credentials.uuid);
      g_free (current_credentials.username);
      current_credentials.uuid = NULL;
      current_credentials.username = NULL;
      return -1;
    }

  /* Sync each file in the directory. */

  while ((port_list_path = g_dir_read_name (dir)))
    if (g_str_has_prefix (port_list_path, ".") == 0
        && strlen (port_list_path) >= (36 /* UUID */ + strlen (".xml"))
        && g_str_has_suffix (port_list_path, ".xml"))
      sync_port_list_with_feed (port_list_path);

  /* Cleanup. */

  g_dir_close (dir);
  g_free (current_credentials.uuid);
  g_free (current_credentials.username);
  current_credentials.uuid = NULL;
  current_credentials.username = NULL;

  return 0;
}
