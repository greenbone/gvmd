/* Copyright (C) 2020 Greenbone Networks GmbH
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
 * @file manage_sql_port_lists.c
 * @brief GVM management layer: Port list SQL
 *
 * The Port List SQL for the GVM management layer.
 */

#include "manage_port_lists.h"
#include "gmp_port_lists.h"
#include "manage.h"
#include "manage_sql_port_lists.h"
#include "utils.h"

#include <string.h>

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
    path = g_build_filename (GVMD_FEED_DIR,
                             GMP_VERSION_FEED,
                             "port_lists",
                             NULL);
  return path;
}

/**
 * @brief Grant 'Feed Import Roles' access to a port list.
 *
 * @param[in]  port_list_id  UUID of port list.
 */
static void
create_feed_port_list_permissions (const gchar *port_list_id)
{
  gchar *roles, **split, **point;

  setting_value (SETTING_UUID_FEED_IMPORT_ROLES, &roles);

  if (roles == NULL || strlen (roles) == 0)
    {
      g_debug ("%s: no 'Feed Import Roles', so not creating permissions",
               __func__);
      g_free (roles);
      return;
    }

  point = split = g_strsplit (roles, ",", 0);
  while (*point)
    {
      permission_t permission;

      if (create_permission_no_acl ("get_port_lists",
                                    "Automatically created for port_list"
                                    " from feed",
                                    NULL,
                                    port_list_id,
                                    "role",
                                    g_strstrip (*point),
                                    &permission))
        /* Keep going because we aren't strict about checking the value
         * of the setting, and because we don't adjust the setting when
         * roles are removed. */
        g_warning ("%s: failed to create permission for role '%s'",
                   __func__, g_strstrip (*point));

      point++;
    }
  g_strfreev (split);

  g_free (roles);
}

/**
 * @brief Create a port list from an XML file.
 *
 * @param[in]  path  Path to port list XML.
 *
 * @return 0 success, -1 error.
 */
static int
create_port_list_from_file (const gchar *path)
{
  entity_t port_list;
  array_t *ranges;
  char *comment, *name;
  const char *port_list_id;
  port_list_t new_port_list;

  g_debug ("%s: creating %s", __func__, path);

  /* Parse the file into an entity. */

  if (parse_xml_file (path, &port_list))
    return 1;

  /* Parse the data out of the entity. */

  parse_port_list_entity (port_list, &port_list_id, &name, &comment,
                          &ranges);

  /* Create the port_list. */

  switch (create_port_list_no_acl (port_list_id,
                                   name,
                                   comment,
                                   NULL,       /* Optional ranges as string. */
                                   ranges,
                                   &new_port_list))
    {
      case 0:
        {
          gchar *uuid;

          uuid = port_list_uuid (new_port_list);
          log_event ("port_list", "Port list", uuid, "created");

          /* Create permissions. */
          create_feed_port_list_permissions (uuid);

          g_free (uuid);
          break;
        }
      case 1:
        g_warning ("%s: Port_List exists already", __func__);
        log_event_fail ("port_list", "Port list", NULL, "created");
        break;
      case 99:
        g_warning ("%s: Permission denied", __func__);
        log_event_fail ("port_list", "Port list", NULL, "created");
        break;
      case -2:
        g_warning ("%s: Import name must be at"
                   " least one character long",
                   __func__);
        log_event_fail ("port_list", "Port list", NULL, "created");
        break;
      case -3:
        g_warning ("%s: Error in NVT_SELECTORS element.", __func__);
        log_event_fail ("port_list", "Port list", NULL, "created");
        break;
      case -4:
        g_warning ("%s: Error in PREFERENCES element.", __func__);
        log_event_fail ("port_list", "Port list", NULL, "created");
        break;
      case -5:
        g_warning ("%s: Error in PORT_LIST @id.", __func__);
        log_event_fail ("port_list", "Port list", NULL, "created");
        break;
      default:
      case -1:
        g_warning ("%s: Internal error", __func__);
        log_event_fail ("port_list", "Port list", NULL, "created");
        break;
    }

  /* Cleanup. */

  free_entity (port_list);
  array_free (ranges);

  return 0;
}

/**
 * @brief Create a port list from an XML file.
 *
 * @param[in]  port_list  Existing port list.
 * @param[in]  path       Full path to port list XML.
 *
 * @return 0 success, -1 error.
 */
static int
update_port_list_from_file (port_list_t port_list, const gchar *path)
{
  entity_t entity;
  array_t *ranges;
  char *comment, *name;
  const char *port_list_id;

  g_debug ("%s: updating %s", __func__, path);

  /* Parse the file into an entity. */

  if (parse_xml_file (path, &entity))
    return 1;

  /* Parse the data out of the entity. */

  parse_port_list_entity (entity, &port_list_id, &name, &comment, &ranges);

  /* Update the port list. */

  update_port_list (port_list, name, comment, ranges);

  /* Cleanup. */

  free_entity (entity);
  array_free (ranges);

  return 0;
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
  port_list_t port_list;

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
  if (find_port_list_no_acl (uuid, &port_list) == 0
      && port_list)
    {
      g_free (uuid);

      g_debug ("%s: considering %s for update", __func__, path);

      if (port_list_updated_in_feed (port_list, full_path))
        {
          g_debug ("%s: updating %s", __func__, path);
          update_port_list_from_file (port_list, full_path);
        }

      g_free (full_path);
      return;
    }

  if (find_trash_port_list_no_acl (uuid, &port_list) == 0
      && port_list)
    {
      g_free (uuid);
      return;
    }

  g_free (uuid);

  g_debug ("%s: adding %s", __func__, path);

  create_port_list_from_file (full_path);

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

  /* Test if base feed directory exists */

  if (port_lists_feed_dir_exists () == FALSE)
    return 0;

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

/**
 * @brief Tests if the port lists feed directory exists.
 * 
 * @return TRUE if the directory exists.
 */
gboolean
port_lists_feed_dir_exists ()
{
  return g_file_test (feed_dir_port_lists (), G_FILE_TEST_EXISTS);
}

/**
 * @brief Sync port lists with the feed.
 */
void
manage_sync_port_lists ()
{
  sync_port_lists_with_feed ();
}
