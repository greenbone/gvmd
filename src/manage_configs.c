/* Copyright (C) 2019-2021 Greenbone Networks GmbH
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
 * @brief GVM manage layer: Configs.
 *
 * General functions for managing scan configs.
 */

#include "gmp_configs.h"
#include "manage_configs.h"
#include "manage_sql.h"
#include "manage_sql_configs.h"
#include "utils.h"

#include <errno.h>
#include <glib.h>
#include <gvm/util/fileutils.h>
#include <stdlib.h>
#include <string.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"


/* Configs. */

/**
 * @brief Return whether a config is predefined.
 *
 * @param[in]  config_id  UUID of config.
 *
 * @return 1 if predefined, else 0.
 */
int
config_predefined_uuid (const gchar *config_id)
{
  config_t config;

  if (find_config_no_acl (config_id, &config)
      || config == 0)
    return 0;

  return config_predefined (config);
}


/* Feed configs. */

/**
 * @brief Get path to configs in feed.
 *
 * @return Path to configs in feed.
 */
static const gchar *
feed_dir_configs ()
{
  static gchar *path = NULL;
  if (path == NULL)
    path = g_build_filename (GVMD_FEED_DIR,
                             GMP_VERSION_FEED,
                             "configs",
                             NULL);
  return path;
}

/**
 * @brief Grant 'Feed Import Roles' access to a config.
 *
 * @param[in]  config_id  UUID of config.
 */
static void
create_feed_config_permissions (const gchar *config_id)
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

      if (create_permission_no_acl ("get_configs",
                                    "Automatically created for config"
                                    " from feed",
                                    NULL,
                                    config_id,
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
 * @brief Create a config from an XML file.
 *
 * @param[in]  config  Existing config.
 * @param[in]  path    Full path to config XML.
 *
 * @return 0 success, -1 error.
 */
static int
update_config_from_file (config_t config, const gchar *path)
{
  entity_t entity;
  array_t *nvt_selectors, *preferences;
  char *comment, *name, *type, *usage_type;
  const char *config_id;
  int all_selector;

  g_debug ("%s: updating %s", __func__, path);

  /* Parse the file into an entity. */

  if (parse_xml_file (path, &entity))
    return 1;

  /* Parse the data out of the entity. */

  switch (parse_config_entity (entity, &config_id, &name, &comment, &type,
                               &usage_type, &all_selector, &nvt_selectors,
                               &preferences))
    {
      case 0:
        break;
      case 1:
        free_entity (entity);
        g_warning ("%s: preference does not exist yet, skipping %s for now",
                   __func__, path);
        return 0;
      default:
        free_entity (entity);
        g_warning ("%s: Failed to parse entity", __func__);
        return -1;
    }

  /* Update the config. */

  update_config (config, type, name, comment, usage_type, all_selector,
                 nvt_selectors, preferences);

  /* Cleanup. */

  free_entity (entity);
  cleanup_import_preferences (preferences);
  array_free (nvt_selectors);

  return 0;
}

/**
 * @brief Create a config from an XML file.
 *
 * @param[in]  path  Path to config XML.
 *
 * @return 0 success, -1 error.
 */
static int
create_config_from_file (const gchar *path)
{
  entity_t config;
  array_t *nvt_selectors, *preferences;
  char *created_name, *comment, *name, *type, *usage_type;
  const char *config_id;
  config_t new_config;
  int all_selector;

  g_debug ("%s: creating %s", __func__, path);

  /* Parse the file into an entity. */

  if (parse_xml_file (path, &config))
    return 1;

  /* Parse the data out of the entity. */

  switch (parse_config_entity (config, &config_id, &name, &comment, &type,
                               &usage_type, &all_selector, &nvt_selectors,
                               &preferences))
    {
      case 0:
        break;
      case 1:
        free_entity (config);
        g_warning ("%s: preference does not exist yet, skipping %s for now",
                   __func__, path);
        return 0;
      default:
        free_entity (config);
        g_warning ("%s: Failed to parse entity", __func__);
        return -1;
    }

  /* Create the config. */

  switch (create_config_no_acl (config_id,
                                name,
                                0,              /* Use name exactly as given. */
                                comment,
                                all_selector,
                                nvt_selectors,
                                preferences,
                                type,
                                usage_type,
                                &new_config,
                                &created_name))
    {
      case 0:
        {
          gchar *uuid;

          uuid = config_uuid (new_config);
          log_event ("config", "Scan config", uuid, "created");

          /* Create permissions. */
          create_feed_config_permissions (uuid);

          g_free (uuid);
          free (created_name);
          break;
        }
      case 1:
        g_warning ("%s: Config exists already", __func__);
        log_event_fail ("config", "Scan config", NULL, "created");
        break;
      case 99:
        g_warning ("%s: Permission denied", __func__);
        log_event_fail ("config", "Scan config", NULL, "created");
        break;
      case -2:
        g_warning ("%s: Import name must be at"
                   " least one character long",
                   __func__);
        log_event_fail ("config", "Scan config", NULL, "created");
        break;
      case -3:
        g_warning ("%s: Error in NVT_SELECTORS element.", __func__);
        log_event_fail ("config", "Scan config", NULL, "created");
        break;
      case -4:
        g_warning ("%s: Error in PREFERENCES element.", __func__);
        log_event_fail ("config", "Scan config", NULL, "created");
        break;
      case -5:
        g_warning ("%s: Error in CONFIG @id.", __func__);
        log_event_fail ("config", "Scan config", NULL, "created");
        break;
      default:
      case -1:
        g_warning ("%s: Internal error", __func__);
        log_event_fail ("config", "Scan config", NULL, "created");
        break;
    }

  /* Cleanup. */

  free_entity (config);
  cleanup_import_preferences (preferences);
  array_free (nvt_selectors);

  return 0;
}

/**
 * @brief Gets if a config must be synced a file path in the feed.
 *
 * @param[in]  path     Path to config XML in feed.
 * @param[in]  rebuild  Whether ignore timestamps to force a rebuild.
 * @param[out] config   Config row id if it already exists, 0 if config is new.
 *
 * @return 1 if config should be synced, 0 otherwise
 */
static int
should_sync_config_from_path (const char *path, gboolean rebuild,
                              config_t *config)
{
  gchar **split, *full_path, *uuid;

  *config = 0;

  split = g_regex_split_simple
           (/* Full-and-Fast--daba56c8-73ec-11df-a475-002264764cea.xml */
            "^.*([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12}).xml$",
            path, 0, 0);

  if (split == NULL || g_strv_length (split) != 7)
    {
      g_strfreev (split);
      g_warning ("%s: path not in required format: %s", __func__, path);
      return 0;
    }

  uuid = g_strdup_printf ("%s-%s-%s-%s-%s",
                          split[1], split[2], split[3], split[4], split[5]);
  g_strfreev (split);
  if (find_config_no_acl (uuid, config) == 0
      && *config)
    {
      if (rebuild)
        return 1;

      full_path = g_build_filename (feed_dir_configs (), path, NULL);

      g_free (uuid);

      g_debug ("%s: considering %s for update", __func__, path);

      if (config_updated_in_feed (*config, full_path))
        {
          return 1;
        }

      g_free (full_path);
      return 0;
    }

  if (find_trash_config_no_acl (uuid, config) == 0
      && *config)
    {
      g_free (uuid);
      *config = 0;
      return 0;
    }

  g_free (uuid);
  *config = 0;
  return 1;
}

/**
 * @brief Sync a single config with the feed.
 *
 * @param[in]  path     Path to config XML in feed.
 * @param[in]  rebuild  Whether ignore timestamps to force a rebuild.
 */
static void
sync_config_with_feed (const gchar *path, gboolean rebuild)
{
  config_t config;

  g_debug ("%s: considering %s", __func__, path);

  if (should_sync_config_from_path (path, rebuild, &config))
    {
      gchar *full_path;
      full_path = g_build_filename (feed_dir_configs (), path, NULL);
      switch (config)
        {
          case 0:
            g_debug ("%s: adding %s", __func__, path);
            create_config_from_file (full_path);
            break;
          default:
            g_debug ("%s: updating %s", __func__, path);
            update_config_from_file (config, full_path);
        }
      g_free (full_path);
    }
}

/**
 * @brief Open the configs feed directory if it is available and the
 * feed owner is set.
 * Optionally set the current user to the feed owner on success.
 * 
 * The sync will be skipped if the feed directory does not exist or
 *  the feed owner is not set. 
 * For configs the NVTs also have to exist.
 * 
 * @param[out]  dir The directory as GDir if available and feed owner is set,
 * NULL otherwise.
 * @param[in]   set_current_user Whether to set current user to feed owner.
 *
 * @return 0 success, 1 no feed directory, 2 no feed owner, 3 NVTs missing,
 *         -1 error.
 */
static int
try_open_configs_feed_dir (GDir **dir, gboolean set_current_user)
{
  char *feed_owner_uuid, *feed_owner_name;
  GError *error;
  gchar *nvt_feed_version;
  
  *dir = NULL;
  
  /* Test if base feed directory exists */

  if (configs_feed_dir_exists () == FALSE)
    return 1;

  /* Only sync if NVTs are up to date. */

  nvt_feed_version = nvts_feed_version ();
  if (nvt_feed_version == NULL)
    {
      g_debug ("%s: no NVTs so not syncing from feed", __func__);
      return 3;
    }
  g_free (nvt_feed_version);

  /* Setup owner. */

  setting_value (SETTING_UUID_FEED_IMPORT_OWNER, &feed_owner_uuid);

  if (feed_owner_uuid == NULL
      || strlen (feed_owner_uuid) == 0)
    {
      /* Sync is disabled by having no "Feed Import Owner". */
      g_debug ("%s: no Feed Import Owner so not syncing from feed", __func__);
      return 2;
    }

  feed_owner_name = user_name (feed_owner_uuid);
  if (feed_owner_name == NULL)
    {
      g_debug ("%s: unknown Feed Import Owner so not syncing from feed", __func__);
      return 2;
    }

  /* Open feed import directory. */

  error = NULL;
  *dir = g_dir_open (feed_dir_configs (), 0, &error);
  if (*dir == NULL)
    {
      g_warning ("%s: Failed to open directory '%s': %s",
                 __func__, feed_dir_configs (), error->message);
      g_error_free (error);
      g_free (current_credentials.uuid);
      g_free (current_credentials.username);
      current_credentials.uuid = NULL;
      current_credentials.username = NULL;
      return -1;
    }

  if (set_current_user)
    {
      current_credentials.uuid = feed_owner_uuid;
      current_credentials.username = feed_owner_name;
    }
  else
    {
      free (feed_owner_uuid);
      free (feed_owner_name);
    }

  return 0;
}

/**
 * @brief Sync all configs with the feed.
 *
 * Create configs that exists in the feed but not in the db.
 * Update configs in the db that have changed on the feed.
 * Do nothing to configs in db that have been removed from the feed.
 *
 * @param[in]  rebuild  Whether ignore timestamps to force a rebuild.
 *
 * @return 0 success, 1 no feed directory, 2 no feed owner, 3 NVTs missing,
 *         -1 error.
 */
int
sync_configs_with_feed (gboolean rebuild)
{
  int ret;
  GDir *dir;
  const gchar *config_path;

  ret = try_open_configs_feed_dir (&dir, TRUE);
  switch (ret)
    {
      case 0:
        // Successfully opened directory
        break;
      default:
        return ret;
    }

  /* Sync each file in the directory. */

  while ((config_path = g_dir_read_name (dir)))
    if (g_str_has_prefix (config_path, ".") == 0
        && strlen (config_path) >= (36 /* UUID */ + strlen (".xml"))
        && g_str_has_suffix (config_path, ".xml"))
      sync_config_with_feed (config_path, rebuild);

  /* Cleanup. */

  g_dir_close (dir);
  g_free (current_credentials.uuid);
  g_free (current_credentials.username);
  current_credentials.uuid = NULL;
  current_credentials.username = NULL;

  return 0;
}

/**
 * @brief Tests if the configs feed directory exists.
 * 
 * @return TRUE if the directory exists.
 */
gboolean
configs_feed_dir_exists ()
{
  return gvm_file_is_readable (feed_dir_configs ());
}

/**
 * @brief Sync configs with the feed.
 */
void
manage_sync_configs ()
{
  sync_configs_with_feed (FALSE);
}

/**
 * @brief Rebuild configs from the feed.
 * 
 * @return 0 success, 1 no feed directory, 2 no feed owner, 3 NVTs missing,
 *         -1 error.
 */
int
manage_rebuild_configs ()
{
  return sync_configs_with_feed (TRUE);
}

/**
 * @brief Checks if the configs should be synced with the feed.
 *
 * @return 1 if configs should be synced, 0 otherwise
 */
gboolean
should_sync_configs ()
{
  GDir *dir;
  const gchar *config_path;
  config_t config;

  if (try_open_configs_feed_dir (&dir, FALSE))
    return FALSE;

  while ((config_path = g_dir_read_name (dir)))
    if (g_str_has_prefix (config_path, ".") == 0
        && strlen (config_path) >= (36 /* UUID */ + strlen (".xml"))
        && g_str_has_suffix (config_path, ".xml")
        && should_sync_config_from_path (config_path, FALSE, &config))
      return TRUE;

  return FALSE;
}
