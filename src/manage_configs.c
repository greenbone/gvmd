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
 * @file
 * @brief GVM manage layer: Configs.
 *
 * General functions for managing scan configs.
 */

#include "gmp_configs.h"
#include "manage_configs.h"
#include "manage_sql.h"
#include "manage_sql_configs.h"

#include <errno.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <stdlib.h>
#include <string.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

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
    path = g_build_filename (GVMD_FEED_DIR, "configs", NULL);
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
 * @brief Create entity from XML file.
 *
 * @param[in]  path    Path to XML.
 * @param[out] config  Config tree.
 *
 * @return 0 success, -1 error.
 */
static int
parse_xml_file (const gchar *path, entity_t *config)
{
  gsize xml_len;
  char *xml;
  GError *error;

  /* Buffer the file. */

  error = NULL;
  g_file_get_contents (path,
                       &xml,
                       &xml_len,
                       &error);
  if (error)
    {
      g_warning ("%s: Failed to read file: %s",
                  __func__,
                  error->message);
      g_error_free (error);
      return -1;
    }

  /* Parse the buffer into an entity. */

  if (parse_entity (xml, config))
    {
      g_free (xml);
      g_warning ("%s: Failed to parse XML", __func__);
      return -1;
    }
  g_free (xml);

  return 0;
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
  char *comment, *name, *type;
  const char *config_id;

  g_debug ("%s: updating %s", __func__, path);

  /* Parse the file into an entity. */

  if (parse_xml_file (path, &entity))
    return 1;

  /* Parse the data out of the entity. */

  if (parse_config_entity (entity, &config_id, &name, &comment, &type,
                           &nvt_selectors, &preferences))
    {
      free_entity (entity);
      g_warning ("%s: Failed to parse entity", __func__);
      return -1;
    }

  /* Update the config. */

  update_config (config, type, name, comment, nvt_selectors, preferences);

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
  char *created_name, *comment, *name, *type;
  const char *config_id;
  config_t new_config;

  g_debug ("%s: creating %s", __func__, path);

  /* Parse the file into an entity. */

  if (parse_xml_file (path, &config))
    return 1;

  /* Parse the data out of the entity. */

  if (parse_config_entity (config, &config_id, &name, &comment, &type,
                           &nvt_selectors, &preferences))
    {
      free_entity (config);
      g_warning ("%s: Failed to parse entity", __func__);
      return -1;
    }

  /* Create the config. */

  switch (create_config_no_acl (config_id,
                                name,
                                0,              /* Use name exactly as given. */
                                comment,
                                nvt_selectors,
                                preferences,
                                type,
                                NULL,           /* Usage type. */
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
 * @brief Sync a single config with the feed.
 *
 * @param[in]  path  Path to config XML in feed.
 */
static void
sync_config_with_feed (const gchar *path)
{
  gchar **split, *full_path, *uuid;
  config_t config;

  g_debug ("%s: considering %s", __func__, path);

  split = g_regex_split_simple
           (/* Full-and-Fast--daba56c8-73ec-11df-a475-002264764cea.xml */
            "^.*([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12}).xml$",
            path, 0, 0);

  if (split == NULL || g_strv_length (split) != 7)
    {
      g_strfreev (split);
      g_warning ("%s: path not in required format: %s", __func__, path);
      return;
    }

  full_path = g_build_filename (feed_dir_configs (), path, NULL);

  uuid = g_strdup_printf ("%s-%s-%s-%s-%s",
                          split[1], split[2], split[3], split[4], split[5]);
  g_strfreev (split);
  if (find_config_no_acl (uuid, &config) == 0
      && config)
    {
      g_free (uuid);

      g_debug ("%s: considering %s for update", __func__, path);

      if (config_updated_in_feed (config, full_path))
        {
          g_debug ("%s: updating %s", __func__, path);
          update_config_from_file (config, full_path);
        }

      g_free (full_path);
      return;
    }
  g_free (uuid);

  g_debug ("%s: adding %s", __func__, path);

  create_config_from_file (full_path);

  g_free (full_path);
}

/**
 * @brief Sync all configs with the feed.
 *
 * Create configs that exists in the feed but not in the db.
 * Update configs in the db that have changed on the feed.
 * Do nothing to configs in db that have been removed from the feed.
 *
 * @return 0 success, -1 error.
 */
int
sync_configs_with_feed ()
{
  GError *error;
  GDir *dir;
  const gchar *config_path;
  gchar *nvt_feed_version;

  /* Only sync if NVTs are up to date. */

  nvt_feed_version = nvts_feed_version ();
  if (nvt_feed_version == NULL)
    {
      g_debug ("%s: no NVTs so not syncing from feed", __func__);
      return 0;
    }
  g_free (nvt_feed_version);

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
  dir = g_dir_open (feed_dir_configs (), 0, &error);
  if (dir == NULL)
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

  /* Sync each file in the directory. */

  while ((config_path = g_dir_read_name (dir)))
    if (g_str_has_prefix (config_path, ".") == 0
        && strlen (config_path) >= (36 /* UUID */ + strlen (".xml"))
        && g_str_has_suffix (config_path, ".xml"))
      sync_config_with_feed (config_path);

  /* Cleanup. */

  g_dir_close (dir);
  g_free (current_credentials.uuid);
  g_free (current_credentials.username);
  current_credentials.uuid = NULL;
  current_credentials.username = NULL;

  return 0;
}

/**
 * @brief Sync configs with the feed.
 */
void
manage_sync_configs ()
{
  sync_configs_with_feed ();
}
