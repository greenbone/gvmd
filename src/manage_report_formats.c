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
 * @file manage_report_formats.c
 * @brief GVM management layer: Report formats.
 *
 * Non-SQL report format code for the GVM management layer.
 */

#include "manage_report_formats.h"
#include "gmp_report_formats.h"
#include "manage.h"
#include "manage_sql.h"
#include "manage_sql_report_formats.h"
#include "utils.h"

#include <assert.h>
#include <errno.h>
#include <glib.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Find a report format for a specific permission, given a UUID.
 *
 * @param[in]   uuid        UUID of report format.
 * @param[out]  report_format  Report format return, 0 if successfully failed to
 *                             find report_format.
 * @param[in]   permission  Permission.
 *
 * @return FALSE on success (including if failed to find report_format), TRUE
 *         on error.
 */
gboolean
find_report_format_with_permission (const char *uuid,
                                    report_format_t *report_format,
                                    const char *permission)
{
  return find_resource_with_permission ("report_format", uuid, report_format,
                                        permission, 0);
}

/**
 * @brief Return whether a report format is writable.
 *
 * @param[in]  report_format Report Format.
 *
 * @return 1 if writable, else 0.
 */
int
report_format_writable (report_format_t report_format)
{
  return report_format_in_use (report_format) == 0;
}

/**
 * @brief Return whether a trashcan report_format is writable.
 *
 * @param[in]  report_format  Report Format.
 *
 * @return 1 if writable, else 0.
 */
int
trash_report_format_writable (report_format_t report_format)
{
  return trash_report_format_in_use (report_format) == 0;
}

/**
 * @brief Get the name of a report format param type.
 *
 * @param[in]  type  Param type.
 *
 * @return The name of the param type.
 */
const char *
report_format_param_type_name (report_format_param_type_t type)
{
  switch (type)
    {
      case REPORT_FORMAT_PARAM_TYPE_BOOLEAN:
        return "boolean";
      case REPORT_FORMAT_PARAM_TYPE_INTEGER:
        return "integer";
      case REPORT_FORMAT_PARAM_TYPE_SELECTION:
        return "selection";
      case REPORT_FORMAT_PARAM_TYPE_STRING:
        return "string";
      case REPORT_FORMAT_PARAM_TYPE_TEXT:
        return "text";
      case REPORT_FORMAT_PARAM_TYPE_REPORT_FORMAT_LIST:
        return "report_format_list";
      default:
        assert (0);
      case REPORT_FORMAT_PARAM_TYPE_ERROR:
        return "ERROR";
    }
}

/**
 * @brief Get a report format param type from a name.
 *
 * @param[in]  name  Param type name.
 *
 * @return The param type.
 */
report_format_param_type_t
report_format_param_type_from_name (const char *name)
{
  if (strcmp (name, "boolean") == 0)
    return REPORT_FORMAT_PARAM_TYPE_BOOLEAN;
  if (strcmp (name, "integer") == 0)
    return REPORT_FORMAT_PARAM_TYPE_INTEGER;
  if (strcmp (name, "selection") == 0)
    return REPORT_FORMAT_PARAM_TYPE_SELECTION;
  if (strcmp (name, "string") == 0)
    return REPORT_FORMAT_PARAM_TYPE_STRING;
  if (strcmp (name, "text") == 0)
    return REPORT_FORMAT_PARAM_TYPE_TEXT;
  if (strcmp (name, "report_format_list") == 0)
    return REPORT_FORMAT_PARAM_TYPE_REPORT_FORMAT_LIST;
  return REPORT_FORMAT_PARAM_TYPE_ERROR;
}

/**
 * @brief Return whether a name is a backup file name.
 *
 * @param[in]  name  Name.
 *
 * @return 0 if normal file name, 1 if backup file name.
 */
static int
backup_file_name (const char *name)
{
  int length = strlen (name);

  if (length && (name[length - 1] == '~'))
    return 1;

  if ((length > 3)
      && (name[length - 4] == '.'))
    return ((name[length - 3] == 'b')
            && (name[length - 2] == 'a')
            && (name[length - 1] == 'k'))
           || ((name[length - 3] == 'B')
               && (name[length - 2] == 'A')
               && (name[length - 1] == 'K'))
           || ((name[length - 3] == 'C')
               && (name[length - 2] == 'K')
               && (name[length - 1] == 'P'));

  return 0;
}

/**
 * @brief Get files associated with a report format.
 *
 * @param[in]   dir_name  Location of files.
 * @param[out]  start     Files on success.
 *
 * @return 0 if successful, -1 otherwise.
 */
static int
get_report_format_files (const char *dir_name, GPtrArray **start)
{
  GPtrArray *files;
  struct dirent **names;
  int n, index;
  char *locale;

  files = g_ptr_array_new ();

  locale = setlocale (LC_ALL, "C");
  n = scandir (dir_name, &names, NULL, alphasort);
  setlocale (LC_ALL, locale);
  if (n < 0)
    {
      g_warning ("%s: failed to open dir %s: %s",
                 __func__,
                 dir_name,
                 strerror (errno));
      return -1;
    }

  for (index = 0; index < n; index++)
    {
      if (strcmp (names[index]->d_name, ".")
          && strcmp (names[index]->d_name, "..")
          && (backup_file_name (names[index]->d_name) == 0))
        g_ptr_array_add (files, g_strdup (names[index]->d_name));
      free (names[index]);
    }
  free (names);

  g_ptr_array_add (files, NULL);

  *start = files;
  return 0;
}

/**
 * @brief Initialise a report format file iterator.
 *
 * @param[in]  iterator       Iterator.
 * @param[in]  report_format  Single report format to iterate over, NULL for
 *                            all.
 *
 * @return 0 on success, -1 on error.
 */
int
init_report_format_file_iterator (file_iterator_t* iterator,
                                  report_format_t report_format)
{
  gchar *dir_name, *uuid, *owner_uuid;

  uuid = report_format_uuid (report_format);
  if (uuid == NULL)
    return -1;

  owner_uuid = report_format_owner_uuid (report_format);
  if (owner_uuid == NULL)
    return -1;
  dir_name = g_build_filename (GVMD_STATE_DIR,
                               "report_formats",
                               owner_uuid,
                               uuid,
                               NULL);
  g_free (owner_uuid);
  g_free (uuid);

  if (get_report_format_files (dir_name, &iterator->start))
    {
      g_free (dir_name);
      return -1;
    }

  iterator->current = iterator->start->pdata;
  iterator->current--;
  iterator->dir_name = dir_name;
  return 0;
}

/**
 * @brief Cleanup a report type iterator.
 *
 * @param[in]  iterator  Iterator.
 */
void
cleanup_file_iterator (file_iterator_t* iterator)
{
  array_free (iterator->start);
  g_free (iterator->dir_name);
}

/**
 * @brief Increment a report type iterator.
 *
 * The caller must stop using this after it returns FALSE.
 *
 * @param[in]  iterator  Task iterator.
 *
 * @return TRUE if there was a next item, else FALSE.
 */
gboolean
next_file (file_iterator_t* iterator)
{
  iterator->current++;
  if (*iterator->current == NULL) return FALSE;
  return TRUE;
}

/**
 * @brief Return the name from a file iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return File name.
 */
const char*
file_iterator_name (file_iterator_t* iterator)
{
  return (const char*) *iterator->current;
}

/**
 * @brief Return the file contents from a file iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Freshly allocated file contents, in base64.
 */
gchar*
file_iterator_content_64 (file_iterator_t* iterator)
{
  gchar *path_name, *content;
  GError *error;
  gsize content_size;

  path_name = g_build_filename (iterator->dir_name,
                                (gchar*) *iterator->current,
                                NULL);

  /* Read in the contents. */

  error = NULL;
  if (g_file_get_contents (path_name,
                           &content,
                           &content_size,
                           &error)
      == FALSE)
    {
      if (error)
        {
          g_debug ("%s: failed to read %s: %s",
                   __func__, path_name, error->message);
          g_error_free (error);
        }
      g_free (path_name);
      return NULL;
    }

  g_free (path_name);

  /* Base64 encode the contents. */

  if (content && (content_size > 0))
    {
      gchar *base64 = g_base64_encode ((guchar*) content, content_size);
      g_free (content);
      return base64;
    }

  return content;
}


/* Feed report formats. */

/**
 * @brief Get path to report formats in feed.
 *
 * @return Path to report formats in feed.
 */
static const gchar *
feed_dir_report_formats ()
{
  static gchar *path = NULL;
  if (path == NULL)
    path = g_build_filename (GVMD_FEED_DIR,
                             GMP_VERSION_FEED,
                             "report_formats",
                             NULL);
  return path;
}

/**
 * @brief Create a report format from an XML file.
 *
 * @param[in]  report_format  Existing report format.
 * @param[in]  path           Full path to report format XML.
 *
 * @return 0 success, -1 error.
 */
static int
update_report_format_from_file (report_format_t report_format,
                                const gchar *path)
{
  entity_t entity;
  array_t *files, *params, *params_options;
  char *name, *content_type, *extension, *summary, *description, *signature;
  const char *report_format_id;

  g_debug ("%s: updating %s", __func__, path);

  /* Parse the file into an entity. */

  if (parse_xml_file (path, &entity))
    return 1;

  /* Parse the data out of the entity. */

  parse_report_format_entity (entity, &report_format_id, &name,
                              &content_type, &extension, &summary,
                              &description, &signature, &files, &params,
                              &params_options);

  /* Update the report format. */

  update_report_format (report_format, report_format_id, name, content_type,
                        extension, summary, description, signature, files,
                        params, params_options);

  /* Cleanup. */

  array_free (files);
  params_options_free (params_options);
  array_free (params);
  free_entity (entity);

  return 0;
}

/**
 * @brief Grant 'Feed Import Roles' access to a report format.
 *
 * @param[in]  report_format_id  UUID of report format.
 */
static void
create_feed_report_format_permissions (const gchar *report_format_id)
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

      if (create_permission_no_acl ("get_report_formats",
                                    "Automatically created for report format"
                                    " from feed",
                                    NULL,
                                    report_format_id,
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
 * @brief Create a report format from an XML file.
 *
 * @param[in]  path  Path to report format XML.
 *
 * @return 0 success, -1 error.
 */
static int
create_report_format_from_file (const gchar *path)
{
  entity_t report_format;
  array_t *files, *params, *params_options;
  char *name, *content_type, *extension, *summary, *description, *signature;
  const char *report_format_id;
  report_format_t new_report_format;

  g_debug ("%s: creating %s", __func__, path);

  /* Parse the file into an entity. */

  if (parse_xml_file (path, &report_format))
    return 1;

  /* Parse the data out of the entity. */

  parse_report_format_entity (report_format, &report_format_id, &name,
                              &content_type, &extension, &summary,
                              &description, &signature, &files, &params,
                              &params_options);

  /* Create the report format. */

  switch (create_report_format_no_acl (report_format_id,
                                       name,
                                       content_type,
                                       extension,
                                       summary,
                                       description,
                                       files,
                                       params,
                                       params_options,
                                       signature,
                                       1,
                                       &new_report_format))
    {
      case 0:
        {
          gchar *uuid;

          uuid = report_format_uuid (new_report_format);
          log_event ("report_format", "Report format", uuid, "created");

          /* Create permissions. */
          create_feed_report_format_permissions (uuid);

          g_free (uuid);
          break;
        }
      case 1:
        g_warning ("%s: Report Format exists already", __func__);
        log_event_fail ("report_format", "Report format", NULL, "created");
        break;
      case 2:
        g_warning ("%s: Every FILE must have a name attribute", __func__);
        log_event_fail ("report_format", "Report Format", NULL,
                        "created");
        break;
      case 3:
        g_warning ("%s: Parameter value validation failed", __func__);
        log_event_fail ("report_format", "Report Format", NULL,
                        "created");
        break;
      case 4:
        g_warning ("%s: Parameter default validation failed", __func__);
        log_event_fail ("report_format", "Report Format", NULL,
                        "created");
        break;
      case 5:
        g_warning ("%s: PARAM requires a DEFAULT element", __func__);
        log_event_fail ("report_format", "Report Format", NULL,
                        "created");
        break;
      case 6:
        g_warning ("%s: PARAM MIN or MAX out of range", __func__);
        log_event_fail ("report_format", "Report Format", NULL,
                        "created");
        break;
      case 7:
        g_warning ("%s: PARAM requires a TYPE element", __func__);
        log_event_fail ("report_format", "Report Format", NULL,
                        "created");
        break;
      case 8:
        g_warning ("%s: Duplicate PARAM name", __func__);
        log_event_fail ("report_format", "Report Format", NULL,
                        "created");
        break;
      case 9:
        g_warning ("%s: Bogus PARAM type", __func__);
        log_event_fail ("report_format", "Report Format", NULL,
                        "created");
        break;
      case 99:
        g_warning ("%s: Permission denied", __func__);
        log_event_fail ("report_format", "Report format", NULL, "created");
        break;
      default:
      case -1:
        g_warning ("%s: Internal error", __func__);
        log_event_fail ("report_format", "Report format", NULL, "created");
        break;
    }

  /* Cleanup. */

  array_free (files);
  params_options_free (params_options);
  array_free (params);
  free_entity (report_format);

  return 0;
}

/**
 * @brief Sync a single report format with the feed.
 *
 * @param[in]  path  Path to report format XML in feed.
 */
static void
sync_report_format_with_feed (const gchar *path)
{
  gchar **split, *full_path, *uuid;
  report_format_t report_format;

  g_debug ("%s: considering %s", __func__, path);

  split = g_regex_split_simple
           (/* Format is: [AnYtHiNg]uuid.xml
             * For example: PDF--daba56c8-73ec-11df-a475-002264764cea.xml */
            "^.*([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12}).xml$",
            path, 0, 0);

  if (split == NULL || g_strv_length (split) != 7)
    {
      g_strfreev (split);
      g_warning ("%s: path not in required format: %s", __func__, path);
      return;
    }

  full_path = g_build_filename (feed_dir_report_formats (), path, NULL);

  uuid = g_strdup_printf ("%s-%s-%s-%s-%s",
                          split[1], split[2], split[3], split[4], split[5]);
  g_strfreev (split);
  if (find_report_format_no_acl (uuid, &report_format) == 0
      && report_format)
    {
      g_free (uuid);

      g_debug ("%s: considering %s for update", __func__, path);

      if (report_format_updated_in_feed (report_format, full_path))
        {
          g_debug ("%s: updating %s", __func__, path);
          update_report_format_from_file (report_format, full_path);
        }

      g_free (full_path);
      return;
    }

  if (find_trash_report_format_no_acl (uuid, &report_format) == 0
      && report_format)
    {
      g_free (uuid);
      return;
    }

  g_free (uuid);

  g_debug ("%s: adding %s", __func__, path);

  create_report_format_from_file (full_path);

  g_free (full_path);
}

/**
 * @brief Sync all report formats with the feed.
 *
 * Create report formats that exists in the feed but not in the db.
 * Update report formats in the db that have changed on the feed.
 * Do nothing to report formats in db that have been removed from the feed.
 *
 * @return 0 success, -1 error.
 */
int
sync_report_formats_with_feed ()
{
  GError *error;
  GDir *dir;
  const gchar *report_format_path;

  /* Test if base feed directory exists */

  if (report_formats_feed_dir_exists () == FALSE)
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
      g_debug ("%s: unknown Feed Import Owner so not syncing from feed",
               __func__);
      return 0;
    }

  /* Open feed import directory. */

  error = NULL;
  dir = g_dir_open (feed_dir_report_formats (), 0, &error);
  if (dir == NULL)
    {
      g_warning ("%s: Failed to open directory '%s': %s",
                 __func__, feed_dir_report_formats (), error->message);
      g_error_free (error);
      g_free (current_credentials.uuid);
      g_free (current_credentials.username);
      current_credentials.uuid = NULL;
      current_credentials.username = NULL;
      return -1;
    }

  /* Sync each file in the directory. */

  while ((report_format_path = g_dir_read_name (dir)))
    if (g_str_has_prefix (report_format_path, ".") == 0
        && strlen (report_format_path) >= (36 /* UUID */ + strlen (".xml"))
        && g_str_has_suffix (report_format_path, ".xml"))
      sync_report_format_with_feed (report_format_path);

  /* Cleanup. */

  g_dir_close (dir);
  g_free (current_credentials.uuid);
  g_free (current_credentials.username);
  current_credentials.uuid = NULL;
  current_credentials.username = NULL;

  return 0;
}

/**
 * @brief Tests if the report formats feed directory exists.
 * 
 * @return TRUE if the directory exists.
 */
gboolean
report_formats_feed_dir_exists ()
{
  return g_file_test (feed_dir_report_formats (), G_FILE_TEST_EXISTS);
}

/**
 * @brief Sync report formats with the feed.
 */
void
manage_sync_report_formats ()
{
  sync_report_formats_with_feed ();
}
