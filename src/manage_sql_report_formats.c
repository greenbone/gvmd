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
 * @file manage_sql_report_formats.c
 * @brief GVM management layer: Report format SQL
 *
 * The report format SQL for the GVM management layer.
 */

#include "manage_sql_report_formats.h"

/**
 * @brief Possible port types.
 */
typedef enum
{
  REPORT_FORMAT_FLAG_ACTIVE = 1
} report_format_flag_t;

/**
 * @brief Find a reportformat for a specific permission, given a UUID.
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
find_report_format_with_permission (const char* uuid,
                                    report_format_t* report_format,
                                    const char *permission)
{
  return find_resource_with_permission ("report_format", uuid, report_format,
                                        permission, 0);
}

/**
 * @brief Find a report format given a name.
 *
 * @param[in]   name           Name of report_format.
 * @param[out]  report_format  Report format return, 0 if successfully failed to
 *                             find report_format.
 *
 * @return FALSE on success (including if failed to find report format), TRUE
 *         on error.
 */
static gboolean
lookup_report_format (const char* name, report_format_t* report_format)
{
  iterator_t report_formats;
  gchar *quoted_name;

  assert (report_format);

  *report_format = 0;
  quoted_name = sql_quote (name);
  init_iterator (&report_formats,
                 "SELECT id, uuid FROM report_formats"
                 " WHERE name = '%s'"
                 " AND CAST (flags & %llu AS boolean)"
                 " ORDER BY (CASE WHEN " ACL_USER_OWNS () " THEN 0"
                 "                WHEN owner is NULL THEN 1"
                 "                ELSE 2"
                 "           END);",
                 quoted_name,
                 (long long int) REPORT_FORMAT_FLAG_ACTIVE,
                 current_credentials.uuid);
  g_free (quoted_name);
  while (next (&report_formats))
    {
      const char *uuid;

      uuid = iterator_string (&report_formats, 1);
      if (uuid
          && acl_user_has_access_uuid ("report_format",
                                       uuid,
                                       "get_report_formats",
                                       0))
        {
          *report_format = iterator_int64 (&report_formats, 0);
          break;
        }
    }
  cleanup_iterator (&report_formats);

  return FALSE;
}

/**
 * @brief Compare files for create_report_format.
 *
 * @param[in]  one  First.
 * @param[in]  two  Second.
 *
 * @return Less than, equal to, or greater than zero if one is found to be
 *         less than, to match, or be greater than two.
 */
static gint
compare_files (gconstpointer one, gconstpointer two)
{
  gchar *file_one, *file_two;
  file_one = *((gchar**) one);
  file_two = *((gchar**) two);
  if (file_one == NULL)
    {
      if (file_two == NULL)
        return 0;
      return 1;
    }
  else if (file_two == NULL)
    return -1;
  return strcoll (file_one, file_two);
}

/**
 * @brief Create a report format.
 *
 * @param[in]   uuid           UUID of format.
 * @param[in]   name           Name of format.
 * @param[in]   content_type   Content type of format.
 * @param[in]   extension      File extension of format.
 * @param[in]   summary        Summary of format.
 * @param[in]   description    Description of format.
 * @param[in]   global         Whether the report is global.
 * @param[in]   files          Array of memory.  Each item is a file name
 *                             string, a terminating NULL, the file contents
 *                             in base64 and a terminating NULL.
 * @param[in]   params         Array of params.
 * @param[in]   params_options Array.  Each item is an array corresponding to
 *                             params.  Each item of an inner array is a string,
 *                             the text of an option in a selection.
 * @param[in]   signature      Signature.
 * @param[out]  report_format  Created report format.
 *
 * @return 0 success, 1 report format exists, 2 empty file name, 3 param value
 *         validation failed, 4 param value validation failed, 5 param default
 *         missing, 6 param min or max out of range, 7 param type missing,
 *         8 duplicate param name, 9 bogus param type name, 99 permission
 *         denied, -1 error.
 */
int
create_report_format (const char *uuid, const char *name,
                      const char *content_type, const char *extension,
                      const char *summary, const char *description, int global,
                      array_t *files, array_t *params, array_t *params_options,
                      const char *signature, report_format_t *report_format)
{
  gchar *quoted_name, *quoted_summary, *quoted_description, *quoted_extension;
  gchar *quoted_content_type, *quoted_signature, *file_name, *dir;
  gchar *candidate_name, *new_uuid, *uuid_actual;
  report_format_t report_format_rowid;
  int index, num;
  gchar *format_signature = NULL;
  gsize format_signature_size;
  int format_trust = TRUST_UNKNOWN;
  create_report_format_param_t *param;

  assert (current_credentials.uuid);
  assert (uuid);
  assert (name);
  assert (files);
  assert (params);

  /* Verify the signature. */

  if ((find_signature ("report_formats", uuid, &format_signature,
                       &format_signature_size, &uuid_actual)
       == 0)
      || signature)
    {
      char *locale;
      GString *format;

      format = g_string_new ("");

      g_string_append_printf (format,
                              "%s%s%s%i",
                              uuid_actual ? uuid_actual : uuid,
                              extension,
                              content_type,
                              global & 1);

      index = 0;
      locale = setlocale (LC_ALL, "C");
      g_ptr_array_sort (files, compare_files);
      setlocale (LC_ALL, locale);
      while ((file_name = (gchar*) g_ptr_array_index (files, index++)))
        g_string_append_printf (format,
                                "%s%s",
                                file_name,
                                file_name + strlen (file_name) + 1);

      index = 0;
      while ((param
               = (create_report_format_param_t*) g_ptr_array_index (params,
                                                                    index++)))
        {
          g_string_append_printf (format,
                                  "%s%s",
                                  param->name,
                                  param->type);

          if (param->type_min)
            {
              long long int min;
              min = strtoll (param->type_min, NULL, 0);
              if (min == LLONG_MIN)
                return 6;
              g_string_append_printf (format, "%lli", min);
            }

          if (param->type_max)
            {
              long long int max;
              max = strtoll (param->type_max, NULL, 0);
              if (max == LLONG_MAX)
                return 6;
              g_string_append_printf (format, "%lli", max);
            }

          g_string_append_printf (format,
                                  "%s",
                                  param->fallback);

          {
            array_t *options;
            int option_index;
            gchar *option_value;

            options = (array_t*) g_ptr_array_index (params_options, index - 1);
            if (options == NULL)
              return -1;
            option_index = 0;
            while ((option_value = (gchar*) g_ptr_array_index (options,
                                                               option_index++)))
              g_string_append_printf (format, "%s", option_value);
          }
        }

      g_string_append_printf (format, "\n");

      if (format_signature)
        signature = (const char*) format_signature;

      if (verify_signature (format->str, format->len, signature,
                            strlen (signature), &format_trust))
        {
          g_free (format_signature);
          g_string_free (format, TRUE);
          return -1;
        }
      g_string_free (format, TRUE);
    }

  sql_begin_immediate ();

  if (acl_user_may ("create_report_format") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (global && acl_user_can_everything (current_credentials.uuid) == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (sql_int ("SELECT COUNT(*) FROM report_formats WHERE uuid = '%s';",
               uuid)
      || sql_int ("SELECT COUNT(*) FROM report_formats_trash"
                  " WHERE original_uuid = '%s';",
                  uuid))
    {
      gchar *base, *new, *old, *path;
      char *real_old;

      /* Make a new UUID, because a report format exists with the given UUID. */

      new_uuid = gvm_uuid_make ();
      if (new_uuid == NULL)
        {
          sql_rollback ();
          return -1;
        }

      /* Setup a private/report_formats/ link to the signature of the existing
       * report format in the feed.  This allows the signature to be shared. */

      base = g_strdup_printf ("%s.asc", uuid);
      old = g_build_filename (GVM_NVT_DIR, "report_formats", base, NULL);
      real_old = realpath (old, NULL);
      if (real_old)
        {
          /* Signature exists in regular directory. */

          g_free (old);
          old = g_strdup (real_old);
          free (real_old);
        }
      else
        {
          struct stat state;

          /* Signature may be in private directory. */

          g_free (old);
          old = g_build_filename (GVMD_STATE_DIR,
                                  "signatures",
                                  "report_formats",
                                  base,
                                  NULL);
          if (lstat (old, &state))
            {
              /* No.  Signature may not exist in the feed yet. */
              g_free (old);
              old = g_build_filename (GVM_NVT_DIR, "report_formats", base,
                                      NULL);
              g_debug ("using standard old: %s", old);
            }
          else
            {
              int count;

              /* Yes.  Use the path it links to. */

              real_old = g_malloc (state.st_size + 1);
              count = readlink (old, real_old, state.st_size + 1);
              if (count < 0 || count > state.st_size)
                {
                  g_free (real_old);
                  g_free (old);
                  g_warning ("%s: readlink failed", __func__);
                  sql_rollback ();
                  return -1;
                }

              real_old[state.st_size] = '\0';
              g_free (old);
              old = real_old;
              g_debug ("using linked old: %s", old);
            }
        }
      g_free (base);

      path = g_build_filename (GVMD_STATE_DIR,
                               "signatures", "report_formats", NULL);

      if (g_mkdir_with_parents (path, 0755 /* "rwxr-xr-x" */))
        {
          g_warning ("%s: failed to create dir %s: %s",
                     __func__, path, strerror (errno));
          g_free (old);
          g_free (path);
          sql_rollback ();
          return -1;
        }

      base = g_strdup_printf ("%s.asc", new_uuid);
      new = g_build_filename (path, base, NULL);
      g_free (path);
      g_free (base);
      if (symlink (old, new))
        {
          g_free (old);
          g_free (new);
          g_warning ("%s: symlink failed: %s", __func__, strerror (errno));
          sql_rollback ();
          return -1;
        }
    }
  else
    new_uuid = NULL;

  candidate_name = g_strdup (name);
  quoted_name = sql_quote (candidate_name);

  num = 1;
  while (1)
    {
      if (!resource_with_name_exists (quoted_name, "report_format", 0))
        break;
      g_free (candidate_name);
      g_free (quoted_name);
      candidate_name = g_strdup_printf ("%s %u", name, ++num);
      quoted_name = sql_quote (candidate_name);
    }
  g_free (candidate_name);

  /* Write files to disk. */

  assert (global == 0);
  if (global)
    dir = predefined_report_format_dir (new_uuid ? new_uuid : uuid);
  else
    {
      assert (current_credentials.uuid);
      dir = g_build_filename (GVMD_STATE_DIR,
                              "report_formats",
                              current_credentials.uuid,
                              new_uuid ? new_uuid : uuid,
                              NULL);
    }

  if (g_file_test (dir, G_FILE_TEST_EXISTS) && gvm_file_remove_recurse (dir))
    {
      g_warning ("%s: failed to remove dir %s", __func__, dir);
      g_free (dir);
      g_free (quoted_name);
      g_free (new_uuid);
      sql_rollback ();
      return -1;
    }

  if (g_mkdir_with_parents (dir, 0755 /* "rwxr-xr-x" */))
    {
      g_warning ("%s: failed to create dir %s: %s",
                 __func__, dir, strerror (errno));
      g_free (dir);
      g_free (quoted_name);
      g_free (new_uuid);
      sql_rollback ();
      return -1;
    }

  if (global == 0)
    {
      gchar *report_dir;

      /* glib seems to apply the mode to the first dir only. */

      report_dir = g_build_filename (GVMD_STATE_DIR,
                                     "report_formats",
                                     current_credentials.uuid,
                                     NULL);

      if (chmod (report_dir, 0755 /* rwxr-xr-x */))
        {
          g_warning ("%s: chmod failed: %s",
                     __func__,
                     strerror (errno));
          g_free (dir);
          g_free (report_dir);
          g_free (quoted_name);
          g_free (new_uuid);
          sql_rollback ();
          return -1;
        }

      g_free (report_dir);
    }

  /* glib seems to apply the mode to the first dir only. */
  if (chmod (dir, 0755 /* rwxr-xr-x */))
    {
      g_warning ("%s: chmod failed: %s",
                 __func__,
                 strerror (errno));
      g_free (dir);
      g_free (quoted_name);
      g_free (new_uuid);
      sql_rollback ();
      return -1;
    }

  index = 0;
  while ((file_name = (gchar*) g_ptr_array_index (files, index++)))
    {
      gchar *contents, *file, *full_file_name;
      gsize contents_size;
      GError *error;
      int ret;

      if (strlen (file_name) == 0)
        {
          gvm_file_remove_recurse (dir);
          g_free (dir);
          g_free (quoted_name);
          g_free (new_uuid);
          sql_rollback ();
          return 2;
        }

      file = file_name + strlen (file_name) + 1;
      if (strlen (file))
        contents = (gchar*) g_base64_decode (file, &contents_size);
      else
        {
          contents = g_strdup ("");
          contents_size = 0;
        }

      full_file_name = g_build_filename (dir, file_name, NULL);

      error = NULL;
      g_file_set_contents (full_file_name, contents, contents_size, &error);
      g_free (contents);
      if (error)
        {
          g_warning ("%s: %s", __func__, error->message);
          g_error_free (error);
          gvm_file_remove_recurse (dir);
          g_free (full_file_name);
          g_free (dir);
          g_free (quoted_name);
          g_free (new_uuid);
          sql_rollback ();
          return -1;
        }

      if (strcmp (file_name, "generate") == 0)
        ret = chmod (full_file_name, 0755 /* rwxr-xr-x */);
      else
        ret = chmod (full_file_name, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
      if (ret)
        {
          g_warning ("%s: chmod failed: %s",
                     __func__,
                     strerror (errno));
          gvm_file_remove_recurse (dir);
          g_free (full_file_name);
          g_free (dir);
          g_free (quoted_name);
          g_free (new_uuid);
          sql_rollback ();
          return -1;
        }

      g_free (full_file_name);
    }

  /* Add format to database. */

  quoted_summary = summary ? sql_quote (summary) : NULL;
  quoted_description = description ? sql_quote (description) : NULL;
  quoted_extension = extension ? sql_quote (extension) : NULL;
  quoted_content_type = content_type ? sql_quote (content_type) : NULL;
  quoted_signature = signature ? sql_quote (signature) : NULL;
  g_free (format_signature);

  if (global)
    sql ("INSERT INTO report_formats"
         " (uuid, name, owner, summary, description, extension, content_type,"
         "  signature, trust, trust_time, flags, creation_time,"
         "  modification_time)"
         " VALUES ('%s', '%s', NULL, '%s', '%s', '%s', '%s', '%s', %i, %i, 0,"
         "         m_now (), m_now ());",
         new_uuid ? new_uuid : uuid,
         quoted_name,
         quoted_summary ? quoted_summary : "",
         quoted_description ? quoted_description : "",
         quoted_extension ? quoted_extension : "",
         quoted_content_type ? quoted_content_type : "",
         quoted_signature ? quoted_signature : "",
         format_trust,
         time (NULL));
  else
    sql ("INSERT INTO report_formats"
         " (uuid, name, owner, summary, description, extension, content_type,"
         "  signature, trust, trust_time, flags, creation_time,"
         "  modification_time)"
         " VALUES ('%s', '%s',"
         " (SELECT id FROM users WHERE users.uuid = '%s'),"
         " '%s', '%s', '%s', '%s', '%s', %i, %i, 0, m_now (), m_now ());",
         new_uuid ? new_uuid : uuid,
         quoted_name,
         current_credentials.uuid,
         quoted_summary ? quoted_summary : "",
         quoted_description ? quoted_description : "",
         quoted_extension ? quoted_extension : "",
         quoted_content_type ? quoted_content_type : "",
         quoted_signature ? quoted_signature : "",
         format_trust,
         time (NULL));

  g_free (new_uuid);
  g_free (quoted_summary);
  g_free (quoted_description);
  g_free (quoted_extension);
  g_free (quoted_content_type);
  g_free (quoted_signature);
  g_free (quoted_name);

  /* Add params to database. */

  report_format_rowid = sql_last_insert_id ();
  index = 0;
  while ((param = (create_report_format_param_t*) g_ptr_array_index (params,
                                                                     index++)))
    {
      gchar *quoted_param_name, *quoted_param_value, *quoted_param_fallback;
      rowid_t param_rowid;
      long long int min, max;

      if (param->type == NULL)
        {
          gvm_file_remove_recurse (dir);
          g_free (dir);
          sql_rollback ();
          return 7;
        }

      if (report_format_param_type_from_name (param->type)
          == REPORT_FORMAT_PARAM_TYPE_ERROR)
        {
          gvm_file_remove_recurse (dir);
          g_free (dir);
          sql_rollback ();
          return 9;
        }

      /* Param min and max are optional.  LLONG_MIN and LLONG_MAX mark in the db
       * that they were missing, so if the user gives LLONG_MIN or LLONG_MAX it
       * is an error.  This ensures that GPG verification works, because the
       * verification knows when to leave out min and max. */

      if (param->type_min)
        {
          min = strtoll (param->type_min, NULL, 0);
          if (min == LLONG_MIN)
            {
              gvm_file_remove_recurse (dir);
              g_free (dir);
              sql_rollback ();
              return 6;
            }
        }
      else
        min = LLONG_MIN;

      if (param->type_max)
        {
          max = strtoll (param->type_max, NULL, 0);
          if (max == LLONG_MAX)
            {
              gvm_file_remove_recurse (dir);
              g_free (dir);
              sql_rollback ();
              return 6;
            }
        }
      else
        max = LLONG_MAX;

      if (param->fallback == NULL)
        {
          gvm_file_remove_recurse (dir);
          g_free (dir);
          sql_rollback ();
          return 5;
        }

      quoted_param_name = sql_quote (param->name);

      if (sql_int ("SELECT count(*) FROM report_format_params"
                   " WHERE name = '%s' AND report_format = %llu;",
                   quoted_param_name,
                   report_format_rowid))
        {
          g_free (quoted_param_name);
          gvm_file_remove_recurse (dir);
          g_free (dir);
          sql_rollback ();
          return 8;
        }

      quoted_param_value = sql_quote (param->value);
      quoted_param_fallback = sql_quote (param->fallback);

      sql ("INSERT INTO report_format_params"
           " (report_format, name, type, value, type_min, type_max, type_regex,"
           "  fallback)"
           " VALUES (%llu, '%s', %u, '%s', %lli, %lli, '', '%s');",
           report_format_rowid,
           quoted_param_name,
           report_format_param_type_from_name (param->type),
           quoted_param_value,
           min,
           max,
           quoted_param_fallback);

      g_free (quoted_param_name);
      g_free (quoted_param_value);
      g_free (quoted_param_fallback);

      param_rowid = sql_last_insert_id ();

      {
        array_t *options;
        int option_index;
        gchar *option_value;

        options = (array_t*) g_ptr_array_index (params_options, index - 1);
        if (options == NULL)
          {
            g_warning ("%s: options was NULL", __func__);
            gvm_file_remove_recurse (dir);
            g_free (dir);
            sql_rollback ();
            return -1;
          }
        option_index = 0;
        while ((option_value = (gchar*) g_ptr_array_index (options,
                                                           option_index++)))
          {
            gchar *quoted_option_value = sql_quote (option_value);
            sql ("INSERT INTO report_format_param_options"
                 " (report_format_param, value)"
                 " VALUES (%llu, '%s');",
                 param_rowid,
                 quoted_option_value);
            g_free (quoted_option_value);
          }
      }

      if (validate_param_value (report_format_rowid, param_rowid, param->name,
                                param->value))
        {
          gvm_file_remove_recurse (dir);
          g_free (dir);
          sql_rollback ();
          return 3;
        }

      if (validate_param_value (report_format_rowid, param_rowid, param->name,
                                param->fallback))
        {
          gvm_file_remove_recurse (dir);
          g_free (dir);
          sql_rollback ();
          return 4;
        }
    }

  if (report_format)
    *report_format = report_format_rowid;

  g_free (dir);

  sql_commit ();

  return 0;
}

/**
 * @brief Create Report Format from an existing Report Format.
 *
 * @param[in]  name                 Name of new Report Format. NULL to copy
 *                                  from existing.
 * @param[in]  source_uuid          UUID of existing Report Format.
 * @param[out] new_report_format    New Report Format.
 *
 * @return 0 success, 1 Report Format exists already, 2 failed to find existing
 *         Report Format, 99 permission denied, -1 error.
 */
int
copy_report_format (const char* name, const char* source_uuid,
                    report_format_t* new_report_format)
{
  report_format_t new, old;
  gchar *copy_uuid, *source_dir, *copy_dir;
  gchar *tmp_dir;
  int predefined, ret;

  assert (current_credentials.uuid);

  sql_begin_immediate ();

  ret = copy_resource_lock ("report_format", name, NULL, source_uuid,
                            "extension, content_type, summary, description,"
                            " signature, trust, trust_time, flags",
                            1, &new, &old);
  if (ret)
    {
      sql_rollback ();
      return ret;
    }

  if (report_format_predefined (old))
    sql ("UPDATE report_formats SET trust = %i, trust_time = %i"
         " WHERE id = %llu;",
         TRUST_YES,
         time (NULL),
         new);

  /* Copy report format parameters. */

  sql ("INSERT INTO report_format_params "
       " (report_format, name, type, value, type_min, type_max,"
       "  type_regex, fallback)"
       " SELECT %llu, name, type, value, type_min, type_max,"
       "  type_regex, fallback"
       "  FROM report_format_params WHERE report_format = %llu;",
       new,
       old);

  /* Copy files on disk. */

  predefined = report_format_predefined (old);
  if (predefined)
    source_dir = predefined_report_format_dir (source_uuid);
  else
    {
      gchar *owner_uuid;
      owner_uuid = report_format_owner_uuid (old);
      assert (owner_uuid);
      source_dir = g_build_filename (GVMD_STATE_DIR,
                                     "report_formats",
                                     owner_uuid,
                                     source_uuid,
                                     NULL);
      g_free (owner_uuid);
    }

  /* Check that the source directory exists. */

  if (!g_file_test (source_dir, G_FILE_TEST_EXISTS))
    {
      g_warning ("%s: report format directory %s not found",
                 __func__, source_dir);
      g_free (source_dir);
      sql_rollback ();
      return -1;
    }

  copy_uuid = report_format_uuid (new);
  if (copy_uuid == NULL)
    {
      sql_rollback ();
      return -1;
    }

  /* Prepare directory to copy into. */

  copy_dir = g_build_filename (GVMD_STATE_DIR,
                               "report_formats",
                               current_credentials.uuid,
                               copy_uuid,
                               NULL);

  if (g_file_test (copy_dir, G_FILE_TEST_EXISTS)
      && gvm_file_remove_recurse (copy_dir))
    {
      g_warning ("%s: failed to remove dir %s", __func__, copy_dir);
      g_free (source_dir);
      g_free (copy_dir);
      g_free (copy_uuid);
      sql_rollback ();
      return -1;
    }

  if (g_mkdir_with_parents (copy_dir, 0755 /* "rwxr-xr-x" */))
    {
      g_warning ("%s: failed to create dir %s", __func__, copy_dir);
      g_free (source_dir);
      g_free (copy_dir);
      g_free (copy_uuid);
      sql_rollback ();
      return -1;
    }

  /* Correct permissions as glib doesn't seem to do so. */

  tmp_dir = g_build_filename (GVMD_STATE_DIR,
                              "report_formats",
                              current_credentials.uuid,
                              NULL);

  if (chmod (tmp_dir, 0755 /* rwxr-xr-x */))
    {
      g_warning ("%s: chmod %s failed: %s",
                 __func__,
                 tmp_dir,
                 strerror (errno));
      g_free (source_dir);
      g_free (copy_dir);
      g_free (copy_uuid);
      g_free (tmp_dir);
      sql_rollback ();
      return -1;
    }
  g_free (tmp_dir);

  tmp_dir = g_build_filename (GVMD_STATE_DIR,
                              "report_formats",
                              current_credentials.uuid,
                              copy_uuid,
                              NULL);

  if (chmod (tmp_dir, 0755 /* rwxr-xr-x */))
    {
      g_warning ("%s: chmod %s failed: %s",
                 __func__,
                 tmp_dir,
                 strerror (errno));
      g_free (source_dir);
      g_free (copy_dir);
      g_free (copy_uuid);
      g_free (tmp_dir);
      sql_rollback ();
      return -1;
    }
  g_free (tmp_dir);
  g_free (copy_uuid);

  /* Copy files into new directory. */
  {
    GDir *directory;
    GError *error;

    error = NULL;
    directory = g_dir_open (source_dir, 0, &error);
    if (directory == NULL)
      {
        if (error)
          {
            g_warning ("g_dir_open(%s) failed - %s",
                       source_dir, error->message);
            g_error_free (error);
          }
        g_free (source_dir);
        g_free (copy_dir);
        sql_rollback ();
        return -1;
      }
    else
      {
        gchar *source_file, *copy_file;
        const gchar *filename;

        filename = g_dir_read_name (directory);
        while (filename)
          {
            source_file = g_build_filename (source_dir, filename, NULL);
            copy_file = g_build_filename (copy_dir, filename, NULL);

            if (gvm_file_copy (source_file, copy_file) == FALSE)
              {
                g_warning ("%s: copy of %s to %s failed",
                           __func__, source_file, copy_file);
                g_free (source_file);
                g_free (copy_file);
                g_free (source_dir);
                g_free (copy_dir);
                sql_rollback ();
                return -1;
              }
            g_free (source_file);
            g_free (copy_file);
            filename = g_dir_read_name (directory);
          }
      }
  }

  sql_commit ();
  g_free (source_dir);
  g_free (copy_dir);
  if (new_report_format) *new_report_format = new;
  return 0;
}

/**
 * @brief Modify a report format.
 *
 * @param[in]  report_format_id  UUID of report format.
 * @param[in]  name              Name of report format.
 * @param[in]  summary           Summary of report format.
 * @param[in]  active            Active flag.
 * @param[in]  param_name        Parameter to modify.
 * @param[in]  param_value       Value of parameter.
 * @param[in]  predefined        Predefined flag.
 *
 * @return 0 success, 1 failed to find report format, 2 report_format_id
 * required, 3 failed to find report format parameter, 4 parameter value
 * validation failed, 5 error in predefined, 99 permission denied, -1 internal
 * error.
 */
int
modify_report_format (const char *report_format_id, const char *name,
                      const char *summary, const char *active,
                      const char *param_name, const char *param_value,
                      const char *predefined)
{
  report_format_t report_format;
  int ret = 0;

  if (report_format_id == NULL)
    return 2;

  if (predefined && strcmp (predefined, "0") && strcmp (predefined, "1"))
    return 5;

  sql_begin_immediate ();

  assert (current_credentials.uuid);

  if (acl_user_may ("modify_report_format") == 0)
    {
      sql_rollback ();
      return 99;
    }

  report_format = 0;
  if (find_report_format_with_permission (report_format_id, &report_format,
                                          "modify_report_format"))
    {
      sql_rollback ();
      return -1;
    }

  if (report_format == 0)
    {
      sql_rollback ();
      return 1;
    }

  /* It is only possible to modify predefined report formats from the command
   * line. */
  if (current_credentials.uuid == NULL
      && report_format_predefined (report_format))
    {
      sql_rollback ();
      return 99;
    }

  /* Update values */
  if (name)
    set_report_format_name (report_format, name);

  if (summary)
    set_report_format_summary (report_format, summary);

  if (active)
    set_report_format_active (report_format, strcmp (active, "0"));

  if (predefined)
    resource_set_predefined ("report_format", report_format,
                             strcmp (predefined, "0"));

  sql_commit ();

  /* Update format params if set */
  if (param_name)
    {
      ret = set_report_format_param (report_format, param_name, param_value);
      if (ret == 1)
        ret = 3;
      if (ret == 2)
        ret = 4;
    }

  return ret;
}

/**
 * @brief Move a report format directory.
 *
 * @param[in]  dir      Old dir.
 * @param[in]  new_dir  New dir.
 *
 * @return 0 success, -1 error.
 */
static int
move_report_format_dir (const char *dir, const char *new_dir)
{
  if (g_file_test (dir, G_FILE_TEST_EXISTS)
      && gvm_file_check_is_dir (dir))
    {
      if (rename (dir, new_dir))
        {
          GError *error;
          GDir *directory;
          const gchar *entry;

          if (errno == EXDEV)
            {
              /* Across devices, move by hand. */

              if (g_mkdir_with_parents (new_dir, 0755 /* "rwxr-xr-x" */))
                {
                  g_warning ("%s: failed to create dir %s", __func__,
                             new_dir);
                  return -1;
                }

              error = NULL;
              directory = g_dir_open (dir, 0, &error);

              if (directory == NULL)
                {
                  g_warning ("%s: failed to g_dir_open %s: %s",
                             __func__, dir, error->message);
                  g_error_free (error);
                  return -1;
                }

              entry = NULL;
              while ((entry = g_dir_read_name (directory)))
                {
                  gchar *entry_path, *new_path;
                  entry_path = g_build_filename (dir, entry, NULL);
                  new_path = g_build_filename (new_dir, entry, NULL);
                  if (gvm_file_move (entry_path, new_path) == FALSE)
                    {
                      g_warning ("%s: failed to move %s to %s",
                                 __func__, entry_path, new_path);
                      g_free (entry_path);
                      g_free (new_path);
                      g_dir_close (directory);
                      return -1;
                    }
                  g_free (entry_path);
                  g_free (new_path);
                }

              g_dir_close (directory);

              gvm_file_remove_recurse (dir);
            }
          else
            {
              g_warning ("%s: rename %s to %s: %s",
                         __func__, dir, new_dir, strerror (errno));
              return -1;
            }
        }
    }
  else
    {
      g_warning ("%s: report dir missing: %s",
                 __func__, dir);
      return -1;
    }
  return 0;
}

/**
 * @brief Delete a report format from the db.
 *
 * @param[in]  report_format  Report format.
 */
static void
delete_report_format_rows (report_format_t report_format)
{
  sql ("DELETE FROM report_format_param_options WHERE report_format_param"
       " IN (SELECT id from report_format_params WHERE report_format = %llu);",
       report_format);
  sql ("DELETE FROM report_format_params WHERE report_format = %llu;",
       report_format);
  sql ("DELETE FROM report_formats WHERE id = %llu;", report_format);
}

/**
 * @brief Delete a report format.
 *
 * @param[in]  report_format_id  UUID of Report format.
 * @param[in]  ultimate          Whether to remove entirely, or to trashcan.
 *
 * @return 0 success, 1 report format in use, 2 failed to find report format,
 *         3 predefined report format, 99 permission denied, -1 error.
 */
int
delete_report_format (const char *report_format_id, int ultimate)
{
  gchar *dir;
  char *owner_uuid;
  report_format_t report_format, trash_report_format;

  /* This is complicated in two ways
   *
   *   - the UUID of a report format is the same every time it is
   *     imported, so to prevent multiple deletes from producing
   *     duplicate UUIDs in the trashcan, each report format in the
   *     trashcan gets a new UUID,
   *
   *   - the report format has information on disk on top of the
   *     info in the db, so the disk information has to be held
   *     in a special trashcan directory. */

  sql_begin_immediate ();

  if (acl_user_may ("delete_report_format") == 0)
    {
      sql_rollback ();
      return 99;
    }

  /* Look in the "real" table. */

  if (find_report_format_with_permission (report_format_id, &report_format,
                                          "delete_report_format"))
    {
      sql_rollback ();
      return -1;
    }

  if (report_format == 0)
    {
      gchar *report_format_string, *base;

      /* Look in the trashcan. */

      if (find_trash ("report_format", report_format_id, &report_format))
        {
          sql_rollback ();
          return -1;
        }
      if (report_format == 0)
        {
          sql_rollback ();
          return 2;
        }
      if (ultimate == 0)
        {
          /* It's already in the trashcan. */
          sql_commit ();
          return 0;
        }

      /* Check if it's in use by a trash alert. */

      if (trash_report_format_in_use (report_format))
        {
          sql_rollback ();
          return 1;
        }

      /* Remove entirely. */

      permissions_set_orphans ("report_format", report_format, LOCATION_TRASH);
      tags_remove_resource ("report_format", report_format, LOCATION_TRASH);

      base = sql_string ("SELECT original_uuid || '.asc'"
                         " FROM report_formats_trash"
                         " WHERE id = %llu;",
                         report_format);
      sql ("DELETE FROM report_format_param_options_trash"
           " WHERE report_format_param"
           " IN (SELECT id from report_format_params_trash"
           "     WHERE report_format = %llu);",
           report_format);
      sql ("DELETE FROM report_format_params_trash WHERE report_format = %llu;",
           report_format);
      sql ("DELETE FROM report_formats_trash WHERE id = %llu;",
           report_format);

      /* Remove the dirs last, in case any SQL rolls back. */

      /* Trash files. */
      report_format_string = g_strdup_printf ("%llu", report_format);
      dir = report_format_trash_dir (report_format_string);
      g_free (report_format_string);
      if (g_file_test (dir, G_FILE_TEST_EXISTS) && gvm_file_remove_recurse (dir))
        {
          g_free (dir);
          g_free (base);
          sql_rollback ();
          return -1;
        }
      g_free (dir);

      /* Links to the feed signatures. */
      dir = g_build_filename (GVMD_STATE_DIR, "signatures",
                              "report_formats", base, NULL);
      g_free (base);
      unlink (dir);
      g_free (dir);
      sql_commit ();

      return 0;
    }

  if (report_format_predefined (report_format))
    {
      sql_rollback ();
      return 3;
    }

  owner_uuid = report_format_owner_uuid (report_format);
  dir = g_build_filename (GVMD_STATE_DIR,
                          "report_formats",
                          owner_uuid,
                          report_format_id,
                          NULL);
  free (owner_uuid);

  if (ultimate)
    {
      permissions_set_orphans ("report_format", report_format, LOCATION_TABLE);
      tags_remove_resource ("report_format", report_format, LOCATION_TABLE);

      /* Check if it's in use by a trash or regular alert. */

      if (sql_int ("SELECT count(*) FROM alert_method_data_trash"
                   " WHERE data = (SELECT uuid FROM report_formats"
                   "               WHERE id = %llu)"
                   " AND (name = 'notice_attach_format'"
                   "      OR name = 'notice_report_format');",
                   report_format))
        {
          g_free (dir);
          sql_rollback ();
          return 1;
        }

      if (report_format_in_use (report_format))
        {
          g_free (dir);
          sql_rollback ();
          return 1;
        }

      /* Remove directory. */

      if (g_file_test (dir, G_FILE_TEST_EXISTS) && gvm_file_remove_recurse (dir))
        {
          g_free (dir);
          sql_rollback ();
          return -1;
        }

      /* Remove from "real" tables. */

      delete_report_format_rows (report_format);
    }
  else
    {
      iterator_t params;
      gchar *trash_dir, *new_dir, *report_format_string;

      /* Check if it's in use by a regular alert. */

      if (report_format_in_use (report_format))
        {
          g_free (dir);
          sql_rollback ();
          return 1;
        }

      /* Move to trash. */

      trash_dir = report_format_trash_dir (NULL);
      if (g_mkdir_with_parents (trash_dir, 0755 /* "rwxr-xr-x" */))
        {
          g_warning ("%s: failed to create dir %s", __func__, trash_dir);
          g_free (trash_dir);
          sql_rollback ();
          return -1;
        }
      g_free (trash_dir);

      sql ("INSERT INTO report_formats_trash"
           " (uuid, owner, name, extension, content_type, summary,"
           "  description, signature, trust, trust_time, flags, original_uuid,"
           "  creation_time, modification_time)"
           " SELECT"
           "  make_uuid (), owner, name, extension, content_type, summary,"
           "  description, signature, trust, trust_time, flags, uuid,"
           "  creation_time, modification_time"
           " FROM report_formats"
           " WHERE id = %llu;",
           report_format);

      trash_report_format = sql_last_insert_id ();

      init_report_format_param_iterator (&params, report_format, 0, 1, NULL);
      while (next (&params))
        {
          report_format_param_t param, trash_param;

          param = report_format_param_iterator_param (&params);

          sql ("INSERT INTO report_format_params_trash"
               " (report_format, name, type, value, type_min, type_max,"
               "  type_regex, fallback)"
               " SELECT"
               "  %llu, name, type, value, type_min, type_max,"
               "  type_regex, fallback"
               " FROM report_format_params"
               " WHERE id = %llu;",
               trash_report_format,
               param);

          trash_param = sql_last_insert_id ();

          sql ("INSERT INTO report_format_param_options_trash"
               " (report_format_param, value)"
               " SELECT %llu, value"
               " FROM report_format_param_options"
               " WHERE report_format_param = %llu;",
               trash_param,
               param);
        }
      cleanup_iterator (&params);

      permissions_set_locations ("report_format", report_format,
                                 trash_report_format, LOCATION_TRASH);
      tags_set_locations ("report_format", report_format,
                          trash_report_format, LOCATION_TRASH);

      /* Remove from "real" tables. */

      delete_report_format_rows (report_format);

      /* Move the dir last, in case any SQL rolls back. */

      report_format_string = g_strdup_printf ("%llu", trash_report_format);
      new_dir = report_format_trash_dir (report_format_string);
      g_free (report_format_string);
      if (move_report_format_dir (dir, new_dir))
        {
          g_free (dir);
          g_free (new_dir);
          sql_rollback ();
          return -1;
        }
      g_free (new_dir);
    }

  g_free (dir);

  sql_commit ();

  return 0;
}

/**
 * @brief Try restore a report format.
 *
 * If success, ends transaction for caller before exiting.
 *
 * @param[in]  report_format_id  UUID of resource.
 *
 * @return 0 success, 1 fail because resource is in use, 2 failed to find
 *         resource, 4 fail because resource with UUID exists, -1 error.
 */
int
restore_report_format (const char *report_format_id)
{
  report_format_t resource, report_format;
  iterator_t params;
  gchar *dir, *trash_dir, *resource_string;
  char *trash_uuid, *owner_uuid;

  if (find_trash ("report_format", id, &resource))
    {
      sql_rollback ();
      return -1;
    }

  if (resource == 0)
    return 2;

  if (sql_int ("SELECT count(*) FROM report_formats"
               " WHERE name ="
               " (SELECT name FROM report_formats_trash WHERE id = %llu)"
               " AND " ACL_USER_OWNS () ";",
               resource,
               current_credentials.uuid))
    {
      sql_rollback ();
      return 3;
    }

  if (sql_int ("SELECT count(*) FROM report_formats"
               " WHERE uuid = (SELECT original_uuid"
               "               FROM report_formats_trash"
               "               WHERE id = %llu);",
               resource))
    {
      sql_rollback ();
      return 4;
    }

  /* Move to "real" tables. */

  sql ("INSERT INTO report_formats"
       " (uuid, owner, name, extension, content_type, summary,"
       "  description, signature, trust, trust_time, flags,"
       "  creation_time, modification_time)"
       " SELECT"
       "  original_uuid, owner, name, extension, content_type, summary,"
       "  description, signature, trust, trust_time, flags,"
       "  creation_time, modification_time"
       " FROM report_formats_trash"
       " WHERE id = %llu;",
       resource);

  report_format = sql_last_insert_id ();

  init_report_format_param_iterator (&params, resource, 1, 1, NULL);
  while (next (&params))
    {
      report_format_param_t param, trash_param;

      trash_param = report_format_param_iterator_param (&params);

      sql ("INSERT INTO report_format_params"
           " (report_format, name, type, value, type_min, type_max,"
           "  type_regex, fallback)"
           " SELECT"
           "  %llu, name, type, value, type_min, type_max,"
           "  type_regex, fallback"
           " FROM report_format_params_trash"
           " WHERE id = %llu;",
           report_format,
           trash_param);

      param = sql_last_insert_id ();

      sql ("INSERT INTO report_format_param_options"
           " (report_format_param, value)"
           " SELECT %llu, value"
           " FROM report_format_param_options_trash"
           " WHERE report_format_param = %llu;",
           param,
           trash_param);
    }
  cleanup_iterator (&params);

  trash_uuid = sql_string ("SELECT original_uuid FROM report_formats_trash"
                           " WHERE id = %llu;",
                           resource);
  if (trash_uuid == NULL)
    abort ();

  permissions_set_locations ("report_format", resource, report_format,
                             LOCATION_TABLE);
  tags_set_locations ("report_format", resource, report_format,
                      LOCATION_TABLE);

  /* Remove from trash tables. */

  sql ("DELETE FROM report_format_param_options_trash"
       " WHERE report_format_param"
       " IN (SELECT id from report_format_params_trash"
       "     WHERE report_format = %llu);",
       resource);
  sql ("DELETE FROM report_format_params_trash WHERE report_format = %llu;",
       resource);
  sql ("DELETE FROM report_formats_trash WHERE id = %llu;",
       resource);

  /* Move the dir last, in case any SQL rolls back. */

  owner_uuid = report_format_owner_uuid (report_format);
  dir = g_build_filename (GVMD_STATE_DIR,
                          "report_formats",
                          owner_uuid,
                          trash_uuid,
                          NULL);
  free (trash_uuid);
  free (owner_uuid);

  resource_string = g_strdup_printf ("%llu", resource);
  trash_dir = report_format_trash_dir (resource_string);
  g_free (resource_string);
  if (move_report_format_dir (trash_dir, dir))
    {
      g_free (dir);
      g_free (trash_dir);
      sql_rollback ();
      return -1;
    }
  g_free (dir);
  g_free (trash_dir);

  sql_commit ();
  return 0;
}

/**
 * @brief Return the UUID of a report format.
 *
 * @param[in]  report_format  Report format.
 *
 * @return Newly allocated UUID.
 */
char *
report_format_uuid (report_format_t report_format)
{
  return sql_string ("SELECT uuid FROM report_formats WHERE id = %llu;",
                     report_format);
}

/**
 * @brief Return the UUID of the owner of a report format.
 *
 * @param[in]  report_format  Report format.
 *
 * @return Newly allocated owner UUID if there is an owner, else NULL.
 */
char *
report_format_owner_uuid (report_format_t report_format)
{
  if (sql_int ("SELECT " ACL_IS_GLOBAL () " FROM report_formats"
               " WHERE id = %llu;",
               report_format))
    return NULL;
  return sql_string ("SELECT uuid FROM users"
                     " WHERE id = (SELECT owner FROM report_formats"
                     "             WHERE id = %llu);",
                     report_format);
}

/**
 * @brief Set the active flag of a report format.
 *
 * @param[in]  report_format  The report format.
 * @param[in]  active         Active flag.
 */
static void
set_report_format_active (report_format_t report_format, int active)
{
  if (active)
    sql ("UPDATE report_formats SET flags = (flags | %llu), "
         "                          modification_time = m_now ()"
         " WHERE id = %llu;",
         (long long int) REPORT_FORMAT_FLAG_ACTIVE,
         report_format);
  else
    sql ("UPDATE report_formats SET flags = (flags & ~ %llu), "
         "                          modification_time = m_now ()"
         " WHERE id = %llu;",
         (long long int) REPORT_FORMAT_FLAG_ACTIVE,
         report_format);
}

/**
 * @brief Return the name of a report format.
 *
 * @param[in]  report_format  Report format.
 *
 * @return Newly allocated name.
 */
char *
report_format_name (report_format_t report_format)
{
  return sql_string ("SELECT name FROM report_formats WHERE id = %llu;",
                     report_format);
}

/**
 * @brief Return the content type of a report format.
 *
 * @param[in]  report_format  Report format.
 *
 * @return Newly allocated content type.
 */
char *
report_format_content_type (report_format_t report_format)
{
  return sql_string ("SELECT content_type FROM report_formats"
                     " WHERE id = %llu;",
                     report_format);
}

/**
 * @brief Return whether a report format is referenced by an alert.
 *
 * @param[in]  report_format  Report Format.
 *
 * @return 1 if in use, else 0.
 */
int
report_format_in_use (report_format_t report_format)
{
  return !!sql_int ("SELECT count(*) FROM alert_method_data"
                    " WHERE data = (SELECT uuid FROM report_formats"
                    "               WHERE id = %llu)"
                    " AND (name = 'notice_attach_format'"
                    "      OR name = 'notice_report_format'"
                    "      OR name = 'scp_report_format'"
                    "      OR name = 'send_report_format'"
                    "      OR name = 'smb_report_format'"
                    "      OR name = 'verinice_server_report_format');",
                    report_format);
}

/**
 * @brief Return whether a report format in trash is referenced by an alert.
 *
 * @param[in]  report_format  Report Format.
 *
 * @return 1 if in use, else 0.
 */
int
trash_report_format_in_use (report_format_t report_format)
{
  return !!sql_int ("SELECT count(*) FROM alert_method_data_trash"
                    " WHERE data = (SELECT original_uuid"
                    "               FROM report_formats_trash"
                    "               WHERE id = %llu)"
                    " AND (name = 'notice_attach_format'"
                    "      OR name = 'notice_report_format'"
                    "      OR name = 'scp_report_format'"
                    "      OR name = 'send_report_format'"
                    "      OR name = 'smb_report_format'"
                    "      OR name = 'verinice_server_report_format');",
                    report_format);
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
  return report_format_in_use (report_format) == 0
         && report_format_predefined (report_format) == 0;
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
 * @brief Return the extension of a report format.
 *
 * @param[in]  report_format  Report format.
 *
 * @return Newly allocated extension.
 */
char *
report_format_extension (report_format_t report_format)
{
  return sql_string ("SELECT extension FROM report_formats WHERE id = %llu;",
                     report_format);
}

/**
 * @brief Set the name of the report format.
 *
 * @param[in]  report_format  The report format.
 * @param[in]  name           Name.
 */
static void
set_report_format_name (report_format_t report_format, const char *name)
{
  gchar *quoted_name = sql_quote (name);
  sql ("UPDATE report_formats SET name = '%s', modification_time = m_now ()"
       " WHERE id = %llu;",
       quoted_name,
       report_format);
  g_free (quoted_name);
}

/**
 * @brief Return whether a report format is predefined.
 *
 * @param[in]  report_format  Report format.
 *
 * @return 1 if predefined, else 0.
 */
int
report_format_predefined (report_format_t report_format)
{
  return resource_predefined ("report_format", report_format);
}

/**
 * @brief Return whether a report format is active.
 *
 * @param[in]  report_format  Report format.
 *
 * @return -1 on error, 1 if active, else 0.
 */
int
report_format_active (report_format_t report_format)
{
  long long int flag;
  switch (sql_int64 (&flag,
                     "SELECT flags & %llu FROM report_formats"
                     " WHERE id = %llu;",
                     (long long int) REPORT_FORMAT_FLAG_ACTIVE,
                     report_format))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        return 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        return -1;
        break;
    }
  return flag ? 1 : 0;
}

/**
 * @brief Set the summary of the report format.
 *
 * @param[in]  report_format  The report format.
 * @param[in]  summary        Summary.
 */
static void
set_report_format_summary (report_format_t report_format, const char *summary)
{
  gchar *quoted_summary = sql_quote (summary);
  sql ("UPDATE report_formats SET summary = '%s', modification_time = m_now ()"
       " WHERE id = %llu;",
       quoted_summary,
       report_format);
  g_free (quoted_summary);
}

/**
 * @brief Return the type max of a report format param.
 *
 * @param[in]  report_format  Report format.
 * @param[in]  name           Name of param.
 *
 * @return Param type.
 */
static report_format_param_type_t
report_format_param_type (report_format_t report_format, const char *name)
{
  report_format_param_type_t type;
  gchar *quoted_name = sql_quote (name);
  type = (report_format_param_type_t)
         sql_int ("SELECT type FROM report_format_params"
                  " WHERE report_format = %llu AND name = '%s';",
                  report_format,
                  quoted_name);
  g_free (quoted_name);
  return type;
}

/**
 * @brief Return the type max of a report format param.
 *
 * @param[in]  report_format  Report format.
 * @param[in]  name           Name of param.
 *
 * @return Max.
 */
static long long int
report_format_param_type_max (report_format_t report_format, const char *name)
{
  long long int max = 0;
  gchar *quoted_name = sql_quote (name);
  /* Assume it's there. */
  sql_int64 (&max,
             "SELECT type_max FROM report_format_params"
             " WHERE report_format = %llu AND name = '%s';",
             report_format,
             quoted_name);
  g_free (quoted_name);
  return max;
}

/**
 * @brief Return the type min of a report format param.
 *
 * @param[in]  report_format  Report format.
 * @param[in]  name           Name of param.
 *
 * @return Min.
 */
static long long int
report_format_param_type_min (report_format_t report_format, const char *name)
{
  long long int min = 0;
  gchar *quoted_name = sql_quote (name);
  /* Assume it's there. */
  sql_int64 (&min,
             "SELECT type_min FROM report_format_params"
             " WHERE report_format = %llu AND name = '%s';",
             report_format,
             quoted_name);
  g_free (quoted_name);
  return min;
}


/**
 * @brief Validate a value for a report format param.
 *
 * @param[in]  report_format  Report format.
 * @param[in]  param          Param.
 * @param[in]  name           Name of param.
 * @param[in]  value          Potential value of param.
 *
 * @return 0 success, 1 fail.
 */
static int
validate_param_value (report_format_t report_format,
                      report_format_param_t param, const char *name,
                      const char *value)
{
  switch (report_format_param_type (report_format, name))
    {
      case REPORT_FORMAT_PARAM_TYPE_INTEGER:
        {
          long long int min, max, actual;
          min = report_format_param_type_min (report_format, name);
          /* Simply truncate out of range values. */
          actual = strtoll (value, NULL, 0);
          if (actual < min)
            return 1;
          max = report_format_param_type_max (report_format, name);
          if (actual > max)
            return 1;
        }
        break;
      case REPORT_FORMAT_PARAM_TYPE_SELECTION:
        {
          iterator_t options;
          int found = 0;

          init_param_option_iterator (&options, param, 1, NULL);
          while (next (&options))
            if (param_option_iterator_value (&options)
                && (strcmp (param_option_iterator_value (&options), value)
                    == 0))
              {
                found = 1;
                break;
              }
          cleanup_iterator (&options);
          if (found)
            break;
          return 1;
        }
      case REPORT_FORMAT_PARAM_TYPE_STRING:
      case REPORT_FORMAT_PARAM_TYPE_TEXT:
        {
          long long int min, max, actual;
          min = report_format_param_type_min (report_format, name);
          actual = strlen (value);
          if (actual < min)
            return 1;
          max = report_format_param_type_max (report_format, name);
          if (actual > max)
            return 1;
        }
        break;
      case REPORT_FORMAT_PARAM_TYPE_REPORT_FORMAT_LIST:
        {
          if (g_regex_match_simple
                ("^(?:[[:alnum:]-_]+)?(?:,(?:[[:alnum:]-_])+)*$", value, 0, 0)
              == FALSE)
            return 1;
          else
            return 0;
        }
        break;
      default:
        break;
    }
  return 0;
}

/**
 * @brief Set the value of the report format param.
 *
 * @param[in]  report_format  The report format.
 * @param[in]  name           Param name.
 * @param[in]  value_64       Param value in base64.
 *
 * @return 0 success, 1 failed to find param, 2 validation of value failed,
 *         -1 error.
 */
static int
set_report_format_param (report_format_t report_format, const char *name,
                         const char *value_64)
{
  gchar *quoted_name, *quoted_value, *value;
  gsize value_size;
  report_format_param_t param;

  quoted_name = sql_quote (name);

  sql_begin_immediate ();

  /* Ensure the param exists. */

  switch (sql_int64 (&param,
                     "SELECT id FROM report_format_params"
                     " WHERE name = '%s';",
                     quoted_name))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        g_free (quoted_name);
        sql_rollback ();
        return 1;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_name);
        sql_rollback ();
        return -1;
        break;
    }

  /* Translate the value. */

  if (value_64 && strlen (value_64))
    value = (gchar*) g_base64_decode (value_64, &value_size);
  else
    {
      value = g_strdup ("");
      value_size = 0;
    }

  /* Validate the value. */

  if (validate_param_value (report_format, param, name, value))
    {
      sql_rollback ();
      g_free (quoted_name);
      return 2;
    }

  quoted_value = sql_quote (value);
  g_free (value);

  /* Update the database. */

  sql ("UPDATE report_format_params SET value = '%s'"
       " WHERE report_format = %llu AND name = '%s';",
       quoted_value,
       report_format,
       quoted_name);

  g_free (quoted_name);
  g_free (quoted_value);

  sql_commit ();

  return 0;
}

/**
 * @brief Return the trust of a report format.
 *
 * @param[in]  report_format  Report format.
 *
 * @return Trust: 1 yes, 2 no, 3 unknown.
 */
int
report_format_trust (report_format_t report_format)
{
  return sql_int ("SELECT trust FROM report_formats WHERE id = %llu;",
                  report_format);
}

/**
 * @brief Filter columns for Report Format iterator.
 */
#define REPORT_FORMAT_ITERATOR_FILTER_COLUMNS                                 \
 { ANON_GET_ITERATOR_FILTER_COLUMNS, "name", "extension", "content_type",     \
   "summary", "description", "trust", "trust_time", "active", NULL }

/**
 * @brief Report Format iterator columns.
 */
#define REPORT_FORMAT_ITERATOR_COLUMNS                                  \
 {                                                                      \
   { "id", NULL, KEYWORD_TYPE_INTEGER },                                \
   { "uuid", NULL, KEYWORD_TYPE_STRING },                               \
   { "name", NULL, KEYWORD_TYPE_STRING },                               \
   { "''", NULL, KEYWORD_TYPE_STRING },                                 \
   { "iso_time (creation_time)", NULL, KEYWORD_TYPE_STRING },           \
   { "iso_time (modification_time)", NULL, KEYWORD_TYPE_STRING },       \
   { "creation_time", "created", KEYWORD_TYPE_INTEGER },                \
   { "modification_time", "modified", KEYWORD_TYPE_INTEGER },           \
   {                                                                    \
     "(SELECT name FROM users WHERE users.id = report_formats.owner)",  \
     "_owner",                                                          \
     KEYWORD_TYPE_STRING                                                \
   },                                                                   \
   { "owner", NULL, KEYWORD_TYPE_INTEGER },                             \
   { "extension", NULL, KEYWORD_TYPE_STRING },                          \
   { "content_type", NULL, KEYWORD_TYPE_STRING },                       \
   { "summary", NULL, KEYWORD_TYPE_STRING },                            \
   { "description", NULL, KEYWORD_TYPE_STRING },                        \
   { "signature", NULL, KEYWORD_TYPE_STRING },                          \
   { "trust", NULL, KEYWORD_TYPE_INTEGER },                             \
   { "trust_time", NULL, KEYWORD_TYPE_INTEGER },                        \
   { "flags & 1", "active", KEYWORD_TYPE_INTEGER },                     \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                 \
 }

/**
 * @brief Report Format iterator columns for trash case.
 */
#define REPORT_FORMAT_ITERATOR_TRASH_COLUMNS                            \
 {                                                                      \
   { "id", NULL, KEYWORD_TYPE_INTEGER },                                \
   { "uuid", NULL, KEYWORD_TYPE_STRING },                               \
   { "name", NULL, KEYWORD_TYPE_STRING },                               \
   { "''", NULL, KEYWORD_TYPE_STRING },                                 \
   { "iso_time (creation_time)", NULL, KEYWORD_TYPE_STRING },           \
   { "iso_time (modification_time)", NULL, KEYWORD_TYPE_STRING },       \
   { "creation_time", "created", KEYWORD_TYPE_INTEGER },                \
   { "modification_time", "modified", KEYWORD_TYPE_INTEGER },           \
   {                                                                    \
     "(SELECT name FROM users"                                          \
     " WHERE users.id = report_formats_trash.owner)",                   \
     "_owner",                                                          \
     KEYWORD_TYPE_STRING                                                \
   },                                                                   \
   { "owner", NULL, KEYWORD_TYPE_INTEGER },                             \
   { "extension", NULL, KEYWORD_TYPE_STRING },                          \
   { "content_type", NULL, KEYWORD_TYPE_STRING },                       \
   { "summary", NULL, KEYWORD_TYPE_STRING },                            \
   { "description", NULL, KEYWORD_TYPE_STRING },                        \
   { "signature", NULL, KEYWORD_TYPE_STRING },                          \
   { "trust", NULL, KEYWORD_TYPE_INTEGER },                             \
   { "trust_time", NULL, KEYWORD_TYPE_INTEGER },                        \
   { "flags & 1", "active", KEYWORD_TYPE_INTEGER },                     \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                 \
 }

/**
 * @brief Get filter columns.
 *
 * @return Constant array of filter columns.
 */
const char**
report_format_filter_columns ()
{
  static const char *columns[] = REPORT_FORMAT_ITERATOR_FILTER_COLUMNS;
  return columns;
}

/**
 * @brief Get select columns.
 *
 * @return Constant array of select columns.
 */
column_t*
report_format_select_columns ()
{
  static column_t columns[] = REPORT_FORMAT_ITERATOR_COLUMNS;
  return columns;
}

/**
 * @brief Count the number of Report Formats.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of Report Formats filtered set.
 */
int
report_format_count (const get_data_t *get)
{
  static const char *filter_columns[] = REPORT_FORMAT_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = REPORT_FORMAT_ITERATOR_COLUMNS;
  static column_t trash_columns[] = REPORT_FORMAT_ITERATOR_TRASH_COLUMNS;
  return count ("report_format", get, columns, trash_columns, filter_columns,
                0, 0, 0, TRUE);
}

/**
 * @brief Initialise a Report Format iterator, including observed Report
 *        Formats.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 *
 * @return 0 success, 1 failed to find Report Format, 2 failed to find filter,
 *         -1 error.
 */
int
init_report_format_iterator (iterator_t* iterator, const get_data_t *get)
{
  static const char *filter_columns[] = REPORT_FORMAT_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = REPORT_FORMAT_ITERATOR_COLUMNS;
  static column_t trash_columns[] = REPORT_FORMAT_ITERATOR_TRASH_COLUMNS;

  return init_get_iterator (iterator,
                            "report_format",
                            get,
                            columns,
                            trash_columns,
                            filter_columns,
                            0,
                            NULL,
                            NULL,
                            TRUE);
}

/**
 * @brief Get the extension from a report format iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Extension, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (report_format_iterator_extension, GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Get the content type from a report format iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Content type, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (report_format_iterator_content_type, GET_ITERATOR_COLUMN_COUNT + 1);

/**
 * @brief Get the summary from a report format iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Summary, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (report_format_iterator_summary, GET_ITERATOR_COLUMN_COUNT + 2);

/**
 * @brief Get the description from a report format iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Description, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (report_format_iterator_description, GET_ITERATOR_COLUMN_COUNT + 3);

/**
 * @brief Get the signature from a report format iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Signature, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (report_format_iterator_signature, GET_ITERATOR_COLUMN_COUNT + 4);

/**
 * @brief Get the trust value from a report format iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Trust value.
 */
const char*
report_format_iterator_trust (iterator_t* iterator)
{
  if (iterator->done) return NULL;
  switch (iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 5))
    {
      case 1:  return "yes";
      case 2:  return "no";
      case 3:  return "unknown";
      default: return NULL;
    }
}

/**
 * @brief Get the trust time from a report format iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Time report format was verified.
 */
time_t
report_format_iterator_trust_time (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (time_t) iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 6);
  return ret;
}

/**
 * @brief Get the active flag from a report format iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Active flag, or -1 if iteration is complete.
 */
int
report_format_iterator_active (iterator_t* iterator)
{
  if (iterator->done) return -1;
  return (iterator_int64 (iterator, GET_ITERATOR_COLUMN_COUNT + 7)
          & REPORT_FORMAT_FLAG_ACTIVE) ? 1 : 0;
}

/**
 * @brief Initialise a Report Format alert iterator.
 *
 * Iterates over all alerts that use the Report Format.
 *
 * @param[in]  iterator          Iterator.
 * @param[in]  report_format     Report Format.
 */
void
init_report_format_alert_iterator (iterator_t* iterator,
                                   report_format_t report_format)
{
  gchar *available, *with_clause;
  get_data_t get;
  array_t *permissions;

  assert (report_format);

  get.trash = 0;
  permissions = make_array ();
  array_add (permissions, g_strdup ("get_alerts"));
  available = acl_where_owned ("alert", &get, 1, "any", 0, permissions,
                               &with_clause);
  array_free (permissions);

  init_iterator (iterator,
                 "%s"
                 " SELECT DISTINCT alerts.name, alerts.uuid, %s"
                 " FROM alerts, alert_method_data"
                 " WHERE alert_method_data.data = '%s'"
                 " AND alert_method_data.alert = alerts.id"
                 " ORDER BY alerts.name ASC;",
                 with_clause ? with_clause : "",
                 available,
                 report_format_uuid (report_format));

  g_free (with_clause);
  g_free (available);
}

/**
 * @brief Get the name from a report_format_alert iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The name of the Report Format, or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (report_format_alert_iterator_name, 0);

/**
 * @brief Get the UUID from a report_format_alert iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The UUID of the Report Format, or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (report_format_alert_iterator_uuid, 1);

/**
 * @brief Get the read permission status from a GET iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 1 if may read, else 0.
 */
int
report_format_alert_iterator_readable (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return iterator_int (iterator, 2);
}

/**
 * @brief Initialise a report format iterator.
 *
 * @param[in]  iterator       Iterator.
 * @param[in]  report_format  Single report_format to iterate over, or 0 for all.
 * @param[in]  trash          Whether to iterate over trashcan report formats.
 * @param[in]  ascending      Whether to sort ascending or descending.
 * @param[in]  sort_field     Field to sort on, or NULL for "id".
 */
void
init_report_format_param_iterator (iterator_t* iterator,
                                   report_format_t report_format,
                                   int trash,
                                   int ascending,
                                   const char* sort_field)
{
  if (report_format)
    init_iterator (iterator,
                   "SELECT id, name, value, type, type_min, type_max,"
                   " type_regex, fallback"
                   " FROM report_format_params%s"
                   " WHERE report_format = %llu"
                   " ORDER BY %s %s;",
                   trash ? "_trash" : "",
                   report_format,
                   sort_field ? sort_field : "id",
                   ascending ? "ASC" : "DESC");
  else
    init_iterator (iterator,
                   "SELECT id, name, value, type, type_min, type_max,"
                   " type_regex, fallback"
                   " FROM report_format_params%s"
                   " ORDER BY %s %s;",
                   trash ? "_trash" : "",
                   sort_field ? sort_field : "id",
                   ascending ? "ASC" : "DESC");
}

/**
 * @brief Get the report format param from a report format param iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Report format param.
 */
report_format_param_t
report_format_param_iterator_param (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (report_format_param_t) iterator_int64 (iterator, 0);
}

/**
 * @brief Get the name from a report format param iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (report_format_param_iterator_name, 1);

/**
 * @brief Get the value from a report format param iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (report_format_param_iterator_value, 2);

/**
 * @brief Get the name of the type of a report format param iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Static string naming type, or NULL if iteration is complete.
 */
const char *
report_format_param_iterator_type_name (iterator_t* iterator)
{
  if (iterator->done) return NULL;
  return report_format_param_type_name (iterator_int (iterator, 3));
}

/**
 * @brief Get the type from a report format param iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Type.
 */
report_format_param_type_t
report_format_param_iterator_type (iterator_t* iterator)
{
  if (iterator->done) return -1;
  return iterator_int (iterator, 3);
}

/**
 * @brief Get the type min from a report format param iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Type min.
 */
long long int
report_format_param_iterator_type_min (iterator_t* iterator)
{
  if (iterator->done) return -1;
  return iterator_int64 (iterator, 4);
}

/**
 * @brief Get the type max from a report format param iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Type max.
 */
long long int
report_format_param_iterator_type_max (iterator_t* iterator)
{
  if (iterator->done) return -1;
  return iterator_int64 (iterator, 5);
}

/**
 * @brief Get the type regex from a report format param iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Type regex, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
static
DEF_ACCESS (report_format_param_iterator_type_regex, 6);

/**
 * @brief Get the default from a report format param iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Default, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (report_format_param_iterator_fallback, 7);

/**
 * @brief Initialise a report format param option iterator.
 *
 * @param[in]  iterator             Iterator.
 * @param[in]  report_format_param  Param whose options to iterate over.
 * @param[in]  ascending            Whether to sort ascending or descending.
 * @param[in]  sort_field           Field to sort on, or NULL for "id".
 */
void
init_param_option_iterator (iterator_t* iterator,
                            report_format_param_t report_format_param,
                            int ascending, const char *sort_field)
{
  init_iterator (iterator,
                 "SELECT id, value"
                 " FROM report_format_param_options"
                 " WHERE report_format_param = %llu"
                 " ORDER BY %s %s;",
                 report_format_param,
                 sort_field ? sort_field : "id",
                 ascending ? "ASC" : "DESC");
}

/**
 * @brief Get the value from a report format param option iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (param_option_iterator_value, 1);

/**
 * @brief Create or update report format for check_report_format.
 *
 * @param[in]  quoted_uuid    UUID of report format, quoted for SQL.
 * @param[in]  name           Name.
 * @param[in]  summary        Summary.
 * @param[in]  description    Description.
 * @param[in]  extension      Extension.
 * @param[in]  content_type   Content type.
 * @param[out] report_format  Created report format.
 *
 * @return 0 success, -1 error.
 */
static int
check_report_format_create (const gchar *quoted_uuid, const gchar *name,
                            const gchar *summary, const gchar *description,
                            const gchar *extension, const gchar *content_type,
                            report_format_t *report_format)
{
  gchar *quoted_name, *quoted_summary, *quoted_description;
  gchar *quoted_extension, *quoted_content_type;

  quoted_name = sql_quote (name);
  quoted_summary = sql_quote (summary);
  quoted_description = sql_quote (description);
  quoted_extension = sql_quote (extension);
  quoted_content_type = sql_quote (content_type);

  if (sql_int ("SELECT count (*) FROM report_formats WHERE uuid = '%s';",
               quoted_uuid))
    {
      sql ("UPDATE report_formats"
           " SET owner = NULL, name = '%s', summary = '%s', description = '%s',"
           "     extension = '%s', content_type = '%s', signature = '',"
           "     trust = %i, trust_time = %i, flags = %llu"
           " WHERE uuid = '%s';",
           g_strstrip (quoted_name),
           g_strstrip (quoted_summary),
           g_strstrip (quoted_description),
           g_strstrip (quoted_extension),
           g_strstrip (quoted_content_type),
           TRUST_YES,
           time (NULL),
           (long long int) REPORT_FORMAT_FLAG_ACTIVE,
           quoted_uuid);

      sql ("UPDATE report_formats SET modification_time = m_now ()"
           " WHERE id"
           " IN (SELECT report_formats.id"
           "     FROM report_formats, report_formats_check"
           "     WHERE report_formats.uuid = '%s'"
           "     AND report_formats.id = report_formats_check.id"
           "     AND (report_formats.owner != report_formats_check.owner"
           "          OR report_formats.name != report_formats_check.name"
           "          OR report_formats.summary != report_formats_check.summary"
           "          OR report_formats.description"
           "             != report_formats_check.description"
           "          OR report_formats.extension"
           "             != report_formats_check.extension"
           "          OR report_formats.content_type"
           "             != report_formats_check.content_type"
           "          OR report_formats.trust != report_formats_check.trust"
           "          OR report_formats.flags != report_formats_check.flags));",
           quoted_uuid);
    }
  else
    sql ("INSERT INTO report_formats"
         " (uuid, name, owner, summary, description, extension, content_type,"
         "  signature, trust, trust_time, flags, creation_time,"
         "  modification_time)"
         " VALUES ('%s', '%s', NULL, '%s', '%s', '%s', '%s', '', %i, %i, %i,"
         "         m_now (), m_now ());",
         quoted_uuid,
         g_strstrip (quoted_name),
         g_strstrip (quoted_summary),
         g_strstrip (quoted_description),
         g_strstrip (quoted_extension),
         g_strstrip (quoted_content_type),
         TRUST_YES,
         time (NULL),
         (long long int) REPORT_FORMAT_FLAG_ACTIVE);

  add_role_permission_resource (ROLE_UUID_ADMIN, "GET_REPORT_FORMATS",
                                "report_format", quoted_uuid);
  add_role_permission_resource (ROLE_UUID_GUEST, "GET_REPORT_FORMATS",
                                "report_format", quoted_uuid);
  add_role_permission_resource (ROLE_UUID_OBSERVER, "GET_REPORT_FORMATS",
                                "report_format", quoted_uuid);
  add_role_permission_resource (ROLE_UUID_USER, "GET_REPORT_FORMATS",
                                "report_format", quoted_uuid);

  g_free (quoted_name);
  g_free (quoted_summary);
  g_free (quoted_description);
  g_free (quoted_extension);
  g_free (quoted_content_type);

  switch (sql_int64 (report_format,
                     "SELECT id FROM report_formats WHERE uuid = '%s';",
                     quoted_uuid))
    {
      case 0:
        break;
      default:       /* Programming error. */
        assert (0);
      case 1:        /* Too few rows in result of query. */
      case -1:
        g_warning ("%s: Report format missing: %s",
                   __func__, quoted_uuid);
        return -1;
    }

  resource_set_predefined ("report_format", *report_format, 1);

  return 0;
}

/**
 * @brief Add params for check_report_format.
 *
 * @param[in]  quoted_uuid      UUID of report format, quoted.
 * @param[in]  config_path      Config path.
 * @param[in]  entity           Parsed XML.
 * @param[out] update_mod_time  Whether to update modification time.
 *
 * @return 0 success, -1 error.
 */
static int
check_report_format_add_params (const gchar *quoted_uuid, const gchar *config_path,
                                entity_t entity, int *update_mod_time)
{
  entities_t entities;
  entity_t param;

  entities = entity->entities;
  while ((param = first_entity (entities)))
    {
      g_debug ("%s: possible param: %s", __func__, entity_name (param));

      if (strcmp (entity_name (param), "param") == 0)
        {
          const char *name, *value, *fallback;
          gchar *quoted_name, *quoted_value, *quoted_fallback, *type;
          const char *min, *max;
          array_t *opts;
          entity_t child;

          opts = NULL;
          min = max = NULL;

          child = entity_child (param, "name");
          if (child == NULL)
            {
              g_warning ("%s: Param missing name in '%s'",
                         __func__, config_path);
              return -1;
            }
          name = entity_text (child);

          child = entity_child (param, "default");
          if (child == NULL)
            {
              g_warning ("%s: Param missing default in '%s'",
                         __func__, config_path);
              return -1;
            }
          fallback = entity_text (child);

          child = entity_child (param, "type");
          if (child == NULL)
            {
              g_warning ("%s: Param missing type in '%s'",
                         __func__, config_path);
              return -1;
            }
          type = g_strstrip (g_strdup (entity_text (child)));
          if (report_format_param_type_from_name (type)
              == REPORT_FORMAT_PARAM_TYPE_ERROR)
            {
              g_warning ("%s: Error in param type in '%s'",
                         __func__, config_path);
              return -1;
            }

          if (strcmp (type, "report_format_list"))
            {
              entity_t bound;

              bound = entity_child (child, "min");
              if (bound && strlen (entity_text (bound)))
                {
                  long long int number;
                  char *end;

                  min = entity_text (bound);
                  number = strtoll (min, &end, 0);
                  if (*end != '\0'
                      || number == LLONG_MAX
                      || number == LLONG_MIN)
                    {
                      g_warning ("%s: Failed to parse min in '%s'",
                                 __func__, config_path);
                      g_free (type);
                      return -1;
                    }
                }

              bound = entity_child (child, "max");
              if (bound && strlen (entity_text (bound)))
                {
                  long long int number;
                  char *end;

                  max = entity_text (bound);
                  number = strtoll (max, &end, 0);
                  if (*end != '\0'
                      || number == LLONG_MAX
                      || number == LLONG_MIN)
                    {
                      g_warning ("%s: Failed to parse max in '%s'",
                                 __func__, config_path);
                      g_free (type);
                      return -1;
                    }
                }

              if (strcmp (type, "selection") == 0)
                {
                  entity_t options, option;
                  entities_t children;

                  options = entity_child (child, "options");
                  if (options == NULL)
                    {
                      g_warning ("%s: Selection missing options in '%s'",
                                 __func__, config_path);
                      g_free (type);
                      return -1;
                    }

                  children = options->entities;
                  opts = make_array ();
                  while ((option = first_entity (children)))
                    {
                      array_add (opts, entity_text (option));
                      children = next_entities (children);
                    }
                }

              child = entity_child (param, "value");
              if (child == NULL)
                {
                  g_warning ("%s: Param missing value in '%s'",
                             __func__, config_path);
                  g_free (type);
                  return -1;
                }
              value = entity_text (child);

            }
          else
            {
              entity_t report_format;

              child = entity_child (param, "value");
              if (child == NULL)
                {
                  g_warning ("%s: Param missing value in '%s'",
                             __func__, config_path);
                  g_free (type);
                  return -1;
                }

              report_format = entity_child (child, "report_format");
              if (report_format == NULL)
                {
                  g_warning ("%s: Param missing report format in '%s'",
                             __func__, config_path);
                  g_free (type);
                  return -1;
                }

              value = entity_attribute (report_format, "id");
              if (value == NULL)
                {
                  g_warning ("%s: Report format missing id in '%s'",
                             __func__, config_path);
                  g_free (type);
                  return -1;
                }
            }

          /* Add or update the param. */

          quoted_name = g_strstrip (sql_quote (name));
          quoted_value = g_strstrip (sql_quote (value));
          quoted_fallback = g_strstrip (sql_quote (fallback));

          g_debug ("%s: param: %s", __func__, name);

          if (sql_int ("SELECT count (*) FROM report_format_params"
                       " WHERE name = '%s'"
                       " AND report_format = (SELECT id FROM report_formats"
                       "                      WHERE uuid = '%s');",
                       quoted_name,
                       quoted_uuid))
            {
              g_debug ("%s: param: %s: updating", __func__, name);

              sql ("UPDATE report_format_params"
                   " SET type = %u, value = '%s', type_min = %s,"
                   "     type_max = %s, type_regex = '', fallback = '%s'"
                   " WHERE name = '%s'"
                   " AND report_format = (SELECT id FROM report_formats"
                   "                      WHERE uuid = '%s');",
                   report_format_param_type_from_name (type),
                   quoted_value,
                   min ? min : "NULL",
                   max ? max : "NULL",
                   quoted_fallback,
                   quoted_name,
                   quoted_uuid);

               /* If any value changed, update the modification time. */

               if (sql_int
                    ("SELECT"
                     " EXISTS"
                     "  (SELECT *"
                     "   FROM report_format_params,"
                     "        report_format_params_check"
                     "   WHERE report_format_params.name = '%s'"
                     "   AND report_format_params_check.name = '%s'"
                     "   AND report_format_params.report_format"
                     "       = report_format_params_check.report_format"
                     "   AND (report_format_params.type"
                     "        != report_format_params_check.type"
                     "        OR report_format_params.value"
                     "           != report_format_params_check.value"
                     "        OR report_format_params.type_min"
                     "           != report_format_params_check.type_min"
                     "        OR report_format_params.type_max"
                     "           != report_format_params_check.type_max"
                     "        OR report_format_params.fallback"
                     "           != report_format_params_check.fallback));",
                     quoted_name,
                     quoted_name))
                 *update_mod_time = 1;

              /* Delete existing param options.
               *
               * Predefined report formats can't be modified so the options
               * don't really matter, so don't worry about them for updating
               * the modification time. */

              sql ("DELETE FROM report_format_param_options"
                   " WHERE report_format_param"
                   "       IN (SELECT id FROM report_format_params"
                   "           WHERE name = '%s'"
                   "           AND report_format = (SELECT id"
                   "                                FROM report_formats"
                   "                                WHERE uuid = '%s'));",
                   quoted_name,
                   quoted_uuid);
            }
          else
            {
              g_debug ("%s: param: %s: creating", __func__, name);

              sql ("INSERT INTO report_format_params"
                   " (report_format, name, type, value, type_min, type_max,"
                   "  type_regex, fallback)"
                   " VALUES"
                   " ((SELECT id FROM report_formats WHERE uuid = '%s'),"
                   "  '%s', %u, '%s', %s, %s, '', '%s');",
                   quoted_uuid,
                   quoted_name,
                   report_format_param_type_from_name (type),
                   quoted_value,
                   min ? min : "NULL",
                   max ? max : "NULL",
                   quoted_fallback);
              *update_mod_time = 1;
            }

          g_free (type);

          /* Keep this param. */

          sql ("DELETE FROM report_format_params_check"
               " WHERE report_format = (SELECT id FROM report_formats"
               "                        WHERE uuid = '%s')"
               " AND name = '%s';",
               quoted_uuid,
               quoted_name);

          /* Add any options. */

          if (opts)
            {
              int index;

              index = 0;
              while (opts && (index < opts->len))
                {
                  gchar *quoted_option;
                  quoted_option = sql_quote (g_ptr_array_index (opts, index++));
                  sql ("INSERT INTO report_format_param_options"
                       " (report_format_param, value)"
                       " VALUES ((SELECT id FROM report_format_params"
                       "          WHERE name = '%s'"
                       "          AND report_format = (SELECT id"
                       "                               FROM report_formats"
                       "                               WHERE uuid = '%s')),"
                       "         '%s');",
                       quoted_name,
                       quoted_uuid,
                       quoted_option);
                  g_free (quoted_option);
                }

              /* array_free would try free the elements too. */
              g_ptr_array_free (opts, TRUE);
            }

          g_free (quoted_name);
          g_free (quoted_value);
          g_free (quoted_fallback);
        }
      entities = next_entities (entities);
    }

  return 0;
}

/**
 * @brief Setup a predefined report format from disk.
 *
 * @param[in]  entity        XML.
 * @param[in]  config_path   Config path.
 * @param[in]  name          Name.
 * @param[in]  summary       Summary.
 * @param[in]  description   Description.
 * @param[in]  extension     Extension.
 * @param[in]  content_type  Content type.
 *
 * @return 0 success, -1 error.
 */
static int
check_report_format_parse (entity_t entity, const char *config_path,
                           const char **name, const char **summary,
                           const char **description, const char **extension,
                           const char **content_type)
{
  entity_t child;

  child = entity_child (entity, "name");
  if (child == NULL)
    {
      g_warning ("%s: Missing name in '%s'", __func__, config_path);
      return -1;
    }
  *name = entity_text (child);

  child = entity_child (entity, "summary");
  if (child == NULL)
    {
      g_warning ("%s: Missing summary in '%s'", __func__, config_path);
      return -1;
    }
  *summary = entity_text (child);

  child = entity_child (entity, "description");
  if (child == NULL)
    {
      g_warning ("%s: Missing description in '%s'",
                 __func__, config_path);
      return -1;
    }
  *description = entity_text (child);

  child = entity_child (entity, "extension");
  if (child == NULL)
    {
      g_warning ("%s: Missing extension in '%s'", __func__, config_path);
      return -1;
    }
  *extension = entity_text (child);

  child = entity_child (entity, "content_type");
  if (child == NULL)
    {
      g_warning ("%s: Missing content_type in '%s'",
                 __func__, config_path);
      return -1;
    }
  *content_type = entity_text (child);

  return 0;
}

/**
 * @brief Setup a predefined report format from disk.
 *
 * @param[in]  uuid  UUID of report format.
 *
 * @return 0 success, -1 error.
 */
static int
check_report_format (const gchar *uuid)
{
  GError *error;
  gchar *path, *config_path, *xml, *quoted_uuid;
  gsize xml_len;
  const char *name, *summary, *description, *extension, *content_type;
  entity_t entity;
  int update_mod_time;
  report_format_t report_format;

  g_debug ("%s: uuid: %s", __func__, uuid);

  update_mod_time = 0;
  path = predefined_report_format_dir (uuid);
  g_debug ("%s: path: %s", __func__, path);
  config_path = g_build_filename (path, "report_format.xml", NULL);
  g_free (path);

  /* Read the file in. */

  error = NULL;
  g_file_get_contents (config_path, &xml, &xml_len, &error);
  if (error)
    {
      g_warning ("%s: Failed to read '%s': %s",
                  __func__,
                 config_path,
                 error->message);
      g_error_free (error);
      g_free (config_path);
      return -1;
    }

  /* Parse it as XML. */

  if (parse_entity (xml, &entity))
    {
      g_warning ("%s: Failed to parse '%s'", __func__, config_path);
      g_free (config_path);
      return -1;
    }

  /* Get the report format properties from the XML. */

  if (check_report_format_parse (entity, config_path, &name, &summary,
                                 &description, &extension, &content_type))
    {
      g_free (config_path);
      free_entity (entity);
      return -1;
    }

  quoted_uuid = sql_quote (uuid);

  /* Create or update the report format. */

  if (check_report_format_create (quoted_uuid, name, summary, description,
                                  extension, content_type, &report_format))
    goto fail;

  /* Add or update the parameters from the parsed XML. */

  if (check_report_format_add_params (quoted_uuid, config_path, entity,
                                      &update_mod_time))
    goto fail;

  free_entity (entity);
  g_free (config_path);

  /* Remove any params that were not defined by the XML. */

  if (sql_int ("SELECT count (*)"
               " FROM report_format_params_check"
               " WHERE report_format = (SELECT id FROM report_formats"
               "                        WHERE uuid = '%s')",
               quoted_uuid))
    {
      sql ("DELETE FROM report_format_param_options"
           " WHERE report_format_param"
           "       IN (SELECT id FROM report_format_params_check"
           "           WHERE report_format = (SELECT id FROM report_formats"
           "                                  WHERE uuid = '%s'));",
           quoted_uuid);
      sql ("DELETE FROM report_format_params"
           " WHERE id IN (SELECT id FROM report_format_params_check"
           "              WHERE report_format = (SELECT id FROM report_formats"
           "                                     WHERE uuid = '%s'));",
           quoted_uuid);
      update_mod_time = 1;
    }

  /* Update modification time if report format changed. */

  if (update_mod_time)
    sql ("UPDATE report_formats SET modification_time = m_now ()"
         " WHERE uuid = '%s';",
         quoted_uuid);

  /* Keep this report format. */

  sql ("DELETE FROM report_formats_check WHERE uuid = '%s';",
       quoted_uuid);

  g_free (quoted_uuid);
  return 0;

 fail:
  g_free (quoted_uuid);
  g_free (config_path);
  free_entity (entity);
  return -1;
}

/**
 * @brief Verify a report format.
 *
 * @param[in]  report_format  Report format.
 *
 * @return 0 success, -1 error.
 */
static int
verify_report_format_internal (report_format_t report_format)
{
  int format_trust = TRUST_UNKNOWN;
  iterator_t formats;
  get_data_t get;
  gchar *uuid;

  memset(&get, '\0', sizeof (get));
  get.id = report_format_uuid (report_format);
  init_report_format_iterator (&formats, &get);
  if (next (&formats))
    {
      const char *signature;
      gchar *format_signature = NULL;
      gsize format_signature_size;

      signature = report_format_iterator_signature (&formats);

      find_signature ("report_formats", get_iterator_uuid (&formats),
                      &format_signature, &format_signature_size, &uuid);

      if ((signature && strlen (signature))
          || format_signature)
        {
          GString *format;
          file_iterator_t files;
          iterator_t params;

          format = g_string_new ("");

          g_string_append_printf
           (format, "%s%s%s%i", uuid ? uuid : get_iterator_uuid (&formats),
            report_format_iterator_extension (&formats),
            report_format_iterator_content_type (&formats),
            report_format_predefined (report_format) & 1);
          g_free (uuid);

          init_report_format_file_iterator (&files, report_format);
          while (next_file (&files))
            {
              gchar *content = file_iterator_content_64 (&files);
              g_string_append_printf (format,
                                      "%s%s",
                                      file_iterator_name (&files),
                                      content);
              g_free (content);
            }
          cleanup_file_iterator (&files);

          init_report_format_param_iterator (&params,
                                             report_format,
                                             0,
                                             1,
                                             NULL);
          while (next (&params))
            {
              g_string_append_printf
               (format,
                "%s%s",
                report_format_param_iterator_name (&params),
                report_format_param_iterator_type_name (&params));

              if (report_format_param_iterator_type_min (&params) > LLONG_MIN)
                g_string_append_printf
                 (format,
                  "%lli",
                  report_format_param_iterator_type_min (&params));

              if (report_format_param_iterator_type_max (&params) < LLONG_MAX)
                g_string_append_printf
                 (format,
                  "%lli",
                  report_format_param_iterator_type_max (&params));

              g_string_append_printf
               (format,
                "%s%s",
                report_format_param_iterator_type_regex (&params),
                report_format_param_iterator_fallback (&params));

              {
                iterator_t options;
                init_param_option_iterator
                 (&options,
                  report_format_param_iterator_param (&params),
                  1,
                  NULL);
                while (next (&options))
                  if (param_option_iterator_value (&options))
                    g_string_append_printf
                     (format,
                      "%s",
                      param_option_iterator_value (&options));
              }
            }
          cleanup_iterator (&params);

          g_string_append_printf (format, "\n");

          if (format_signature)
            {
              /* Try the feed signature. */
              if (verify_signature (format->str, format->len, format_signature,
                                    strlen (format_signature), &format_trust))
                {
                  cleanup_iterator (&formats);
                  g_free (format_signature);
                  g_string_free (format, TRUE);
                  return -1;
                }
            }
          else if (signature && strlen (signature))
            {
              /* Try the signature from the database. */
              if (verify_signature (format->str, format->len, signature,
                                    strlen (signature), &format_trust))
                {
                  cleanup_iterator (&formats);
                  g_free (format_signature);
                  g_string_free (format, TRUE);
                  return -1;
                }
            }

          g_free (format_signature);
          g_string_free (format, TRUE);
        }
    }
  else
    {
      return -1;
    }
  cleanup_iterator (&formats);

  sql ("UPDATE report_formats SET trust = %i, trust_time = %i,"
       "                          modification_time = m_now ()"
       " WHERE id = %llu;",
       format_trust,
       time (NULL),
       report_format);

  return 0;
}

/**
 * @brief Verify a report format.
 *
 * @param[in]  report_format_id  Report format UUID.
 *
 * @return 0 success, 1 failed to find report format, 99 permission denied,
 *         -1 error.
 */
int
verify_report_format (const char *report_format_id)
{
  int ret;
  report_format_t report_format;

  sql_begin_immediate ();

  if (acl_user_may ("verify_report_format") == 0)
    {
      sql_rollback ();
      return 99;
    }

  report_format = 0;
  if (find_report_format_with_permission (report_format_id, &report_format,
                                          "verify_report_format"))
    {
      sql_rollback ();
      return -1;
    }
  if (report_format == 0)
    {
      sql_rollback ();
      return 1;
    }

  ret = verify_report_format_internal (report_format);
  if (ret)
    {
      sql_rollback ();
      return ret;
    }
  sql_commit ();
  return 0;
}
