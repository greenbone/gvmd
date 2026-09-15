/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: VT Technical Info.
 *
 * Vulnerability test optional metadata for the GVM management layer.
 */

#include "manage_sql_copy.h"
#include "manage_vt_tech_info.h"
#include "manage_sql_vt_tech_info.h"
#include "sql.h"

#include <fcntl.h>
#include <glib.h>
#include <gvm/util/compressutils.h>
#include <gvm/util/jsonpull.h>
#include <stdio.h>
#include <unistd.h>



#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"


/**
 * @brief Parse a VT tech info JSON file until the items list start
 *
 * @param[in]  parser   The parser handling the VT tech info JSON file.
 * @param[in]  event    The parser event data structure.
 *
 * @return 0 success, -1 error
 */
static int
vt_tech_info_json_skip_to_items (gvm_json_pull_parser_t *parser,
                                 gvm_json_pull_event_t *event)
{
  gvm_json_pull_parser_next (parser, event);
  switch (event->type)
  {
    case GVM_JSON_PULL_EVENT_ERROR:
      g_warning ("%s: Failed to parse JSON: %s",
                 __func__, event->error_message);
      return -1;
    case GVM_JSON_PULL_EVENT_EOF:
      g_warning ("%s: Unexpected EOF", __func__);
      return -1;
    case GVM_JSON_PULL_EVENT_ARRAY_START:
      return 0;
    default:
      g_warning ("%s: Expected JSON array start", __func__);
      return -1;
  }
}

/**
 * @brief Parse a single VT tech info item, adding it to the database
 *
 * @param[in]  parser       The parser handling the VT tech info JSON file.
 * @param[in]  event        The parser event data structure.
 * @param[in]  copy_buffer  The SQL copy buffer for wrtiting to the database.
 *
 * @return 0 item parsed successfully, 1 end of items array, -1 error
 */
static int
parse_and_update_vt_tech_info_item (gvm_json_pull_parser_t *parser,
                                    gvm_json_pull_event_t *event,
                                    db_copy_buffer_t *copy_buffer)
{
  cJSON *json;
  gchar *error_message = NULL;
  char *oid, *description_md;
  time_t now;
  gchar *oid_escaped, *description_md_escaped;
  int ret;

  gvm_json_pull_parser_next (parser, event);
  switch (event->type)
  {
    case GVM_JSON_PULL_EVENT_ERROR:
      g_warning ("%s: Failed to parse JSON: %s",
                 __func__, event->error_message);
      return -1;
    case GVM_JSON_PULL_EVENT_EOF:
      g_warning ("%s: Unexpected EOF", __func__);
      return -1;
    case GVM_JSON_PULL_EVENT_OBJECT_START:
      break;
    case GVM_JSON_PULL_EVENT_ARRAY_END:
      return 1;
    default:
      g_warning ("%s: Expected JSON object start or array end", __func__);
      return -1;
  }

  json = gvm_json_pull_expand_container (parser, &error_message);
  if (json == NULL)
    {
      g_warning ("%s: Error expanding object: %s", __func__, error_message);
      g_free (error_message);
      return -1;
    }

  gvm_json_obj_check_str (json, "oid", &oid);
  gvm_json_obj_check_str (json, "description_md", &description_md);

  if (oid == NULL)
    {
      g_warning ("%s: List item without 'oid' field", __func__);
      cJSON_Delete (json);
      return -1;
    }

  if (description_md == NULL)
    {
      g_warning ("%s: Missing 'description_md' in item %s", __func__, oid);
      cJSON_Delete (json);
      return -1;
    }

  now = time (NULL);
  oid_escaped = sql_copy_escape (oid);
  description_md_escaped = sql_copy_escape (description_md);

  ret = db_copy_buffer_append_printf (copy_buffer,
                                      "%s\t%s\t%lu\t%lu\n",
                                      oid_escaped,
                                      description_md_escaped,
                                      now,
                                      now);

  cJSON_Delete (json);
  g_free (oid_escaped);
  g_free (description_md_escaped);

  return ret ? -1 : 0;
}

/**
 * @brief Update VT technical info from a single JSON file
 *
 * @param[in]  full_path  Full path to the file
 *
 * @return 0 success, -1 error
 */
static int
update_vt_tech_info_from_file (const char *full_path)
{
  int ret;
  gvm_json_pull_event_t event;
  gvm_json_pull_parser_t parser;
  int fd;
  FILE *stream = NULL;
  db_copy_buffer_t copy_buffer;

  fd = open (full_path, O_RDONLY);
  if (fd < 0)
  {
    g_warning ("%s: Failed to open NVT meta data file '%s': %s",
               __func__, full_path, strerror(errno));
    return -1;
  }

  stream = gvm_gzip_open_file_reader_fd (fd);
  if (stream == NULL)
    {
      g_warning ("%s: Failed to open NVT file: %s",
                __func__,
                strerror (errno));
      close (fd);
      return -1;
    }

  g_info ("Updating Technical Descriptions from %s", full_path);

  gvm_json_pull_event_init (&event);
  gvm_json_pull_parser_init (&parser, stream);

  sql_begin_immediate ();

  if (vt_tech_info_json_skip_to_items (&parser, &event))
    {
      gvm_json_pull_event_cleanup (&event);
      gvm_json_pull_parser_cleanup (&parser);
      fclose (stream);
      sql_rollback ();
      return -1;
    }

  db_copy_buffer_init (&copy_buffer,
                       1024 * 1024 * 20,
                       "COPY vts.vt_tech_info"
                       " (vt_id, description_md,"
                       "  creation_time, modification_time)"
                       " FROM STDIN;");

  while (1)
    {
      ret = parse_and_update_vt_tech_info_item (&parser, &event, &copy_buffer);
      if (ret == -1)
        {
          gvm_json_pull_event_cleanup (&event);
          gvm_json_pull_parser_cleanup (&parser);
          fclose (stream);
          db_copy_buffer_cleanup (&copy_buffer);
          sql_rollback ();
          return -1;
        }
      if (ret)
        break;
    }

  gvm_json_pull_event_cleanup (&event);
  gvm_json_pull_parser_cleanup (&parser);
  fclose (stream);

  if (db_copy_buffer_commit (&copy_buffer, TRUE))
    {
      db_copy_buffer_cleanup (&copy_buffer);
      sql_rollback ();
      return -1;
    }

  sql_commit ();

  return 0;
}

/**
 * @brief Update the VT technical information from feed files.
 *
 * @return 0 success, -1 error.
 */
int
update_vt_tech_info_from_feed_files ()
{
  GError *error = NULL;
  GDir *dir;
  const gchar *file_path;

  dir = g_dir_open (GVM_VT_TECH_INFO_DIR, 0, &error);
  if (dir == NULL)
    {
      g_warning ("%s: Failed to open directory '%s': %s",
                 __func__, GVM_VT_TECH_INFO_DIR, error->message);
      g_error_free (error);
      return -1;
    }

  g_info ("Updating VT Technical Information");

  sql ("TRUNCATE vts.vt_tech_info");

  while ((file_path = g_dir_read_name (dir)))
    if (g_str_has_suffix (file_path, ".json.gz")
        || g_str_has_suffix (file_path, ".json"))
      {
        gchar *full_path = g_build_filename (GVM_VT_TECH_INFO_DIR,
                                             file_path, NULL);
        if (update_vt_tech_info_from_file (full_path))
          {
            g_free (full_path);
            g_dir_close (dir);
            return -1;
          }
        g_free (full_path);
      }
  g_dir_close (dir);

  return 0;
}

/**
 * Get the technical description markdown for a single VT by id.
 *
 * @param[in]  vt_id  Identifier of the VT, e.g. a nasl OID.
 *
 * @return Newly allocated technical description markdown text.
 */
gchar *
vt_tech_info_description_md_by_vt_id (const char *vt_id)
{
  return sql_string_ps ("SELECT description_md FROM vts.vt_tech_info"
                        " WHERE vt_id = $1;",
                        SQL_STR_PARAM (vt_id),
                        NULL);
}
