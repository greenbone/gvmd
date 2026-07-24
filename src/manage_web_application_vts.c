/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Web application vulnerability test.
 *
 * Web application vulnerability test code for the GVM management layer.
 */

#include "manage_utils.h"
#include "manage_sql.h"
#include "manage_web_application_vts.h"
#include "manage_sql_web_application_vts.h"

#include <gvm/util/compressutils.h>
#include <gvm/util/jsonpull.h>

#include <fcntl.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

#define ZAP_VT_FEED_SCHEMA_VERSION 1

/**
 * @brief Convert a ZAP risk rating to a CVSS score.
 *
 * @param[in]  risk  The ZAP risk rating to convert.
 *
 * @return The corresponding CVSS score.
 */
double
zap_risk_to_cvss (const char *risk)
{
  if (risk == NULL)
    return SEVERITY_MISSING;
  else if (strcasecmp (risk, "high") == 0)
    return 10.0;
  else if (strcasecmp (risk, "medium") == 0)
    return 6.9;
  else if (strcasecmp (risk, "low") == 0)
    return 3.9;
  else if (strcasecmp (risk, "informational") == 0
           || strcasecmp (risk, "info") == 0)
    return 0.0;

  return SEVERITY_UNDEFINED;
}

/**
 * @brief Parse an entry in a JSON ZAP alerts array, add its data to the DB.
 *
 * @param[in]  parser   The JSON pull parser used for parsing.
 * @param[in]  event    The JSON pull parser event output structure.
 *
 * @return 0 if entry was processed successfully, 1 if end of array was reached,
 *         -1 on error.
 */
static int
parse_and_insert_zap_vt_json (gvm_json_pull_parser_t *parser,
                              gvm_json_pull_event_t *event)
{
  cJSON *entry = NULL;
  gchar *error_message = NULL;

  if (event->type == GVM_JSON_PULL_EVENT_ERROR)
    {
      g_warning ("%s: Parser error: %s", __func__, event->error_message);
      return -1;
    }
  else if (event->type == GVM_JSON_PULL_EVENT_ARRAY_END)
    return 1;
  else if (event->type != GVM_JSON_PULL_EVENT_OBJECT_START)
    {
      g_warning ("%s: JSON object expected as alerts list item", __func__);
      return -1;
    }

  entry = gvm_json_pull_expand_container (parser, &error_message);
  if (error_message)
    {
      g_warning ("%s: Error expanding ZAP alert item: %s",
                 __func__, error_message);
      g_free (error_message);
      cJSON_Delete (entry);
      return -1;
    }

  if (insert_zap_vt_from_json (entry))
    {
      cJSON_Delete (entry);
      return -1;
    }

  cJSON_Delete (entry);
  return 0;
}

/**
 * @brief Parse a JSON document until the start of the "alerts" array.
 *
 * The function expects a JSON object that first contains the "schema_version"
 * field, which is also validated, followed by the "alerts" array.
 *
 * @param[in]  parser   The JSON pull parser used for parsing.
 * @param[in]  event    The JSON pull parser event output structure.
 *
 * @return 0 on success, -1 on error
 */
static int
seek_zap_alerts_array (gvm_json_pull_parser_t *parser,
                       gvm_json_pull_event_t *event)
{
  gvm_json_path_elem_t *path_tail;
  gvm_json_pull_parser_next (parser, event);

  if (event->type == GVM_JSON_PULL_EVENT_ERROR)
    {
      g_warning ("%s: Parser error: %s", __func__, event->error_message);
      return -1;
    }
  else if (event->type != GVM_JSON_PULL_EVENT_OBJECT_START)
    {
      g_warning ("%s: File must contain a JSON object", __func__);
      return -1;
    }

  gvm_json_pull_parser_next (parser, event);
  path_tail = g_queue_peek_tail (event->path);
  if (event->type == GVM_JSON_PULL_EVENT_ERROR)
    {
      g_warning ("%s: Parser error: %s", __func__, event->error_message);
      return -1;
    }
  else if (path_tail->key == NULL
           || strcmp (path_tail->key, "schema_version")
           || event->type != GVM_JSON_PULL_EVENT_NUMBER
           || event->value->valueint != ZAP_VT_FEED_SCHEMA_VERSION)
    {
      g_warning ("%s: expected 'schema_version' field containing number '%d'",
                 __func__, ZAP_VT_FEED_SCHEMA_VERSION);
      return -1;
    }

  gvm_json_pull_parser_next (parser, event);
  path_tail = g_queue_peek_tail (event->path);
  if (event->type == GVM_JSON_PULL_EVENT_ERROR)
    {
      g_warning ("%s: Parser error: %s", __func__, event->error_message);
      return -1;
    }
  else if (path_tail->key == NULL
           || strcmp (path_tail->key, "alerts")
           || event->type != GVM_JSON_PULL_EVENT_ARRAY_START)
    {
      g_warning ("%s: expected 'alerts' field containing array of ZAP alerts",
                 __func__);
      return -1;
    }

  return 0;
}

/**
 * @brief Opens a file at the given path and uses it to update ZAP VTs / alerts
 *
 * @param[in]  full_path  The full path to the file.
 *
 * @return 0 on success, -1 on error
 */
static int
update_zap_vts_from_json_file (const gchar *full_path)
{
  gvm_json_pull_parser_t parser;
  gvm_json_pull_event_t event;
  FILE *vts_file;
  int ret;

  int fd = open (full_path, O_RDONLY);

  if (fd < 0)
  {
    g_warning ("%s: Failed to open ZAP VT meta data file '%s': %s",
               __func__, full_path, strerror(errno));
    return -1;
  }

  g_info ("Updating %s", full_path);

  vts_file = gvm_gzip_open_file_reader_fd (fd);
  if (vts_file == NULL)
    {
      g_warning ("%s: Failed to open ZAP VT file: %s",
                __func__,
                strerror (errno));
      close (fd);
      return -1;
    }

  gvm_json_pull_parser_init_full (&parser, vts_file,
                                  GVM_JSON_PULL_PARSE_BUFFER_LIMIT,
                                  GVM_JSON_PULL_READ_BUFFER_SIZE * 8);
  gvm_json_pull_event_init (&event);

  if (seek_zap_alerts_array (&parser, &event))
    {
      gvm_json_pull_event_cleanup (&event);
      gvm_json_pull_parser_cleanup (&parser);
      fclose (vts_file);
      return -1;
    }

  sql_begin_immediate ();
  gvm_json_pull_parser_next (&parser, &event);
  while ((ret = parse_and_insert_zap_vt_json (&parser, &event)) != 1)
    {
      if (ret == -1)
        {
          g_warning ("%s: Error parsing ZAP VT item: %s",
                      __func__, event.error_message);
          gvm_json_pull_event_cleanup (&event);
          gvm_json_pull_parser_cleanup (&parser);
          fclose (vts_file);
          sql_rollback ();
          return -1;
        }

      gvm_json_pull_parser_next (&parser, &event);
    }

  g_info ("%s: Finalizing ZAP VTs insert", __func__);

  // finalize_nvts_insert (count_new_vts, count_modified_vts,
  //                       nvts_feed_file_version, 1);
  sql_commit ();

  gvm_json_pull_event_cleanup (&event);
  gvm_json_pull_parser_cleanup (&parser);
  fclose (vts_file);

  return 0;
}

/**
 * @brief Update ZAP VTs from feed.
 *
 * @return 0 success, -1 error.
 */
int
update_zap_vts_from_feed ()
{
  gchar *full_path;
  GStatBuf state;

  g_info ("%s: Updating ZAP VTs from feed", __func__);

  full_path = g_build_filename (GVM_WEB_APPLICATION_VTS_DIR,
                                "zap-alerts.json.gz",
                                NULL);

  if (g_stat (full_path, &state))
    {
      g_free (full_path);
      full_path = g_build_filename (GVM_WEB_APPLICATION_VTS_DIR,
                                    "zap-alerts.json",
                                    NULL);
    }

  if (g_stat (full_path, &state))
    {
      g_warning ("%s: No ZAP VT metadata file found at %s",
                 __func__,
                 full_path);
      g_free (full_path);
      return -1;
    }

  if (update_zap_vts_from_json_file (full_path))
    {
      g_warning ("%s: Update of ZAP VTs failed", __func__);
      g_free (full_path);
      return -1;
    }
  g_free (full_path);

  return 0;
}
