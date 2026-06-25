/* Copyright (C) 2010-2025 Greenbone AG
*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: openvasd NVT SQL logic
 *
 * NVT SQL logic specific to openvasd in the GVM management layer.
 */

/**
 * @brief Enable extra GNU functions.
 */
#define _GNU_SOURCE         /* See feature_test_macros(7) */
/**
 * @brief Enable large file support.
 */
#define _FILE_OFFSET_BITS 64
#include <stdio.h>

#include "manage_sql_nvts_common.h"
#if ENABLE_HTTP_SCANNER
#include "manage_http_scanner.h"
#endif
#include "manage_runtime_flags.h"
#include "manage_sql.h"
#include "manage_sql_configs.h"
#include "manage_sql_nvts_openvasd.h"
#include "manage_sql_resources.h"
#include "sql.h"

#if ENABLE_CONTAINER_SCANNING
#include "manage_container_image_scanner.h"
#endif

#include <gvm/util/jsonpull.h>
#include <gvm/util/vtparser.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

#if ENABLE_OPENVASD

/**
 * @brief Max number of retries when no vts are received from openvasd.
 */
#define VTS_STREAM_MAX_RETRIES 60

/**
 * @brief Number of seconds to sleep between retries when no VTs are received.
 */
#define VTS_STREAM_RETRY_DELAY_S 1

/**
 * @brief Max number of rows inserted per statement.
 */
static int vt_ref_insert_size = VT_REF_INSERT_SIZE_DEFAULT;

/**
 * @brief Max number of rows inserted per statement.
 */
static int vt_sev_insert_size = VT_SEV_INSERT_SIZE_DEFAULT;

/**
 * @brief Struct containing the stream buffer.
 */
struct FILESTREAM
{
  char *stream_buffer;
  size_t size_of_buffer;
  size_t last_read;
  size_t last_write;

  http_scanner_connector_t connector;
  gboolean finished;
  gboolean error;
};

/**
 * @brief Hook function to close the stream file cookie
 */
static int
closecookie (void *filestream)
{
  struct FILESTREAM *stream = filestream;
  if (!stream)
    return 0;
  g_free (stream->stream_buffer);
  stream->size_of_buffer = 0;
  stream->stream_buffer = NULL;
  g_free (stream);
  return 0;
}

/**
 * @brief  Helper function to write to the stream file cookie.
 *         This function is only called from append_vts_chunk
 *         when new data is fetched.
 *
 * @param  stream_cookie The file cookie to write to.
 * @param  buf The buffer to write.
 * @param  size The size of the buffer.
 *
 * @return The number of bytes written, or 0 on error.
 */
static size_t
write_to_buffer (void *stream_cookie, const char *buf, size_t size)
{
  struct FILESTREAM *stream = stream_cookie;

  // Compact buffer first to avoid unnecessary reallocations.
  if (stream->last_read > 0)
    {
      size_t unread = stream->last_write - stream->last_read;
      if (unread > 0)
        memmove (stream->stream_buffer,
                 stream->stream_buffer + stream->last_read,
                 unread);
      stream->last_write = unread;
      stream->last_read = 0;
    }

  size_t next_size = stream->last_write + size;
  if (next_size > stream->size_of_buffer)
    {
      stream->size_of_buffer = next_size + GVM_JSON_PULL_PARSE_BUFFER_LIMIT;
      stream->stream_buffer = g_realloc (stream->stream_buffer,
                                         stream->size_of_buffer);
      if (stream->stream_buffer == NULL)
        {
          g_message ("%s: Buffer overflow", __func__);
          return 0;
        }
    }

  memcpy (&(stream->stream_buffer[stream->last_write]), buf, size);
  stream->last_write += size;

  return size;
}

/**
 * @brief  Helper function to fetch VTs from openvasd and write
 *         to file stream cookie.
 * @return 0 on success including if the stream has finished, -1 on error.
 */
static int
append_vts_chunk (struct FILESTREAM *stream)
{
  int running;
  size_t len;
  int retries = 0;

  if (!stream || !stream->connector)
    return -1;

  if (stream->error)
    return -1;

  if (stream->finished)
    return 0;

  while (1)
   {
     running = openvasd_get_vt_stream (stream->connector);
     if (running < 0)
       {
         g_warning ("%s: failed to get VTs", __func__);
         stream->error = TRUE;
         return -1;
       }

     len = http_scanner_stream_len (stream->connector);
     if (len > 0)
      {
        if (write_to_buffer (stream, http_scanner_stream_str (stream->connector),
                             len) != (size_t) len)
          {
            g_warning ("%s: failed to write to stream buffer", __func__);
            stream->error = TRUE;
            return -1;
          }
        http_scanner_reset_stream (stream->connector);

        // if last chunk, mark stream as finished now to avoid extra calls.
        if (running == 0)
          stream->finished = TRUE;

        return 0;
      }

     if (running == 0)
      {
        stream->finished = TRUE;
        return 0;
      }

     if (++retries > VTS_STREAM_MAX_RETRIES)
       {
          g_warning ("%s: no data received from openvasd after %d retries (total %ds)",
                     __func__,
                     VTS_STREAM_MAX_RETRIES,
                     VTS_STREAM_MAX_RETRIES * VTS_STREAM_RETRY_DELAY_S);
          stream->error = TRUE;
          return -1;
       }

     gvm_sleep (VTS_STREAM_RETRY_DELAY_S);
   }
}

/**
 * @brief Hook function to read the stream file cookie
 */
static ssize_t
readcookie (void *stream_cookie, char *buf, size_t size)
{
  struct FILESTREAM *stream = stream_cookie;

  while (stream->last_read >= stream->last_write)
    {
      if (stream->error)
        return -1;
      if (stream->finished)
        return 0;

      if (append_vts_chunk (stream) < 0)
        return -1;
    }

  size_t to_read = stream->last_write - stream->last_read;

  if (to_read > size)
    to_read = size;
  memcpy (buf, &stream->stream_buffer[stream->last_read], to_read);

  stream->last_read += to_read;
  return to_read;
}

/**
 * @brief Update NVTs from Json response chunk by chunk
 *
 * @param[in]  connector             openvasd connector
 * @param[in]  scanner_feed_version  Version of feed from scanner.
 * @param[in]  rebuild               Whether we're rebuilding the tables.
 *
 * @return 0 success, 1 VT integrity check failed, -1 error
 */
static int
update_nvts_from_openvasd_vts (http_scanner_connector_t connector,
                               const gchar *scanner_feed_version,
                               int rebuild)
{
  GList *preferences;
  int count_modified_vts, count_new_vts;
  time_t feed_version_epoch;
  batch_t *vt_refs_batch, *vt_sevs_batch;

  count_modified_vts = 0;
  count_new_vts = 0;

  feed_version_epoch = nvts_feed_version_epoch ();

  sql_begin_immediate ();
  prepare_nvts_insert (rebuild);

  vt_refs_batch = batch_start (vt_ref_insert_size);
  vt_sevs_batch = batch_start (vt_sev_insert_size);

  http_scanner_resp_t resp;
  gvm_json_pull_event_t event;
  gvm_json_pull_parser_t parser;
  FILE *stream = NULL;
  struct FILESTREAM *filestream;
  nvti_t *nvti = NULL;

  resp = openvasd_get_vt_stream_init (connector);
  if (resp->code < 0)
    {
      http_scanner_response_cleanup (resp);
      g_warning ("%s: failed to get VTs", __func__);
      sql_rollback ();
      return -1;
    }

  http_scanner_response_cleanup (resp);

  cookie_io_functions_t cookiehooks = {
    .read = readcookie,
    .write = NULL,
    .seek = NULL,
    .close = closecookie,
  };

  filestream = g_malloc0 (sizeof (struct FILESTREAM));
  filestream->size_of_buffer = GVM_JSON_PULL_PARSE_BUFFER_LIMIT;
  filestream->stream_buffer =
    g_malloc0 (sizeof (char) * filestream->size_of_buffer);
  filestream->connector = connector;
  filestream->finished = FALSE;
  filestream->error = FALSE;

  stream = fopencookie (filestream, "r", cookiehooks);

  gvm_json_pull_parser_init_full (&parser, stream,
                                  GVM_JSON_PULL_PARSE_BUFFER_LIMIT,
                                  GVM_JSON_PULL_READ_BUFFER_SIZE * 8);
  gvm_json_pull_event_init (&event);

  while (1)
    {
      int ret = parse_vt_json (&parser, &event, &nvti);
      if (ret == -1)
        {
          g_warning ("%s: Parser error: %s", __func__, event.error_message);
          gvm_json_pull_event_cleanup (&event);
          gvm_json_pull_parser_cleanup (&parser);
          fclose (stream);
          sql_rollback ();
          return -1;
        }
      if (ret)
        break;

      if (nvti_creation_time (nvti) > feed_version_epoch)
        count_new_vts += 1;
      else
        count_modified_vts += 1;

      insert_nvt (nvti, rebuild, vt_refs_batch, vt_sevs_batch);

      preferences = NULL;
      update_preferences_from_nvti (nvti, &preferences);

      if (rebuild == 0)
        {
          gchar *quoted_oid = sql_quote (nvti_oid (nvti));
          sql ("DELETE FROM nvt_preferences%s WHERE name LIKE '%s:%%';",
               rebuild ? "_rebuild" : "",
               quoted_oid);
          g_free (quoted_oid);
        }

      insert_nvt_preferences_list (preferences, rebuild);
      g_list_free_full (preferences, (GDestroyNotify) preference_free);

      g_free (nvti);
    }

  gvm_json_pull_event_cleanup (&event);
  gvm_json_pull_parser_cleanup (&parser);
  fclose (stream);

  batch_end (vt_refs_batch);
  batch_end (vt_sevs_batch);

  finalize_nvts_insert (count_new_vts, count_modified_vts, scanner_feed_version,
                        rebuild);
  sql_commit ();

  g_debug ("%s: No SHA-256 hash received from scanner, skipping check.",
             __func__);

  return 0;
}
#endif /* ENABLE_OPENVASD */

/**
 * @brief Update scanner preferences via openvasd.
 *
 * @param[in]  scan  openvasd scanner.
 *
 * @return 0 success, -1 error.
 */
int
update_scanner_preferences_openvasd (scanner_t scan)
{
#if ENABLE_HTTP_SCANNER
  int first;
  http_scanner_connector_t connector = NULL;
  GString *prefs_sql;
  GSList *point;
  GSList *scan_prefs = NULL;

  connector = http_scanner_connect (scan, NULL);
  if (!connector)
    {
      g_warning ("%s: failed to connect to scanner (%s)", __func__,
                 SCANNER_UUID_DEFAULT);
      return -1;
    }
#if ENABLE_OPENVASD
  if (feature_enabled (FEATURE_ID_OPENVASD_SCANNER))
    {
      http_scanner_resp_t resp;

      resp = openvasd_get_vts (connector);
      if (resp->code != 200)
        {
          http_scanner_response_cleanup (resp);
          g_warning ("%s: failed to get scanner preferences", __func__);
          return -1;
        }

      http_scanner_parsed_scans_preferences (connector, &scan_prefs);
      g_debug ("There %d scan preferences", g_slist_length (scan_prefs));
      http_scanner_response_cleanup (resp);
      http_scanner_connector_free (connector);
    }
  else
    {
      g_warning ("%s: openvasd runtime flag is disabled", __func__);
    }
#endif

#if ENABLE_CONTAINER_SCANNING

  if (feature_enabled (FEATURE_ID_CONTAINER_SCANNING))
    {
      connector = container_image_scanner_connect (scan, NULL);
      if (!connector)
        {
          g_warning (
            "%s: failed to get preferences from container image scanner",
            __func__);
          return -1;
        }

      http_scanner_parsed_scans_preferences (connector, &scan_prefs);
      g_debug ("There are %d scan preferences for container image scanner",
               g_slist_length (scan_prefs));
      http_scanner_connector_free (connector);
    }
  else
    {
      g_warning ("%s: container scanning runtime flag is disabled", __func__);
    }

#endif

  point = scan_prefs;
  first = 1;

  prefs_sql = g_string_new ("INSERT INTO nvt_preferences (name, value)"
                            " VALUES");
  while (point)
    {
      http_scanner_param_t *param;
      gchar *quoted_name, *quoted_value;

      param = point->data;
      quoted_name = sql_quote (http_scanner_param_id (param));
      quoted_value = sql_quote (http_scanner_param_default (param));

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
  g_slist_free_full (scan_prefs, (GDestroyNotify) http_scanner_param_free);

  g_string_append (prefs_sql,
                   " ON CONFLICT (name)"
                   " DO UPDATE SET value = EXCLUDED.value;");

  if (first == 0)
    {
      sql ("%s", prefs_sql->str);
    }

  g_string_free (prefs_sql, TRUE);

  return 0;
#else
  g_debug ("%s: openvasd or container scanning feature is disabled.", __func__);
  return -1;
#endif
}

/**
 * @brief Update VTs via openvasd.
 *
 * @param[in]  db_feed_version       Feed version from meta table.
 * @param[in]  scanner_feed_version  Feed version from scanner.
 * @param[in]  rebuild               Whether to rebuild the NVT tables from scratch.
 *
 * @return 0 success, 1 VT integrity check failed, -1 error.
 */
int
update_nvt_cache_openvasd (const gchar *db_feed_version,
                           const gchar *scanner_feed_version, int rebuild)
{
#if ENABLE_OPENVASD
  if (!feature_enabled (FEATURE_ID_OPENVASD_SCANNER))
    {
      g_warning ("%s: openvasd runtime flag is disabled", __func__);
      return -1;
    }

  http_scanner_connector_t connector = NULL;
  scanner_t scan;
  time_t old_nvts_last_modified;
  int ret;

  if (rebuild
      || db_feed_version == NULL
      || strcmp (db_feed_version, "") == 0
      || strcmp (db_feed_version, "0") == 0)
    old_nvts_last_modified = 0;
  else
    old_nvts_last_modified
      = (time_t) sql_int64_0 ("SELECT max(modification_time) FROM nvts");

  /* Update NVTs. */
  if (find_resource_no_acl ("scanner", SCANNER_UUID_DEFAULT, &scan))
    return -1;
  if (scan == 0)
    return -1;

  connector = http_scanner_connect (scan, NULL);
  if (!connector)
    {
      g_warning ("%s: failed to connect to scanner (%s)", __func__,
                 SCANNER_UUID_DEFAULT);
      return -1;
    }

  ret = update_nvts_from_openvasd_vts (connector, scanner_feed_version,
                                       rebuild);

  http_scanner_connector_free (connector);

  if (ret)
    return ret;

  /* Update scanner preferences */
  ret = update_scanner_preferences_openvasd (scan);

  if (ret)
    return ret;

  update_nvt_end (old_nvts_last_modified);

  return 0;
#else
  g_debug ("%s: Openvasd feature is disabled", __func__);
  return -1;
#endif
}

/**
 * @brief Get VTs feed information from a scanner.
 *
 * @param[in]  scanner_uuid  The uuid of the scanner to be used.
 * @param[out] vts_version   Output of scanner feed version.
 *
 * @return 0 success, 1 connection to scanner failed, 2 scanner still starting,
 *         -1 other error.
 */
int
nvts_feed_info_internal_from_openvasd (const gchar *scanner_uuid,
                                       gchar **vts_version)
{
#if ENABLE_OPENVASD
  scanner_t scan;
  http_scanner_connector_t connector = NULL;
  http_scanner_resp_t resp = NULL;
  int ret;

  if (find_resource_no_acl ("scanner", scanner_uuid, &scan))
    return -1;

  if (scan == 0)
    return -1;

  connector = http_scanner_connect (scan, NULL);
  if (!connector)
    return 1;

  resp = http_scanner_get_health_ready (connector);
  if (resp->code == -1)
    {
      gboolean has_relay = scanner_has_relay (scan);
      g_warning ("%s: failed to connect to %s:%d", __func__,
                 scanner_host (scan, has_relay),
                 scanner_port (scan, has_relay));
      ret = 1;
    }
  else if (resp->code == 503)
    ret = 2;
  else
    {
      *vts_version = g_strdup (resp->header);
      ret = 0;
    }

  http_scanner_response_cleanup (resp);
  http_scanner_connector_free (connector);
  return ret;
#else
  g_debug ("%s: Openvasd feature is disabled", __func__);
  return -1;
#endif
}

/**
 * @brief Check VTs feed version status via openvasd, optionally get versions.
 *
 * @param[out] db_feed_version_out       Output of database feed version.
 * @param[out] scanner_feed_version_out  Output of scanner feed version.
 *
 * @return -1 error (*_version_out params will be NULL), 0 VTs feed current,
 *         1 VT update needed.
 */
int
nvts_feed_version_status_internal_openvasd (gchar **db_feed_version_out,
                                            gchar **scanner_feed_version_out)
{
#if ENABLE_OPENVASD
  if (!feature_enabled (FEATURE_ID_OPENVASD_SCANNER))
    {
      g_warning ("%s: openvasd runtime flag is disabled", __func__);
      return -1;
    }

  gchar *db_feed_version = NULL;
  gchar *scanner_feed_version = NULL;

  if (db_feed_version_out)
    *db_feed_version_out = NULL;
  if (scanner_feed_version_out)
    *scanner_feed_version_out = NULL;

  db_feed_version = nvts_feed_version ();
  g_debug ("%s: db_feed_version: %s", __func__, db_feed_version);

  nvts_feed_info_internal_from_openvasd (SCANNER_UUID_DEFAULT,
                                         &scanner_feed_version);

  g_debug ("%s: scanner_feed_version: %s", __func__, scanner_feed_version);
  if (scanner_feed_version == NULL
      || strcmp (scanner_feed_version, "unavailable") == 0)
    {
      g_warning ("%s: failed to get scanner feed version.", __func__);
      g_free (db_feed_version);
      g_free (scanner_feed_version);
      return -1;
    }

  if (db_feed_version_out && db_feed_version)
    *db_feed_version_out = g_strdup (db_feed_version);
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
#else
  g_debug ("%s: Openvasd feature is disabled", __func__);
  return -1;
#endif
}

/**
 * @brief Update VTs via http/https.
 *
 * Expect to be called in the child after a fork.
 *
 * @return 0 success, -1 error, 1 VT integrity check failed.
 */
int
manage_update_nvt_cache_openvasd ()
{
#if ENABLE_OPENVASD

  gchar *db_feed_version, *scanner_feed_version;
  int ret;

  /* Try update VTs. */

  ret = nvts_feed_version_status_internal_openvasd (&db_feed_version,
                                                    &scanner_feed_version);
  if (ret == 1)
    {
      g_info ("openvasd service has different VT status (version %s)"
              " from database (version %s, %i VTs). Starting update ...",
              scanner_feed_version, db_feed_version,
              sql_int ("SELECT count (*) FROM nvts;"));

      ret = update_nvt_cache_openvasd (db_feed_version,
                                       scanner_feed_version, 0);

      g_free (db_feed_version);
      g_free (scanner_feed_version);
      return ret;
    }

  g_free (db_feed_version);
  g_free (scanner_feed_version);
  return ret;
#else
  g_debug ("%s: Openvasd feature is disabled", __func__);
  return -1;
#endif
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
update_or_rebuild_nvts_openvasd (int update)
{
#if ENABLE_OPENVASD

  gchar *db_feed_version = NULL;
  gchar *scanner_feed_version = NULL;
  int ret = 0;

  ret = nvts_feed_version_status_internal_openvasd (&db_feed_version,
                                                    &scanner_feed_version);
  if (ret == -1)
    {
      g_warning ("Failed to get scanner feed version.");
      return -3;
    }

  g_debug ("%s: db_feed_version: %s", __func__, db_feed_version);

  if (update == 0)
    set_nvts_feed_version ("0");
  ret = update_nvt_cache_openvasd (db_feed_version,
                                   scanner_feed_version, 0);
  if (ret != 0)
    ret = -1;

  g_free (db_feed_version);
  g_free (scanner_feed_version);
  return ret;
#else
  g_debug ("%s: Openvasd feature is disabled", __func__);
  return -1;
#endif
}
