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
 * @file manage_sql_nvts_openvasd.c
 * @brief GVM management layer: openvasd NVT logic
 *
 * NVT logic specific to openvasd in the GVM management layer.
 */

#if OPENVASD
/**
 * @brief Enable extra GNU functions.
 */
#define _GNU_SOURCE         /* See feature_test_macros(7) */
#define _FILE_OFFSET_BITS 64
#include <stdio.h>

#include "manage_sql.h"
#include "manage_sql_configs.h"
#include "manage_sql_nvts_openvasd.h"
#include "sql.h"

#include <gvm/util/jsonpull.h>
#include <gvm/util/vtparser.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Max number of rows inserted per statement.
 */
static int vt_ref_insert_size = VT_REF_INSERT_SIZE_DEFAULT;

/**
 * @brief Max number of rows inserted per statement.
 */
static int vt_sev_insert_size = VT_SEV_INSERT_SIZE_DEFAULT;

/**
 * @brief Update NVT from an NVTI structure
 *
 * @param[in]  vt           OSP GET_VTS VT element.
 * @param[in]  oid          OID of NVT.
 * @param[in]  preferences  All NVT preferences.
 *
 * @return 0 success, -1 error.
 */
static int
update_preferences_from_openvasd_nvt (nvti_t *nvti, GList **preferences)
{
  assert (preferences);

  int prefs_count = nvti_pref_len(nvti);
  for (int j = 0; j < prefs_count; j++)
    {
      int id;
      char *char_id, *type, *name, *def;
      const nvtpref_t *pref = NULL;

      pref = nvti_pref (nvti, j);

      id = nvtpref_id (pref);
      char_id = g_strdup_printf ("%d", id);
      type = g_strdup (nvtpref_type (pref));
      name = g_strdup (nvtpref_name (pref));
      def = g_strdup (nvtpref_default (pref));

      if (type == NULL)
        {
          GString *debug = g_string_new ("");
          g_warning ("%s: PARAM missing type attribute for OID: %s",
                     __func__, nvti_oid(nvti));
          g_string_free (debug, TRUE);
        }
      else if (id < 0)
        {
          GString *debug = g_string_new ("");
          g_warning ("%s: PARAM missing id attribute for OID: %s",
                     __func__, nvti_oid(nvti));
          g_string_free (debug, TRUE);
        }
      else if (name == NULL)
        {
          GString *debug = g_string_new ("");
          g_warning ("%s: PARAM missing NAME for OID: %s",
                     __func__, nvti_oid (nvti));
          g_string_free (debug, TRUE);
        }
      else
        {
          gchar *full_name;
          preference_t *preference;

          full_name = g_strdup_printf ("%s:%d:%s:%s",
                                       nvti_oid (nvti),
                                       id,
                                       type,
                                       name);

          blank_control_chars (full_name);
          preference = g_malloc0 (sizeof (preference_t));
          preference->free_strings = 1;
          preference->name = full_name;
          if (def)
            preference->value = g_strdup (def);
          else
            preference->value = g_strdup ("");
          preference->nvt_oid = g_strdup (nvti_oid (nvti));
          preference->id = g_strdup (char_id);
          preference->type = g_strdup (type);
          preference->pref_name = g_strdup (name);
          *preferences = g_list_prepend (*preferences, preference);
        }

      g_free (char_id);
      g_free (name);
      g_free (type);
      g_free (def);
    }

  return 0;
}

/**
 * @brief Struct containing the stream buffer.
 */
struct FILESTREAM {
  char *stream_buffer;
  size_t size_of_buffer;
  size_t last_read;
  size_t last_write;
};

/**
 * @brief Hook function to read the stream file cookie
 */
static ssize_t
readcookie (void *stream_cookie, char *buf, size_t size)
{
  struct FILESTREAM *stream = stream_cookie;
  size_t to_read = stream->last_write - stream->last_read;
  if (to_read < 0)
    to_read = 0;

  if (to_read > size)
    to_read = size;
  memcpy (buf, &stream->stream_buffer[stream->last_read], to_read);

  stream->last_read += to_read;
  return to_read;
}

/**
 * @brief Hook function to close the stream file cookie
 */
static int
closecookie (void *filestream)
{
  struct FILESTREAM *stream = filestream;
  g_free(stream->stream_buffer);
  stream->size_of_buffer = 0;
  stream->stream_buffer = NULL;
  return 0;
}

/**
 * @brief Hook function to write the stream file cookie
 */
static ssize_t
writecookie (void *stream_cookie, const char *buf, size_t size)
{
  struct FILESTREAM *stream = stream_cookie;
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
  stream->last_write+=size;

  return size;
}

/**
 * @brief Move non read data to beggining of the buffer
 */
static int
move_buffer_data (struct FILESTREAM *filestream){
  char *auxbuf;
  size_t non_read_chars_count = filestream->last_write - filestream->last_read;

  auxbuf = g_malloc0 (sizeof(char) * filestream->size_of_buffer);
  if (auxbuf == NULL)
    return -1;

  memcpy (auxbuf, &filestream->stream_buffer[filestream->last_read],
          non_read_chars_count);
  memset (filestream->stream_buffer, '\0', filestream->size_of_buffer);
  memcpy (filestream->stream_buffer, auxbuf, non_read_chars_count);

  filestream->last_read = 0;
  filestream->last_write = non_read_chars_count;

  g_free(auxbuf);

  return 0;
}

/**
 * @brief Update NVTs from Json response chunk by chunk
 *
 * @param[in]  conn                  openvasd connector
 * @param[in]  scanner_feed_version  Version of feed from scanner.
 * @param[in]  rebuild               Whether we're rebuilding the tables.
 *
 * @return 0 success, 1 VT integrity check failed, -1 error
 */
static int
update_nvts_from_openvasd_vts (openvasd_connector_t connector,
                               const gchar *scanner_feed_version,
                               int rebuild)
{
  GList *preferences;
  int count_modified_vts, count_new_vts;
  time_t feed_version_epoch;
  batch_t *vt_refs_batch, *vt_sevs_batch;

  count_modified_vts = 0;
  count_new_vts = 0;

  feed_version_epoch = nvts_feed_version_epoch();

  //osp_vt_hash = element_attribute (vts, "sha256_hash");

  sql_begin_immediate ();
  prepare_nvts_insert (rebuild);

  vt_refs_batch = batch_start (vt_ref_insert_size);
  vt_sevs_batch = batch_start (vt_sev_insert_size);

  int running = 0;
  openvasd_resp_t resp;
  gvm_json_pull_event_t event;
  gvm_json_pull_parser_t parser;
  FILE *stream = NULL;
  struct FILESTREAM *filestream;
  nvti_t *nvti = NULL;

  resp = openvasd_get_vt_stream_init (connector);
  if (resp->code < 0)
    {
      openvasd_response_cleanup (resp);
      g_warning ("%s: failed to get VTs", __func__);
      return -1;
    }

  cookie_io_functions_t cookiehooks = {
    .read = readcookie,
    .write = writecookie,
    .seek = NULL,
    .close = closecookie,
  };

  filestream = g_malloc0 (sizeof(struct FILESTREAM));
  filestream->size_of_buffer = GVM_JSON_PULL_PARSE_BUFFER_LIMIT;
  filestream->stream_buffer =
    g_malloc0 (sizeof(char) * filestream->size_of_buffer);

  stream = fopencookie (filestream, "a+", cookiehooks);

  gvm_json_pull_parser_init_full (&parser, stream,
                                  GVM_JSON_PULL_PARSE_BUFFER_LIMIT,
                                  GVM_JSON_PULL_READ_BUFFER_SIZE * 8);
  gvm_json_pull_event_init (&event);

  // First run for initial data in the stream
  running = openvasd_get_vt_stream (connector);
  fwrite (openvasd_vt_stream_str (connector), 1,
          openvasd_vt_stream_len (connector), stream);

  openvasd_reset_vt_stream (connector);
  int break_flag = 0;
  while (running)
    {
      size_t non_read_count = 0;
      // Ensure a big chunk of data.
      // Realloc is expensive therefore we realloc with bigger chuncks
      while (running > 0 && openvasd_vt_stream_len (connector) < GVM_JSON_PULL_READ_BUFFER_SIZE * 8)
          running = openvasd_get_vt_stream (connector);

      if (openvasd_vt_stream_len (connector) > 0)
        {
          move_buffer_data (filestream);
          fwrite (openvasd_vt_stream_str (connector), 1, openvasd_vt_stream_len (connector), stream);
          openvasd_reset_vt_stream (connector);
        }

      non_read_count = filestream->last_write - filestream->last_read;
      // While streaming, parse some VTs and continue for a new chunk.
      // If the stream is not running anymore, parse the remaining VTs.
      while ((running && non_read_count > GVM_JSON_PULL_READ_BUFFER_SIZE * 8) || !running)
        {
          if (parse_vt_json (&parser, &event, &nvti))
            {
              break_flag = 1;
              break;
            }
          if (nvti_creation_time (nvti) > feed_version_epoch)
            count_new_vts += 1;
          else
            count_modified_vts += 1;

          insert_nvt (nvti, rebuild, vt_refs_batch, vt_sevs_batch);

          preferences = NULL;
          if (update_preferences_from_openvasd_nvt (nvti, &preferences))
            {
              sql_rollback ();
              return -1;
            }
          if (rebuild == 0)
            sql ("DELETE FROM nvt_preferences%s WHERE name LIKE '%s:%%';",
                 rebuild ? "_rebuild" : "",
                 nvti_oid (nvti));
          insert_nvt_preferences_list (preferences, rebuild);
          g_list_free_full (preferences, (GDestroyNotify) preference_free);

          g_free(nvti);
          non_read_count = filestream->last_write - filestream->last_read;
        }
      if (break_flag)
          break;
    }

  gvm_json_pull_event_cleanup (&event);
  gvm_json_pull_parser_cleanup (&parser);
  fclose (stream);

  openvasd_response_cleanup (resp);

  batch_end (vt_refs_batch);
  batch_end (vt_sevs_batch);

  finalize_nvts_insert (count_new_vts, count_modified_vts,scanner_feed_version,
                        rebuild);
  sql_commit ();

  g_warning ("%s: No SHA-256 hash received from scanner, skipping check.",
             __func__);

  return 0;
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
update_nvt_cache_openvasd (gchar *db_feed_version,
                           gchar *scanner_feed_version, int rebuild)
{
  openvasd_connector_t connector = NULL;
  openvasd_resp_t resp;
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
  if (find_resource_no_acl ("scanner", SCANNER_UUID_OPENVASD_DEFAULT, &scan))
    return -1;
  if (scan == 0)
    return -1;

  connector = openvasd_scanner_connect (scan, NULL);
  if (!connector)
    {
      g_warning ("%s: failed to connect to scanner (%s)", __func__,
                 SCANNER_UUID_OPENVASD_DEFAULT);
      return -1;
    }

  ret = update_nvts_from_openvasd_vts (connector, scanner_feed_version, rebuild);

  if (ret)
    {
      openvasd_connector_free (connector);
      return ret;
    }

  /* Update scanner preferences */
  // TODO: update scanner preferences

  resp = openvasd_get_vts (connector);
  if (resp->code != 200)
    {
      openvasd_response_cleanup (resp);
      g_warning ("%s: failed to get scanner preferences", __func__);
      return -1;
    }
  GSList *scan_prefs = NULL;

  openvasd_parsed_scans_preferences (connector, &scan_prefs);
  g_debug ("There %d scan preferences", g_slist_length (scan_prefs));
  openvasd_connector_free (connector);

  GString *prefs_sql;
  GSList *point;
  int first;

  point = scan_prefs;
  first = 1;

  prefs_sql = g_string_new ("INSERT INTO nvt_preferences (name, value)"
                            " VALUES");
  while (point)
    {
      openvasd_param_t *param;
      gchar *quoted_name, *quoted_value;

      param = point->data;
      quoted_name = sql_quote (openvasd_param_id (param));
      quoted_value = sql_quote (openvasd_param_default (param));

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
  g_slist_free_full (scan_prefs, (GDestroyNotify) openvasd_param_free);

  g_string_append (prefs_sql,
                   " ON CONFLICT (name)"
                   " DO UPDATE SET value = EXCLUDED.value;");

  if (first == 0)
    {
      sql ("%s", prefs_sql->str);
    }

  g_string_free (prefs_sql, TRUE);

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

  openvasd_response_cleanup (resp);

  return 0;
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
  scanner_t scan;
  openvasd_connector_t connector = NULL;
  openvasd_resp_t resp = NULL;
  int ret;

  if (find_resource_no_acl ("scanner", scanner_uuid, &scan))
    return -1;

  if (scan == 0)
    return -1;

  connector = openvasd_scanner_connect (scan, NULL);
  if (!connector)
    return 1;

  resp = openvasd_get_health_ready (connector);
  if (resp->code == -1)
    {
      gboolean has_relay = scanner_has_relay (scan);
      g_warning ("%s: failed to connect to %s:%d", __func__,
                 scanner_host (scan, has_relay),
                 scanner_port (scan, has_relay));
      ret = 1;
    }
  else if (resp->code  == 503)
    ret = 2;
  else
    {
      *vts_version = g_strdup (resp->header);
      ret = 0;
    }

  openvasd_response_cleanup (resp);
  openvasd_connector_free (connector);
  return ret;
}

/**
 * @brief Check VTs feed version status via openvasd, optionally get versions.
 *
 * @param[out] db_feed_version_out       Output of database feed version.
 * @param[out] scanner_feed_version_out  Output of scanner feed version.
 *
 * @return 0 VTs feed current, -1 error, 1 VT update needed.
 */
int
nvts_feed_version_status_internal_openvasd (gchar **db_feed_version_out,
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

  nvts_feed_info_internal_from_openvasd (SCANNER_UUID_OPENVASD_DEFAULT,
                                         &scanner_feed_version);

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
 * @brief Update VTs via http/https.
 *
 * Expect to be called in the child after a fork.
 *
 * @return 0 success, -1 error, 1 VT integrity check failed.
 */
int
manage_update_nvt_cache_openvasd ()
{
  gchar *db_feed_version, *scanner_feed_version;
  int ret;

  /* Re-open DB after fork. */

  reinit_manage_process ();
  manage_session_init (current_credentials.uuid);

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

  return ret;
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

  return ret;
}

#endif
