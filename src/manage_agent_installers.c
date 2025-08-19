/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM manage layer: Agent installers.
 *
 * General management of agent installers.
 */

#include "gmp_base.h"
#include "manage_agent_installers.h"
#include "manage_sql_agent_installers.h"
#include <gvm/util/jsonpull.h>
#include <gvm/util/fileutils.h>
#include <glib/gstdio.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/* Agent installer data structures */

/**
 * @brief Free a agent_installer_data_t structure and its fields.
 *
 * @param[in] data  The data structure to free.
 */
void
agent_installer_data_free (agent_installer_data_t *data)
{
  g_free (data->uuid);
  g_free (data->name);
  g_free (data->description);
  g_free (data->content_type);
  g_free (data->file_extension);
  g_free (data->installer_path);
  g_free (data->version);
  g_free (data->checksum);
  g_ptr_array_free (data->cpes, TRUE);
  g_free (data);
}

/**
 * @brief Free a agent_installer_cpe_data_t structure and its fields.
 *
 * @param[in] data  The data structure to free.
 */
void
agent_installer_cpe_data_free (agent_installer_cpe_data_t *data)
{
  g_free (data->criteria);
  g_free (data->version_start_incl);
  g_free (data->version_start_excl);
  g_free (data->version_end_incl);
  g_free (data->version_end_excl);
  g_free (data);
}

/* File handling */

/**
 * @brief Open an agent installer file.
 *
 * @param[in]  installer_path  The relative installer path to open.
 * @param[out] message         Optional result message output.
 *
 * @return FILE pointer on success, NULL on failure.
 */
FILE *
open_agent_installer_file (const char *installer_path, gchar **message)
{
  gchar *canonical_feed_path, *full_installer_path, *canonical_installer_path;
  FILE *file;

  canonical_feed_path = g_canonicalize_filename (feed_dir_agent_installers (),
                                                 "/");
  full_installer_path = g_build_filename (feed_dir_agent_installers (),
                                          installer_path,
                                          NULL);
  canonical_installer_path = g_canonicalize_filename (full_installer_path,
                                                      "/");

  if (! g_str_has_prefix (canonical_installer_path, canonical_feed_path))
    {
      if (message)
        *message = g_strdup_printf ("invalid installer path:"
                                    " '%s' is outside feed directory",
                                    installer_path);

      g_debug ("%s: canonical_feed_path = %s",
               __func__, canonical_feed_path);
      g_debug ("%s: full_installer_path = %s",
               __func__, full_installer_path);
      g_debug ("%s: canonical_installer_path = %s",
               __func__, canonical_installer_path);

      g_free (canonical_feed_path);
      g_free (full_installer_path);
      g_free (canonical_installer_path);

      return NULL;
    }

  g_free (canonical_feed_path);
  g_free (full_installer_path);

  file = fopen (canonical_installer_path, "rb");
  g_free (canonical_installer_path);
  if (file == NULL)
    {
      if (message)
        *message = g_strdup_printf ("error opening installer file: %s",
                                    strerror (errno));
      return NULL;
    }
  return file;
}

/**
 * @brief Read a stream and check if it is a valid agent installer file.
 *
 * @param[in]  stream             The stream to check.
 * @param[in]  validator          The validator to use.
 * @param[out] message            Optional result message output.
 *
 * @return TRUE if file is valid, FALSE otherwise.
 */
gboolean
agent_installer_stream_is_valid (FILE *stream,
                                 gvm_stream_validator_t validator,
                                 gchar **message)
{
  gvm_stream_validator_return_t validator_return;
  char file_buffer[AGENT_INSTALLER_READ_BUFFER_SIZE];
  size_t read_bytes;

  do {
    read_bytes = fread (file_buffer,
                        1,
                        AGENT_INSTALLER_READ_BUFFER_SIZE,
                        stream);
    if (read_bytes)
      {
        validator_return = gvm_stream_validator_write (validator,
                                                       file_buffer,
                                                       read_bytes);
        if (validator_return)
          {
            if (message)
              *message = g_strdup_printf ("file validation failed: %s",
                                          gvm_stream_validator_return_str (
                                            validator_return));
            return FALSE;
          }
      }
  } while (read_bytes);

  if (ferror (stream))
    {
      if (message)
        *message = g_strdup_printf ("error reading installer file: %s",
                                    strerror (errno));
      return FALSE;
    }

  validator_return = gvm_stream_validator_end (validator);
  if (validator_return)
    {
      if (message)
        *message = g_strdup_printf ("file validation failed: %s",
                                    gvm_stream_validator_return_str (
                                      validator_return));
      return FALSE;
    }

  return TRUE;
}

/**
 * @brief Check if an agent installer file is valid.
 *
 * @param[in]  installer_path     Path of the installer file to check.
 * @param[in]  expected_checksum  The expected checksum.
 * @param[in]  expected_size      The expected file size.
 * @param[out] message            Optional result message output.
 *
 * @return TRUE if file is valid, FALSE otherwise.
 */
gboolean
agent_installer_file_is_valid (const char *installer_path,
                               const char *expected_checksum,
                               int expected_size,
                               gchar **message)
{
  FILE *file;
  gvm_stream_validator_t validator = NULL;
  gvm_stream_validator_return_t validator_return;

  validator_return = gvm_stream_validator_new (expected_checksum,
                                               expected_size,
                                               &validator);
  if (validator_return)
    {
      if (message)
        *message = g_strdup_printf ("error in expected checksum: %s",
                                    gvm_stream_validator_return_str (
                                      validator_return));
      return FALSE;
    }

  file = open_agent_installer_file (installer_path, message);
  if (file == NULL)
    {
      gvm_stream_validator_free (validator);
      return FALSE;
    }

  if (! agent_installer_stream_is_valid (file, validator, message))
    {
      gvm_stream_validator_free (validator);
      fclose (file);
      return FALSE;
    }

  gvm_stream_validator_free (validator);
  fclose (file);

  if (message)
    *message = g_strdup ("valid");
  return TRUE;
}


/* Agent installer feed sync */

/**
 * @brief Current agent installer feed directory.
 */
static const char *agent_installer_feed_path = NULL;

/**
 * @brief Get path to agent installers directory in feed.
 *
 * @return Path to agent installers in feed.
 */
const gchar *
feed_dir_agent_installers ()
{
  if (agent_installer_feed_path == NULL)
    agent_installer_feed_path = g_build_filename (GVMD_FEED_DIR,
                                                  "agent-installers",
                                                  NULL);
  return agent_installer_feed_path;
}

/**
 * @brief Get path to agent installers metadata file in feed.
 *
 * @return Path to agent installers metadata file in feed.
 */
static const gchar *
feed_metadata_file_agent_installers ()
{
  static gchar *path = NULL;
  if (path == NULL)
    path = g_build_filename (GVMD_FEED_DIR,
                             "agent-installers",
                             "agent-installers.json",
                             NULL);
  return path;
}

/**
 * @brief Tests if the agent installers metadata file exists.
 *
 * @return TRUE if the file exists.
 */
gboolean
agent_installers_feed_metadata_file_exists ()
{
  return gvm_file_is_readable (feed_metadata_file_agent_installers ());
}

/**
 * @brief Makes a JSON parser skip from the start to the agent installers list.
 *
 * @param[in]  parser  The JSON pull parser.
 * @param[in]  event   The JSON pull event structure.
 *
 * @return 0 success, -1 error.
 */
static int
agent_installers_json_skip_to_installers (gvm_json_pull_parser_t *parser,
                                          gvm_json_pull_event_t *event)
{
  gboolean found_installers = FALSE;

  gvm_json_pull_parser_next (parser, event);
  if (event->type == GVM_JSON_PULL_EVENT_ERROR)
    {
      g_warning ("%s: Parser error: %s", __func__, event->error_message);
      return -1;
    }
  else if (event->type != GVM_JSON_PULL_EVENT_OBJECT_START)
    {
      g_warning ("%s: File content is not a JSON object.", __func__);
      return -1;
    }

  while (! found_installers)
    {
      gvm_json_pull_parser_next (parser, event);
      gvm_json_path_elem_t *path_tail = g_queue_peek_tail (event->path);

      if (event->type == GVM_JSON_PULL_EVENT_ERROR)
        {
          g_warning ("%s: Parser error: %s", __func__, event->error_message);
          return -1;
        }
      else if (event->type == GVM_JSON_PULL_EVENT_ARRAY_START
               && path_tail
               && path_tail->key
               && strcmp (path_tail->key, "installers") == 0)
        {
          found_installers = TRUE;
        }
      else if (event->type == GVM_JSON_PULL_EVENT_OBJECT_END)
        {
          g_warning ("%s: Unexpected end of JSON object.", __func__);
          return -1;
        }
      else if (event->type == GVM_JSON_PULL_EVENT_EOF)
        {
          g_warning ("%s: Unexpected end of JSON file.", __func__);
          return -1;
        }
    }
  return 0;
}

/**
 * @brief Extracts data of a agent installer CPE entry from JSON
 *
 * The struct will reference the strings from the cJSON object, so
 *  they will only be valid until the cJSON object is freed and the
 *  struct should *not* be freed with agent_installer_cpe_data_free.
 *
 * @param[in]  json   The JSON object to get data from.
 * @param[out] data   The data structure to add the data to.
 *
 * @return 0 success, -1 error
 */
static int
get_agent_installer_cpe_data_from_json (cJSON *json,
                                        agent_installer_cpe_data_t *data)
{
  memset (data, 0, sizeof(agent_installer_cpe_data_t));

  data->criteria = gvm_json_obj_str (json, "criteria");
  if (data->criteria == NULL)
    {
      g_warning ("%s: CPE field '%s' is missing or not a string",
                 __func__, "criteria");
      return -1;
    }

  data->version_start_incl = gvm_json_obj_str (json, "versionStartIncluding");
  data->version_start_excl = gvm_json_obj_str (json, "versionStartExcluding");
  data->version_end_incl = gvm_json_obj_str (json, "versionEndIncluding");
  data->version_end_excl = gvm_json_obj_str (json, "versionEndExcluding");

  return 0;
}

#define GET_AGENT_INSTALLER_JSON_STR(struct_field, json_field)          \
  data->struct_field = gvm_json_obj_str (json, json_field);             \
  if (data->struct_field == NULL)                                       \
    {                                                                   \
      g_warning ("%s: Field '%s' is missing or not a string",           \
                 __func__, json_field);                                 \
      return -1;                                                        \
    }

/**
 * @brief Extracts a agent installer data entry from JSON
 *
 * The struct will reference the strings from the cJSON object, so
 *  they will only be valid until the cJSON object is freed and the
 *  struct should *not* be freed with agent_installer_data_free.
 * Instead only the cpes array has to be freed with g_ptr_array_free.
 *
 * @param[in]  json   The JSON object to get data from.
 * @param[out] data   The data structure to add the data to.
 *
 * @return 0 success, -1 error
 */
static int
get_agent_installer_data_from_json (cJSON *json,
                                    agent_installer_data_t *data)
{
  cJSON *cpes, *cpe_json;
  const char *creation_time_str, *modification_time_str;

  memset (data, 0, sizeof(agent_installer_data_t));

  GET_AGENT_INSTALLER_JSON_STR (uuid, "uuid");
  GET_AGENT_INSTALLER_JSON_STR (name, "name");
  GET_AGENT_INSTALLER_JSON_STR (description, "description");
  GET_AGENT_INSTALLER_JSON_STR (content_type, "contentType");
  GET_AGENT_INSTALLER_JSON_STR (file_extension, "fileExtension");
  GET_AGENT_INSTALLER_JSON_STR (installer_path, "installerPath");
  GET_AGENT_INSTALLER_JSON_STR (version, "version");
  GET_AGENT_INSTALLER_JSON_STR (checksum, "checksum");

  data->file_size = gvm_json_obj_int (json, "fileSize");
  if (data->file_size <= 0)
    {
      g_warning ("%s: Field '%s' is missing or not a positive integer",
                 __func__, "fileSize");
      return -1;
    }

  creation_time_str = gvm_json_obj_str (json, "created");
  if (creation_time_str == NULL)
    {
      g_warning ("%s: Field '%s' is missing or not a string",
                 __func__, "created");
      return -1;
    }
  data->creation_time = parse_iso_time (creation_time_str);
  if (data->creation_time == 0)
    {
      g_warning ("%s: Field '%s' is not a valid ISO date-time",
                 __func__, "created");
      return -1;
    }

  modification_time_str = gvm_json_obj_str (json, "lastModified");
  if (modification_time_str == NULL)
    {
      g_warning ("%s: Field '%s' is missing or not a string",
                 __func__, "lastModified");
      return -1;
    }
  data->modification_time = parse_iso_time (modification_time_str);
  if (data->modification_time == 0)
    {
      g_warning ("%s: Field '%s' is not a valid ISO date-time",
                 __func__, "lastModified");
      return -1;
    }

  cpes = cJSON_GetObjectItemCaseSensitive (json, "cpes");
  if (! cJSON_IsArray(cpes))
    {
      g_warning ("%s: Field '%s' is missing or not an array",
                 __func__, "cpes");
      return -1;
    }

  data->cpes = g_ptr_array_new_full (0, g_free);
  cJSON_ArrayForEach (cpe_json, cpes)
    {
      agent_installer_cpe_data_t *cpe_data;
      cpe_data = g_malloc0 (sizeof (agent_installer_cpe_data_t));
      if (get_agent_installer_cpe_data_from_json (cpe_json, cpe_data))
        {
          g_free (cpe_data);
          g_ptr_array_free (data->cpes, TRUE);
          return -1;
        }
      g_ptr_array_add (data->cpes, cpe_data);
    }

  return 0;
}

/**
 * @brief Handle a Agent Installer entry from the JSON metadata.
 *
 * If the entry is new or updated, the agent installer will be added to or
 *  updated in the database.
 *
 * @param[in]  entry    The JSON object to process.
 * @param[in]  rebuild  Whether to also update installers with old timestamps.
 * @param[in,out] installers_list_sql  String buffer for a list of UUIDs
 *                                     of installers in the feed in SQL-quoted
 *                                     form.
 *
 * @return 0 success, -1 error.
 */
static int
agent_installers_json_handle_entry (cJSON *entry, gboolean rebuild,
                                    GString *installers_list_sql)
{
  agent_installer_data_t data;
  agent_installer_t agent_installer;
  time_t db_modification_time = 0;
  int ret = 0;
  gchar *quoted_uuid;

  memset (&data, 0, sizeof (data));
  if (get_agent_installer_data_from_json (entry, &data))
    {
      char *entry_str = cJSON_Print(entry);
      g_message ("%s: entry: %s", __func__, entry_str);
      g_free (entry_str);
      return -1;
    }

  agent_installer = agent_installer_by_uuid (data.uuid);
  if (agent_installer)
    {
      db_modification_time
        = agent_installer_modification_time (agent_installer);
    }

  if (agent_installer == 0)
    ret = create_agent_installer_from_data (&data);
  else if (rebuild || db_modification_time < data.modification_time)
    ret = update_agent_installer_from_data (agent_installer, &data);
  else
    g_debug ("%s: skipping agent installer %s", __func__, data.uuid);

  quoted_uuid = sql_quote (data.uuid);
  g_string_append_printf (installers_list_sql,
                          "%s'%s'",
                          installers_list_sql->len ? ", " : "",
                          quoted_uuid);
  g_free (quoted_uuid);

  g_ptr_array_free (data.cpes, TRUE);
  return ret ? -1 : 0;
}

/**
 * @brief Handle the list of agent installers in the JSON metadata file.
 *
 * The JSON parser is expected to be at the start of the list.
 *
 * @param[in]  parser   The JSON parser.
 * @param[in]  parser   The JSON parser event data structure.
 * @param[in]  rebuild  Whether to also update installers with old timestamps.
 * @param[in,out] installers_list_sql  String buffer for a list of UUIDs
 *                                     of installers in the feed in SQL-quoted
 *                                     form.
 *
 * @return 0 success, -1 error.
 */
static int
agent_installers_json_handle_list_items (gvm_json_pull_parser_t *parser,
                                         gvm_json_pull_event_t *event,
                                         gboolean rebuild,
                                         GString *installers_list_sql)
{
  gvm_json_pull_parser_next (parser, event);
  while (event->type != GVM_JSON_PULL_EVENT_ARRAY_END)
    {
      if (event->type == GVM_JSON_PULL_EVENT_OBJECT_START)
        {
          gchar *error_message;
          cJSON *entry = NULL;

          entry = gvm_json_pull_expand_container (parser, &error_message);

          if (error_message)
            {
              g_warning ("%s: Error expanding agent installer item: %s",
                         __func__, error_message);
              cJSON_Delete (entry);
              return -1;
            }
          else if (agent_installers_json_handle_entry (entry,
                                                       rebuild,
                                                       installers_list_sql)) {
            cJSON_Delete (entry);
            return -1;
          }
          cJSON_Delete (entry);
        }
      else if (event->type == GVM_JSON_PULL_EVENT_ERROR)
        {
          g_warning ("%s: Parser error: %s", __func__, event->error_message);
          return -1;
        }
      else
        {
          g_warning ("%s: Unexpected list content", event->error_message);
          return -1;
        }
      gvm_json_pull_parser_next (parser, event);
    }

  return 0;
}



/**
 * @brief Sync agent installers with the feed.
 *
 * @param[in]  rebuild  Whether to also update installers with old timestamps.
 *
 * @return 0 success, -1 error.
 */
int
sync_agent_installers_with_feed (gboolean rebuild)
{
  gchar *feed_owner_uuid, *feed_owner_name;
  gvm_json_pull_parser_t parser;
  gvm_json_pull_event_t event;
  GString *installers_list_sql;

  g_info ("Updating agent installers%s", rebuild ? " (rebuild)" : "");
  update_meta_agent_installers_last_update ();

  FILE *stream = fopen (feed_metadata_file_agent_installers (), "r");
  if (stream == NULL)
    {
      g_warning ("%s: error opening agent installers metadata file: %s",
                 __func__,
                 strerror (errno));
      return -1;
    }

  /* Setup owner. */

  setting_value (SETTING_UUID_FEED_IMPORT_OWNER, &feed_owner_uuid);

  if (feed_owner_uuid == NULL
      || strlen (feed_owner_uuid) == 0)
    {
      /* Sync is disabled by having no "Feed Import Owner". */
      free (feed_owner_uuid);
      g_debug ("%s: no Feed Import Owner so not syncing from feed", __func__);
      return 2;
    }

  feed_owner_name = user_name (feed_owner_uuid);
  if (feed_owner_name == NULL)
    {
      free (feed_owner_uuid);
      g_debug ("%s: unknown Feed Import Owner so not syncing from feed", __func__);
      return 2;
    }

  current_credentials.uuid = feed_owner_uuid;
  current_credentials.username = feed_owner_name;

  /* Parse JSON metadata file */

  gvm_json_pull_parser_init (&parser, stream);
  gvm_json_pull_event_init (&event);

  if (agent_installers_json_skip_to_installers (&parser, &event))
    {
      gvm_json_pull_parser_cleanup (&parser);
      gvm_json_pull_event_cleanup (&event);
      fclose (stream);
      return -1;
    }

  installers_list_sql = g_string_new ("");

  if (agent_installers_json_handle_list_items (&parser, &event, rebuild,
                                               installers_list_sql))
    {
      gvm_json_pull_parser_cleanup (&parser);
      gvm_json_pull_event_cleanup (&event);
      g_string_free (installers_list_sql, TRUE);
      fclose (stream);
      return -1;
    }

  gvm_json_pull_parser_cleanup (&parser);
  gvm_json_pull_event_cleanup (&event);
  fclose (stream);

  if (installers_list_sql->len)
    {
      iterator_t deleted_installers;

      sql_begin_immediate ();

      sql ("DELETE FROM agent_installer_cpes WHERE agent_installer NOT IN"
          " (SELECT id FROM agent_installers WHERE uuid IN (%s));",
          installers_list_sql->str);

      init_iterator (&deleted_installers,
                     "DELETE FROM agent_installers WHERE uuid NOT IN (%s)"
                     " RETURNING uuid;",
                     installers_list_sql->str);
      while (next (&deleted_installers))
        {
          log_event ("agent_installer", "Agent Installer",
                     iterator_string (&deleted_installers, 0),
                     "deleted");
        }
      cleanup_iterator (&deleted_installers);
  
      sql_commit ();
    }
  else
    g_warning ("%s: No agent installers found in metadata file", __func__);

  g_string_free (installers_list_sql, TRUE);

  g_info ("Finished updating agent installers");
  return 0;
}

/**
 * @brief Sync agent installers with the feed.
 */
void
manage_sync_agent_installers ()
{
  sync_agent_installers_with_feed (FALSE);
}


/**
 * @brief Checks if the agent_installers should be synced with the feed.
 *
 * @return 1 if agent_installers should be synced, 0 otherwise
 */
gboolean
should_sync_agent_installers ()
{
#if ENABLE_AGENTS
  time_t db_last_update;
  GStatBuf state;
  if (! agent_installers_feed_metadata_file_exists ())
    return FALSE;

  db_last_update = get_meta_agent_installers_last_update ();

  if (g_stat (feed_metadata_file_agent_installers(), &state))
    {
      g_warning ("%s: Failed to stat feed config file: %s",
                 __func__,
                 strerror (errno));
      return 0;
    }

  if (state.st_mtime >= db_last_update)
    return TRUE;
#endif /* ENABLE_AGENTS */
  return FALSE;
}
