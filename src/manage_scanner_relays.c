/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Greenbone Vulnerability Manager scanner relays.
 */

#include "gmp_base.h"
#include "manage_scanner_relays.h"
#include "manage_sql_scanner_relays.h"
#include "manage_sql.h"

#include <glib/gstdio.h>
#include <gvm/util/json.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain used for messages from this module.
 */
#define G_LOG_DOMAIN "md   manage"

/**
 * @brief Path to the relay mappings JSON file, NULL to disable relays.
 */
static gchar *relays_path = NULL;

/**
 * @brief Gets the current path of the relay mappings data file.
 *
 * @return The current relay mappings path.
 */
const char *
get_relays_path ()
{
  return relays_path;
}

/**
 * @brief Sets a new path for the relay mappings data file.
 *
 * @param[in]  new_path  The new relay mappings path.
 */
void
set_relays_path (const char *new_path)
{
  g_free (relays_path);
  relays_path = (new_path && strcmp (new_path, ""))
                  ? g_strdup (new_path) : NULL;
}

/**
 * @brief Checks if relays are managed externally.
 *
 * @return TRUE if relays are managed externally, FALSE if not.
 */
gboolean
relays_managed_externally ()
{
  return relays_path ? TRUE : FALSE;
}

/**
 * @brief Extract the fields from the root object of a relays JSON file.
 *
 * @param[in]  parsed_file  Root object of the file to get fields from.
 * @param[out] relays_out   Output of the relays array.
 *
 * @return 0 success, -1 error
 */
static int
extract_relays_fields_from_root_cjson (cJSON *parsed_file,
                                       cJSON **relays_out)
{
  cJSON *relays;

  if (! parsed_file)
    return -1;

  if (relays_out)
    *relays_out = NULL;

  if (! cJSON_IsObject (parsed_file))
    {
      g_warning ("%s: root element must be an object", __func__);
      return -1;
    }

  relays = cJSON_GetObjectItem (parsed_file, "relays");
  if (relays == NULL)
    {
      g_warning ("%s: missing 'relays' array", __func__);
      return -1;
    }
  if (! cJSON_IsArray (relays))
    {
      g_warning ("%s: 'relays' field is not an array", __func__);
      return -1;
    }

  if (relays_out)
    *relays_out = relays;
  return 0;
}

/**
 * @brief Extract the fields from a cJSON item from a relays array.
 *
 * Strings are freed when the cJSON item is destroyed.
 *
 * @param[in]  json_item  The list item as a cJSON object.
 * @param[out] item_out   Pointer to structure holding the field values.
 *
 * @return 0 success, -1 error
 */
static int
extract_relay_fields_from_json_item (cJSON *json_item,
                                     relays_list_item_t *item_out)
{
  if (item_out == NULL)
    {
      g_warning ("%s: no output item given", __func__);
      return -1;
    }

  item_out->original_host = NULL;
  item_out->original_port = 0;
  item_out->relay_host = NULL;
  item_out->relay_port = 0;
  item_out->protocol = NULL;

  if (json_item == NULL)
    {
      g_warning ("%s: no input JSON object given", __func__);
      return -1;
    }

  gvm_json_obj_check_str (json_item, "original_host",
                          &item_out->original_host);
  gvm_json_obj_check_int (json_item, "original_port",
                          &item_out->original_port);
  gvm_json_obj_check_str (json_item, "relay_host",
                          &item_out->relay_host);
  gvm_json_obj_check_int (json_item, "relay_port",
                          &item_out->relay_port);
  gvm_json_obj_check_str (json_item, "protocol",
                          &item_out->protocol);

  if (item_out->original_host == NULL)
    {
      g_debug ("%s: mandatory original_host field missing or not a string",
               __func__);
      return -1;
    }

  return 0;
}

/**
 * @brief Update all scanner relays using a parsed JSON file.
 *
 * If the update is successful, the scanner_relays_update_time entry in the
 * meta table is updated and events are logged for the updated scanners.
 *
 * @param[in]  parsed_file    The root cJSON object of the parsed file.
 * @param[in]  file_mod_time  Modification time of the file.
 */
static int
update_all_scanner_relays_from_json (cJSON *parsed_file,
                                     time_t file_mod_time)
{
  cJSON *relays, *json_item;
  GHashTable *updated_scanners;
  GHashTableIter scanners_iter;
  gchar *scanner_id;

  if (extract_relays_fields_from_root_cjson (parsed_file, &relays))
    return -1;

  updated_scanners
    = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

  update_all_scanner_relays_start ();

  cJSON_ArrayForEach (json_item, relays)
    {
      relays_list_item_t parsed_item;
      if (extract_relay_fields_from_json_item (json_item, &parsed_item))
        continue;

      if (update_all_scanner_relays_from_item (&parsed_item, updated_scanners))
        {
          g_hash_table_destroy (updated_scanners);
          return -1;
        }
    }

  update_all_scanner_relays_end (file_mod_time);

  g_hash_table_iter_init (&scanners_iter, updated_scanners);
  while (g_hash_table_iter_next (&scanners_iter,
                                 (gpointer*)(&scanner_id), NULL))
    {
      log_event ("scanner", "Scanner", scanner_id,
                 "updated according to relays file");
    }
  g_hash_table_destroy (updated_scanners);
  return 0;
}

/**
 * @brief Update the scanner relays from a file if neeeded.
 *
 * The scanners are updated if a path is set for the relays file and if the
 * file is updated more recently than the scanner_relays_update_time entry
 * in the meta table.
 *
 * @return 0 success, -1 error.
 */
int
sync_scanner_relays ()
{
  time_t db_mod_time;
  GStatBuf stat_buffer;
  GError *error = NULL;
  gchar *file_contents = NULL;
  size_t file_size = 0;
  cJSON *parsed_file;

  if (relays_path == NULL || strcmp (relays_path, "") == 0)
    return 0;

  if (g_stat (relays_path, &stat_buffer))
    {
      g_warning ("%s: Failed to stat scanner relays file: %s",
                 __func__, strerror (errno));
      return -1;
    }

  db_mod_time = get_scanner_relays_db_update_time ();
  if (stat_buffer.st_mtime <= db_mod_time)
    {
      g_debug ("%s: relays file not modified since last sync", __func__);
      return -1;
    }

  if (! g_file_get_contents (relays_path, &file_contents, &file_size, &error))
    {
      g_warning ("%s: could not read file: %s", __func__, error->message);
      g_error_free (error);
      return -1;
    }

  parsed_file = cJSON_ParseWithLength (file_contents, file_size);
  if (parsed_file == NULL)
    {
      g_warning ("%s: could not parse JSON", __func__);
      return -1;
    }

  if (update_all_scanner_relays_from_json (parsed_file, stat_buffer.st_mtime))
    {
      g_warning ("%s: could not update relays", __func__);
      cJSON_Delete (parsed_file);
      return -1;
    }

  cJSON_Delete (parsed_file);
  return 0;
}

/**
 * @brief Check if a scanner type matches a relays file "protocol" string.
 *
 * @param[in]  scanner_type  The scanner type to check
 * @param[in]  protocol      The protocol string from the relays file to check
 *
 * @return TRUE if the two match, FALSE otherwise
 */
static gboolean
scanner_type_matches_relay_protocol (int scanner_type,
                                     const char *protocol)
{
  switch (scanner_type)
  {
    case SCANNER_TYPE_AGENT_CONTROLLER_SENSOR:
      return protocol == NULL
             || strcasecmp (protocol, "agent-control") == 0;
    case SCANNER_TYPE_OPENVASD_SENSOR:
      return protocol == NULL
             || strcasecmp (protocol, "openvasd") == 0;
    case SCANNER_TYPE_OSP_SENSOR:
      return protocol == NULL
             || strcasecmp (protocol, "osp") == 0;
    default:
      return FALSE;
  }
}

/**
 * @brief Get the relays host and port matching the data of a single scanner.
 *
 * @param[in]  scanner_type   The type of scanner to match
 * @param[in]  original_host  Original host of the scanner to match
 * @param[in]  original_port  Original port of the scanner to match, 0 for any
 * @param[out] relay_host     Output of the relay host
 * @param[out] relay_port     Output of the relay port
 *
 * @return 0 success, -1 error
 */
int
get_single_relay_from_file (int scanner_type,
                            const char *original_host,
                            int original_port,
                            char **relay_host,
                            int *relay_port)
{
  GError *error = NULL;
  gchar *file_contents = NULL;
  size_t file_size = 0;
  cJSON *parsed_file, *relays, *json_item;

  if (relay_host == NULL || relay_port == NULL)
    {
      g_warning ("%s: output parameters must not be NULL", __func__);
      return -1;
    }

  *relay_host = NULL;
  *relay_port = 0;

  if (! g_file_get_contents (relays_path, &file_contents, &file_size, &error))
    {
      g_warning ("%s: could not read file: %s", __func__, error->message);
      g_error_free (error);
      return -1;
    }

  parsed_file = cJSON_ParseWithLength (file_contents, file_size);
  if (parsed_file == NULL)
    {
      g_warning ("%s: could not parse JSON", __func__);
      return -1;
    }

  if (extract_relays_fields_from_root_cjson (parsed_file, &relays))
    {
      cJSON_Delete (parsed_file);
      return -1;
    }

  cJSON_ArrayForEach (json_item, relays)
    {
      relays_list_item_t parsed_item;
      if (extract_relay_fields_from_json_item (json_item, &parsed_item))
        continue;
      if (scanner_type_matches_relay_protocol (scanner_type,
                                               parsed_item.protocol)
          && (parsed_item.original_port == 0
              || parsed_item.original_port == original_port)
          && (strcmp (original_host, parsed_item.original_host) == 0))
        {
          g_free (*relay_host);
          *relay_host = g_strdup (parsed_item.relay_host);
          *relay_port = parsed_item.relay_port;
        }
    }
  return 0;
}
