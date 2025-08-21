/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief SQL backend implementation for agent management in GVMD.
 *
 * This file provides the implementation of SQL interactions related to
 * agent data, including creation, update, deletion, and synchronization
 * with the Agent Controller. It supports both direct SQL operations and
 * optimized bulk operations using PostgreSQL COPY. Functions are also provided
 * for iterating agent data and handling agent IP address relationships.
 */

#if ENABLE_AGENTS

#include "manage_sql_agents.h"

#include "manage_sql_copy.h"

#include <util/uuidutils.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Delete all existing IP addresses for a given agent.
 *
 * @param[in] agent_id Agent identifier whose IPs will be removed.
 */
static void
delete_existing_agent_ips (const gchar *agent_id)
{
  gchar *insert_agent_id = sql_insert (agent_id);
  sql ("DELETE FROM agent_ip_addresses WHERE agent_id = %s;", insert_agent_id);
  g_free (insert_agent_id);
}

/**
 * @brief Check if a value exists in a given column of the agents table.
 *
 * @param[in] column_name Column to search (e.g., "agent_id" or "uuid").
 * @param[in] value       Value to match against.
 * @return 1 if exists, 0 if not, -1 on error.
 */
static int
agent_column_exists (const gchar *column_name, const gchar *value)
{
  if (!column_name || !value)
    {
      g_warning ("%s: column_name or value is NULL", __func__);
      return -1;
    }

  gchar *insert_value = sql_insert (value);
  gchar *query = g_strdup_printf ("SELECT COUNT(*) FROM agents WHERE %s = %s;",
                                  column_name, insert_value);

  int result = sql_int (query);

  g_free (query);
  g_free (insert_value);

  if (result < 0)
    g_warning ("%s: SQL execution failed for column %s", __func__, column_name);

  return result < 0 ? -1 : (result > 0);
}

/**
 * @brief Update an existing agent record in the database.
 *
 * @param[in] agent Pointer to the agent data to update.
 */
static void
update_existing_agent (agent_data_t agent)
{
  gchar *config_string =
    agent_controller_convert_scan_agent_config_string (agent->config);
  if (!config_string)
    config_string = g_strdup ("");

  gchar *insert_hostname = sql_insert (agent->hostname);
  gchar *insert_connection_status = sql_insert (agent->connection_status);
  gchar *insert_config = sql_insert (config_string);
  gchar *insert_agent_id = sql_insert (agent->agent_id);
  gchar *insert_updater_version = sql_insert (agent->updater_version);
  gchar *insert_agent_version = sql_insert (agent->agent_version);
  gchar *insert_operating_system = sql_insert (agent->operating_system);
  gchar *insert_architecture = sql_insert (agent->architecture);

  sql ("UPDATE agents SET "
       " hostname = %s,"
       " authorized = %d,"
       " connection_status = %s,"
       " last_update = %ld,"
       " last_updater_heartbeat = %ld,"
       " config = %s,"
       " owner = %u,"
       " modification_time = %ld,"
       " scanner = %llu,"
       " updater_version = %s,"
       " agent_version = %s,"
       " operating_system = %s,"
       " architecture = %s,"
       " update_to_latest = %d"
       " WHERE agent_id = %s;",
       insert_hostname, agent->authorized, insert_connection_status,
       agent->last_update_agent_control, agent->last_updater_heartbeat,
       insert_config, agent->owner, agent->modification_time, agent->scanner,
       insert_updater_version, insert_agent_version, insert_operating_system,
       insert_architecture, agent->update_to_latest ? 1 : 0, insert_agent_id);

  g_free (insert_hostname);
  g_free (insert_connection_status);
  g_free (insert_config);
  g_free (insert_agent_id);
  g_free (insert_updater_version);
  g_free (insert_agent_version);
  g_free (insert_operating_system);
  g_free (insert_architecture);
  g_free (config_string);
}

/**
 * @brief Append an agent's data as a row to a COPY buffer.
 *
 * @param[out] buffer COPY buffer for agents.
 * @param[in] agent  Agent whose data will be appended.
 */
static void
append_agent_row_to_buffer (db_copy_buffer_t *buffer, agent_data_t agent)
{
  if (!agent->uuid)
    {
      agent->uuid = gvm_uuid_make ();
      if (agent->uuid == NULL)
        return;
    }

  gchar *config_string =
    agent_controller_convert_scan_agent_config_string (agent->config);
  if (!config_string)
    config_string = g_strdup ("");

  gchar *escaped_hostname = sql_copy_escape (agent->hostname);
  gchar *escaped_connection_status = sql_copy_escape (agent->connection_status);
  gchar *escaped_config = sql_copy_escape (config_string);
  gchar *escaped_comment = sql_copy_escape ("");

  gchar *escaped_updater_version = sql_copy_escape (agent->updater_version);
  gchar *escaped_agent_version = sql_copy_escape (agent->agent_version);
  gchar *escaped_operating_system = sql_copy_escape (agent->operating_system);
  gchar *escaped_architecture = sql_copy_escape (agent->architecture);

  db_copy_buffer_append_printf (
    buffer,
    "%s\t%s\t%s\t%llu\t%s\t%d\t%s\t%ld\t%ld\t%s\t%u\t%s\t%ld\t%ld\t%s\t%s\t%"
    "s\t%s\t%d\n",
    agent->uuid, agent->name, agent->agent_id, agent->scanner, escaped_hostname,
    agent->authorized, escaped_connection_status,
    agent->last_update_agent_control, agent->last_updater_heartbeat,
    escaped_config, agent->owner, escaped_comment,
    time (NULL), // creation_time
    agent->modification_time, escaped_updater_version, escaped_agent_version,
    escaped_operating_system, escaped_architecture,
    agent->update_to_latest ? 1 : 0);

  g_free (escaped_hostname);
  g_free (escaped_connection_status);
  g_free (escaped_config);
  g_free (escaped_comment);
  g_free (escaped_updater_version);
  g_free (escaped_agent_version);
  g_free (escaped_operating_system);
  g_free (escaped_architecture);
  g_free (config_string);
}

/**
 * @brief Append all IPs of an agent to a COPY buffer.
 *
 * @param[out] buffer   COPY buffer for agent IPs.
 * @param[in] agent_id ID of the agent.
 * @param[in] ip_list  List of IP addresses to append.
 */
static void
append_ip_rows_to_buffer (db_copy_buffer_t *buffer, const gchar *agent_id,
                          agent_ip_data_list_t ip_list)
{
  if (!ip_list)
    return;

  gchar *escaped_agent_id = sql_copy_escape (agent_id);

  for (int j = 0; j < ip_list->count; ++j)
    {
      agent_ip_data_t ip = ip_list->items[j];
      gchar *escaped_ip_address = sql_copy_escape (ip->ip_address);

      db_copy_buffer_append_printf (buffer, "%s\t%s\n", escaped_agent_id,
                                    escaped_ip_address);

      g_free (escaped_ip_address);
    }

  g_free (escaped_agent_id);
}

/**
 * @brief Resolve a scanner_t from an agent UUID string.
 *
 * Looks up the agents table to fetch the scanner ID that corresponds
 * to the provided agent UUID.
 *
 * @param[in] agent_uuid UUID of the agent as a string.
 * @param[out] scanner scanner row id of the agent.
 * @return 0 on success, or -1 on failure if agent uuid is missing
 *                       or -2 on failure if DB error occurred
 *                       or -3 on failure if the agent uuid not found
 *                       or -4 on failure if the scanner row id not found
 */
int
get_scanner_from_agent_uuid (const gchar *agent_uuid, scanner_t *scanner)
{
  if (!agent_uuid)
    {
      g_warning ("%s: Agent UUID is required but missing", __func__);
      manage_option_cleanup ();
      return -1;
    }

  int exists = agent_column_exists ("uuid", agent_uuid);
  if (exists == -1)
    {
      g_warning ("%s: Failed to check if agent UUID '%s' exists (DB error)",
                 __func__, agent_uuid);
      manage_option_cleanup ();
      return -2;
    }
  if (exists == 0)
    {
      g_warning ("%s: Agent UUID '%s' not found", __func__, agent_uuid);
      manage_option_cleanup ();
      return -3;
    }

  gchar *insert_agent_uuid = sql_insert (agent_uuid);
  *scanner =
    sql_int ("SELECT scanner FROM agents WHERE uuid = %s;", insert_agent_uuid);
  g_free (insert_agent_uuid);

  if (*scanner <= 0)
    {
      g_warning ("%s: Failed to find scanner for agent UUID %s", __func__,
                 agent_uuid);
      manage_option_cleanup ();
      return -4;
    }

  return 0;
}

/**
 * @brief Synchronize agent data list into the SQL database.
 *
 * Performs UPSERT logic: existing agents are updated, new agents
 * and all IPs are inserted via COPY.
 *
 * @param[in] agent_list List of agents to sync.
 * @return 0 on success, -1 on failure.
 */
int
sync_agents_from_data_list (agent_data_list_t agent_list)
{
  if (!agent_list || agent_list->count == 0)
    return 0;

  db_copy_buffer_t agent_buffer = {0};
  db_copy_buffer_t ip_buffer = {0};
  int status = 0;

  db_copy_buffer_init (&agent_buffer, 64 * 1024,
                       "COPY agents ("
                       " uuid,"
                       " name,"
                       " agent_id,"
                       " scanner,"
                       " hostname,"
                       " authorized,"
                       " connection_status,"
                       " last_update,"
                       " last_updater_heartbeat,"
                       " config,"
                       " owner,"
                       " comment,"
                       " creation_time,"
                       " modification_time,"
                       " updater_version,"
                       " agent_version,"
                       " operating_system,"
                       " architecture,"
                       " update_to_latest"
                       ") FROM STDIN;");

  db_copy_buffer_init (
    &ip_buffer, 32 * 1024,
    "COPY agent_ip_addresses (agent_id, ip_address) FROM STDIN;");

  sql_begin_immediate ();

  for (int i = 0; i < agent_list->count; ++i)
    {
      agent_data_t agent = agent_list->agents[i];

      gboolean exists = agent_column_exists ("agent_id", agent->agent_id);

      if (exists)
        {
          update_existing_agent (agent);
          delete_existing_agent_ips (agent->agent_id);
        }
      else
        {
          append_agent_row_to_buffer (&agent_buffer, agent);
        }

      append_ip_rows_to_buffer (&ip_buffer, agent->agent_id,
                                agent->ip_addresses);
    }

  if (db_copy_buffer_commit (&agent_buffer, TRUE))
    {
      g_warning ("%s: COPY for agents failed", __func__);
      status = -1;
    }

  if (status == 0)
    {
      if (db_copy_buffer_commit (&ip_buffer, TRUE))
        {
          g_warning ("%s: COPY for agent_ip_addresses failed", __func__);
          status = -1;
        }
    }

  if (status != 0)
    sql_rollback ();
  else
    sql_commit ();

  db_copy_buffer_cleanup (&agent_buffer);
  db_copy_buffer_cleanup (&ip_buffer);

  return status;
}

/**
 * @brief Initialize SQL-based agent iterator with filtering support.
 *
 * @param[out] iterator Pointer to the iterator to initialize.
 * @param[in]  get      Get parameters containing filtering criteria (e.g.,
 * agent ID).
 *
 * @return 0 on success, -1 on failure.
 */
int
init_agent_iterator (iterator_t *iterator, get_data_t *get)
{
  g_return_val_if_fail (iterator, -1);
  g_return_val_if_fail (get, -1);

  static column_t columns[] = AGENT_ITERATOR_COLUMNS;
  static const char *filter_columns[] = AGENT_ITERATOR_FILTER_COLUMNS;

  gchar *quoted = NULL;
  gchar *where_clause = NULL;

  if (get->id)
    {
      quoted = sql_quote (get->id);
      where_clause = g_strdup_printf ("agent_id = '%s'", quoted);
    }

  int ret = init_get_iterator (iterator, "agent", get, columns,
                               NULL, // no trash columns
                               filter_columns,
                               0,    // no trashcan
                               NULL, // no joins
                               where_clause, 0);

  g_free (where_clause);
  g_free (quoted);

  return ret;
}

/**
 * @brief Initialize an agent iterator for a specific scanner and list of agent
 * UUIDs.
 *
 * @param[out] iterator  Pointer to the iterator to initialize.
 * @param[in] uuid_list List of agent UUIDs to include in the iteration.
 */
void
init_agent_uuid_list_iterator (iterator_t *iterator,
                               agent_uuid_list_t uuid_list)
{
  get_data_t get;
  memset (&get, 0, sizeof (get));
  get.type = "agent";
  get.ignore_pagination = 1;
  get.ignore_max_rows_per_page = 1;

  GString *where_clause = g_string_new (NULL);

  // Add UUID conditions if any
  if (uuid_list && uuid_list->count > 0)
    {
      g_string_append (where_clause, " AND uuid IN (");
      for (int i = 0; i < uuid_list->count; ++i)
        {
          gchar *quoted_uuid = sql_quote (uuid_list->agent_uuids[i]);
          g_string_append_printf (where_clause, "'%s'%s", quoted_uuid,
                                  (i < uuid_list->count - 1) ? ", " : "");
          g_free (quoted_uuid);
        }
      g_string_append (where_clause, ")");
    }
  static column_t columns[] = AGENT_ITERATOR_COLUMNS;
  static const char *filter_columns[] = AGENT_ITERATOR_FILTER_COLUMNS;
  init_get_iterator (iterator, "agent", &get, columns,
                     NULL, // no trash columns
                     filter_columns,
                     0,    // no trashcan
                     NULL, // no joins
                     where_clause->str, 0);

  g_string_free (where_clause, TRUE);
}

/**
 * @brief Load all IP addresses associated with a given agent.
 *
 * @param[in] agent_id ID of the agent.
 *
 * @return List of IP addresses associated with the agent.
 */
agent_ip_data_list_t
load_agent_ip_addresses (const char *agent_id)
{
  g_return_val_if_fail (agent_id, NULL);

  gchar *inserted_agent_id = sql_insert (agent_id);
  gchar *count_query = g_strdup_printf (
    "SELECT COUNT(*) FROM agent_ip_addresses WHERE agent_id = %s;",
    inserted_agent_id);
  int count = sql_int (count_query);
  g_free (count_query);

  if (count <= 0)
    return NULL;

  agent_ip_data_list_t list = agent_ip_data_list_new (count);
  if (!list)
    return NULL;

  iterator_t ip_iterator;

  init_iterator (
    &ip_iterator,
    "SELECT ip_address FROM agent_ip_addresses WHERE agent_id = %s;",
    inserted_agent_id);

  int index = 0;
  while (next (&ip_iterator) && index < count)
    {
      const char *ip_str = iterator_string (&ip_iterator, 0);
      if (!ip_str)
        continue;

      list->items[index] = g_malloc0 (sizeof (struct agent_ip_data));
      list->items[index]->ip_address = g_strdup (ip_str);
      index++;
    }

  cleanup_iterator (&ip_iterator);
  return list;
}

/**
 * @brief Retrieve agent_id from iterator.
 */
const char *
agent_iterator_agent_id (iterator_t *iterator)
{
  return iterator_string (iterator, GET_ITERATOR_COLUMN_COUNT);
}

/**
 * @brief Retrieve hostname of current agent.
 */
const char *
agent_iterator_hostname (iterator_t *iterator)
{
  return iterator_string (iterator, GET_ITERATOR_COLUMN_COUNT + 1);
}

/**
 * @brief Retrieve authorization status of current agent.
 */
int
agent_iterator_authorized (iterator_t *iterator)
{
  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 2);
}

/**
 * @brief Retrieve connection status string of current agent.
 */
const char *
agent_iterator_connection_status (iterator_t *iterator)
{
  return iterator_string (iterator, GET_ITERATOR_COLUMN_COUNT + 3);
}

/**
 * @brief Retrieve last update timestamp of current agent.
 */
time_t
agent_iterator_last_update (iterator_t *iterator)
{
  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 4);
}

/**
 * @brief Retrieve last update timestamp of current agent.
 */
time_t
agent_iterator_last_updater_heartbeat (iterator_t *iterator)
{
  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 5);
}

/**
 * @brief Retrieve config string of current agent.
 */
const char *
agent_iterator_config (iterator_t *iterator)
{
  return iterator_string (iterator, GET_ITERATOR_COLUMN_COUNT + 6);
}

/**
 * @brief Retrieve scanner ID of current agent.
 */
scanner_t
agent_iterator_scanner (iterator_t *iterator)
{
  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 7);
}

/**
 * @brief Retrieve updater version of current agent.
 */
const char *
agent_iterator_updater_version (iterator_t *iterator)
{
  return iterator_string (iterator, GET_ITERATOR_COLUMN_COUNT + 8);
}

/**
 * @brief Retrieve agent version of current agent.
 */
const char *
agent_iterator_agent_version (iterator_t *iterator)
{
  return iterator_string (iterator, GET_ITERATOR_COLUMN_COUNT + 9);
}

/**
 * @brief Retrieve operating system of current agent.
 */
const char *
agent_iterator_operating_system (iterator_t *iterator)
{
  return iterator_string (iterator, GET_ITERATOR_COLUMN_COUNT + 10);
}

/**
 * @brief Retrieve architecture system of current agent.
 */
const char *
agent_iterator_architecture (iterator_t *iterator)
{
  return iterator_string (iterator, GET_ITERATOR_COLUMN_COUNT + 11);
}

/**
 * @brief Retrieve latest update status of current agent.
 */
int
agent_iterator_update_to_latest (iterator_t *iterator)
{
  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 12);
}

/**
 * @brief Count number of agents in the database based on filter.
 *
 * @param get GET parameters to use for filtering.
 * @return Count of matching agents.
 */
int
agent_count (const get_data_t *get)
{
  static const char *extra_columns[] = AGENT_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = AGENT_ITERATOR_COLUMNS;

  return count ("agent", get, columns, NULL, extra_columns, 0, 0, 0, TRUE);
}

/**
 * @brief Check if an agent is writable.
 *
 * @param agent Resource identifier.
 * @return Always returns 1 (writable).
 */
int
agent_writable (agent_t agent)
{
  (void) agent;
  return 1;
}

/**
 * @brief Check if an agent is currently in use.
 *
 * @param agent Resource identifier.
 * @return 1 if the agent is in use, 0 otherwise.
 */
int
agent_in_use (agent_t agent)
{
  return !!sql_int (
    "WITH usage_counts AS ("
    "  SELECT COUNT(*) AS count FROM agent_group_agents WHERE agent_id = %llu"
    "  UNION ALL "
    "  SELECT COUNT(*) AS count FROM agent_group_agents_trash WHERE agent = "
    "%llu"
    ") "
    "SELECT SUM(count) FROM usage_counts;",
    agent, agent);
}

/**
 * @brief Delete agents and associated IPs using a filtered UUID list.
 *
 * Deletes agents from the database and their associated IPs.
 * If @p agent_uuids is provided and non-empty, only those agents will be
 * deleted. If @p agent_uuids is NULL or empty, and @p scanner is non-zero,
 * deletes all agents associated with that scanner.
 *
 * @param[in] scanner     Optional scanner filter (0 to ignore).
 * @param[in] agent_uuids List of agent UUIDs to delete.
 */
void
delete_agents_by_scanner_and_uuids (scanner_t scanner,
                                    agent_uuid_list_t agent_uuids)
{
  GString *where_clause = g_string_new ("WHERE 1=1");

  if (agent_uuids && agent_uuids->count > 0)
    {
      g_string_append (where_clause, " AND uuid IN (");

      for (int i = 0; i < agent_uuids->count; ++i)
        {
          if (i > 0)
            g_string_append (where_clause, ", ");
          g_string_append_printf (where_clause, "'%s'",
                                  agent_uuids->agent_uuids[i]);
        }

      g_string_append (where_clause, ")");
    }

  if (scanner != 0)
    {
      g_string_append_printf (where_clause, " AND scanner = %lld", scanner);
    }

  sql_begin_immediate ();

  // Delete associated IPs
  sql ("DELETE FROM agent_ip_addresses "
       "WHERE agent_id IN (SELECT agent_id FROM agents %s);",
       where_clause->str);

  // Delete agents
  sql ("DELETE FROM agents %s;", where_clause->str);

  sql_commit ();

  g_string_free (where_clause, TRUE);
}

/**
 * @brief Update comment field for a set of agents.
 *
 * @param[in] agent_uuids  List of agent UUIDs to update.
 * @param[in] new_comment  New comment to set.
 */
void
update_agents_comment (agent_uuid_list_t agent_uuids, const gchar *new_comment)
{
  if (!agent_uuids || agent_uuids->count == 0 || !new_comment)
    return;

  GString *uuid_list = g_string_new (NULL);

  for (int i = 0; i < agent_uuids->count; ++i)
    {
      if (i > 0)
        g_string_append (uuid_list, ", ");
      g_string_append_printf (uuid_list, "'%s'", agent_uuids->agent_uuids[i]);
    }

  sql_begin_immediate ();

  sql ("UPDATE agents SET comment = '%s' WHERE uuid IN (%s);", new_comment,
       uuid_list->str);

  sql_commit ();

  g_string_free (uuid_list, TRUE);
}

/**
 * @brief Retrieve the internal row ID of an agent by its UUID and scanner ID.
 *
 * @param[in]  agent_uuid   The UUID of the agent.
 * @param[in]  scanner_id   The expected scanner row ID.
 * @param[out] agent_id_out Pointer to store the resolved agent ID.
 *
 * @return 0 if success,
 *         1 if agent not found,
 *         2 if scanner mismatch.
 */
int
agent_id_by_uuid_and_scanner (const gchar *agent_uuid, scanner_t scanner_id,
                              agent_t *agent_id_out)
{
  g_return_val_if_fail (agent_uuid != NULL, 1);
  g_return_val_if_fail (agent_id_out != NULL, 1);

  // Get the agent ID with matching scanner
  agent_t agent_id =
    sql_int64_0 ("SELECT id FROM agents WHERE uuid = '%s' AND scanner = %llu;",
                 agent_uuid, scanner_id);

  if (agent_id != 0)
    {
      *agent_id_out = agent_id;
      return 0; // success
    }

  // Check if agent exists but scanner doesn't match
  agent_id =
    sql_int64_0 ("SELECT id FROM agents WHERE uuid = '%s';", agent_uuid);

  if (agent_id != 0)
    return 2; // scanner mismatch

  return 1; // agent not found
}

/**
 * @brief Check if any agent in the UUID list is currently in use.
 *
 * @param[in] agent_uuids List of agent UUIDs to check.
 *
 * @return TRUE if any agent is in use, FALSE otherwise.
 */
gboolean
agents_in_use (agent_uuid_list_t agent_uuids)
{
  if (!agent_uuids || agent_uuids->count == 0)
    return FALSE;

  GString *uuid_filter = g_string_new ("");

  for (int i = 0; i < agent_uuids->count; ++i)
    {
      if (i > 0)
        g_string_append (uuid_filter, ", ");
      g_string_append_printf (uuid_filter, "'%s'", agent_uuids->agent_uuids[i]);
    }

  int count = sql_int ("WITH matching_agents AS ("
                       "  SELECT id FROM agents WHERE uuid IN (%s)"
                       ") "
                       "SELECT COUNT(*) FROM ("
                       "  SELECT agent_id AS id FROM agent_group_agents"
                       "  WHERE agent_id IN (SELECT id FROM matching_agents)"
                       "  UNION ALL "
                       "  SELECT agent AS id FROM agent_group_agents_trash"
                       "  WHERE agent IN (SELECT id FROM matching_agents)"
                       ") AS used_agents;",
                       uuid_filter->str);

  g_string_free (uuid_filter, TRUE);

  return count > 0 ? TRUE : FALSE;
}

#endif // ENABLE_AGENTS