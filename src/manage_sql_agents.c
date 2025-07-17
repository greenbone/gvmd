/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file manage_sql_agents.c
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
   sql ("DELETE FROM agent_ip_addresses WHERE agent_id = %s;",
                  insert_agent_id);
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
  gchar *query = g_strdup_printf (
    "SELECT COUNT(*) FROM agents WHERE %s = %s;", column_name, insert_value);

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
   gchar *insert_hostname = sql_insert (agent->hostname);
   gchar *insert_connection_status = sql_insert (agent->connection_status);
   gchar *insert_schedule = sql_insert (agent->schedule);
   gchar *insert_agent_id = sql_insert (agent->agent_id);

   sql ("UPDATE agents SET hostname = %s, authorized = %d, min_interval = %d,"
        " heartbeat_interval = %d, connection_status = %s, last_update = %ld,"
        " schedule = %s, owner = %u, modification_time = %ld, scanner = %llu "
        " WHERE agent_id = %s;",
        insert_hostname,
        agent->authorized,
        agent->min_interval,
        agent->heartbeat_interval,
        insert_connection_status,
        agent->last_update_agent_control,
        insert_schedule,
        agent->owner,
        agent->modification_time,
        agent->scanner,
        insert_agent_id);

  g_free (insert_hostname);
  g_free (insert_connection_status);
  g_free (insert_schedule);
  g_free (insert_agent_id);
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
   gchar *escaped_hostname =  sql_copy_escape (agent->hostname);
   gchar *escaped_connection_status =  sql_copy_escape (agent->connection_status);
   gchar *escaped_schedule =  sql_copy_escape (agent->schedule);
   gchar *escaped_comment =  sql_copy_escape ("");

  db_copy_buffer_append_printf (
    buffer,
    "%s\t%s\t%s\t%s\t%d\t%d\t%d\t%s\t%ld\t%s\t%u\t%s\t%ld\t%ld\t%llu\n",
    agent->uuid,
    agent->name,
    agent->agent_id,
    escaped_hostname,
    agent->authorized,
    agent->min_interval,
    agent->heartbeat_interval,
    escaped_connection_status,
    agent->last_update_agent_control,
    escaped_schedule,
    agent->owner,
    escaped_comment,
    time (NULL),     // creation time
    agent->modification_time,
    agent->scanner
  );

  g_free (escaped_hostname);
  g_free (escaped_connection_status);
  g_free (escaped_schedule);
  g_free (escaped_comment);
}

/**
 * @brief Append all IPs of an agent to a COPY buffer.
 *
 * @param[out] buffer   COPY buffer for agent IPs.
 * @param[in] agent_id ID of the agent.
 * @param[in] ip_list  List of IP addresses to append.
 */
static void
append_ip_rows_to_buffer (db_copy_buffer_t *buffer,
                          const gchar *agent_id,
                          agent_ip_data_list_t ip_list)
{
  if (!ip_list) return;

  gchar *escaped_agent_id =  sql_copy_escape (agent_id);

  for (int j = 0; j < ip_list->count; ++j)
    {
      agent_ip_data_t ip = ip_list->items[j];
      gchar *escaped_ip_address =  sql_copy_escape (ip->ip_address);

      db_copy_buffer_append_printf (
        buffer,
        "%s\t%s\n",
        escaped_agent_id,
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
      g_warning ("%s: Failed to check if agent UUID '%s' exists (DB error)", __func__, agent_uuid);
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
  *scanner = sql_int ("SELECT scanner FROM agents WHERE uuid = %s;", insert_agent_uuid);
  g_free (insert_agent_uuid);

  if (*scanner <= 0)
    {
      g_warning ("%s: Failed to find scanner for agent UUID %s", __func__, agent_uuid);
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

  db_copy_buffer_t agent_buffer = { 0 };
  db_copy_buffer_t ip_buffer = { 0 };
  int status = 0;

  db_copy_buffer_init (
    &agent_buffer,
    64 * 1024,
    "COPY agents (uuid, name, agent_id, hostname, authorized, min_interval, heartbeat_interval,"
    " connection_status, last_update, schedule, owner, comment, creation_time,"
    " modification_time, scanner) FROM STDIN;"
  );


  db_copy_buffer_init (
    &ip_buffer,
    32 * 1024,
    "COPY agent_ip_addresses (agent_id, ip_address) FROM STDIN;"
  );

  sql_begin_immediate ();

  for (int i = 0; i < agent_list->count; ++i)
    {
      agent_data_t agent = agent_list->agents[i];

      gboolean exists = agent_column_exists ("agent_id", agent->agent_id);

      if (exists)
        {
          update_existing_agent(agent);
          delete_existing_agent_ips(agent->agent_id);
        }
      else
        {
          append_agent_row_to_buffer (&agent_buffer, agent);
        }

      append_ip_rows_to_buffer (&ip_buffer, agent->agent_id, agent->ip_addresses);
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
 * @param[in]  get      Get parameters containing filtering criteria (e.g., agent ID).
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

  int ret = init_get_iterator (iterator,
                               "agent",
                               get,
                               columns,
                               NULL,              // no trash columns
                               filter_columns,
                               0,                 // no trashcan
                               NULL,              // no joins
                               where_clause,
                               0);

  g_free (where_clause);
  g_free (quoted);

  return ret;
}

/**
 * @brief Initialize an agent iterator for a specific scanner and list of agent UUIDs.
 *
 * @param[out] iterator  Pointer to the iterator to initialize.
 * @param[in] uuid_list List of agent UUIDs to include in the iteration.
 */
void
init_agent_uuid_list_iterator (iterator_t *iterator,
                               agent_uuid_list_t uuid_list)
{
  get_data_t get;
  memset(&get, 0, sizeof(get));
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
          g_string_append_printf (where_clause, "'%s'%s",
                                  quoted_uuid,
                                  (i < uuid_list->count - 1) ? ", " : "");
          g_free (quoted_uuid);
        }
      g_string_append (where_clause, ")");
    }
  static column_t columns[] = AGENT_ITERATOR_COLUMNS;
  static const char *filter_columns[] = AGENT_ITERATOR_FILTER_COLUMNS;
  init_get_iterator (iterator,
                     "agent",
                     &get,
                     columns,
                     NULL,              // no trash columns
                     filter_columns,
                     0,                 // no trashcan
                     NULL,              // no joins
                     where_clause->str,
                     0);

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

  init_iterator (&ip_iterator,
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
 * @brief Retrieve min_interval of current agent.
 */
int
agent_iterator_min_interval (iterator_t *iterator)
{
  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 3);
}

/**
 * @brief Retrieve heartbeat_interval of current agent.
 */
int
agent_iterator_heartbeat_interval (iterator_t *iterator)
{
  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 4);
}

/**
 * @brief Retrieve connection status string of current agent.
 */
const char *
agent_iterator_connection_status (iterator_t *iterator)
{
  return iterator_string (iterator, GET_ITERATOR_COLUMN_COUNT + 5);
}

/**
 * @brief Retrieve last update timestamp of current agent.
 */
time_t
agent_iterator_last_update (iterator_t *iterator)
{
  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 6);
}

/**
 * @brief Retrieve schedule string of current agent.
 */
const char *
agent_iterator_schedule (iterator_t *iterator)
{
  return iterator_string (iterator, GET_ITERATOR_COLUMN_COUNT + 7);
}

/**
 * @brief Retrieve scanner ID of current agent.
 */
scanner_t
agent_iterator_scanner (iterator_t *iterator)
{
  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 8);
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

  return count ("agent", get, columns, NULL, extra_columns,
                0, 0, 0, TRUE);
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
  (void)agent;
  return 1;
}

/**
 * @brief Check if an agent is currently in use.
 *
 * @param agent Resource identifier.
 * @return Always returns 0 (not in use).
 */
int
agent_in_use (agent_t agent)
{
  (void)agent;
  return 0;
}

/**
 * @brief Delete agents and associated IPs using a filtered UUID list.
 *
 * Deletes agents from the database and their associated IPs.
 * If @p agent_uuids is provided and non-empty, only those agents will be deleted.
 * If @p agent_uuids is NULL or empty, and @p scanner is non-zero,
 * deletes all agents associated with that scanner.
 *
 * @param[in] scanner     Optional scanner filter (0 to ignore).
 * @param[in] agent_uuids List of agent UUIDs to delete.
 */
void
delete_agents_by_scanner_and_uuids (scanner_t scanner, agent_uuid_list_t agent_uuids)
{
  GString *where_clause = g_string_new ("WHERE 1=1");

  if (agent_uuids && agent_uuids->count > 0)
    {
      g_string_append (where_clause, " AND uuid IN (");

      for (int i = 0; i < agent_uuids->count; ++i)
        {
          if (i > 0)
            g_string_append (where_clause, ", ");
          g_string_append_printf (where_clause, "'%s'", agent_uuids->agent_uuids[i]);
        }

      g_string_append (where_clause, ")");
    }

  if (scanner != 0)
    {
      g_string_append_printf (where_clause, " AND scanner = %lld", scanner);
    }

  sql_begin_immediate ();

  // Delete associated IPs
  sql (
    "DELETE FROM agent_ip_addresses "
    "WHERE agent_id IN (SELECT agent_id FROM agents %s);",
    where_clause->str);

  // Delete agents
  sql (
    "DELETE FROM agents %s;",
    where_clause->str);

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

  sql (
    "UPDATE agents SET comment = '%s' WHERE uuid IN (%s);",
    new_comment,
    uuid_list->str);

  sql_commit ();

  g_string_free (uuid_list, TRUE);
}

/**
 * @brief Retrieve the internal row ID of an agent by its UUID and scanner ID.
 *
 * @param[in]  agent_uuid   The UUID of the agent.
 * @param[in]  scanner_id   The scanner row ID.
 *
 * @return The row ID of the agent if found and associated with the scanner,
 *         otherwise returns 0.
 */
agent_t
agent_id_by_uuid_and_scanner (const gchar *agent_uuid, scanner_t scanner_id)
{
  g_return_val_if_fail (agent_uuid != NULL, 0);

  return sql_int64_0 (
    "SELECT id FROM agents WHERE uuid = '%s' AND scanner = %llu;",
    agent_uuid, scanner_id);
}

#endif // ENABLE_AGENTS