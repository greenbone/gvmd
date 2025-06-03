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
 * @param agent_id Agent identifier whose IPs will be removed.
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
 * @brief Check whether an agent already exists in the database.
 *
 * @param agent_id Agent identifier to search.
 * @return 1 if exists, 0 if not, -1 on error.
 */
static int
agent_exists (const gchar *agent_id)
{
  gchar *insert_agent_id = sql_insert (agent_id);
  int result = sql_int (
    "SELECT COUNT(*) FROM agents WHERE agent_id = %s;",
    insert_agent_id);
  g_free (insert_agent_id);
  return result < 0 ? -1 : (result > 0);
}

/**
 * @brief Update an existing agent record in the database.
 *
 * @param agent Pointer to the agent data to update.
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
 * @param buffer COPY buffer for agents.
 * @param agent  Agent whose data will be appended.
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
 * @param buffer   COPY buffer for agent IPs.
 * @param agent_id ID of the agent.
 * @param ip_list  List of IP addresses to append.
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
 * @brief Add an IP data entry to an agent_ip_data_list.
 *
 * @param list     Target IP list.
 * @param ip_data  IP data to append.
 */
static void
agent_ip_data_list_add (agent_ip_data_list_t list, agent_ip_data_t ip_data)
{
  g_return_if_fail (list);

  list->items = g_realloc (list->items, (list->count + 1) * sizeof (agent_ip_data_t));
  list->items[list->count++] = ip_data;
}

/**
 * @brief Synchronize agent data list into the SQL database.
 *
 * Performs UPSERT logic: existing agents are updated, new agents
 * and all IPs are inserted via COPY.
 *
 * @param agent_list List of agents to sync.
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

      gboolean exists = agent_exists(agent->agent_id);

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
 * @param iterator Pointer to iterator to initialize.
 * @param get      Get parameters to construct SQL WHERE clause.
 * @return 0 on success, -1 on failure.
 */
int
init_agent_iterator (iterator_t *iterator, get_data_t *get)
{
  g_return_val_if_fail (iterator, -1);
  g_return_val_if_fail (get, -1);

  static column_t columns[] = AGENT_ITERATOR_COLUMNS;
  static const char *filter_columns[] = AGENT_ITERATOR_FILTER_COLUMNS;

  g_autofree gchar *id_clause = NULL;
  g_autofree gchar *full_clause = NULL;

  if (get->id)
    {
      g_autofree gchar *quoted = sql_quote (get->id);
      id_clause = g_strdup_printf ("agent_id = '%s'", quoted);
    }

  if (id_clause)
    {
      full_clause = g_strdup (id_clause);
    }

  int ret = init_get_iterator (iterator,
                               "agent",
                               get,
                               columns,
                               NULL,              // no trash columns
                               filter_columns,
                               0,                 // no trashcan
                               NULL,              // no joins
                               full_clause,
                               0);

  return ret;
}

/**
 * @brief Initialize a raw agent iterator with a custom WHERE clause.
 *
 * @param iterator Pointer to iterator to initialize.
 * @param clause   Custom SQL WHERE clause.
 */
void
init_custom_agent_iterator (iterator_t *iterator, const gchar *clause)
{
  init_iterator (
   iterator,
   "SELECT id, uuid, name, comment, creation_time, modification_time, "
   "creation_time AS created, modification_time AS modified, "
   "id, name, agent_id, hostname, authorized, min_interval, heartbeat_interval, "
   "connection_status, last_update, schedule, comment, creation_time, "
   "modification_time, uuid, scanner, owner "
   "FROM agents WHERE %s",
   clause);
}

/**
 * @brief Load all IP addresses associated with a given agent.
 *
 * @param agent_id ID of the agent.
 * @return List of IP addresses associated with the agent.
 */
agent_ip_data_list_t
load_agent_ip_addresses (const char *agent_id)
{
  g_return_val_if_fail (agent_id, NULL);

  agent_ip_data_list_t list = g_malloc0 (sizeof (struct agent_ip_data_list));
  list->count = 0;
  list->items = NULL;  // Start empty

  iterator_t ip_iterator;

  init_iterator (&ip_iterator,
                 "SELECT ip_address FROM agent_ip_addresses WHERE agent_id = '%s';",
                 agent_id);

  while (next (&ip_iterator))
    {
      const char *ip_str = iterator_string (&ip_iterator, 0);
      if (!ip_str)
        continue;

      agent_ip_data_t ip_data = g_malloc0 (sizeof (struct agent_ip_data));
      ip_data->ip_address = g_strdup (ip_str);

      agent_ip_data_list_add (list, ip_data);
    }

  cleanup_iterator (&ip_iterator);
  return list;
}

/**
 * @brief Retrieve UUID of current row from agent iterator.
 */
const char *
agent_iterator_uuid (iterator_t *iterator)
{
  return iterator_string (iterator, 1);
}

/**
 * @brief Retrieve name of current agent.
 */
const char *
agent_iterator_name (iterator_t *iterator)
{
  return iterator_string (iterator, 2);
}

/**
 * @brief Retrieve agent_id from iterator.
 */
const char *
agent_iterator_agent_id (iterator_t *iterator)
{
  return iterator_string (iterator, 10);
}

/**
 * @brief Retrieve scanner ID of current agent.
 */
scanner_t
agent_iterator_scanner (iterator_t *iterator)
{
  return iterator_int (iterator, 22);
}

/**
 * @brief Retrieve hostname of current agent.
 */
const char *
agent_iterator_hostname (iterator_t *iterator)
{
  return iterator_string (iterator, 11);
}

/**
 * @brief Retrieve authorization status of current agent.
 */
int
agent_iterator_authorized (iterator_t *iterator)
{
  return iterator_int (iterator, 12);
}

/**
 * @brief Retrieve min_interval of current agent.
 */
int
agent_iterator_min_interval (iterator_t *iterator)
{
  return iterator_int (iterator, 13);
}

/**
 * @brief Retrieve heartbeat_interval of current agent.
 */
int
agent_iterator_heartbeat_interval (iterator_t *iterator)
{
  return iterator_int (iterator, 14);
}

/**
 * @brief Retrieve connection status string of current agent.
 */
const char *
agent_iterator_connection_status (iterator_t *iterator)
{
  return iterator_string (iterator, 15);
}

/**
 * @brief Retrieve last update timestamp of current agent.
 */
time_t
agent_iterator_last_update (iterator_t *iterator)
{
  return iterator_int (iterator, 16);
}

/**
 * @brief Retrieve schedule string of current agent.
 */
const char *
agent_iterator_schedule (iterator_t *iterator)
{
  return iterator_string (iterator, 17);
}

/**
 * @brief Retrieve owner of the agent.
 */
user_t
agent_iterator_owner (iterator_t *iterator)
{
  return iterator_int (iterator, 23);
}

/**
 * @brief Retrieve comment field of the agent.
 */
const char *
agent_iterator_comment (iterator_t *iterator)
{
  return iterator_string (iterator, 3);
}

/**
 * @brief Retrieve creation timestamp of the agent.
 */
time_t
agent_iterator_creation_time (iterator_t *iterator)
{
  return iterator_int (iterator, 4);
}

/**
 * @brief Retrieve modification timestamp of the agent.
 */
time_t
agent_iterator_modification_time (iterator_t *iterator)
{
  return iterator_int (iterator, 7);
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
 * Optionally filters by scanner. Uses SQL transactions.
 *
 * @param agent_uuids List of agent UUIDs to delete.
 * @param scanner     Optional scanner filter (0 to ignore).
 */
void
delete_agents_filtered (agent_uuid_list_t agent_uuids, scanner_t scanner)
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
 * @param agent_uuids  List of agent UUIDs to update.
 * @param new_comment  New comment to set.
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

#endif // ENABLE_AGENTS