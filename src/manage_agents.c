/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file manage_agents.c
 * @brief Agent management implementation for GVMD.
 *
 * This file contains the logic for synchronizing, modifying, and deleting agents
 * between GVMD and the Agent Controller. It provides utility functions to convert
 * between GVMD agent structures and agent controller representations, as well as
 * helpers for filtering, iteration, and connector setup.
 */

#if ENABLE_AGENTS
#include "manage_agents.h"
#include "manage_sql_agents.h"

#include <assert.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Convert agent controller list to GVMD agent data list.
 *
 * Copies agent metadata from the agent controller representation to GVMD's
 * internal format for further processing or persistence.
 *
 * @param list     List of agents from the agent controller.
 * @param scanner  Scanner ID associated with these agents.
 * @return Newly allocated agent_data_list_t or NULL on failure.
 */
static agent_data_list_t
convert_agent_control_list_to_agent_data_list (agent_controller_agent_list_t list,
                                               scanner_t scanner)
{
  if (!list || list->count == 0)
    return NULL;

  agent_data_list_t result = g_malloc0 (sizeof (struct agent_data_list));
  result->count = list->count;
  result->agents = g_malloc0 (sizeof (agent_data_t) * list->count);
  char *owner_uuid = NULL;
  user_t owner = 0;
  setting_value (SETTING_UUID_AGENT_OWNER, &owner_uuid);
  if (owner_uuid == NULL)
    {
      g_warning ("%s: Failed to retrieve owner UUID from settings (SETTING_UUID_AGENT_OWNER is NULL)", __func__);
      agent_data_list_free (result);
      return NULL;
    }

  find_resource_no_acl ("user", owner_uuid, &owner);

  if (owner == 0)
    {
      g_warning ("%s: Failed to find user resource with UUID '%s'", __func__, owner_uuid);
      return NULL;
    }

  for (int i = 0; i < list->count; ++i)
    {
      agent_controller_agent_t src = list->agents[i];
      agent_data_t dest = g_malloc0 (sizeof (struct agent_data));

      dest->agent_id = g_strdup (src->agent_id);
      dest->hostname = g_strdup (src->hostname);
      dest->authorized = src->authorized;
      dest->min_interval = src->min_interval;
      dest->heartbeat_interval = src->heartbeat_interval;
      dest->connection_status = g_strdup (src->connection_status);
      dest->last_update_agent_control = src->last_update;

      if (src->schedule_config && src->schedule_config->schedule)
        dest->schedule = g_strdup (src->schedule_config->schedule);
      else
        dest->schedule = g_strdup ("");

      dest->scanner = scanner;

      // Initialize and copy IP addresses
      if (src->ip_address_count > 0 && src->ip_addresses)
        {
          dest->ip_addresses = g_malloc0 (sizeof (struct agent_ip_data_list));
          dest->ip_addresses->count = src->ip_address_count;
          dest->ip_addresses->items = g_malloc0 (sizeof (agent_ip_data_t) * src->ip_address_count);

          for (int j = 0; j < src->ip_address_count; ++j)
            {
              if (!src->ip_addresses[j])
                continue;

              dest->ip_addresses->items[j] = g_malloc0 (sizeof (struct agent_ip_data));
              dest->ip_addresses->items[j]->ip_address = g_strdup (src->ip_addresses[j]);
            }
        }
      else
        {
          dest->ip_addresses = NULL;
        }

      dest->owner = owner;
      dest->modification_time = time (NULL);
      dest->name = g_strdup (src->agent_id);
      dest->comment = g_strdup ("");
      result->agents[i] = dest;
    }

  return result;
}

/**
 * @brief Convert GVMD agent data list to agent controller format.
 *
 * Transforms internal GVMD agent records into a format understood
 * by the agent controller for update or deletion operations.
 *
 * @param list  List of GVMD agent_data_t.
 * @return Newly allocated agent_controller_agent_list_t or NULL.
 */
static agent_controller_agent_list_t
convert_agent_data_list_to_agent_control_list (agent_data_list_t list)
{
  if (!list || list->count == 0)
    return NULL;

  agent_controller_agent_list_t result = agent_controller_agent_list_new (list->count);

  for (int i = 0; i < list->count; ++i)
    {
      agent_data_t src = list->agents[i];
      agent_controller_agent_t dest = agent_controller_agent_new ();

      dest->agent_id = g_strdup (src->agent_id);
      dest->hostname = g_strdup (src->hostname);
      dest->authorized = src->authorized;
      dest->min_interval = src->min_interval;
      dest->heartbeat_interval = src->heartbeat_interval;
      dest->connection_status = g_strdup (src->connection_status);
      dest->last_update = src->last_update_agent_control;

      // Schedule config
      if (src->schedule && strlen (src->schedule) > 0)
        {
          dest->schedule_config = agent_controller_config_schedule_new ();
          dest->schedule_config->schedule = g_strdup (src->schedule);
        }

      // IP addresses
      if (src->ip_addresses && src->ip_addresses->count > 0)
        {
          dest->ip_address_count = src->ip_addresses->count;
          dest->ip_addresses = g_malloc0 (sizeof (char *) * dest->ip_address_count);

          for (int j = 0; j < dest->ip_address_count; ++j)
            {
              dest->ip_addresses[j] = g_strdup (src->ip_addresses->items[j]->ip_address);
            }
        }

      result->agents[i] = dest;
    }

  return result;
}

/**
 * @brief Resolve a scanner_t from a UUID string.
 *
 * Validates and fetches the scanner ID that matches the given UUID,
 * ensuring proper permissions.
 *
 * @param scanner_uuid  UUID of the scanner as a string.
 * @return Scanner ID, or 0/-1 on failure.
 */
static scanner_t
get_scanner_from_uuid(const gchar *scanner_uuid)
{
  scanner_t scanner = 0;

  if (!scanner_uuid)
    {
      g_warning ("%s: Scanner UUID is required but missing", __func__);
      manage_option_cleanup ();
      return -1;
    }

  if (find_scanner_with_permission (scanner_uuid, &scanner, "get_scanners"))
    {
      g_warning ("%s: Failed to find scanner with UUID %s", __func__, scanner_uuid);
      manage_option_cleanup ();
      return -1;
    }

  return scanner;
}

/**
 * @brief Retrieve agent controller agents from GVMD UUIDs.
 *
 * Filters and converts a list of agent UUIDs to agent controller format.
 *
 * @param scanner       Scanner ID used for filtering.
 * @param agent_uuids   List of agent UUIDs.
 * @return agent_controller_agent_list_t or NULL on failure.
 */
static agent_controller_agent_list_t
get_agent_controller_agents_from_uuid (scanner_t scanner,
                                       agent_uuid_list_t agent_uuids)
{
  if (!scanner || !agent_uuids )
    {
      g_warning ("%s: Invalid parameters", __func__);
      return NULL;
    }

  agent_data_list_t agent_data_list = get_filtered_agents (scanner, agent_uuids);
  if (agent_data_list->count == 0)
    {
      g_warning ("%s: No matching agents found for scanner", __func__);
      agent_data_list_free (agent_data_list);
      manage_option_cleanup ();
      return NULL;
    }

  agent_controller_agent_list_t agent_control_list =
    convert_agent_data_list_to_agent_control_list (agent_data_list);

  if (!agent_control_list || agent_control_list->count == 0)
    {
      g_warning ("%s: Failed to convert agent data list to controller format", __func__);
      agent_data_list_free (agent_data_list);
      agent_controller_agent_list_free (agent_control_list);
      manage_option_cleanup ();
      return NULL;
    }
  agent_data_list_free (agent_data_list);

  return agent_control_list;
}

/**
 * @brief Initialize a new GVMD agent connector from a scanner.
 *
 * Builds and configures a connection to the agent controller using
 * scanner information.
 *
 * @param scanner  Scanner ID used to resolve connection info.
 * @return Allocated gvmd_agent_connector_t or NULL on failure.
 */
gvmd_agent_connector_t
gvmd_agent_connector_new_from_scanner (scanner_t scanner)
{
  assert (scanner);

  gboolean has_relay = scanner_has_relay (scanner);
  char *host = scanner_host (scanner, has_relay);
  int port = scanner_port (scanner, has_relay);
  char *ca_cert = scanner_ca_pub (scanner);
  char *cert = scanner_key_pub (scanner);
  char *key = scanner_key_priv (scanner);

  if (!host || port <= 0)
    {
      g_warning ("%s: Invalid scanner host or port", __func__);
      g_free (host);
      g_free (ca_cert);
      g_free (cert);
      g_free (key);
      return NULL;
    }

  const char *protocol = "https";
  if (!ca_cert || !cert)
    {
      g_debug ("%s: Falling back to HTTP due to missing CA or cert", __func__);
      protocol = "http";
    }

  gvmd_agent_connector_t conn = g_malloc0 (sizeof (struct gvmd_agent_connector));
  conn->base = agent_controller_connector_new ();

  agent_controller_connector_builder (conn->base, AGENT_CONTROLLER_HOST, host);
  agent_controller_connector_builder (conn->base, AGENT_CONTROLLER_PORT, &port);
  agent_controller_connector_builder (conn->base, AGENT_CONTROLLER_PROTOCOL, protocol);

  if (ca_cert)
    agent_controller_connector_builder (conn->base, AGENT_CONTROLLER_CA_CERT, ca_cert);
  if (cert)
    agent_controller_connector_builder (conn->base, AGENT_CONTROLLER_CERT, cert);
  if (key)
    agent_controller_connector_builder (conn->base, AGENT_CONTROLLER_KEY, key);

  conn->scanner_id = scanner;

  g_free (host);
  g_free (ca_cert);
  g_free (cert);
  g_free (key);

  return conn;
}

/**
 * @brief Free a GVMD agent connector.
 *
 * @param conn GVMD agent connector to free.
 */
void
gvmd_agent_connector_free (gvmd_agent_connector_t conn)
{
  if (!conn) return;
  agent_controller_connector_free (conn->base);
  g_free (conn);
}

/**
 * @brief Free an agent_ip_data_list_t and its contents.
 *
 * @param ip_list The list of IP addresses to free.
 */
void
agent_ip_data_list_free (agent_ip_data_list_t ip_list)
{
  if (!ip_list)
    return;

  if (ip_list->items && ip_list->count > 0)
    {
      for (int i = 0; i < ip_list->count; ++i)
        {
          if (ip_list->items[i])
            {
              if (ip_list->items[i]->ip_address)
                g_free(ip_list->items[i]->ip_address);

              g_free(ip_list->items[i]);
              ip_list->items[i] = NULL;
            }
        }
      g_free(ip_list->items);
      ip_list->items = NULL;
    }

  g_free(ip_list);
}

/**
 * @brief Free a single agent_ip_data_t instance.
 *
 * @param ip_data The IP data structure to free.
 */
void
agent_ip_data_free (agent_ip_data_t ip_data)
{
  if (!ip_data)
    return;

  g_free (ip_data->ip_address);
  g_free (ip_data);
}

/**
 * @brief Free an agent_data_t structure and its fields.
 *
 * Cleans up all dynamically allocated fields within the agent.
 *
 * @param data Pointer to agent_data_t to be freed.
 */
void
agent_data_free (agent_data_t data)
{
  if (!data)
    return;

  if (data->agent_id)
    g_free (data->agent_id);

  if (data->name)
    g_free (data->name);

  if (data->hostname)
    g_free (data->hostname);

  if (data->connection_status)
    g_free (data->connection_status);

  if (data->schedule)
    g_free (data->schedule);

  if (data->comment)
    g_free (data->comment);

  agent_ip_data_list_free (data->ip_addresses);

  g_free (data);
}

/**
 * @brief Free a list of agent_data_t structures.
 *
 * Releases all agent data and the container structure.
 *
 * @param agents List to free.
 */
void
agent_data_list_free (agent_data_list_t agents)
{
  if (!agents)
    return;

  for (int i = 0; i < agents->count; ++i)
    {
      if (agents->agents[i])
        agent_data_free (agents->agents[i]);
    }

  g_free (agents->agents);
  g_free (agents);
}

/**
 * @brief Free an agent_uuid_list_t and its contents.
 *
 * @param uuid_list List of agent UUIDs to free.
 */
void
agent_uuid_list_free (agent_uuid_list_t uuid_list)
{
  if (!uuid_list)
    return;

  for (int i = 0; i < uuid_list->count; ++i)
    g_free (uuid_list->agent_uuids[i]);

  g_free (uuid_list->agent_uuids);
  g_free (uuid_list);
}

/**
 * @brief Synchronize agents from the agent controller to GVMD.
 *
 * Gets all agent information from the agent controller
 * and saves it into GVMD's internal database.
 *
 * @param connector Initialized agent controller connector.
 * @return 0 on success, or -1 on failure.
 */
int
sync_agents_from_agent_controller (gvmd_agent_connector_t connector)
{
  if (!connector)
    return -1;

  agent_controller_agent_list_t agent_controller_agents =
    agent_controller_get_agents (connector->base);
  if (!agent_controller_agents || agent_controller_agents->count == 0)
    {
      agent_controller_agent_list_free (agent_controller_agents);
      return 0;
    }

  agent_data_list_t agent_data_list =
    convert_agent_control_list_to_agent_data_list (agent_controller_agents,
                                                   connector->scanner_id);
  if (!agent_data_list || agent_data_list->count == 0)
    {
      agent_data_list_free (agent_data_list);
      agent_controller_agent_list_free (agent_controller_agents);
      return 0;
    }

  int result = sync_agents_from_data_list (agent_data_list);

  agent_data_list_free (agent_data_list);
  agent_controller_agent_list_free (agent_controller_agents);

  return result;
}

/**
 * @brief Retrieve GVMD agents filtered by scanner and UUIDs.
 *
 * Queries the local GVMD agent table using an iterator and constructs
 * a filtered list of agent_data_t.
 *
 * @param scanner    Scanner to filter by.
 * @param uuid_list  Optional list of UUIDs to restrict results.
 * @return Allocated agent_data_list_t or NULL.
 */
agent_data_list_t
get_filtered_agents (scanner_t scanner, agent_uuid_list_t uuid_list)
{
  iterator_t iterator;
  GString *filter = g_string_new (NULL);

  // Add scanner condition
  g_string_append_printf (filter, "scanner = %llu", scanner);

  // Add UUID conditions if any
  if (uuid_list && uuid_list->count > 0)
    {
      g_string_append (filter, " AND (");
      for (int i = 0; i < uuid_list->count; ++i)
        {
          g_string_append_printf (filter, "uuid = '%s'%s",
                                  uuid_list->agent_uuids[i],
                                  (i < uuid_list->count - 1) ? " OR " : "");
        }
      g_string_append (filter, ")");
    }

  init_custom_agent_iterator (&iterator, filter->str);

  agent_data_list_t list = g_malloc0 (sizeof (struct agent_data_list));
  list->count = 0;
  list->agents = NULL;

  while (next (&iterator))
    {
      agent_data_t agent = g_malloc0 (sizeof (struct agent_data));
      if (agent == NULL)
        continue;

      agent->row_id = iterator_int64 (&iterator, 0);
      agent->agent_id = g_strdup (agent_iterator_agent_id (&iterator));
      agent->hostname = g_strdup (agent_iterator_hostname (&iterator));
      agent->authorized = agent_iterator_authorized (&iterator);
      agent->min_interval = agent_iterator_min_interval (&iterator);
      agent->heartbeat_interval = agent_iterator_heartbeat_interval (&iterator);
      agent->connection_status = g_strdup (agent_iterator_connection_status (&iterator));
      agent->last_update_agent_control = agent_iterator_last_update (&iterator);
      agent->schedule = g_strdup (agent_iterator_schedule (&iterator));
      agent->comment = g_strdup (agent_iterator_comment (&iterator));
      agent->creation_time = agent_iterator_creation_time (&iterator);
      agent->modification_time = agent_iterator_modification_time (&iterator);
      agent->scanner = agent_iterator_scanner (&iterator);
      agent->owner = agent_iterator_owner (&iterator);
      agent->uuid = g_strdup (agent_iterator_uuid (&iterator));
      agent->ip_addresses = load_agent_ip_addresses (agent->agent_id);

      list->agents = g_realloc (list->agents, sizeof (agent_data_t) * (list->count + 1));
      list->agents[list->count++] = agent;
    }

  g_string_free (filter, TRUE);
  cleanup_iterator (&iterator);
  return list;
}

/**
 * @brief Modify and resynchronize agents via the agent controller.
 *
 * Sends update instructions for the selected agents and re-synchronizes
 * their state from the agent controller.
 *
 * @param scanner_uuid  UUID of the scanner used.
 * @param agent_uuids   UUID list of agents to update.
 * @param agent_update  Update parameters for the agent controller.
 * @param comment       Optional comment to apply to agents.
 * @return 0 on success, -1 on error.
 */
int
modify_and_resync_agents (const gchar *scanner_uuid,
                          agent_uuid_list_t agent_uuids,
                          agent_controller_agent_update_t agent_update,
                          const gchar *comment)
{
  scanner_t scanner = 0;
  agent_controller_agent_list_t agent_control_list = NULL;
  gvmd_agent_connector_t connector = NULL;
  int result = -1;

  scanner = get_scanner_from_uuid (scanner_uuid);

  if (!scanner)
    {
      g_warning ("%s: get_scanner_from_uuid failed", __func__);
      return -1;
    }

  agent_control_list = get_agent_controller_agents_from_uuid (scanner, agent_uuids);
  if (!agent_control_list || agent_control_list->count == 0)
    {
      g_warning ("%s: get_agent_controller_agents_from_uuid failed", __func__);
      agent_controller_agent_list_free (agent_control_list);
      return -1;
    }

  connector = gvmd_agent_connector_new_from_scanner (scanner);
  if (!connector)
    {
      g_warning ("%s: Failed to create agent connector for scanner %s", __func__, scanner_uuid);
      agent_controller_agent_list_free (agent_control_list);
      manage_option_cleanup ();
      return -1;
    }

  int update_result = agent_controller_update_agents (
                        connector->base,
                        agent_control_list,
                        agent_update);

  if (update_result < 0)
    {
      g_warning ("%s: agent_controller_update_agents failed", __func__);
      agent_controller_agent_list_free (agent_control_list);
      gvmd_agent_connector_free (connector);
      manage_option_cleanup ();
      return -1;
    }

 if (comment)
   update_agents_comment (agent_uuids, comment);

  result = sync_agents_from_agent_controller (connector);
  if (result < 0)
    g_warning ("%s: sync_agents_from_agent_controller failed", __func__);

  // Cleanup
  agent_controller_agent_list_free (agent_control_list);
  gvmd_agent_connector_free (connector);
  manage_option_cleanup ();

  return result;
}

/**
 * @brief Delete agents via the agent controller and resynchronize.
 *
 * Issues deletion requests for the specified agents and re-synchronizes
 * the GVMD agent list to reflect the updated state.
 *
 * @param scanner_uuid  UUID of the scanner.
 * @param agent_uuids   List of UUIDs to delete.
 * @return 0 on success, -1 on failure.
 */
int
delete_and_resync_agents (const gchar *scanner_uuid,
                          agent_uuid_list_t agent_uuids)
{
  scanner_t scanner = 0;
  agent_controller_agent_list_t agent_control_list = NULL;
  gvmd_agent_connector_t connector = NULL;
  int result = -1;

  scanner = get_scanner_from_uuid (scanner_uuid);

  if (!scanner)
    {
      g_warning ("%s: get_scanner_from_uuid failed", __func__);
      return -1;
    }
  agent_control_list = get_agent_controller_agents_from_uuid (scanner, agent_uuids);
  if (!agent_control_list || agent_control_list->count == 0)
    {
      g_warning ("%s: get_agent_controller_agents_from_uuid failed", __func__);
      agent_controller_agent_list_free (agent_control_list);
      return -1;
    }

  connector = gvmd_agent_connector_new_from_scanner (scanner);
  if (!connector)
    {
      g_warning ("%s: Failed to create agent connector for scanner %s", __func__, scanner_uuid);
      agent_controller_agent_list_free (agent_control_list);
      manage_option_cleanup ();
      return -1;
    }

  int update_result = agent_controller_delete_agents (
                        connector->base,
                        agent_control_list);

  if (update_result < 0)
    {
      g_warning ("%s: agent_controller_delete_agents failed", __func__);
      agent_controller_agent_list_free (agent_control_list);
      gvmd_agent_connector_free (connector);
      manage_option_cleanup ();
      return -1;
    }

  delete_agents_filtered (agent_uuids, 0);

  result = sync_agents_from_agent_controller (connector);
  if (result < 0)
    g_warning ("%s: sync_agents_from_agent_controller failed", __func__);

  // Cleanup
  agent_controller_agent_list_free (agent_control_list);
  gvmd_agent_connector_free (connector);
  manage_option_cleanup ();

  return result;
}

#endif // ENABLE_AGENTS