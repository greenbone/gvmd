/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
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
 * @brief Allocate and initialize a new agent_data_list_t structure.
 *
 * @param[in] count Number of agent entries to allocate space for.
 *
 * @return A newly allocated agent_data_list_t on success, or NULL on memory
 * allocation failure.
 */
static agent_data_list_t
agent_data_list_new (int count)
{
  agent_data_list_t list = g_malloc0 (sizeof (struct agent_data_list));

  list->count = count;
  list->agents = g_malloc0 (sizeof (agent_data_t) * (count + 1));

  return list;
}

/**
 * @brief Deep-copy a GPtrArray of char*.
 *
 * @param[in] src  Source pointer array to duplicate (may be NULL).
 *
 * @return A newly allocated #GPtrArray on success; NULL if @p src is NULL
 *         or if an allocation fails.
 */
static GPtrArray *
dup_str_ptr_array (const GPtrArray *src)
{
  if (!src)
    return NULL;

  GPtrArray *dst = g_ptr_array_sized_new (src->len);
  if (!dst)
    return NULL;

  g_ptr_array_set_free_func (dst, g_free);

  for (guint i = 0; i < src->len; ++i)
    {
      const char *s = g_ptr_array_index ((GPtrArray *) src, i);
      char *copy = s ? g_strdup (s) : NULL;

      if (s && !copy)
        {
          g_ptr_array_free (dst, TRUE);
          return NULL;
        }

      g_ptr_array_add (dst, copy);
    }

  return dst;
}

/**
 * @brief Deep-copy a scan agent configuration structure.
 *
 * @param[in] src  Source configuration to copy. May be NULL.
 *
 * @return A newly allocated #agent_controller_scan_agent_config_t on success;
 *         NULL if @p src is NULL or if any allocation fails. On failure, any
 *         partially allocated memory is released.
 */
static agent_controller_scan_agent_config_t
copy_agent_controller_scan_agent_config (
  agent_controller_scan_agent_config_t src)
{
  if (!src)
    return NULL;

  agent_controller_scan_agent_config_t dst =
    agent_controller_scan_agent_config_new ();

  /* Plain struct copies */
  dst->agent_control.retry.attempts = src->agent_control.retry.attempts;
  dst->agent_control.retry.delay_in_seconds =
    src->agent_control.retry.delay_in_seconds;
  dst->agent_control.retry.max_jitter_in_seconds =
    src->agent_control.retry.max_jitter_in_seconds;

  dst->agent_script_executor.bulk_size = src->agent_script_executor.bulk_size;
  dst->agent_script_executor.bulk_throttle_time_in_ms =
    src->agent_script_executor.bulk_throttle_time_in_ms;
  dst->agent_script_executor.indexer_dir_depth =
    src->agent_script_executor.indexer_dir_depth;

  dst->heartbeat.interval_in_seconds = src->heartbeat.interval_in_seconds;
  dst->heartbeat.miss_until_inactive = src->heartbeat.miss_until_inactive;

  /* Deep copy of GPtrArray<char*> */
  dst->agent_script_executor.scheduler_cron_time =
    dup_str_ptr_array (src->agent_script_executor.scheduler_cron_time);

  if (src->agent_script_executor.scheduler_cron_time
      && !dst->agent_script_executor.scheduler_cron_time)
    {
      /* allocation failed – clean up partial dst */
      agent_controller_scan_agent_config_free (dst);
      return NULL;
    }

  return dst;
}

/**
 * @brief Populate GVMD agent data list from agent controller list.
 *
 * Copies agent metadata from the agent controller representation to GVMD's
 * internal format for further processing or persistence.
 *
 * @param[in]  list     List of agents from the agent controller.
 * @param[in]  scanner  Scanner ID associated with these agents.
 * @param[out] out_list Pre-allocated agent_data_list_t with `count` matching
 * `list->count`.
 *
 * @return AGENT_RESPONSE_SUCCESS on success, or an appropriate AGENT_RESPONSE_*
 * error code.
 */
static agent_response_t
convert_agent_control_list_to_agent_data_list (
  agent_controller_agent_list_t list, scanner_t scanner,
  agent_data_list_t out_list)
{
  if (!list || list->count == 0 || !out_list)
    return AGENT_RESPONSE_INVALID_ARGUMENT;

  char *owner_uuid = NULL;
  user_t owner = 0;
  setting_value (SETTING_UUID_AGENT_OWNER, &owner_uuid);
  if (owner_uuid == NULL)
    {
      return AGENT_RESPONSE_INVALID_AGENT_OWNER;
    }

  find_resource_no_acl ("user", owner_uuid, &owner);

  if (owner == 0)
    {
      return AGENT_RESPONSE_INVALID_AGENT_OWNER;
    }

  for (int i = 0; i < list->count; ++i)
    {
      agent_controller_agent_t src = list->agents[i];
      agent_data_t dest = g_malloc0 (sizeof (struct agent_data));

      dest->agent_id = g_strdup (src->agent_id);
      dest->hostname = g_strdup (src->hostname);
      dest->authorized = src->authorized;
      dest->connection_status = g_strdup (src->connection_status);
      dest->last_update_agent_control = src->last_update;
      dest->config = copy_agent_controller_scan_agent_config (src->config);
      dest->updater_version = g_strdup (src->updater_version);
      dest->agent_version = g_strdup (src->agent_version);
      dest->operating_system = g_strdup (src->operating_system);
      dest->architecture = g_strdup (src->architecture);
      dest->update_to_latest = src->update_to_latest;

      dest->scanner = scanner;

      // Initialize and copy IP addresses
      if (src->ip_address_count > 0 && src->ip_addresses)
        {
          dest->ip_addresses = agent_ip_data_list_new (src->ip_address_count);
          dest->ip_addresses->count = src->ip_address_count;
          dest->ip_addresses->items =
            g_malloc0 (sizeof (agent_ip_data_t) * src->ip_address_count);

          for (int j = 0; j < src->ip_address_count; ++j)
            {
              if (!src->ip_addresses[j])
                continue;

              dest->ip_addresses->items[j] =
                g_malloc0 (sizeof (struct agent_ip_data));
              dest->ip_addresses->items[j]->ip_address =
                g_strdup (src->ip_addresses[j]);
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
      out_list->agents[i] = dest;
    }

  return AGENT_RESPONSE_SUCCESS;
}

/**
 * @brief Convert GVMD agent data list to agent controller format.
 *
 * Transforms internal GVMD agent records into a format understood
 * by the agent controller for update or deletion operations.
 *
 * The caller is responsible for freeing the populated
 * `agent_controller_agent_list_t` using the appropriate cleanup function.
 *
 * @param[in]  list      Source list of GVMD agent_data_t entries.
 * @param[out] out_list  Target agent controller list to populate.
 *
 * @return AGENT_RESPONSE_SUCCESS on success, otherwise an error code on failure
 */
static agent_response_t
convert_agent_data_list_to_agent_control_list (
  agent_data_list_t list, agent_controller_agent_list_t out_list)
{
  if (!list || list->count == 0)
    return AGENT_RESPONSE_INVALID_ARGUMENT;

  for (int i = 0; i < list->count; ++i)
    {
      agent_data_t src = list->agents[i];
      agent_controller_agent_t dest = agent_controller_agent_new ();

      dest->agent_id = g_strdup (src->agent_id);
      dest->hostname = g_strdup (src->hostname);
      dest->authorized = src->authorized;
      dest->connection_status = g_strdup (src->connection_status);
      dest->last_update = src->last_update_agent_control;
      dest->last_updater_heartbeat = src->last_updater_heartbeat;
      dest->config = copy_agent_controller_scan_agent_config (src->config);
      dest->updater_version = g_strdup (src->updater_version);
      dest->agent_version = g_strdup (src->agent_version);
      dest->operating_system = g_strdup (src->operating_system);
      dest->architecture = g_strdup (src->architecture);
      dest->last_update = src->update_to_latest;

      // IP addresses
      if (src->ip_addresses && src->ip_addresses->count > 0)
        {
          dest->ip_address_count = src->ip_addresses->count;
          dest->ip_addresses =
            g_malloc0 (sizeof (char *) * dest->ip_address_count);

          for (int j = 0; j < dest->ip_address_count; ++j)
            {
              dest->ip_addresses[j] =
                g_strdup (src->ip_addresses->items[j]->ip_address);
            }
        }

      out_list->agents[i] = dest;
    }

  return AGENT_RESPONSE_SUCCESS;
}

/**
 * @brief Retrieve agent controller agents from GVMD UUIDs.
 *
 * Filters and converts a list of agent UUIDs to agent controller format.
 *
 * @param[in]  scanner      Scanner ID used to filter relevant agents.
 * @param[in]  agent_uuids  List of agent UUIDs to retrieve.
 * @param[out] out_list     Output list for agent controller formatted agents.
 *
 * @return AGENT_RESPONSE_SUCCESS on success, or an appropriate error code on
 * failure.
 */
agent_response_t
get_agent_controller_agents_from_uuids (scanner_t scanner,
                                        agent_uuid_list_t agent_uuids,
                                        agent_controller_agent_list_t out_list)
{
  if (!scanner)
    {
      g_warning ("%s: scanner ID is missing or invalid", __func__);
      return AGENT_RESPONSE_INVALID_ARGUMENT;
    }

  if (!agent_uuids || agent_uuids->count == 0)
    {
      g_warning ("%s: agent UUID list is NULL or empty", __func__);
      return AGENT_RESPONSE_INVALID_ARGUMENT;
    }

  if (!out_list || out_list->count == 0)
    {
      g_warning ("%s: output list is NULL or empty", __func__);
      return AGENT_RESPONSE_INVALID_ARGUMENT;
    }

  agent_data_list_t agent_data_list = agent_data_list_new (agent_uuids->count);
  agent_response_t get_agent_result =
    get_agents_by_scanner_and_uuids (scanner, agent_uuids, agent_data_list);
  if (get_agent_result != 0)
    {
      agent_data_list_free (agent_data_list);
      manage_option_cleanup ();

      return get_agent_result;
    }

  int convert_result =
    convert_agent_data_list_to_agent_control_list (agent_data_list, out_list);

  if (convert_result != AGENT_RESPONSE_SUCCESS)
    {
      agent_data_list_free (agent_data_list);
      manage_option_cleanup ();
      return convert_result;
    }
  agent_data_list_free (agent_data_list);

  return AGENT_RESPONSE_SUCCESS;
}

/**
 * @brief Maps the return value of get_scanner_from_agent_uuid() to
 * agent_response_t.
 *
 * @param[in] result Return code from get_scanner_from_agent_uuid().
 *
 * @return Corresponding agent_response_t enum value.
 */
static agent_response_t
map_get_scanner_result_to_agent_response (int result)
{
  switch (result)
    {
    case 0:
      return AGENT_RESPONSE_SUCCESS;
    case -1:
      return AGENT_RESPONSE_INVALID_ARGUMENT;
    case -2:
      return AGENT_RESPONSE_INTERNAL_ERROR;
    case -3:
      return AGENT_RESPONSE_AGENT_NOT_FOUND;
    case -4:
      return AGENT_RESPONSE_SCANNER_LOOKUP_FAILED;
    default:
      return AGENT_RESPONSE_INTERNAL_ERROR;
    }
}

/**
 * @brief Free an agent_ip_data_list_t and its contents.
 *
 * @param[in] ip_list The list of IP addresses to free.
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
                g_free (ip_list->items[i]->ip_address);

              g_free (ip_list->items[i]);
              ip_list->items[i] = NULL;
            }
        }
      g_free (ip_list->items);
      ip_list->items = NULL;
    }

  g_free (ip_list);
}

/**
 * @brief Allocate and initialize an agent_ip_data_list_t structure.
 *
 * @param[in] count Number of IP address items to allocate.
 * @return A newly allocated agent_ip_data_list_t, or NULL on allocation
 * failure.
 */
agent_ip_data_list_t
agent_ip_data_list_new (int count)
{
  if (count <= 0)
    return NULL;

  agent_ip_data_list_t list = g_malloc0 (sizeof (struct agent_ip_data_list));

  list->count = count;
  list->items = g_malloc0 (sizeof (agent_ip_data_t) * (count + 1));

  return list;
}

/**
 * @brief Free a single agent_ip_data_t instance.
 *
 * @param[in] ip_data The IP data structure to free.
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
 * @param[in] data Pointer to agent_data_t to be freed.
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

  if (data->config)
    agent_controller_scan_agent_config_free (data->config);

  if (data->updater_version)
    g_free (data->updater_version);

  if (data->agent_version)
    g_free (data->agent_version);

  if (data->operating_system)
    g_free (data->operating_system);

  if (data->architecture)
    g_free (data->architecture);

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
 * @param[in] agents List to free.
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
  agents->count = 0;
  g_free (agents->agents);
  g_free (agents);
}

/**
 * @brief Synchronize agents from the agent controller to GVMD.
 *
 * Gets all agent information from the agent controller
 * and saves it into GVMD's internal database.
 *
 * @param[in] connector An initialized agent controller connector with scanner
 * ID.
 *
 * @return AGENT_RESPONSE_SUCCESS on success,
 *         or a specific AGENT_RESPONSE_* error code on failure.
 */
agent_response_t
sync_agents_from_agent_controller (gvmd_agent_connector_t connector)
{
  if (!connector)
    return AGENT_RESPONSE_CONNECTOR_CREATION_FAILED;

  agent_controller_agent_list_t agent_controller_agents =
    agent_controller_get_agents (connector->base);

  if (!agent_controller_agents)
    return AGENT_RESPONSE_SYNC_FAILED;

  if (agent_controller_agents->count == 0)
    {
      agent_controller_agent_list_free (agent_controller_agents);
      return AGENT_RESPONSE_SUCCESS;
    }

  agent_data_list_t agent_data_list =
    agent_data_list_new (agent_controller_agents->count);
  agent_response_t convert_result =
    convert_agent_control_list_to_agent_data_list (
      agent_controller_agents, connector->scanner_id, agent_data_list);

  if (convert_result != AGENT_RESPONSE_SUCCESS)
    {
      agent_data_list_free (agent_data_list);
      agent_controller_agent_list_free (agent_controller_agents);
      return convert_result;
    }

  int result = sync_agents_from_data_list (agent_data_list);

  if (result < 0)
    {
      agent_data_list_free (agent_data_list);
      agent_controller_agent_list_free (agent_controller_agents);
      return AGENT_RESPONSE_SYNC_FAILED;
    }

  agent_data_list_free (agent_data_list);
  agent_controller_agent_list_free (agent_controller_agents);

  return AGENT_RESPONSE_SUCCESS;
}

/**
 * @brief Retrieve GVMD agents filtered by scanner and UUIDs.
 *
 * Queries the local GVMD agent table using an iterator and constructs
 * a filtered list of agent_data_t.
 *
 * @param[in]  scanner    The scanner ID to filter agents by.
 * @param[in]  uuid_list  List of agent UUIDs to look up.
 * @param[out] out_list   Output list to populate with matching agents.
 *
 * @return AGENT_RESPONSE_SUCCESS on success,
 *         or a specific AGENT_RESPONSE_* error code on failure.
 */
agent_response_t
get_agents_by_scanner_and_uuids (scanner_t scanner, agent_uuid_list_t uuid_list,
                                 agent_data_list_t out_list)
{
  if (!out_list || !uuid_list || out_list->count == 0 || uuid_list->count == 0)
    return AGENT_RESPONSE_INVALID_ARGUMENT;

  if (!scanner)
    return AGENT_RESPONSE_INVALID_ARGUMENT;

  iterator_t iterator;
  init_agent_uuid_list_iterator (&iterator, uuid_list);
  int count = 0;
  for (size_t i = 0; i < uuid_list->count && next (&iterator); ++i)
    {
      if (agent_iterator_scanner (&iterator) != scanner)
        {
          cleanup_iterator (&iterator);
          return AGENT_RESPONSE_AGENT_SCANNER_MISMATCH;
        }

      agent_data_t agent = g_malloc0 (sizeof (struct agent_data));
      if (!agent)
        continue;

      /* config conversion */
      const gchar *cfg_str = g_strdup (agent_iterator_config (&iterator));
      agent_controller_scan_agent_config_t config =
        agent_controller_parse_scan_agent_config_string (cfg_str);

      agent->row_id = iterator_int64 (&iterator, 0);
      agent->agent_id = g_strdup (agent_iterator_agent_id (&iterator));
      agent->hostname = g_strdup (agent_iterator_hostname (&iterator));
      agent->authorized = agent_iterator_authorized (&iterator);
      agent->connection_status =
        g_strdup (agent_iterator_connection_status (&iterator));
      agent->last_update_agent_control = agent_iterator_last_update (&iterator);
      agent->config = config;
      agent->comment = g_strdup (get_iterator_comment (&iterator));
      agent->creation_time = get_iterator_creation_time (&iterator);
      agent->modification_time = get_iterator_modification_time (&iterator);
      agent->updater_version =
        g_strdup (agent_iterator_updater_version (&iterator));
      agent->agent_version =
        g_strdup (agent_iterator_agent_version (&iterator));
      agent->operating_system =
        g_strdup (agent_iterator_operating_system (&iterator));
      agent->architecture = g_strdup (agent_iterator_architecture (&iterator));
      agent->update_to_latest = agent_iterator_update_to_latest (&iterator);
      agent->scanner = scanner;
      agent->owner = get_iterator_owner (&iterator);
      agent->uuid = g_strdup (get_iterator_uuid (&iterator));
      agent->ip_addresses = load_agent_ip_addresses (agent->agent_id);

      out_list->agents[i] = agent;
      count++;
    }
  if (count != uuid_list->count)
    {
      cleanup_iterator (&iterator);
      return AGENT_RESPONSE_AGENT_NOT_FOUND;
    }

  cleanup_iterator (&iterator);
  return AGENT_RESPONSE_SUCCESS;
}

/**
 * @brief Modify and resynchronize agents via the agent controller.
 *
 * Sends update instructions for the selected agents and re-synchronizes
 * their state from the agent controller.
 *
 * @param[in]  agent_uuids   List of agent UUIDs to be modified.
 * @param[in]  agent_update  Update parameters to apply (e.g. authorize/revoke).
 * @param[in]  comment       Optional comment string to apply to agents in GVMD.
 *
 * @return AGENT_RESPONSE_SUCCESS on success,
 *         or a specific AGENT_RESPONSE_* error code on failure.
 */
agent_response_t
modify_and_resync_agents (agent_uuid_list_t agent_uuids,
                          agent_controller_agent_update_t agent_update,
                          const gchar *comment,
                          GPtrArray **errors)
{
  scanner_t scanner = 0;
  agent_controller_agent_list_t agent_control_list = NULL;
  gvmd_agent_connector_t connector = NULL;

  if (!agent_uuids || agent_uuids->count == 0)
    {
      return AGENT_RESPONSE_NO_AGENTS_PROVIDED;
    }

  int ret = get_scanner_from_agent_uuid (agent_uuids->agent_uuids[0], &scanner);
  agent_response_t map_response =
    map_get_scanner_result_to_agent_response (ret);
  if (map_response != AGENT_RESPONSE_SUCCESS)
    return map_response;

   /* Prevent unauthorized modification if the agent is currently in use. */
  if (agents_in_use (agent_uuids) && agent_update->authorized == 0)
    {
      g_warning ("%s: Agent is in use by an agent group ", __func__);
      return AGENT_RESPONSE_IN_USE_ERROR;
    }

  agent_control_list = agent_controller_agent_list_new (agent_uuids->count);
  agent_response_t get_response = get_agent_controller_agents_from_uuids (
    scanner, agent_uuids, agent_control_list);
  if (get_response != AGENT_RESPONSE_SUCCESS)
    {
      agent_controller_agent_list_free (agent_control_list);
      return get_response;
    }

  connector = gvmd_agent_connector_new_from_scanner (scanner);
  if (!connector)
    {
      g_warning ("%s: Failed to create agent connector for scanner ", __func__);
      agent_controller_agent_list_free (agent_control_list);
      manage_option_cleanup ();
      return AGENT_RESPONSE_CONNECTOR_CREATION_FAILED;
    }

  int update_result = agent_controller_update_agents (
  connector->base, agent_control_list, agent_update, errors);

  if (update_result < 0 && errors && *errors && (*errors)->len > 0)
    {
      g_warning ("%s: agent_controller_update_agents rejected", __func__);
      agent_controller_agent_list_free (agent_control_list);
      gvmd_agent_connector_free (connector);
      manage_option_cleanup ();
      return AGENT_RESPONSE_CONTROLLER_UPDATE_REJECTED;
    }

  if (update_result < 0)
    {
      g_warning ("%s: agent_controller_update_agents failed", __func__);
      agent_controller_agent_list_free (agent_control_list);
      gvmd_agent_connector_free (connector);
      manage_option_cleanup ();
      return AGENT_RESPONSE_CONTROLLER_UPDATE_FAILED;
    }

  if (comment)
    update_agents_comment (agent_uuids, comment);

  agent_response_t result = sync_agents_from_agent_controller (connector);
  if (result != AGENT_RESPONSE_SUCCESS)
    {
      g_warning ("%s: sync_agents_from_agent_controller failed", __func__);
      agent_controller_agent_list_free (agent_control_list);
      gvmd_agent_connector_free (connector);
      manage_option_cleanup ();
      return result;
    }

  // Cleanup
  agent_controller_agent_list_free (agent_control_list);
  gvmd_agent_connector_free (connector);
  manage_option_cleanup ();

  return AGENT_RESPONSE_SUCCESS;
}

/**
 * @brief Delete agents via the agent controller and resynchronize.
 *
 * Issues deletion requests for the specified agents and re-synchronizes
 * the GVMD agent list to reflect the updated state.
 *
 * @param[in] agent_uuids  List of agent UUIDs to be deleted.
 *
 * @return AGENT_RESPONSE_SUCCESS on success,
 *         or a specific AGENT_RESPONSE_* error code on failure.
 */
agent_response_t
delete_and_resync_agents (agent_uuid_list_t agent_uuids)
{
  scanner_t scanner = 0;
  agent_controller_agent_list_t agent_control_list = NULL;
  gvmd_agent_connector_t connector = NULL;

  if (!agent_uuids || agent_uuids->count == 0)
    {
      return AGENT_RESPONSE_NO_AGENTS_PROVIDED;
    }

  int ret = get_scanner_from_agent_uuid (agent_uuids->agent_uuids[0], &scanner);
  agent_response_t map_response =
    map_get_scanner_result_to_agent_response (ret);
  if (map_response != AGENT_RESPONSE_SUCCESS)
    return map_response;

  agent_control_list = agent_controller_agent_list_new (agent_uuids->count);
  agent_response_t get_result = get_agent_controller_agents_from_uuids (
    scanner, agent_uuids, agent_control_list);
  if (get_result != AGENT_RESPONSE_SUCCESS)
    {
      agent_controller_agent_list_free (agent_control_list);
      return get_result;
    }

  if (agents_in_use (agent_uuids))
    {
      agent_controller_agent_list_free (agent_control_list);
      manage_option_cleanup ();
      return AGENT_RESPONSE_IN_USE_ERROR;
    }

  connector = gvmd_agent_connector_new_from_scanner (scanner);
  if (!connector)
    {
      g_warning ("%s: Failed to create agent connector for scanner", __func__);
      agent_controller_agent_list_free (agent_control_list);
      manage_option_cleanup ();
      return AGENT_RESPONSE_CONNECTOR_CREATION_FAILED;
    }

  int update_result =
    agent_controller_delete_agents (connector->base, agent_control_list);

  if (update_result < 0)
    {
      g_warning ("%s: agent_controller_delete_agents failed", __func__);
      agent_controller_agent_list_free (agent_control_list);
      gvmd_agent_connector_free (connector);
      manage_option_cleanup ();
      return AGENT_RESPONSE_CONTROLLER_DELETE_FAILED;
    }

  delete_agents_by_scanner_and_uuids (0, agent_uuids);

  agent_response_t result = sync_agents_from_agent_controller (connector);
  if (result != AGENT_RESPONSE_SUCCESS)
    {
      g_warning ("%s: sync_agents_from_agent_controller failed", __func__);
      agent_controller_agent_list_free (agent_control_list);
      gvmd_agent_connector_free (connector);
      manage_option_cleanup ();
      return result;
    }

  // Cleanup
  agent_controller_agent_list_free (agent_control_list);
  gvmd_agent_connector_free (connector);
  manage_option_cleanup ();

  return AGENT_RESPONSE_SUCCESS;
}

#endif // ENABLE_AGENTS