/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Agent group data utilities and access control checks for GVMD.
 */

#include "manage_agents.h"
#include "manage_sql_agents.h"
#include "manage_sql_agent_groups.h"
#if ENABLE_AGENTS
#include "manage_agent_groups.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Maps an agent response code to an agent group response code.
 *
 * @param response Agent response code.
 *
 * @return Matching agent group response code.
 */
static agent_group_resp_t
agent_response_to_agent_group_resp (agent_response_t response)
{
  switch (response)
    {
    case AGENT_RESPONSE_SUCCESS:
      return AGENT_GROUP_RESP_SUCCESS;

    case AGENT_RESPONSE_NO_AGENTS_PROVIDED:
      return AGENT_GROUP_RESP_NO_AGENTS_PROVIDED;

    case AGENT_RESPONSE_SCANNER_LOOKUP_FAILED:
      return AGENT_GROUP_RESP_SCANNER_NOT_FOUND;

    case AGENT_RESPONSE_AGENT_SCANNER_MISMATCH:
      return AGENT_GROUP_RESP_AGENT_SCANNER_MISMATCH;

    case AGENT_RESPONSE_INVALID_ARGUMENT:
      return AGENT_GROUP_RESP_INVALID_ARGUMENT;

    case AGENT_RESPONSE_AGENT_NOT_FOUND:
      return AGENT_GROUP_RESP_AGENT_NOT_FOUND;

    case AGENT_RESPONSE_INVALID_AGENT_OWNER:
    case AGENT_RESPONSE_INTERNAL_ERROR:
    case AGENT_RESPONSE_CONNECTOR_CREATION_FAILED:
    case AGENT_RESPONSE_CONTROLLER_UPDATE_FAILED:
    case AGENT_RESPONSE_CONTROLLER_DELETE_FAILED:
    case AGENT_RESPONSE_SYNC_FAILED:
    case AGENT_RESPONSE_IN_USE_ERROR:
    case AGENT_RESPONSE_CONTROLLER_UPDATE_REJECTED:
    default:
      return AGENT_GROUP_RESP_INTERNAL_ERROR;
    }
}

/**
 * @brief Fill an agent update list with the current scheduler cron times.
 *
 * @param[in]  agent_uuids  List of agent UUIDs to retrieve cron times for.
 * @param[in]  scanner      Scanner ID associated with the agents.
 * @param[out] update_list  Pre-allocated update list to fill. Its count must
 *                          match @p agent_uuids->count.
 *
 * @return AGENT_GROUP_RESP_SUCCESS on success,
 *         or a specific AGENT_GROUP_RESP_* error code on failure.
 */
static agent_group_resp_t
fill_agents_update_list_from_group_crons (
  agent_uuid_list_t agent_uuids,
  scanner_t scanner,
  agent_controller_agent_update_list_t update_list)
{
  agent_controller_agent_list_t current_agents = NULL;
  agent_response_t response;
  agent_group_resp_t result = AGENT_GROUP_RESP_SUCCESS;

  if (agent_uuids == NULL || agent_uuids->count == 0 || update_list == NULL)
    return AGENT_GROUP_RESP_INVALID_ARGUMENT;

  current_agents = agent_controller_agent_list_new (agent_uuids->count);
  if (current_agents == NULL)
    return AGENT_GROUP_RESP_INTERNAL_ERROR;

  response =
    get_agent_controller_agents_from_uuids (
      scanner, agent_uuids, current_agents);

  if (response != AGENT_RESPONSE_SUCCESS)
    {
      result = agent_response_to_agent_group_resp (response);
      goto cleanup;
    }

  for (int i = 0; i < current_agents->count; ++i)
    {
      GPtrArray *scheduler_cron_times = NULL;
      agent_controller_agent_t agent = current_agents->agents[i];
      agent_controller_agent_update_t update = NULL;
      agent_controller_agent_config_t config = NULL;

      response =
        agent_group_schedule_cron_times_for_agent_uuid (
          agent_uuids->agent_uuids[i], &scheduler_cron_times);

      if (response != AGENT_RESPONSE_SUCCESS)
        {
          result = agent_response_to_agent_group_resp (response);
          goto cleanup;
        }

      update = agent_controller_agent_update_new ();
      if (update == NULL)
        {
          g_ptr_array_unref (scheduler_cron_times);
          result = AGENT_GROUP_RESP_INTERNAL_ERROR;
          goto cleanup;
        }

      config = agent_controller_agent_config_new ();
      if (config == NULL)
        {
          g_ptr_array_unref (scheduler_cron_times);
          agent_controller_agent_update_free (update);
          result = AGENT_GROUP_RESP_INTERNAL_ERROR;
          goto cleanup;
        }

      config->agent_script_executor.scheduler_cron_time =
        scheduler_cron_times;

      update->update_config =
        copy_agent_controller_scan_agent_config (config);

      update->base_config =
        copy_agent_controller_scan_agent_config (agent->config);
      update->agent_id = g_strdup (agent->agent_id);

      agent_controller_agent_config_free (config);
      config = NULL;

      if (update->update_config == NULL || update->base_config == NULL)
        {
          agent_controller_agent_update_free (update);
          result = AGENT_GROUP_RESP_INTERNAL_ERROR;
          goto cleanup;
        }

      update_list->updates[i] = update;
    }

cleanup:
  agent_controller_agent_list_free (current_agents);

  return result;
}

/**
 * @brief Resolve and validate the scanner for an agent group operation.
 *
 * Resolves the scanner from the first agent UUID, checks whether the current
 * user has access to it, and stores the scanner on the group data.
 *
 * @param[in,out] group_data   Agent group data to update with scanner ID.
 * @param[in]     agent_uuids  Agent UUID list used to resolve the scanner.
 * @param[out]    scanner      Resolved scanner ID.
 *
 * @return AGENT_GROUP_RESP_SUCCESS on success,
 *         or a specific AGENT_GROUP_RESP_* error code on failure.
 */
static agent_group_resp_t
get_agent_group_scanner (agent_group_data_t group_data,
                         agent_uuid_list_t agent_uuids,
                         scanner_t *scanner)
{
  int ret;
  agent_group_resp_t response;

  if (group_data == NULL || scanner == NULL)
    return AGENT_GROUP_RESP_INVALID_ARGUMENT;

  if (agent_uuids == NULL || agent_uuids->count == 0)
    return AGENT_GROUP_RESP_NO_AGENTS_PROVIDED;

  *scanner = 0;

  ret = get_scanner_from_agent_uuid (agent_uuids->agent_uuids[0], scanner);
  response = map_get_scanner_result_to_agent_group_resp (ret);

  if (response != AGENT_GROUP_RESP_SUCCESS)
    return response;

  if (!user_has_get_access_to_scanner (*scanner))
    return AGENT_GROUP_RESP_SCANNER_PERMISSION;

  group_data->scanner = *scanner;

  return AGENT_GROUP_RESP_SUCCESS;
}

/**
 * @brief Synchronize agent controller cron config from current group DB state.
 *
 * @param[in] agent_uuids  Agent UUIDs to update.
 * @param[in] scanner      Scanner ID used for the controller update.
 *
 * @return AGENT_GROUP_RESP_SUCCESS on success,
 *         or a specific AGENT_GROUP_RESP_* error code on failure.
 */
static agent_group_resp_t
sync_agent_group_agents_from_group_crons (agent_uuid_list_t agent_uuids,
                                          scanner_t scanner)
{
  agent_controller_agent_update_list_t update_list = NULL;
  agent_group_resp_t group_response;
  agent_response_t agent_response;
  GPtrArray *errs = NULL;

  if (agent_uuids == NULL || agent_uuids->count == 0)
    return AGENT_GROUP_RESP_NO_AGENTS_PROVIDED;

  update_list =
    agent_controller_agent_update_list_new (agent_uuids->count);

  if (update_list == NULL)
    return AGENT_GROUP_RESP_INTERNAL_ERROR;

  group_response =
    fill_agents_update_list_from_group_crons (
      agent_uuids, scanner, update_list);

  if (group_response != AGENT_GROUP_RESP_SUCCESS)
    {
      agent_controller_agent_update_list_free (update_list);
      return group_response;
    }

  agent_response =
    modify_and_resync_agents_with_update_list (
      scanner, update_list, &errs);

  agent_controller_agent_update_list_free (update_list);

  if (agent_response != AGENT_RESPONSE_SUCCESS)
    {
      if (errs)
        g_ptr_array_free (errs, TRUE);

      return agent_response_to_agent_group_resp (agent_response);
    }

  if (errs)
    g_ptr_array_free (errs, TRUE);

  return AGENT_GROUP_RESP_SUCCESS;
}

/**
 * @brief Create a union of two agent UUID lists.
 *
 * @param[in] first   First agent UUID list, may be NULL.
 * @param[in] second  Second agent UUID list, may be NULL.
 *
 * @return Newly allocated union list, or NULL if both input lists are empty.
 *         Caller must free the returned list with agent_uuid_list_free().
 */
static agent_uuid_list_t
agent_uuid_list_union (agent_uuid_list_t first, agent_uuid_list_t second)
{
  GHashTable *seen;
  GPtrArray *uuids;
  agent_uuid_list_t result;
  int i;

  seen = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  uuids = g_ptr_array_new_with_free_func (g_free);

  if (first)
    {
      for (i = 0; i < first->count; ++i)
        {
          const gchar *uuid = first->agent_uuids[i];

          if (uuid == NULL || *uuid == '\0')
            continue;

          if (g_hash_table_contains (seen, uuid) == FALSE)
            {
              g_hash_table_add (seen, g_strdup (uuid));
              g_ptr_array_add (uuids, g_strdup (uuid));
            }
        }
    }

  if (second)
    {
      for (i = 0; i < second->count; ++i)
        {
          const gchar *uuid = second->agent_uuids[i];

          if (uuid == NULL || *uuid == '\0')
            continue;

          if (g_hash_table_contains (seen, uuid) == FALSE)
            {
              g_hash_table_add (seen, g_strdup (uuid));
              g_ptr_array_add (uuids, g_strdup (uuid));
            }
        }
    }

  if (uuids->len == 0)
    {
      g_ptr_array_free (uuids, TRUE);
      g_hash_table_destroy (seen);
      return NULL;
    }

  result = agent_uuid_list_new ((int) uuids->len);
  if (result == NULL)
    {
      g_ptr_array_free (uuids, TRUE);
      g_hash_table_destroy (seen);
      return NULL;
    }

  for (i = 0; i < (int) uuids->len; ++i)
    result->agent_uuids[i] = g_strdup (g_ptr_array_index (uuids, i));

  result->count = (int) uuids->len;

  g_ptr_array_free (uuids, TRUE);
  g_hash_table_destroy (seen);

  return result;
}

/**
 * @brief Allocate and initialize a new agent_group_data_t structure.
 *
 * @return A newly allocated agent_group_data_t pointer, or NULL on failure.
 */
agent_group_data_t
agent_group_data_new ()
{
  return (agent_group_data_t) g_malloc0 (sizeof (struct agent_group_data));
}

/**
 * @brief Free an agent_group_data_t structure and its contents.
 *
 * @param[in] data Pointer to the agent_group_data structure to free.
 */
void
agent_group_data_free (agent_group_data_t data)
{
  if (!data)
    return;

  g_free (data->uuid);
  g_free (data->name);
  g_free (data->comment);
  g_free (data->scheduler_cron_time);
  g_free (data);
}

/**
 *@brief Create Agent Group and synchronize agent controller cron config
 *       from current group DB state.
 *
 * @param group_data Agent group metadata and configuration.
 * @param agent_uuids List of agent UUIDs to associate with the group.
 *
 * @return AGENT_GROUP_RESP_SUCCESS on success,
 *         or a specific AGENT_GROUP_RESP_* error code on failure.
 */
agent_group_resp_t
create_and_sync_agent_group (agent_group_data_t group_data,
                             agent_uuid_list_t agent_uuids)
{
  scanner_t scanner = 0;
  agent_group_resp_t response;
  int delete_response;

  assert (current_credentials.uuid);

  response = get_agent_group_scanner (group_data, agent_uuids, &scanner);

  if (response != AGENT_GROUP_RESP_SUCCESS)
    return response;

  /*
   * Create the group first so the DB contains the new group cron.
   * After this, the cron-list helper can read the complete current cron state.
   */
  response = create_agent_group (group_data, agent_uuids);

  if (response != AGENT_GROUP_RESP_SUCCESS)
    return response;

  response = sync_agent_group_agents_from_group_crons (agent_uuids, scanner);

  if (response != AGENT_GROUP_RESP_SUCCESS)
    {
      g_warning ("%s: failed to sync agent controller after group creation: %d",
                 __func__, response);
      delete_response = delete_agent_group (group_data->uuid, 1);

      if (delete_response)
        {
          g_warning ("%s: failed to delete agent group %s after sync failure, "
                     "delete_agent_group returned %d",
                     __func__, group_data->uuid, delete_response);
        }

      return response;
    }
  return AGENT_GROUP_RESP_SUCCESS;
}

/**
 *@brief Modify an existing Agent Group and sync agent controller cron config
 *       from current group DB state.
 *
 * @param agent_group Agent group ID to modify
 * @param group_data Agent group metadata and configuration to update
 * @param agent_uuids Agent UUIDs to associate with the group
 *
 * @return AGENT_GROUP_RESP_SUCCESS on success,
 *         or a specific AGENT_GROUP_RESP_* error code on failure.
 */
agent_group_resp_t
modify_and_sync_agent_group (agent_group_t agent_group,
                             agent_group_data_t group_data,
                             agent_uuid_list_t agent_uuids)
{
  scanner_t scanner = 0;
  agent_group_resp_t response;
  agent_group_resp_t sync_response;
  agent_group_resp_t rollback_response;
  agent_group_data_t old_group_data = NULL;
  agent_uuid_list_t old_agent_uuids = NULL;
  agent_uuid_list_t sync_agent_uuids = NULL;

  assert (current_credentials.uuid);

  response = get_agent_group (agent_group, &old_group_data);
  if (response != AGENT_GROUP_RESP_SUCCESS)
    return response;

  scanner = old_group_data->scanner;

  response = get_agent_group_agent_uuids (agent_group, &old_agent_uuids);
  if (response != AGENT_GROUP_RESP_SUCCESS)
    {
      agent_group_data_free (old_group_data);
      return response;
    }

  /*
   * Sync target must include both old and new agents:
   * - added agents need the new cron
   * - removed agents need stale cron removed
   * - kept agents may need updated cron
   */
  sync_agent_uuids = agent_uuid_list_union (old_agent_uuids, agent_uuids);

  response = modify_agent_group (agent_group, group_data, agent_uuids);
  if (response != AGENT_GROUP_RESP_SUCCESS)
    {
      agent_uuid_list_free (sync_agent_uuids);
      agent_uuid_list_free (old_agent_uuids);
      agent_group_data_free (old_group_data);
      return response;
    }

  if (sync_agent_uuids)
    sync_response =
      sync_agent_group_agents_from_group_crons (sync_agent_uuids, scanner);
  else
    sync_response = AGENT_GROUP_RESP_SUCCESS;

  if (sync_response != AGENT_GROUP_RESP_SUCCESS)
    {
      g_warning (
        "%s: failed to sync agent controller after group modification: %d",
        __func__, sync_response);

      rollback_response = modify_agent_group (agent_group,
                                              old_group_data,
                                              old_agent_uuids);

      if (rollback_response != AGENT_GROUP_RESP_SUCCESS)
        {
          g_warning (
            "%s: failed to rollback agent group %llu after sync failure, "
            "modify_agent_group returned %d",
            __func__, agent_group, rollback_response);
        }

      response = sync_response;
    }
  else
    {
      response = AGENT_GROUP_RESP_SUCCESS;
    }

  agent_uuid_list_free (sync_agent_uuids);
  agent_uuid_list_free (old_agent_uuids);
  agent_group_data_free (old_group_data);

  return response;
}
#endif //ENABLE_AGENTS
