/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief SQL backend implementation for agent group management in GVMD.
 *
 * This file provides the implementation of SQL interactions related to
 * agent group data, including creation, update, deletion, and assignment of agents
 * to groups. It supports both regular SQL operations and trash handling.
 */

#if ENABLE_AGENTS

#include "manage_acl.h"
#include "manage_sql_agent_groups.h"
#include "manage_sql_agents.h"
#include "manage_sql_copy.h"

#include <util/uuidutils.h>

#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Retrieve the scanner ID for a given agent group.
 *
 * @param[in]  agent_group_id  Row ID of the agent group.
 * @param[out] scanner         Pointer to store the resulting scanner ID.
 *
 * @return 0 on success, -1 on failure.
 */
static int
get_scanner_by_agent_group_id (agent_group_t agent_group_id, scanner_t *scanner)
{
  g_return_val_if_fail (scanner, -1);

  if (sql_int64 (scanner,
                 "SELECT scanner FROM agent_groups WHERE id = %llu;",
                 agent_group_id) != 0)
    return -1;

  return 0;
}

/**
 * @brief Maps result of get_scanner_from_agent_uuid to agent_group_resp_t.
 *
 * @param[in] result The integer result returned by get_scanner_from_agent_uuid.
 *
 * @return The corresponding agent_group_resp_t value.
 */
static agent_group_resp_t
map_get_scanner_result_to_agent_group_resp (int result)
{
  switch (result)
  {
    case 0:
      return AGENT_GROUP_RESP_SUCCESS;

    case -1:
    case -4:
      return AGENT_GROUP_RESP_INVALID_ARGUMENT;

    case -2:
      return AGENT_GROUP_RESP_INTERNAL_ERROR;

    case -3:
      return AGENT_GROUP_RESP_AGENT_NOT_FOUND;

    default:
      return AGENT_GROUP_RESP_INTERNAL_ERROR;
  }
}

/**
 * @brief Check if the current user has "get_scanners" permission on a scanner.
 *
 * @param[in] scanner  Scanner row ID to check.
 *
 * @return TRUE if the user has access, FALSE otherwise.
 */
static gboolean
user_has_get_access_to_scanner (scanner_t scanner)
{
  char *s_uuid = scanner_uuid (scanner);
  if (!s_uuid)
    return FALSE;

  gboolean allowed = acl_user_has_access_uuid ("scanner", s_uuid, "get_scanners", 0);
  g_free (s_uuid);
  return allowed;
}

/**
 * @brief Count the number of agent groups based on filter criteria.
 *
 * @param[in] get  Pointer to the get_data_t structure containing filters and options.
 *
 * @return The number of matching agent groups.
 */
int
agent_group_count (const get_data_t *get)
{
  static const char *extra_columns[] = AGENT_GROUP_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = AGENT_GROUP_ITERATOR_COLUMNS;
  static column_t trash_columns[] = AGENT_GROUP_ITERATOR_TRASH_COLUMNS;
  const char *join_clause = " LEFT JOIN"
                            " (SELECT id as scanner_id, name AS scanner_name, uuid AS scanner_uuid FROM scanners )"
                            " ON scanner_id = scanner";

  return count ("agent_group", get, columns, trash_columns, extra_columns, 0, join_clause, 0, TRUE);
}

/**
 * @brief Initialize an iterator for retrieving agent groups.
 *
 * @param[in,out] iterator  Pointer to the iterator to initialize.
 * @param[in]     get       Pointer to the get_data_t structure containing filters and options.
 *
 * @return 0 on success, non-zero on failure.
 */
int
init_agent_group_iterator (iterator_t *iterator, get_data_t *get)
{
  static const char *filter_columns[] = AGENT_GROUP_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = AGENT_GROUP_ITERATOR_COLUMNS;
  static column_t trash_columns[] = AGENT_GROUP_ITERATOR_TRASH_COLUMNS;
  const char *join_clause = " LEFT JOIN"
                            " (SELECT id as scanner_id, name AS scanner_name, uuid AS scanner_uuid FROM scanners )"
                            " ON scanner_id = scanner";

  return init_get_iterator (iterator, "agent_group", get, columns, trash_columns, filter_columns, 0,
                            join_clause, NULL, TRUE);
}

/**
 * @brief Initialize an iterator to retrieve all agents belonging to a specific agent group.
 *
 * @param[out] iterator   The iterator to initialize.
 * @param[in]  group_id   The internal row ID of the agent group whose agents should be listed.
 *
 * @return 0 on success, non-zero on error.
 */
void
init_agent_group_agents_iterator (iterator_t *iterator,
                                  agent_group_t group_id)
{
   init_iterator (iterator, "SELECT agents.uuid, agents.name FROM agents"
                            " LEFT JOIN agent_group_agents ON agent_group_agents.agent_id = agents.id"
                            " WHERE agent_group_agents.group_id = %llu;", group_id);
}

/**
 * @brief Create a new agent group with associated agents.
 *
 * Generates a UUID for the group, validates the scanner UUID, inserts the group into the DB,
 * and associates the specified agents with the group (validating scanner ownership).
 *
 * @param[in,out] group_data     Pointer to the agent group data. `uuid` will be set if not provided.
 * @param[in]     agent_uuids    List of agent UUIDs to assign to the group.
 *
 * @return Response code indicating result:
 *         - AGENT_GROUP_RESP_SUCCESS on success
 *         - Error code (e.g., AGENT_GROUP_RESP_SCANNER_NOT_FOUND) on failure
 */
agent_group_resp_t
create_agent_group (agent_group_data_t group_data,
                    agent_uuid_list_t agent_uuids)
{
  assert (current_credentials.uuid);

  if (!agent_uuids || agent_uuids->count == 0)
    return AGENT_GROUP_RESP_NO_AGENTS_PROVIDED;

  // GET scanner ID from the first agent
  scanner_t scanner = 0;
  int ret = get_scanner_from_agent_uuid (agent_uuids->agent_uuids[0], &scanner);
  agent_group_resp_t map_response = map_get_scanner_result_to_agent_group_resp (ret);
  if (map_response != AGENT_GROUP_RESP_SUCCESS)
    return map_response;

  // Check scanner permission
  if (!user_has_get_access_to_scanner (scanner))
    return AGENT_GROUP_RESP_SCANNER_PERMISSION;

  //Set scanner to agent_group
  group_data->scanner = scanner;

  // Ensure UUID is generated
  if (!group_data->uuid)
    {
      group_data->uuid = gvm_uuid_make ();
      if (!group_data->uuid)
        return AGENT_GROUP_RESP_INTERNAL_ERROR;
    }

  gchar *quoted_uuid = sql_quote (group_data->uuid);
  gchar *quoted_name = sql_quote (group_data->name);
  gchar *quoted_comment = sql_quote (group_data->comment);
  gchar *quoted_user_uuid = sql_quote (current_credentials.uuid);

  sql_begin_immediate ();

  // Insert into agent_groups (scanner added)
  sql ("INSERT INTO agent_groups (uuid, name, comment, scanner, owner, creation_time, modification_time) "
       "VALUES ('%s', '%s', '%s', %llu, "
       "  (SELECT id FROM users WHERE uuid = '%s'),"
       "  %ld, %ld);",
       quoted_uuid,
       quoted_name,
       quoted_comment,
       group_data->scanner,
       quoted_user_uuid,
       group_data->creation_time,
       group_data->modification_time);

  g_free (quoted_uuid);
  g_free (quoted_name);
  g_free (quoted_comment);
  g_free (quoted_user_uuid);

  agent_group_t new_agent_group = sql_last_insert_id ();
  if (new_agent_group == 0)
    {
      sql_rollback ();
      return AGENT_GROUP_RESP_INTERNAL_ERROR;
    }

  // Prepare COPY buffer
  db_copy_buffer_t buffer;
  db_copy_buffer_init (&buffer, 16 * 1024,
                       "COPY agent_group_agents (group_id, agent_id) FROM STDIN;");

  for (int i = 0; i < agent_uuids->count; ++i)
    {
      const gchar *uuid = agent_uuids->agent_uuids[i];
      agent_t agent_id;
      int result = agent_id_by_uuid_and_scanner (uuid, group_data->scanner, &agent_id);
      if (result != 0)
        {
           db_copy_buffer_cleanup (&buffer);
           sql_rollback ();

           if (result == 1)
             return AGENT_GROUP_RESP_AGENT_NOT_FOUND;
           else if (result == 2)
             return AGENT_GROUP_RESP_AGENT_SCANNER_MISMATCH;
        }

      db_copy_buffer_append_printf (&buffer, "%llu\t%llu\n", new_agent_group, agent_id);
    }

  db_copy_buffer_commit (&buffer, TRUE);
  db_copy_buffer_cleanup (&buffer);

  sql_commit ();

  return AGENT_GROUP_RESP_SUCCESS;
}

/**
 * @brief Modify an existing agent group (metadata and associated agents).
 *
 * @param agent_group ID of the group to modify.
 * @param group_data New metadata for the group.
 * @param agent_uuids New list of agent UUIDs to associate.
 *
 * @return Response code indicating result:
 *         - AGENT_GROUP_RESP_SUCCESS on success
 *         - Error code (e.g., AGENT_GROUP_RESP_AGENT_NOT_FOUND) on failure
 */
agent_group_resp_t
modify_agent_group (agent_group_t agent_group,
                    agent_group_data_t group_data,
                    agent_uuid_list_t agent_uuids)
{
  gchar *quoted_name = sql_quote (group_data->name);
  gchar *quoted_comment = sql_quote (group_data->comment);

  sql_begin_immediate ();

  sql ("UPDATE agent_groups SET name = '%s', comment = '%s', "
       "modification_time = %ld WHERE id = %llu;",
       quoted_name,
       quoted_comment,
       group_data->modification_time,
       agent_group);

  g_free (quoted_name);
  g_free (quoted_comment);

  if (!agent_uuids || agent_uuids->count == 0)
    {
      sql_commit ();
      return AGENT_GROUP_RESP_SUCCESS;
    }

  // Clean up old agents from db
  sql ("DELETE FROM agent_group_agents WHERE group_id = %llu;", agent_group);

  db_copy_buffer_t buffer;
  db_copy_buffer_init (&buffer, 16 * 1024,
                       "COPY agent_group_agents (group_id, agent_id) FROM STDIN;");

  scanner_t scanner = 0;
  int ret = get_scanner_by_agent_group_id (agent_group, &scanner);
  if (ret == -1)
    {
      db_copy_buffer_cleanup (&buffer);
      sql_rollback ();
      return AGENT_GROUP_RESP_SCANNER_NOT_FOUND;
    }
  // Check scanner permission
  if (!user_has_get_access_to_scanner (scanner))
    {
      db_copy_buffer_cleanup (&buffer);
      sql_rollback ();
      return AGENT_GROUP_RESP_SCANNER_PERMISSION;
    }

  group_data->scanner = scanner;

  for (int i = 0; i < agent_uuids->count; ++i)
    {
    const gchar *uuid = agent_uuids->agent_uuids[i];
    agent_t agent_id;
    int result = agent_id_by_uuid_and_scanner (uuid, group_data->scanner, &agent_id);
    if (result != 0)
    {
      db_copy_buffer_cleanup (&buffer);
      sql_rollback ();

      if (result == 1)
        return AGENT_GROUP_RESP_AGENT_NOT_FOUND;
      else if (result == 2)
        return AGENT_GROUP_RESP_AGENT_SCANNER_MISMATCH;
    }

     db_copy_buffer_append_printf (&buffer, "%llu\t%llu\n", agent_group, agent_id);
    }

  db_copy_buffer_commit (&buffer, TRUE);
  db_copy_buffer_cleanup (&buffer);

  sql_commit ();

  return AGENT_GROUP_RESP_SUCCESS;
}

/**
 * @brief Delete an agent group, either softly (move to trash) or permanently.
 *
 * @param[in] agent_group_uuid  UUID of the agent group to delete.
 * @param[in] ultimate          If 0, perform a soft delete (move to trash);
 *                              if non-zero, perform a hard delete.
 *
 * @return 0 on success, 1 if already exists, 2 if not found, 99 permission denied, -1 on error.
 */
int
delete_agent_group (const char *agent_group_uuid, int ultimate)
{
  agent_group_t agent_group = 0;

  sql_begin_immediate ();

  if (acl_user_may ("delete_agent_group") == 0)
    {
      sql_rollback ();
      return 99;
    }

  // Try to find in active agent_groups
  if (find_resource_with_permission ("agent_group", agent_group_uuid,
                                     &agent_group, "delete_agent_group", 0))
    {
      sql_rollback ();
      return -1;
    }

  if (agent_group == 0)
    {
      // Try to find in trash
      if (find_trash ("agent_group", agent_group_uuid, &agent_group))
        {
          sql_rollback ();
          return -1;
        }

      if (agent_group == 0)
        {
          sql_rollback ();
          return 2;
        }

      if (ultimate == 0)
        {
          sql_commit ();
          return 0;  // Already in trash
        }

      // Hard delete from trash
      sql ("DELETE FROM permissions"
           " WHERE resource_type = 'agent_group'"
           " AND resource_location = %i"
           " AND resource = %llu;",
           LOCATION_TRASH,
           agent_group);

      tags_remove_resource ("agent_group", agent_group, LOCATION_TRASH);

      sql ("DELETE FROM agent_group_agents_trash WHERE agent_group = %llu;", agent_group);
      sql ("DELETE FROM agent_groups_trash WHERE id = %llu;", agent_group);

      sql_commit ();
      return 0;
    }

  if (ultimate == 0)
    {
      agent_group_t trash_id;

      // Move to trash
      sql ("INSERT INTO agent_groups_trash"
           " (uuid, name, comment, owner, scanner, creation_time, modification_time)"
           " SELECT uuid, name, comment, owner, scanner, creation_time, modification_time"
           " FROM agent_groups WHERE id = %llu;",
           agent_group);

      trash_id = sql_last_insert_id ();

      sql ("INSERT INTO agent_group_agents_trash"
           " (agent_group, agent)"
           " SELECT %llu, agent_id FROM agent_group_agents WHERE group_id = %llu;",
           trash_id, agent_group);

      permissions_set_locations ("agent_group", agent_group, trash_id, LOCATION_TRASH);
      tags_set_locations ("agent_group", agent_group, trash_id, LOCATION_TRASH);
    }
  else
    {
      // Hard delete
      sql ("DELETE FROM permissions"
           " WHERE resource_type = 'agent_group'"
           " AND resource_location = %i"
           " AND resource = %llu;",
           LOCATION_TABLE,
           agent_group);

      tags_remove_resource ("agent_group", agent_group, LOCATION_TABLE);
    }

  // Clean up active entries
  sql ("DELETE FROM agent_group_agents WHERE group_id = %llu;", agent_group);
  sql ("DELETE FROM agent_groups WHERE id = %llu;", agent_group);

  sql_commit ();
  return 0;
}

/**
 * @brief Restore an agent group from trash.
 *
 * If successful, commits the transaction before returning.
 *
 * @param[in]  agent_group_uuid  UUID of the trashed agent group.
 *
 * @return 0 success, 2 not found, -1 error.
 */
int
restore_agent_group (const char *agent_group_uuid)
{
  agent_group_t trash_id, restored_id;

  sql_begin_immediate ();

  if (find_trash ("agent_group", agent_group_uuid, &trash_id))
  {
    sql_rollback ();
    return -1;
  }

  if (trash_id == 0)
  {
    sql_rollback ();
    return 2;
  }

  // Restore agent group metadata
  sql ("INSERT INTO agent_groups"
       " (uuid, name, comment, owner, scanner, creation_time, modification_time)"
       " SELECT uuid, name, comment, owner, scanner, creation_time, modification_time"
       " FROM agent_groups_trash WHERE id = %llu;",
       trash_id);

  restored_id = sql_last_insert_id ();

  // Restore agents associated with the group
  sql ("INSERT INTO agent_group_agents"
       " (group_id, agent_id)"
       " SELECT %llu, agent"
       " FROM agent_group_agents_trash"
       " WHERE agent_group = %llu;",
       restored_id, trash_id);

  // Restore permissions and tags
  permissions_set_locations ("agent_group", trash_id, restored_id, LOCATION_TABLE);
  tags_set_locations ("agent_group", trash_id, restored_id, LOCATION_TABLE);

  // Clean up trash entries
  sql ("DELETE FROM agent_group_agents_trash WHERE agent_group = %llu;", trash_id);
  sql ("DELETE FROM agent_groups_trash WHERE id = %llu;", trash_id);

  sql_commit ();
  return 0;
}

/**
 * @brief Empty agent group trashcans for current user.
 */
void
empty_trashcan_agent_groups ()
{
  sql ("DELETE FROM permissions"
       " WHERE resource_type = 'agent_group'"
       " AND resource_location = %i"
       " AND resource IN (SELECT id FROM agent_groups_trash"
       "                  WHERE owner = (SELECT id FROM users"
       "                                 WHERE uuid = '%s'));",
       LOCATION_TRASH,
       current_credentials.uuid);

  sql ("DELETE FROM agent_group_agents_trash"
       " WHERE agent_group IN (SELECT id FROM agent_groups_trash"
       "                       WHERE owner = (SELECT id FROM users"
       "                                      WHERE uuid = '%s'));",
       current_credentials.uuid);

  sql ("DELETE FROM agent_groups_trash"
       " WHERE owner = (SELECT id FROM users WHERE uuid = '%s');",
       current_credentials.uuid);
}

/**
 * @brief Retrieve scanner ID of current agent group.
 *
 * @param[in] iterator  Iterator pointing to the current agent group entry.
 *
 * @return The scanner ID associated with the current agent group.
 */
scanner_t
agent_group_iterator_scanner (iterator_t *iterator)
{
  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT);
}

/**
 * @brief Retrieve scanner name of current agent group.
 *
 * @param[in] iterator  Iterator pointing to the current agent group entry.
 *
 * @return The scanner name associated with the current agent group.
 */
DEF_ACCESS (agent_group_iterator_scanner_name, GET_ITERATOR_COLUMN_COUNT + 1);

/**
 * @brief Retrieve scanner uuid of current agent group.
 *
 * @param[in] iterator  Iterator pointing to the current agent group entry.
 *
 * @return The scanner uuid associated with the current agent group.
 */
DEF_ACCESS (agent_group_iterator_scanner_id, GET_ITERATOR_COLUMN_COUNT + 2);


/**
 * @brief Copy an agent group including its agent assignments.
 *
 * @param[in]  comment         Optional new comment.
 * @param[in]  group_uuid      UUID of the agent group to copy.
 * @param[out] new_group_return    Output: ID of the newly created agent group.
 *
 * @return 0 on success, 1 if already exists, 2 if not found, 99 permission denied, -1 on error.
 */
int
copy_agent_group (const char *name,
                  const char *comment,
                  const char *group_uuid,
                  agent_group_t *new_group_return)
{
  int ret;
  agent_group_t new_group, old_group;

  g_return_val_if_fail (group_uuid, -1);

  sql_begin_immediate ();

  // Copy core resource fields into new row
  ret = copy_resource_lock ("agent_group", name, comment, group_uuid, "scanner", 1, &new_group,
                            &old_group);
  if (ret)
  {
    sql_rollback ();
    return ret;  // 1=already exists, 2=not found, 99=perm denied, -1=error
  }

  // Copy agent mappings
  sql ("INSERT INTO agent_group_agents (group_id, agent_id) "
             "SELECT %llu, agent_id FROM agent_group_agents "
             "WHERE group_id = %llu;",
             new_group, old_group);

  sql_commit ();

  if (new_group_return)
    *new_group_return = new_group;

  return 0;
}

/**
 * @brief Return the UUID of an agent group.
 *
 * @param[in]  group_id  Agent group ID.
 *
 * @return Newly allocated UUID string if found, else NULL.
 */
char *
agent_group_uuid (agent_group_t group_id)
{
  g_return_val_if_fail (group_id, NULL);
  return sql_string ("SELECT uuid FROM agent_groups WHERE id = %llu;", group_id);
}

/**
 * @brief Return the row_id of an agent group.
 *
 * @param[in]  group_uuid  Agent group UUID.
 *
 * @return Allocated row_id if found, else 0.
 */
agent_group_t
agent_group_id_by_uuid (const gchar *group_uuid)
{
  g_return_val_if_fail (group_uuid != NULL, 0);
  return sql_int64_0 ("SELECT id FROM agent_groups WHERE uuid = '%s';", group_uuid);
}

/**
 * @brief Delete agent groups by scanner ID.
 *
 * Deletes all agent groups, their agent mappings, and corresponding
 * trash entries that are associated with the given scanner.
 * It is called before scanner(Agent Controller) deletion.
 *
 * @param[in] scanner  Scanner row_id
 */
void
delete_agent_groups_by_scanner (scanner_t scanner)
{
  if (!scanner)
    return;

  // Build common WHERE clause
  GString *where_clause = g_string_new (NULL);
  g_string_append_printf (where_clause, "WHERE scanner = %llu", scanner);

  sql_begin_immediate ();

  // Delete agent_group_agents entries for groups associated with the scanner
  sql (
    "DELETE FROM agent_group_agents "
    "WHERE group_id IN (SELECT id FROM agent_groups %s);",
    where_clause->str);

  // Delete agent_groups entries
  sql (
    "DELETE FROM agent_groups %s;",
    where_clause->str);

  // Delete agent_group_agents_trash entries for trashed groups with the scanner
  sql (
    "DELETE FROM agent_group_agents_trash "
    "WHERE agent_group IN (SELECT id FROM agent_groups_trash %s);",
    where_clause->str);

  // Delete agent_groups_trash entries
  sql (
    "DELETE FROM agent_groups_trash %s;",
    where_clause->str);

  sql_commit ();

  g_string_free (where_clause, TRUE);
}

/**
 * @brief Retrieve the UUID of the current agent in the agent group agent iterator.
 *
 * @param[in] iterator The iterator positioned at the current agent row.
 *
 * @return A pointer to the UUID string, or NULL if not available.
 */
const char *
agent_group_agent_iterator_uuid (iterator_t *iterator)
{
  return iterator_string (iterator, 0);
}

/**
 * @brief Retrieve the name of the current agent in the agent group agent iterator.
 *
 * @param[in] iterator The iterator positioned at the current agent row.
 *
 * @return A pointer to the agent name string, or NULL if not available.
 */
const char *
agent_group_agent_iterator_name (iterator_t *iterator)
{
  return iterator_string (iterator, 1);
}

#endif // ENABLE_AGENTS
