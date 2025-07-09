/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file manage_sql_agent_groups.c
 * @brief SQL backend implementation for agent group management in GVMD.
 *
 * This file provides the implementation of SQL interactions related to
 * agent data, including creation, update, deletion, and synchronization
 * with the Agent Controller. It supports both direct SQL operations and
 * optimized bulk operations using PostgreSQL COPY. Functions are also provided
 * for iterating agent data and handling agent IP address relationships.
 */

#include "manage_sql_agent_groups.h"
#include "manage_sql_copy.h"
#include <util/uuidutils.h>

#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Return the UUID of an agent group.
 *
 * @param[in]  agent_group  The Agent group whose UUID should be fetched.
 *
 * @return Newly allocated UUID if available, else NULL.
 */
char*
agent_group_uuid (agent_group_t agent_group)
{
  return sql_string ("SELECT uuid FROM agent_groups WHERE id = %llu;",
                     agent_group);
}

/**
 * @brief Return the name of an agent group.
 *
 * @param[in]  agent_group  The Agent group whose name should be fetched.
 *
 * @return the name of an agent group if available, else NULL.
 */
const char *
agent_iterator_name (iterator_t *iterator)
{
  return iterator_string (iterator, GET_ITERATOR_COLUMN_COUNT + 1);
}

/**
 * @brief Return the comment of an agent group.
 *
 * @param[in]  agent_group  The Agent group whose comment should be fetched.
 *
 * @return the comment of an agent group if available, else NULL.
 */
const char *
agent_iterator_comment (iterator_t *iterator)
{
  return iterator_string (iterator, GET_ITERATOR_COLUMN_COUNT + 2);
}

/**
 * @brief Return the agent controller id of an agent group.
 *
 * @param[in]  agent_group  The Agent group whose controller id should be fetched.
 *
 * @return the controller id of an agent group if available, else NULL.
 */
const char *
agent_iterator_controller_id (iterator_t *iterator)
{
  return iterator_string (iterator, GET_ITERATOR_COLUMN_COUNT + 3);
}

/**
 * @brief Count number of agent groups.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of agent groups in filtered set.
 */
int
agent_group_count (const get_data_t *get)
{
    static const char *extra_columns = AGENT_GROUP_ITERATOR_FILTER_COLUMNS;
    static column_t columns[] = AGENT_GROUP_ITERATOR_COLUMNS;
    static column_t trash_columns[] = AGENT_GROUP_ITERATOR_TRASH_COLUMNS;

    return count("agent_group", get, columns, trash_columns, extra_columns, 0,
                 0, 0, TRUE);
}

/**
 * @brief Init an agen group iterator
 * 
 * @param[in] iterator the iterator
 * @param[in] get      the data
 * 
 * @return 0 success, 1 failed to find agent group, 2 failed to find filter,
 *         -1 error.
 */
int
init_agent_group_iterator (iterator_t iterator, get_data_t *get)
{
    static const char *filter_columns[] = AGENT_GROUP_ITERATOR_FILTER_COLUMNS;
    static column_t columns[] = AGENT_GROUP_ITERATOR_COLUMNS;
    static column_t trash_columns[] = AGENT_GROUP_ITERATOR_TRASH_COLUMNS;

    return init_get_iterator (iterator,
                              "agent_group",
                              get,
                              columns,
                              trash_columns,
                              filter_columns,
                              0,
                              NULL,
                              NULL,
                              TRUE);
}

/**
 * @brief Create an agent group from an existing agent group.
 *
 * @param[in]  comment     Comment for the new agent group.  NULL to copy from existing.
 * @param[in]  agent_group_id   UUID of existing agent group.
 * @param[out] new_agent_group  New agent group.
 *
 * @return 0 success, 1 agent group exists already, 2 failed to find existing
 *         agent group, 99 permission denied, -1 error.
 */
int
copy_agent_group (const char *comment, const char *agent_group_id, 
                  agent_group_t *new_agent_group)
{
    int ret;
    agent_group_t old_group;

    assert (new_agent_group);

    ret = copy_resource("agent_group", NULL, comment, agent_group_id,
                        "controller_id", 0, new_agent_group, &old_agent_group);

    if (ret)
        return ret;

    return 0;
}

/**
 * @brief Create an agent group.
 *
 * @param[in]   name            Name of the agent_group.
 * @param[in]   comment         Comment on agent_group
 * @param[in]   controller_id   the id of the controller the agent is associated to.
 * @param[out]  ticket          Created agent group.
 *
 * @return 0 success, 99 permission to create ticket denied, -1 error.
 */
int
create_agent_group (const char *name, const char *comment,
                    const char *controller_id, agent_group_t *agent_group)
{
    agent_group_t new_agent_group;

    gchar *quoted_name, *quoted_comment, *quoted_controller_id;
    char *new_agent_group_id;
    int ret;

    sql_begin_immediate ();

    if (acl_user_may ("create_agent_group") == 0)
        {
            sql_rollback ();
            return 99;
        }

    if (comment)
        quoted_comment = sql_quote (comment);
    else
        quoted_comment = sql_quote ("");

    quoted_name = sql_quote (name);
    quoted_controller_id = sql_quote (controller_id);

    sql ("INSERT INTO agent_groups"
         " (uuid, name, comment, controller_id, creation_time, "
         "  modification_time)"
         " VALUES"
         " (make_uuid (), '%s', '%s', '%s', m_now (), m_now ());"
         quote_name,
         quote_comment,
         quote_controller_id);

    g_free (quoted_name);
    g_free (quote_comment);
    g_free (quote_controller_id);

    new_agent_group = sql_last_insert_id ();
    if (agent_group)
        *agent_group = new_agent_group;

    sql_comment ();

    return 0;
}

/**
 * @brief Modify an agent_group.
 *
 * @param[in]   agent_group_id  UUID of the agent group to update.
 * @param[in]   name            Name of the agent_group.
 * @param[in]   comment         Comment on agent_group
 * @param[in]   controller_id   the id of the controller the agent is associated to.
 *
 * @return 0 success, 2 failed to find agent group, 99 permission denied,
 *         -1 error.
 */
int
modify_agent_group (const char *agent_group_id, const char *name,
                    const char *comment, const char *controller_id)
{
    agent_group_t agent_group;
    int updated;
    gchar *quoted_name, *quoted_comment, *quoted_controller_id;

    assert (agent_group_id);

    sql_begin_immediate ();

    updated = 0;

    if (acl_user_may ("modify_agent_group") == 0)
        {
            sql_rollback ();
            return 99;
        }

    agent_group = 0;
    if (find_resource_with_permission ("agent_group", agent_group_id,
                                       &agent_group, "modify_agent_group", 0))
        {
            sql_rollback ();
            return -1;
        }

    if (agent_group == 0)
        {
            sql_rollback ();
            return 2;
        }

    quoted_name = sql_quote (name);
    quoted_controller_id = sql_quote (controller_id);

    if (comment)
        {
            quoted_comment = sql_quote (comment);
            sql ("UPDATE agent_groups SET"
                 " name = '%s',"
                 " controller_id = '%s',"
                 " comment = '%s',"
                 " modification_time = m_now ()"
                 " WHERE id = %llu;",
                 quoted_name,
                 quoted_controller_id,
                 quoted_comment,
                 agent_group);
            
            updated = 1;
        }
    else
        {
            sql ("UPDATE agent_groups SET"
                 " name = '%s',"
                 " controller_id = '%s',"
                 " modification_time = m_now ()"
                 " WHERE id = %llu;",
                 quoted_name,
                 quoted_controller_id,
                 agent_group);
            
            updated = 1;
        }

    sql_commit ();
    
    return 0;
}

/**
 * @brief Delete an agent_group or move it to the trashcan, depending on 
 * ultimate flag.
 *
 * @param[in]   agent_group_id  UUID of the agent group to update.
 * @param[in]   ultimate        A flag for whether or not the Agent Group is
 *                              truly deleted or only moved to the trashcan.
 *
 * @return 0 success, 2 failed to find agent group, 99 permission denied,
 *         -1 error.
 */
delete_agent_group (const char *agent_group_id, int ultimate)
{
        agent_group_t agent_group = 0;

        sql_begin_immediate ();

        if (acl_user_may ("delete_agent_group") == 0)
            {
                sql_rollback ();
                return 99;
            }

        if (find_resource_with_permission ("agent_group", agent_group_id,
                                           &agent_group, "modify_agent_group", 0))
        {
            sql_rollback ();
            return -1;
        }

    if (agent_group == 0)
        {
            if (find_trash ("agent_gorup", agent_group_id, &agent_group))
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
                    /* agent group is already in trashcan */
                    sql_comment ();
                    return 0;
                }
        }

    if (ultimate == 0)
        {
            sql ("INSERT INTO agent_groups"
                 " (uuid, name, comment, controller_id, creation_time, "
                 "  modification_time)"
                 " VALUES"
                 " SELECT uuid, name, comment, controller_id, creation_time,"
                 "        modification_time "
                 " FROM agent_groups "
                 " WHERE id = %llu;",
                 agent_group_id);
        }
    
    sql ("DELETE FROM agent_groups WHERE id = %llu;", agent_group);

    sql_commit ();
    return 0;
}

/**
 * @brief Empty agent group trashcan
 */
void
empty_trashcan_agent_groups ()
{
    sql ("DELETE FROM agent_groups_trash"
         " WHERE owner (SELECT id FROM users WHERE uuid = '%s');"
         current_credentials.uuid);
}