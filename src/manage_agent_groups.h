/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Agent group management interface for GVMD.
 *
 * This header defines core data structures and function prototypes
 * for managing agent groups within GVMD, including creation, modification,
 * deletion, and membership listing. It also provides iterator-based access
 * for frontend filtering and listing.
 */

#if ENABLE_AGENTS
#ifndef _GVMD_MANAGE_AGENT_GROUPS_H
#define _GVMD_MANAGE_AGENT_GROUPS_H

#include "iterator.h"
#include "manage_agent_common.h"
#include "manage_get.h"
#include "manage_resources.h"

/**
 * @struct agent_group_data
 * @brief Represents an agent group and its metadata.
 */
struct agent_group_data
{
  agent_group_t row_id;
  gchar *uuid;
  gchar *name;
  gchar *comment;
  user_t owner;
  scanner_t scanner;
  time_t creation_time;
  time_t modification_time;
};
typedef struct agent_group_data *agent_group_data_t;

typedef enum {
    AGENT_GROUP_RESP_SUCCESS = 0,                       ///< Success
    AGENT_GROUP_RESP_NO_AGENTS_PROVIDED = -1,           ///< No agent UUIDs provided
    AGENT_GROUP_RESP_SCANNER_NOT_FOUND = -2,            ///< Scanner not found
    AGENT_GROUP_RESP_SCANNER_PERMISSION = -3,           ///< Permission issue for getting Scanner
    AGENT_GROUP_RESP_AGENT_SCANNER_MISMATCH = -4,       ///< Agent list count mismatch (not same scanner)
    AGENT_GROUP_RESP_INVALID_ARGUMENT = -5,             ///< Failed invalid argument
    AGENT_GROUP_RESP_AGENT_NOT_FOUND = -6,              ///< Failed getting agent id
    AGENT_GROUP_RESP_INTERNAL_ERROR = -7,               ///< Internal error
    AGENT_GROUP_RESP_AGENT_UNAUTHORIZED = -8            ///< Failed to create group with unauthorized agent
  } agent_group_resp_t;

agent_group_data_t
agent_group_data_new ();

void
agent_group_data_free (agent_group_data_t data);

agent_group_resp_t
create_agent_group (agent_group_data_t group_data,
                    agent_uuid_list_t agent_uuids);

agent_group_resp_t
modify_agent_group (agent_group_t agent_group,
                    agent_group_data_t group_data,
                    agent_uuid_list_t agent_uuids);

int
delete_agent_group (const gchar *agent_group_uuid, int ultimate);

int
agent_group_count (const get_data_t *get);

int
init_agent_group_iterator (iterator_t *iterator, get_data_t *get);

scanner_t
agent_group_iterator_scanner (iterator_t *iterator);

const char*
agent_group_iterator_scanner_name (iterator_t *iterator);

const char*
agent_group_iterator_scanner_id (iterator_t *iterator);

int
copy_agent_group (const char *name,
                  const char *comment,
                  const char *group_uuid,
                  agent_group_t *new_group_return);

char *
agent_group_uuid (agent_group_t group_id);

agent_group_t
agent_group_id_by_uuid (const gchar *agent_group_uuid);

int
agent_group_in_use (agent_group_t);

int
trash_agent_group_in_use (agent_group_t);

int
agent_group_writable (agent_group_t);

int
trash_agent_group_writable (agent_group_t);

void
delete_agent_groups_by_scanner (scanner_t scanner);

void
init_agent_group_agents_iterator (iterator_t *iterator,
                                  agent_group_t group_id);

const char*
agent_group_agent_iterator_uuid (iterator_t *iterator);

const char*
agent_group_agent_iterator_name (iterator_t *iterator);

gboolean
find_agent_group_with_permission (const char* uuid, agent_group_t* agent_group,
                                  const char *permission);

scanner_t
agent_group_scanner (agent_group_t agent_group);

#endif // _GVMD_MANAGE_AGENT_GROUPS_H
#endif // ENABLE_AGENTS
