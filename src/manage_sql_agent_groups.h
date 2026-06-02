/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief SQL management functions and iterator definitions for agent groups.
 *
 * This header provides iterator macros and function declarations used
 * for managing agent groups in the SQL layer of GVMD, including support
 * for trashcan handling and restoration.
 */

#if ENABLE_AGENTS
#ifndef _GVMD_MANAGE_SQL_AGENT_GROUPS_H
#define _GVMD_MANAGE_SQL_AGENT_GROUPS_H


#include "manage_agent_groups.h"

#define AGENT_GROUP_ITERATOR_FILTER_COLUMNS \
{                                           \
  GET_ITERATOR_FILTER_COLUMNS,              \
  "scanner_name",                           \
  "scanner_id",                             \
  "scheduler_cron_time",                    \
  NULL                                      \
}

#define AGENT_GROUP_ITERATOR_COLUMNS                          \
{                                                             \
  GET_ITERATOR_COLUMNS (agent_groups),                        \
  { "scanner", NULL, KEYWORD_TYPE_INTEGER },                  \
  { "scanner_name", "scanner_name", KEYWORD_TYPE_STRING },    \
  { "scanner_uuid", "scanner_id", KEYWORD_TYPE_STRING },      \
  { "scheduler_cron_time", NULL, KEYWORD_TYPE_STRING },       \
  { NULL,      NULL, KEYWORD_TYPE_UNKNOWN }                   \
}

#define AGENT_GROUP_ITERATOR_TRASH_COLUMNS                    \
{                                                             \
  GET_ITERATOR_COLUMNS (agent_groups_trash),                  \
  { "scanner", NULL, KEYWORD_TYPE_INTEGER },                  \
  { "scanner_name", "scanner_name", KEYWORD_TYPE_STRING },    \
  { "scanner_uuid", "scanner_id", KEYWORD_TYPE_STRING },      \
  { "scheduler_cron_time", NULL, KEYWORD_TYPE_STRING },       \
  { NULL,      NULL, KEYWORD_TYPE_UNKNOWN }                   \
}

agent_group_resp_t
create_agent_group (agent_group_data_t, agent_uuid_list_t);

agent_group_resp_t
modify_agent_group (agent_group_t,
                    agent_group_data_t,
                    agent_uuid_list_t);

agent_group_resp_t
get_agent_group (agent_group_t , agent_group_data_t *);

agent_group_resp_t
get_agent_group_agent_uuids (agent_group_t,
                             agent_uuid_list_t *);

int
restore_agent_group (const char *);

void
empty_trashcan_agent_groups (void);

int
agent_group_schedule_cron_times_for_agent_uuid (const gchar *,
                                                GPtrArray **);

#endif // not _GVMD_MANAGE_SQL_AGENT_GROUPS_H
#endif // ENABLE_AGENTS
