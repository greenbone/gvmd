/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief SQL interaction layer for agent data in GVMD.
 *
 * This header defines SQL-related operations for managing agents,
 * including synchronization from agent data lists and updating
 * agent metadata (e.g., comments). It also defines column and filter
 * macros for iterating over agent records in the database.
 */

#if ENABLE_AGENTS
#ifndef _GVMD_MANAGE_SQL_AGENTS_H
#define _GVMD_MANAGE_SQL_AGENTS_H

#include "manage_sql.h"
#include "manage_agents.h"

/**
 * @brief Agent iterator columns.
 */
#define AGENT_ITERATOR_COLUMNS                                               \
{                                                                            \
  GET_ITERATOR_COLUMNS     (agents),                                         \
  { "agent_id",            NULL, KEYWORD_TYPE_STRING  },                     \
  { "hostname",            NULL, KEYWORD_TYPE_STRING  },                     \
  { "authorized",          NULL, KEYWORD_TYPE_INTEGER },                     \
  { "min_interval",        NULL, KEYWORD_TYPE_INTEGER },                     \
  { "heartbeat_interval",  NULL, KEYWORD_TYPE_INTEGER },                     \
  { "connection_status",   NULL, KEYWORD_TYPE_STRING  },                     \
  { "last_update",         NULL, KEYWORD_TYPE_INTEGER },                     \
  { "schedule",            NULL, KEYWORD_TYPE_STRING  },                     \
  { "scanner",             NULL, KEYWORD_TYPE_INTEGER },                     \
  { NULL,                  NULL, KEYWORD_TYPE_UNKNOWN }                      \
}

/**
 * @brief Filter columns for agent iterator.
 */
#define AGENT_ITERATOR_FILTER_COLUMNS         \
{                                             \
  "uuid",                                     \
  "agent_id",                                 \
  "name",                                     \
  "hostname",                                 \
  "scanner",                                  \
  "authorized",                               \
  "min_interval",                             \
  "heartbeat_interval",                       \
  "connection_status",                        \
  "last_update",                              \
  "schedule",                                 \
  "comment",                                  \
  "creation_time",                            \
  "modification_time",                        \
  "owner",                                    \
  "id",                                       \
  NULL                                        \
}

int
sync_agents_from_data_list (agent_data_list_t agent_list);

void
update_agents_comment (agent_uuid_list_t agent_uuids, const gchar *new_comment);

int
get_scanner_from_agent_uuid(const gchar *agent_uuid, scanner_t *scanner);

int
agent_id_by_uuid_and_scanner (const gchar *agent_uuid, scanner_t scanner_id, agent_t *agent_id);

#endif //_GVMD_MANAGE_SQL_AGENTS_H
#endif // ENABLE_AGENTS