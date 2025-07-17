/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file manage_sql_agent_groups.h
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
#include "manage_sql.h"

#define AGENT_GROUP_ITERATOR_FILTER_COLUMNS \
{                                           \
  GET_ITERATOR_FILTER_COLUMNS,              \
  "scanner",                                \
  NULL                                      \
}

#define AGENT_GROUP_ITERATOR_COLUMNS                  \
{                                                     \
  GET_ITERATOR_COLUMNS (agent_groups),                \
  { "scanner", NULL, KEYWORD_TYPE_INTEGER },          \
  { NULL,      NULL, KEYWORD_TYPE_UNKNOWN }           \
}

#define AGENT_GROUP_ITERATOR_TRASH_COLUMNS             \
{                                                      \
  GET_ITERATOR_COLUMNS (agent_groups_trash),           \
  { NULL,      NULL, KEYWORD_TYPE_UNKNOWN }            \
}

int
restore_agent_group (const char *agent_group_uuid);

void
empty_trashcan_agent_groups (void);

#endif // _GVMD_MANAGE_SQL_AGENT_GROUPS_H
#endif // ENABLE_AGENTS
