/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file manage_sql_agent_groups.h
 * @brief SQL interaction layer for agent data in GVMD.
 *
 * Includes SQL related operations and defintions which are used to make
 * agent group queries and statements calls in the database.
 */

#ifndef _GVMD_MANAGE_SQL_AGENT_GROUPS_H
#define _GVMD_MANAGE_SQL_AGENT_GROUPS_H

#include "manage.h"

/**
 * @brief Columns used by the agent group iterator for filtering
 */
#define AGENT_GROUP_ITERATOR_FILTER_COLUMNS   \
{                                             \
    GET_ITERATOR_FILTER_COLUMNS,              \
    "installer",                              \
    NULL                                      \
}

/**
 * @brief Columns used by the agent group iterator for fetching data
 */
#define AGENT_GROUP_ITERATOR_COLUMNS                                \
{                                                                   \
    GET_ITERATOR_COLUMNS (agent_groups),                            \
    {                                                               \
      "(SELECT uuid FROM agent_installers WHERE id = installer)",   \
      NULL,                                                         \
      KEYWORD_TYPE_STRING                                           \
    },                                                              \
}

/**
 * @brief Columns used by the agent group iterator for fetching data in trash
 */
#define AGENT_GROUP_ITERATOR_TRASH_COLUMNS                          \
{                                                                   \
    GET_ITERATOR_COLUMNS (agent_groups_trash),                      \
    {                                                               \
      "(SELECT uuid FROM agent_installers WHERE id = installer)",   \
      NULL,                                                         \
      KEYWORD_TYPE_STRING                                           \
    },                                                              \
}

/**
 * @brief Is the trashcan agent gorup writable or not
 * 
 * @param[in] agent_group   The Agent Group
 * 
 * @return 1, if writable else 0
 */
int
trash_agent_group_writable (agent_group_t);