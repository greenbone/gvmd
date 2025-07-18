/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file manage_agent_common.h
 * @brief Common utilities for agent management in GVMD.
 *
 * This header provides shared data structures and utility functions
 * used by both the agent and agent group management.
 */

#if ENABLE_AGENTS
#ifndef _GVMD_MANAGE_AGENT_COMMON_H
#define _GVMD_MANAGE_AGENT_COMMON_H

#include <glib.h>

/**
 * @struct agent_uuid_list
 * @brief A structure to store a list of agent UUIDs.
 */
struct agent_uuid_list
{
    int count;           ///< Number of UUIDs in the list
    gchar **agent_uuids; ///< Array of UUID strings
};
typedef struct agent_uuid_list *agent_uuid_list_t;

agent_uuid_list_t
agent_uuid_list_new (int count);

void
agent_uuid_list_free (agent_uuid_list_t uuid_list);

#endif // _GVMD_MANAGE_AGENT_COMMON_H
#endif // ENABLE_AGENTS
