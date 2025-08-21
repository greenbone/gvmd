/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Common utilities for agent management in GVMD.
 *
 * This header provides shared data structures and utility functions
 * used by both the agent and agent group management.
 */

#if ENABLE_AGENTS
#ifndef _GVMD_MANAGE_AGENT_COMMON_H
#define _GVMD_MANAGE_AGENT_COMMON_H

#include "iterator.h"
#include "manage_get.h"
#include "manage_resources.h"

#include <agent_controller/agent_controller.h>
#include <glib.h>

/**
 * @struct gvmd_agent_connector
 * @brief Holds scanner context and base agent controller connection.
 */
struct gvmd_agent_connector
{
  agent_controller_connector_t base; ///< Original gvm-libs connector
  scanner_t scanner_id;              ///< GVMD-specific scanner id
};
typedef struct gvmd_agent_connector *gvmd_agent_connector_t;

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

gvmd_agent_connector_t
gvmd_agent_connector_new_from_scanner (scanner_t scanner);

void
gvmd_agent_connector_free (gvmd_agent_connector_t conn);

agent_uuid_list_t
agent_uuid_list_new (int count);

void
agent_uuid_list_free (agent_uuid_list_t uuid_list);

gchar *
concat_error_messages (const GPtrArray *errors, const gchar *sep);

#endif // _GVMD_MANAGE_AGENT_COMMON_H
#endif // ENABLE_AGENTS
