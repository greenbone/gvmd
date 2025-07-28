/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file manage_agent_groups.c
 * @brief Agent group data utilities and access control checks for GVMD.
 */

#if ENABLE_AGENTS
#include "manage_agent_groups.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

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
  g_free (data);
}

#endif //ENABLE_AGENTS