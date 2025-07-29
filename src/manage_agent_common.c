/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Implementation of shared agent utilities for GVMD.
 */

#if ENABLE_AGENTS
#include "manage_agent_common.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Allocate and initialize a new agent_uuid_list_t structure.
 *
 * @param[in] count Number of UUID entries to allocate.
 *
 * @return A newly allocated agent_uuid_list_t, or NULL on allocation failure.
 */
agent_uuid_list_t
agent_uuid_list_new (int count)
{
    if (count <= 0)
        return NULL;

    agent_uuid_list_t list = g_malloc0 (sizeof (struct agent_uuid_list));

    list->count = count;
    list->agent_uuids = g_malloc0 (sizeof (gchar *) * (count + 1));

    return list;
}

/**
 * @brief Free an agent_uuid_list_t and its contents.
 *
 * @param[in] uuid_list List of agent UUIDs to free.
 */
void
agent_uuid_list_free (agent_uuid_list_t uuid_list)
{
    if (!uuid_list)
        return;

    for (int i = 0; i < uuid_list->count; ++i)
        g_free (uuid_list->agent_uuids[i]);

    g_free (uuid_list->agent_uuids);
    g_free (uuid_list);
}

#endif // ENABLE_AGENTS