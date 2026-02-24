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

#include "manage_agents.h"
#include "manage_sql.h"

/**
 * @brief Agent iterator columns.
 */
#define AGENT_ITERATOR_COLUMNS                                              \
  {                                                                         \
    GET_ITERATOR_COLUMNS (agents), {"agent_id", NULL, KEYWORD_TYPE_STRING}, \
      {"hostname", NULL, KEYWORD_TYPE_STRING},                              \
      {"authorized", NULL, KEYWORD_TYPE_INTEGER},                           \
      {"connection_status", NULL, KEYWORD_TYPE_STRING},                     \
      {"last_update", NULL, KEYWORD_TYPE_INTEGER},                          \
      {"last_updater_heartbeat", NULL, KEYWORD_TYPE_INTEGER},               \
      {"config", NULL, KEYWORD_TYPE_STRING},                                \
      {"scanner", NULL, KEYWORD_TYPE_INTEGER},                              \
      {"updater_version", NULL, KEYWORD_TYPE_STRING},                       \
      {"agent_version", NULL, KEYWORD_TYPE_STRING},                         \
      {"operating_system", NULL, KEYWORD_TYPE_STRING},                      \
      {"architecture", NULL, KEYWORD_TYPE_STRING},                          \
      {"update_to_latest", NULL, KEYWORD_TYPE_INTEGER},                     \
      {"agent_update_available", NULL, KEYWORD_TYPE_INTEGER},               \
      {"updater_update_available", NULL, KEYWORD_TYPE_INTEGER},             \
      {"latest_agent_version", NULL, KEYWORD_TYPE_STRING},                  \
      {"latest_updater_version", NULL, KEYWORD_TYPE_STRING},                \
    {                                                                       \
      NULL, NULL, KEYWORD_TYPE_UNKNOWN                                      \
    }                                                                       \
  }

/**
 * @brief Filter columns for agent iterator.
 */
#define AGENT_ITERATOR_FILTER_COLUMNS                                          \
  {                                                                            \
    "uuid", "agent_id", "name", "hostname", "scanner", "authorized",           \
      "min_interval", "last_update", "last_updater_heartbeat", "comment",      \
      "creation_time", "modification_time", "owner", "id", "updater_version",  \
      "agent_version", "operating_system", "architecture", "update_to_latest", \
      "agent_update_available", "updater_update_available",                    \
      "latest_agent_version", "latest_updater_version", "connection_status",   \
      NULL                                                                     \
  }

int
sync_agents_from_data_list (agent_data_list_t agent_list);

void
update_agents_comment (agent_uuid_list_t agent_uuids, const gchar *new_comment);

int
get_scanner_from_agent_uuid (const gchar *agent_uuid, scanner_t *scanner);

int
agent_id_by_uuid_and_scanner (const gchar *agent_uuid, scanner_t scanner_id,
                              agent_t *agent_id);

gboolean
agent_authorized (const gchar *agent_uuid, scanner_t scanner_id);

#endif // not _GVMD_MANAGE_SQL_AGENTS_H
#endif // ENABLE_AGENTS
