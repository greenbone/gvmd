/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Agent management interface for GVMD.
 *
 * This header defines core data structures and function prototypes
 * for handling agent data within GVMD, including agent retrieval,
 * modification, synchronization, and filtering. It also provides
 * interfaces for interacting with the agent controller and agent-related
 * iteration and query logic.
 */

#if ENABLE_AGENTS
#ifndef _GVMD_MANAGE_AGENTS_H
#define _GVMD_MANAGE_AGENTS_H

/**
 * @brief Agent support bundle buffer sizes.
 */
#define AGENT_SUPPORT_BUNDLE_READ_BUFFER_SIZE 4096
#define AGENT_SUPPORT_BUNDLE_BASE64_BUFFER_SIZE \
(((AGENT_SUPPORT_BUNDLE_READ_BUFFER_SIZE + 2) / 3) * 4 + 16)

#include "iterator.h"
#include "manage_agent_common.h"

#include <agent_controller/agent_controller.h>

/**
 * @brief Represents a single IP address associated with an agent.
 */
struct agent_ip_data
{
  gchar *ip_address;
};
typedef struct agent_ip_data *agent_ip_data_t;

/**
 * @brief Represents a list of IP addresses for an agent.
 */
struct agent_ip_data_list
{
  int count;
  agent_ip_data_t *items;
};
typedef struct agent_ip_data_list *agent_ip_data_list_t;

/**
 * @brief Represents metadata and configuration details for a single agent.
 */
struct agent_data
{
  agent_t row_id;
  gchar *uuid;
  gchar *name;
  gchar *agent_id;
  gchar *hostname;
  int authorized;
  gchar *connection_status;
  agent_ip_data_list_t ip_addresses;
  int ip_address_count;
  time_t creation_time;
  time_t modification_time;
  time_t last_update_agent_control;
  time_t last_updater_heartbeat;
  agent_controller_agent_config_t config;
  gchar *comment;
  user_t owner;
  scanner_t scanner;
  gchar *updater_version;
  gchar *agent_version;
  gchar *operating_system;
  gchar *architecture;
  int update_to_latest;
  int agent_update_available;
  int updater_update_available;
  gchar *latest_agent_version;
  gchar *latest_updater_version;
};
typedef struct agent_data *agent_data_t;

/**
 * @brief A collection of agent data.
 */
struct agent_data_list
{
  int count;            ///< Number of agents in the list
  agent_data_t *agents; ///< Array of pointers to agents
};
typedef struct agent_data_list *agent_data_list_t;

typedef enum
{
  AGENT_RESPONSE_SUCCESS = 0,                ///< Success
  AGENT_RESPONSE_NO_AGENTS_PROVIDED = -1,    ///< No agent UUIDs provided
  AGENT_RESPONSE_SCANNER_LOOKUP_FAILED = -2, ///< Scanner lookup failed
  AGENT_RESPONSE_AGENT_SCANNER_MISMATCH = -3, ///< Agent list count mismatch (not same scanner)
  AGENT_RESPONSE_CONNECTOR_CREATION_FAILED = -4, ///< Failed to create connector
  AGENT_RESPONSE_CONTROLLER_UPDATE_FAILED = -5,  ///< Failed to update agents
  AGENT_RESPONSE_CONTROLLER_DELETE_FAILED = -6,  ///< Failed to delete agents
  AGENT_RESPONSE_SYNC_FAILED = -7,               ///< Failed during sync
  AGENT_RESPONSE_INVALID_ARGUMENT = -8,          ///< Failed invalid argument
  AGENT_RESPONSE_INVALID_AGENT_OWNER = -9,       ///< Failed getting owner UUID
  AGENT_RESPONSE_AGENT_NOT_FOUND = -10,          ///< Failed getting owner UUID
  AGENT_RESPONSE_INTERNAL_ERROR = -11,           ///< Internal error
  AGENT_RESPONSE_IN_USE_ERROR = -12, ///< Agent is used by an Agent Group
  AGENT_RESPONSE_CONTROLLER_UPDATE_REJECTED = -13, ///< Agent update validation error
  AGENT_RESPONSE_DOWNLOAD_FAILED = -14 ///< Agent support bundle download failed
} agent_response_t;

void
agent_ip_data_list_free (agent_ip_data_list_t);

void
agent_data_free (agent_data_t);

agent_ip_data_list_t
agent_ip_data_list_new (int);

void
agent_ip_data_free (agent_ip_data_t);

void
agent_data_list_free (agent_data_list_t);

agent_response_t
sync_agents_from_agent_controller (gvmd_agent_connector_t);

agent_response_t
get_agents_by_scanner_and_uuids (scanner_t, agent_uuid_list_t,
                                 agent_data_list_t);

agent_response_t
modify_and_resync_agents (agent_uuid_list_t,
                          agent_controller_agent_update_t,
                          const gchar *,
                          GPtrArray **);

agent_response_t
modify_and_resync_agents_with_update_list (scanner_t,
                                           agent_controller_agent_update_list_t,
                                           GPtrArray **);

agent_controller_agent_config_t
copy_agent_controller_scan_agent_config (agent_controller_agent_config_t);

agent_response_t
delete_and_resync_agents (agent_uuid_list_t);

int
manage_agents_sync_from_agent_controllers (gboolean *);

agent_response_t
get_agent_support_bundle (const gchar *, int,
                          agent_controller_support_bundle_t *);

int
init_agent_iterator (iterator_t *iterator, get_data_t *);

void
init_agent_uuid_list_iterator (iterator_t *,
                               agent_uuid_list_t);

agent_ip_data_list_t
load_agent_ip_addresses (const gchar *);

const gchar *
agent_iterator_agent_id (iterator_t *);

const gchar *
agent_iterator_hostname (iterator_t *);

const gchar *
agent_iterator_connection_status (iterator_t *);

const gchar *
agent_iterator_config (iterator_t *);

int
agent_iterator_authorized (iterator_t *);

time_t
agent_iterator_last_update (iterator_t *);

time_t
agent_iterator_last_updater_heartbeat (iterator_t *);

scanner_t
agent_iterator_scanner (iterator_t *);

const gchar *
agent_iterator_updater_version (iterator_t *);

const gchar *
agent_iterator_agent_version (iterator_t *);

const gchar *
agent_iterator_operating_system (iterator_t *);

const gchar *
agent_iterator_architecture (iterator_t *);

int
agent_iterator_update_to_latest (iterator_t *);

int
agent_iterator_agent_update_available (iterator_t *);

int
agent_iterator_updater_update_available (iterator_t *);

const gchar*
agent_iterator_latest_agent_version (iterator_t*);

const gchar*
agent_iterator_latest_updater_version (iterator_t*);

const gchar*
agent_iterator_scanner_name (iterator_t*);

const gchar*
agent_iterator_scanner_uuid (iterator_t*);

int
agent_count (const get_data_t *);

int
agent_writable (agent_t);

int
agent_in_use (agent_t);

void
delete_agents_by_scanner_and_uuids (scanner_t,
                                    agent_uuid_list_t);

gboolean
agents_in_use (agent_uuid_list_t);

agent_response_t
get_agent_controller_agents_from_uuids (scanner_t,
                                        agent_uuid_list_t,
                                        agent_controller_agent_list_t);

const gchar *
agent_response_to_string (agent_response_t);

gchar *
agent_id_by_uuid (const gchar *);

scanner_t
agent_scanner_id_by_uuid (const gchar *);

#endif // not _GVMD_MANAGE_AGENTS_H
#endif // ENABLE_AGENTS
