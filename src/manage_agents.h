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

#include "iterator.h"
#include "manage_agent_common.h"

#include <agent_controller/agent_controller.h>

typedef resource_t agent_t;

/**
 * @struct agent_ip_data
 * @brief Represents a single IP address associated with an agent.
 */
struct agent_ip_data
{
  gchar *ip_address;
};
typedef struct agent_ip_data *agent_ip_data_t;

/**
 * @struct agent_ip_data_list
 * @brief Represents a list of IP addresses for an agent.
 */
struct agent_ip_data_list
{
  int count;
  agent_ip_data_t *items;
};
typedef struct agent_ip_data_list *agent_ip_data_list_t;

/**
 * @struct agent_data
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
  agent_controller_scan_agent_config_t config;
  gchar *comment;
  user_t owner;
  scanner_t scanner;
  gchar *updater_version;
  gchar *agent_version;
  gchar *operating_system;
  gchar *architecture;
  int update_to_latest;
};
typedef struct agent_data *agent_data_t;

/**
 * @struct agent_data_list
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
  AGENT_RESPONSE_CONTROLLER_UPDATE_REJECTED = -13 ///< Agent update validation error
} agent_response_t;

void
agent_ip_data_list_free (agent_ip_data_list_t ip_list);

void
agent_data_free (agent_data_t data);

agent_ip_data_list_t
agent_ip_data_list_new (int count);

void
agent_ip_data_free (agent_ip_data_t ip_data);

void
agent_data_list_free (agent_data_list_t agents);

agent_response_t
sync_agents_from_agent_controller (gvmd_agent_connector_t connector);

agent_response_t
get_agents_by_scanner_and_uuids (scanner_t scanner, agent_uuid_list_t uuid_list,
                                 agent_data_list_t out_list);

agent_response_t
modify_and_resync_agents (agent_uuid_list_t agent_uuids,
                          agent_controller_agent_update_t agent_update,
                          const gchar *comment,
                          GPtrArray **errors);

agent_response_t
delete_and_resync_agents (agent_uuid_list_t agent_uuids);

int
init_agent_iterator (iterator_t *iterator, get_data_t *get);

void
init_agent_uuid_list_iterator (iterator_t *iterator,
                               agent_uuid_list_t uuid_list);

agent_ip_data_list_t
load_agent_ip_addresses (const gchar *agent_id);

const gchar *
agent_iterator_agent_id (iterator_t *iterator);

const gchar *
agent_iterator_hostname (iterator_t *iterator);

const gchar *
agent_iterator_connection_status (iterator_t *iterator);

const gchar *
agent_iterator_config (iterator_t *iterator);

int
agent_iterator_authorized (iterator_t *iterator);

time_t
agent_iterator_last_update (iterator_t *iterator);

time_t
agent_iterator_last_updater_heartbeat (iterator_t *iterator);

scanner_t
agent_iterator_scanner (iterator_t *iterator);

const gchar *
agent_iterator_updater_version (iterator_t *iterator);

const gchar *
agent_iterator_agent_version (iterator_t *iterator);

const gchar *
agent_iterator_operating_system (iterator_t *iterator);

const gchar *
agent_iterator_architecture (iterator_t *iterator);

int
agent_iterator_update_to_latest (iterator_t *iterator);

int
agent_count (const get_data_t *get);

int
agent_writable (agent_t agent);

int
agent_in_use (agent_t agent);

void
delete_agents_by_scanner_and_uuids (scanner_t scanner,
                                    agent_uuid_list_t agent_uuids);

gboolean
agents_in_use (agent_uuid_list_t agent_uuids);

#endif // _GVMD_MANAGE_AGENTS_H
#endif // ENABLE_AGENTS