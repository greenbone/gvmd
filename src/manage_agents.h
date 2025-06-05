/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file manage_agents.h
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
#include "manage.h"

typedef resource_t agent_t;

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
  gchar * uuid;
  gchar * name;
  gchar *agent_id;
  gchar *hostname;
  int authorized;
  int min_interval;
  int heartbeat_interval;
  gchar *connection_status;
  agent_ip_data_list_t ip_addresses;
  int ip_address_count;
  time_t creation_time;
  time_t modification_time;
  time_t last_update_agent_control;
  gchar *schedule;
  gchar *comment;
  user_t owner;
  scanner_t scanner;
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

struct agent_uuid_list
{
  int count;
  gchar **agent_uuids;
};
typedef struct agent_uuid_list *agent_uuid_list_t;

typedef enum {
  AGENT_RESPONSE_SUCCESS = 0,                     ///< Success
  AGENT_RESPONSE_NO_AGENTS_PROVIDED = -1,         ///< No agent UUIDs provided
  AGENT_RESPONSE_SCANNER_LOOKUP_FAILED = -2,      ///< Scanner lookup failed
  AGENT_RESPONSE_GET_AGENTS_FAILED = -3,          ///< Failed to get agents from controller
  AGENT_RESPONSE_AGENT_SCANNER_MISMATCH = -4,       ///< Agent list count mismatch (not same scanner)
  AGENT_RESPONSE_CONNECTOR_CREATION_FAILED = -5,  ///< Failed to create connector
  AGENT_RESPONSE_CONTROLLER_UPDATE_FAILED = -6,   ///< Failed to update agents
  AGENT_RESPONSE_CONTROLLER_DELETE_FAILED = -7,   ///< Failed to delete agents
  AGENT_RESPONSE_SYNC_FAILED = -8                 ///< Failed during sync
} agent_response_t;

gvmd_agent_connector_t
gvmd_agent_connector_new_from_scanner (scanner_t scanner);

void
gvmd_agent_connector_free (gvmd_agent_connector_t conn);

void
agent_ip_data_list_free (agent_ip_data_list_t ip_list);

void
agent_data_free (agent_data_t data);

void
agent_ip_data_free (agent_ip_data_t ip_data);

void
agent_data_list_free (agent_data_list_t agents);

void
agent_uuid_list_free (agent_uuid_list_t uuid_list);

int
sync_agents_from_agent_controller (gvmd_agent_connector_t connector);

agent_data_list_t
get_agents_by_scanner_and_uuids (scanner_t scanner, agent_uuid_list_t uuid_list);

agent_response_t
modify_and_resync_agents (agent_uuid_list_t agent_uuids,
                          agent_controller_agent_update_t agent_update,
                          const gchar *comment);

agent_response_t
delete_and_resync_agents (agent_uuid_list_t agent_uuids);

int
init_agent_iterator (iterator_t *iterator, get_data_t *get);

void
init_agent_uuid_list_iterator (iterator_t *iterator, scanner_t scanner,
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
agent_iterator_schedule (iterator_t *iterator);

int
agent_iterator_authorized (iterator_t *iterator);

int
agent_iterator_min_interval (iterator_t *iterator);

int
agent_iterator_heartbeat_interval (iterator_t *iterator);

time_t
agent_iterator_last_update (iterator_t *iterator);

scanner_t
agent_iterator_scanner (iterator_t *iterator);

int
agent_count (const get_data_t *get);

int
agent_writable (agent_t agent);

int
agent_in_use (agent_t agent);

void
delete_agents_filtered (agent_uuid_list_t agent_uuids, scanner_t scanner);

#endif // _GVMD_MANAGE_AGENTS_H
#endif // ENABLE_AGENTS