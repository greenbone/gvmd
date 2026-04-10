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

#include "manage_sql.h"

#include <assert.h>

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

/**
 * @brief Allocate and fill agent_uuid_list_t structure using agent group.
 *
 * @param[in] group Agent group row id
 *
 * @return A newly allocated filled agent_uuid_list_t,
 *         or NULL on allocation failure.
 */
agent_uuid_list_t
agent_uuid_list_from_group (agent_group_t group)
{
  int count = 0;
  iterator_t it;
  init_agent_group_agents_iterator (&it, group);
  while (next (&it))
    {
      const char *uuid = agent_group_agent_iterator_uuid (&it);
      if (uuid && *uuid)
        count++;
    }

  if (count == 0)
    return NULL;

  agent_uuid_list_t list = agent_uuid_list_new (count);
  if (!list)
    return NULL;

  int i = 0;
  init_agent_group_agents_iterator (&it, group);
  while (next (&it))
    {
      const char *uuid = agent_group_agent_iterator_uuid (&it);
      if (!uuid || !*uuid)
        continue;
      list->agent_uuids[i++] = g_strdup (uuid);
    }

  return list;
}

/**
 * @brief Initialize a new GVMD agent connector from a scanner.
 *
 * Builds and configures a connection to the agent controller using
 * scanner information. If the scanner host is a Unix domain socket path,
 * the connector is configured to use UDS instead of TCP.
 *
 * @param[in] scanner  Scanner ID used to resolve connection info.
 * @return Allocated gvmd_agent_connector_t or NULL on failure.
 */
gvmd_agent_connector_t
gvmd_agent_connector_new_from_scanner (scanner_t scanner)
{
  assert (scanner);

  gboolean has_relay = scanner_has_relay (scanner);
  char *host = scanner_host (scanner, has_relay);
  int port = scanner_port (scanner, has_relay);
  char *ca_cert = scanner_ca_pub (scanner);
  char *cert = scanner_key_pub (scanner);
  char *key = scanner_key_priv (scanner);

  gboolean is_socket_path = host && *host != '\0' && g_path_is_absolute (host);

  if (!host || *host == '\0' || (!is_socket_path && port <= 0))
    {
      g_warning ("%s: Invalid scanner host or port", __func__);
      g_free (host);
      g_free (ca_cert);
      g_free (cert);
      g_free (key);
      return NULL;
    }

  const char *protocol = "https";
  if (!ca_cert || !cert)
    {
      g_debug ("%s: Falling back to HTTP due to missing CA or cert", __func__);
      protocol = "http";
    }

  gvmd_agent_connector_t conn =
    g_malloc0 (sizeof (struct gvmd_agent_connector));
  conn->base = agent_controller_connector_new ();

  if (is_socket_path)
    {
      g_debug ("%s: Falling back to socket: %s", __func__, host);
      agent_controller_connector_builder (
        conn->base, AGENT_CONTROLLER_UNIX_SOCKET_PATH, host);
    }
  else
    {
      agent_controller_connector_builder (conn->base, AGENT_CONTROLLER_HOST,
                                          host);
      agent_controller_connector_builder (conn->base, AGENT_CONTROLLER_PORT,
                                          &port);
      agent_controller_connector_builder (conn->base, AGENT_CONTROLLER_PROTOCOL,
                                          protocol);
    }

  if (ca_cert)
    agent_controller_connector_builder (conn->base, AGENT_CONTROLLER_CA_CERT,
                                        ca_cert);
  if (cert)
    agent_controller_connector_builder (conn->base, AGENT_CONTROLLER_CERT,
                                        cert);
  if (key)
    agent_controller_connector_builder (conn->base, AGENT_CONTROLLER_KEY, key);

  conn->scanner_id = scanner;

  g_free (host);
  g_free (ca_cert);
  g_free (cert);
  g_free (key);

  return conn;
}

/**
 * @brief Free a GVMD agent connector.
 *
 * @param[in] conn GVMD agent connector to free.
 */
void
gvmd_agent_connector_free (gvmd_agent_connector_t conn)
{
  if (!conn)
    return;
  agent_controller_connector_free (conn->base);
  g_free (conn);
}

/**
 * @brief Verify connectivity to the agent controller.
 *
 * @param[in] scanner Scanner row id used to obtain the agent connector.
 *
 * @return 0 if the connection and configuration retrieval succeed,
 *         1 if the agent configuration could not be obtained.
 */
int
verify_agent_controller_connection (scanner_t scanner)
{
  gvmd_agent_connector_t connector = NULL;
  agent_controller_scan_agent_config_t agent_config = NULL;

  connector = gvmd_agent_connector_new_from_scanner (scanner);
  agent_config = agent_controller_get_scan_agent_config (connector->base);

  gvmd_agent_connector_free (connector);

  if (agent_config == NULL)
    return 1;

  agent_controller_scan_agent_config_free (agent_config);
  return 0;
}

#endif // ENABLE_AGENTS
