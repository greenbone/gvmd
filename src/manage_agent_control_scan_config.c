/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Manage layer: Agent Controller scan-agent configuration.
 *
 * Functions for retrieving and updating the scan-agent configuration
 * stored by an Agent Controller scanner.
 */

#if ENABLE_AGENTS
#include "manage_agent_control_scan_config.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Retrieve the scan agent configuration for a given scanner.
 *
 * @param[in] scanner  Scanner row id whose agent config is requested.
 *
 * @return A newly allocated #agent_controller_scan_agent_config_t on success;
 *         NULL if @p scanner is invalid, no configuration is available, or an
 *         allocation/parse error occurs.
 */
agent_controller_scan_agent_config_t
get_agent_control_scan_config (scanner_t scanner)
{
  gvmd_agent_connector_t connector = NULL;
  agent_controller_scan_agent_config_t agent_config = NULL;

  if (scanner == 0)
    return NULL;

  connector = gvmd_agent_connector_new_from_scanner (scanner);

  if (!connector)
    return NULL;
  agent_config = agent_controller_get_scan_agent_config (connector->base);
  if (!agent_config)
    {
      gvmd_agent_connector_free (connector);
      return NULL;
    }

  gvmd_agent_connector_free (connector);

  return agent_config;
}

/**
 * @brief Modify (persist/propagate) the scan agent configuration for a scanner.
 *
 * @param[in] scanner  Scanner row identifier (must be non-zero).
 * @param[in] cfg      New configuration to apply (must be non-NULL).
 *
 * @return
 *   0   on success (configuration accepted by the Agent Controller).
 *  -1   invalid arguments (either @p scanner == 0 or @p cfg == NULL).
 *  -2   failed to create a connector for @p scanner
 *       (e.g., scanner not found/misconfigured).
 *  -3   Agent Controller update rejected with validation (error propagated from
 *       agent_controller_update_scan_agent_config(), e.g., validation).
 *  -4   Agent Controller update failed (error propagated from
 *       agent_controller_update_scan_agent_config(),
 *       communication failure).
 */
int
modify_agent_control_scan_config (scanner_t scanner,
                                  agent_controller_scan_agent_config_t cfg,
                                  GPtrArray **errors)
{
  int ret = 0;
  gvmd_agent_connector_t connector = NULL;

  /* Avoid returning stale error arrays from previous calls */
  if (errors)
    *errors = NULL;

  if (!scanner || !cfg)
    return -1;

  connector = gvmd_agent_connector_new_from_scanner (scanner);
  if (!connector)
    {
      ret = -2;
      goto cleanup;
    }

  int rc = agent_controller_update_scan_agent_config (
    connector->base, cfg, errors);

  if (rc == AGENT_RESP_OK)
    {
      ret = 0;
    }
  else if (errors && *errors && (*errors)->len > 0)
    {
      g_warning ("%s: Agent Controller rejected scan-agent-config update",
                 __func__);
      ret = -3;
    }
  else
    {
      g_warning ("%s: Agent Controller update failed (no details)", __func__);
      ret = -4;
    }

cleanup:
  if (connector)
    gvmd_agent_connector_free (connector);

  agent_controller_scan_agent_config_free (cfg);

  return ret;
}
#endif // ENABLE_AGENTS