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
#ifndef _GVMD_MANAGE_AGENT_SCAN_CONFIG_H
#define _GVMD_MANAGE_AGENT_SCAN_CONFIG_H

#include "manage_agent_common.h"

agent_controller_scan_agent_config_t
get_agent_control_scan_config (scanner_t scanner);

int
modify_agent_control_scan_config (scanner_t scanner,
                                  agent_controller_scan_agent_config_t);

#endif //_GVMD_MANAGE_AGENT_SCAN_CONFIG_H
#endif // ENABLE_AGENTS
