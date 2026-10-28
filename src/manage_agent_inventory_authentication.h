/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#if ENABLE_AGENTS
#ifndef _GVMD_MANAGE_AGENT_INVENTORY_AUTHENTICATION_H
#define _GVMD_MANAGE_AGENT_INVENTORY_AUTHENTICATION_H

#include <glib.h>

/**
 * @brief Result of generating an agent inventory token.
 */
enum agent_inventory_token_rc
{
  AGENT_INVENTORY_TOKEN_ERROR = -1,
  AGENT_INVENTORY_TOKEN_OK = 0,
  AGENT_INVENTORY_TOKEN_UNAVAILABLE = 1,
};

int
load_agent_inventory_authentication_config (void);

int
generate_agent_inventory_token (gchar **);

#endif /* not _GVMD_MANAGE_AGENT_INVENTORY_AUTHENTICATION_H */
#endif /* ENABLE_AGENTS */
