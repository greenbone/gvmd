/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Headers for GMP agent inventory authentication handlers.
 */

#ifndef _GVMD_GMP_AGENT_INVENTORY_AUTHENTICATION_H
#define _GVMD_GMP_AGENT_INVENTORY_AUTHENTICATION_H

#include "gmp_base.h"

void
get_agent_inventory_token_run (gmp_parser_t *, GError **);

void
get_agent_inventory_token_start (const gchar **, const gchar **);

#endif /* _GVMD_GMP_AGENT_INVENTORY_AUTHENTICATION_H */
