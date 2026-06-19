/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Agent installer instruction headers.
 *
 * Headers for GMP handlers for agent installer instructions.
 */


#ifndef _GVMD_GMP_AGENT_INSTALLER_INSTRUCTIONS_H
#define _GVMD_GMP_AGENT_INSTALLER_INSTRUCTIONS_H

#include "gmp_base.h"

void
get_agent_installer_instruction_run (gmp_parser_t *,
                                      GError **);

void
get_agent_installer_instruction_start (const gchar **,
                                       const gchar **);

#endif // _GVMD_GMP_AGENT_INSTALLER_INSTRUCTIONS_H
