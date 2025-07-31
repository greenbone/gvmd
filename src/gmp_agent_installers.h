/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Agent installer headers.
 *
 * Headers for GMP handlers for agent installers.
 */


#ifndef _GVMD_GMP_AGENT_INSTALLERS_H
#define _GVMD_GMP_AGENT_INSTALLERS_H

#include "gmp_base.h"

void
get_agent_installers_run (gmp_parser_t *,
                          GError **);

void
get_agent_installers_start (const gchar **,
                            const gchar **);

void
get_agent_installer_file_run (gmp_parser_t *,
                              GError **);

void
get_agent_installer_file_start (const gchar **,
                                const gchar **);

#endif // not _GVMD_GMP_AGENT_INSTALLERS_H
