/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gmp_agent_installers.c
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
get_agent_installers_element_start (gmp_parser_t *,
                                    const gchar *,
                                    const gchar **,
                                    const gchar **);

int
get_agent_installers_element_end (gmp_parser_t *,
                                  GError **,
                                  const gchar *);

void
get_agent_installers_element_text (const gchar *,
                                   gsize);

#endif // not _GVMD_GMP_AGENT_INSTALLERS_H
