/* Copyright (C) 2009-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Agent Group headers.
 *
 * Header for GMP Agent Group handlers
 */

#ifndef _GVMD_GMP_AGENT_GROUPS_H
#define _GVMD_GMP_AGENT_GROUPS_H

#include "gmp_base.h"
#include "gmp_get.h"

void
get_agent_groups_start (const gchar **,
                        const gchar **);

void
get_agent_groups_run (gmp_parser_t *, GError **);

void
create_agent_group_start (gmp_parser_t *gmp_parser,
                          const gchar **attribute_names,
                          const gchar **attribute_values);

void
create_agent_group_element_start (gmp_parser_t *, const gchar *,
                                  const gchar **,
                                  const gchar **);

void
create_agent_group_run (gmp_parser_t *, GError **);

int
create_agent_group_element_end (gmp_parser_t *, GError **,
                                const gchar *);

void
create_agent_group_element_text (const gchar *, gsize);

void
modify_agent_group_element_start (gmp_parser_t *,
                                  const gchar *,
                                  const gchar **,
                                  const gchar **);

void
modify_agent_group_start (gmp_parser_t *,
                          const gchar **,
                          const gchar **);

void
modify_agent_group_element_text (const gchar *text, gsize text_len);

void
modify_agent_group_run (gmp_parser_t *, GError **);

int
modify_agent_group_element_end (gmp_parser_t *, GError **,
                                const gchar *);

#endif // not _GVMD_GMP_AGENT_GROUPS_H