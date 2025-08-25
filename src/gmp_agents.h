/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Agent headers.
 *
 * Headers for GMP handlers for agent control commands.
 */
#ifndef _GVMD_GMP_AGENTS_H
#define _GVMD_GMP_AGENTS_H

#include "gmp_base.h"

/* GET_AGENTS. */

void
get_agents_start (const gchar **, const gchar **);

void
get_agents_run (gmp_parser_t *gmp_parser, GError **error);

/* MODIFY_AGENT. */

void
modify_agents_element_start (gmp_parser_t *gmp_parser, const gchar *name,
                             const gchar **attribute_names,
                             const gchar **attribute_values);

void
modify_agents_start (gmp_parser_t *gmp_parser, const gchar **attribute_names,
                     const gchar **attribute_values);

void
modify_agents_element_text (const gchar *text, gsize text_len);

int
modify_agents_element_end (gmp_parser_t *gmp_parser, GError **error,
                           const gchar *name);

void
modify_agents_run (gmp_parser_t *gmp_parser, GError **error);

/* DELETE_AGENTS. */

void
delete_agents_element_start (gmp_parser_t *gmp_parser, const gchar *name,
                             const gchar **attribute_names,
                             const gchar **attribute_values);

void
delete_agents_start (gmp_parser_t *gmp_parser, const gchar **attribute_names,
                     const gchar **attribute_values);

void
delete_agents_element_text (const gchar *text, gsize text_len);

int
delete_agents_element_end (gmp_parser_t *gmp_parser, GError **error,
                           const gchar *name);

void
delete_agents_run (gmp_parser_t *gmp_parser, GError **error);

#endif //_GVMD_GMP_AGENTS_H
