/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Modify Agent-Controller scan-agent configuration.
 *
 */

#ifndef _GVMD_GMP_AGENT_CONTROL_SCAN_AGENT_CONFIG_H
#define _GVMD_GMP_AGENT_CONTROL_SCAN_AGENT_CONFIG_H

#include "gmp_base.h"

#include <agent_controller/agent_controller.h>
#include <util/xmlutils.h>

/* -------- MODIFY_AGENT_CONTROL_SCAN_CONFIG -------- */

void
modify_agent_control_scan_config_start (gmp_parser_t *gmp_parser,
                                        const gchar **attribute_names,
                                        const gchar **attribute_values);

void
modify_agent_control_scan_config_element_start (gmp_parser_t *gmp_parser,
                                                const gchar *name,
                                                const gchar **attribute_names,
                                                const gchar **attribute_values);

void
modify_agent_control_scan_config_element_text (const gchar *text, gsize len);

int
modify_agent_control_scan_config_element_end (gmp_parser_t *gmp_parser,
                                              GError **error,
                                              const gchar *name);

void
modify_agent_control_scan_config_run (gmp_parser_t *gmp_parser, GError **error);

int
build_scan_agent_config_from_entity (
  entity_t root,
  agent_controller_scan_agent_config_t out_cfg);

#endif /* _GVMD_GMP_AGENT_CONTROL_SCAN_AGENT_CONFIG_H */
