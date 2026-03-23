/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Integration Configuration headers
 *
 * Headers for GMP handling of licence configuration.
 */

#ifndef _GVMD_GMP_INTEGRATION_CONFIGS_H
#define _GVMD_GMP_INTEGRATION_CONFIGS_H

#include "gmp_base.h"

/* GET_INTEGRATION_CONFIGS. */

void
get_integration_configs_start (const gchar**, const gchar**);

void
get_integration_configs_run (gmp_parser_t* gmp_parser, GError** error);

/* MODIFY_INTEGRATION_CONFIG. */

void
modify_integration_config_element_start(gmp_parser_t* gmp_parser, const gchar* name,
                                        const gchar** attribute_names,
                                        const gchar** attribute_values);

void
modify_integration_config_start (gmp_parser_t* gmp_parser, const gchar** attribute_names,
                                 const gchar** attribute_values);

void
modify_integration_config_element_text (const gchar* text, gsize text_len);

int
modify_integration_config_element_end (gmp_parser_t* gmp_parser, GError** error,
                                       const gchar* name);

void
modify_integration_config_run(gmp_parser_t* gmp_parser, GError** error);

#endif //_GVMD_GMP_INTEGRATION_CONFIGS_H
