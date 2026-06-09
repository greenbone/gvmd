/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Web Application Target headers.
 *
 * Headers for GMP handlers for web application target commands.
 */

#if ENABLE_WEB_APPLICATION_SCANNING

#ifndef _GVMD_GMP_WEB_APPLICATION_TARGETS_H
#define _GVMD_GMP_WEB_APPLICATION_TARGETS_H

#include "gmp_base.h"

/* GET_WEB_APPLICATION_TARGETS. */

void
get_web_application_targets_start (const gchar **,
                                   const gchar **);

void
get_web_application_targets_run (gmp_parser_t *, GError **);

/* CREATE_WEB_APPLICATION_TARGET. */

void
create_web_application_target_start (gmp_parser_t *,
                                     const gchar **,
                                     const gchar **);

void
create_web_application_target_element_start (gmp_parser_t *,
                                             const gchar *,
                                             const gchar **,
                                             const gchar **);

void
create_web_application_target_element_text (const gchar *,
                                            gsize);

int
create_web_application_target_element_end (gmp_parser_t *,
                                           GError **,
                                           const gchar *);

void
create_web_application_target_run (gmp_parser_t *, GError **);

/* MODIFY_WEB_APPLICATION_TARGET. */

void
modify_web_application_target_start (gmp_parser_t *,
                                     const gchar **,
                                     const gchar **);

void
modify_web_application_target_element_start (gmp_parser_t *,
                                             const gchar *,
                                             const gchar **,
                                             const gchar **);

void
modify_web_application_target_element_text (const gchar *,
                                            gsize);

int
modify_web_application_target_element_end (gmp_parser_t *,
                                           GError **,
                                           const gchar *);

void
modify_web_application_target_run (gmp_parser_t *, GError **);

#endif /* not _GVMD_GMP_WEB_APPLICATION_TARGETS_H */

#endif /* ENABLE_WEB_APPLICATION_SCANNING */
