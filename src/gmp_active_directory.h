
/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Active Directory headers.
 *
 * Header for GMP Active Directory handlers
 */

#ifndef _GVMD_GMP_ACTIVE_DIRECTORY_H
#define _GVMD_GMP_ACTIVE_DIRECTORY_H

#include "gmp_base.h"

void
verify_active_directory_credential_start (gmp_parser_t *,
                                          const gchar **,
                                          const gchar **);

void
verify_active_directory_credential_run (gmp_parser_t *, GError **);

void
verify_active_directory_credential_element_start (gmp_parser_t *,
                                                  const gchar *,
                                                  const gchar **,
                                                  const gchar **);

void
verify_active_directory_credential_element_text (const gchar *,
                                                 gsize);

int
verify_active_directory_credential_element_end (gmp_parser_t *,
                                                GError **,
                                                const gchar *);

#endif // not _GVMD_GMP_ACTIVE_DIRECTORY_H
