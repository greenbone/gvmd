/* Copyright (C) 2009-2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Credential headers.
 *
 * Header for GMP Credential handlers
 */

#ifndef _GVMD_GMP_CREDENTIALS_H
#define _GVMD_GMP_CREDENTIALS_H

#include "gmp_base.h"

void
create_credential_start (gmp_parser_t *,
                         const gchar **,
                         const gchar **);

void
create_credential_element_start (gmp_parser_t *,
                                 const gchar *,
                                 const gchar **,
                                 const gchar **);

void
create_credential_element_text (const gchar *, gsize);

int
create_credential_element_end (gmp_parser_t *,
                               GError **,
                               const gchar *);

void
modify_credential_start (gmp_parser_t *,
                         const gchar **,
                         const gchar **);

void
modify_credential_element_start (gmp_parser_t *,
                                 const gchar *,
                                 const gchar **,
                                 const gchar **);

void
modify_credential_element_text (const gchar *,
                                gsize);

int
modify_credential_element_end (gmp_parser_t *, GError **,
                               const gchar *);

#endif // not _GVMD_GMP_CREDENTIALS_H
