/* Copyright (C) 2009-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer headers: Credential stores.
 *
 * GMP handler headers for reading and managing credential stores.
 */

#ifndef _GVMD_GMP_CREDENTIAL_STORES_H
#define _GVMD_GMP_CREDENTIAL_STORES_H

#include "gmp_base.h"

void
get_credential_stores_start (const gchar **,
                             const gchar **);

void
get_credential_stores_run (gmp_parser_t *, GError **);

void
create_credential_store_start (gmp_parser_t *gmp_parser,
                               const gchar **attribute_names,
                               const gchar **attribute_values);

void
create_credential_store_element_start (gmp_parser_t *, const gchar *,
                                       const gchar **,
                                       const gchar **);

void
create_credential_store_run (gmp_parser_t *, GError **);

int
create_credential_store_element_end (gmp_parser_t *, GError **,
                                     const gchar *);

void
create_credential_store_element_text (const gchar *, gsize);

void
modify_credential_store_element_start (gmp_parser_t *,
                                       const gchar *,
                                       const gchar **,
                                       const gchar **);

void
modify_credential_store_start (gmp_parser_t *,
                               const gchar **,
                               const gchar **);

void
modify_credential_store_element_text (const gchar *text, gsize text_len);

void
modify_credential_store_run (gmp_parser_t *, GError **);

int
modify_credential_store_element_end (gmp_parser_t *, GError **,
                                     const gchar *);

#endif /* _GVMD_GMP_CREDENTIAL_STORES_H */
