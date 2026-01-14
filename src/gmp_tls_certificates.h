/* Copyright (C) 2019-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: TLS Certificates headers
 *
 * Headers for GMP handling of TLS Certificates.
 */

#ifndef _GVMD_GMP_TLS_CERTIFICATES_H
#define _GVMD_GMP_TLS_CERTIFICATES_H

#include "gmp_base.h"
#include "manage.h"

void
get_tls_certificates_start (const gchar **, const gchar **);

void
get_tls_certificates_run (gmp_parser_t *, GError **);

void
create_tls_certificate_start (gmp_parser_t *, const gchar **, const gchar **);

void
create_tls_certificate_element_start (gmp_parser_t *, const gchar *,
                                      const gchar **, const gchar **);

int
create_tls_certificate_element_end (gmp_parser_t *, GError **error,
                                    const gchar *);

void
create_tls_certificate_element_text (const gchar *, gsize);

void
modify_tls_certificate_start (gmp_parser_t *, const gchar **, const gchar **);

void
modify_tls_certificate_element_start (gmp_parser_t *, const gchar *,
                                      const gchar **, const gchar **);

int
modify_tls_certificate_element_end (gmp_parser_t *, GError **error,
                                    const gchar *);

void
modify_tls_certificate_element_text (const gchar *, gsize);

gchar *
tls_certificate_origin_extra_xml (const char *, const char *, const char *);

#endif /* not _GVMD_GMP_TLS_CERTIFICATES_H */
