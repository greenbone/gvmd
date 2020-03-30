/* Copyright (C) 2019 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file gmp_tls_certificates.h
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
