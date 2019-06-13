/* Copyright (C) 2019 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * @file manage_sql_tls_certificates.h
 * @brief GVM management layer: TLS Certificates SQL headers
 *
 * Headers for TLS Certificates SQL for the GVM management layer.
 */

#ifndef _GVMD_MANAGE_TLS_CERTIFICATES_H
#define _GVMD_MANAGE_TLS_CERTIFICATES_H

#include "manage.h"
#include "iterator.h"

int
tls_certificate_count (const get_data_t *);

int
init_tls_certificate_iterator (iterator_t *, const get_data_t *);

const char*
tls_certificate_iterator_certificate (iterator_t*);

const char*
tls_certificate_iterator_subject_dn (iterator_t*);

const char*
tls_certificate_iterator_issuer_dn (iterator_t*);

int
tls_certificate_iterator_trust (iterator_t *);

const char*
tls_certificate_iterator_md5_fingerprint (iterator_t*);

const char*
tls_certificate_iterator_activation_time (iterator_t*);

const char*
tls_certificate_iterator_expiration_time (iterator_t*);

int
tls_certificate_iterator_valid (iterator_t *);

int
tls_certificate_in_use (tls_certificate_t);

int
trash_tls_certificate_in_use (tls_certificate_t);

int
tls_certificate_writable (tls_certificate_t);

int
trash_tls_certificate_writable (tls_certificate_t);

int
create_tls_certificate (const char *, const char *, const char *,
                        tls_certificate_t *);

int
copy_tls_certificate (const char*, const char*, const char*,
                      tls_certificate_t*);

int
modify_tls_certificate (const gchar *, const gchar *, const gchar *,
                        const gchar *);

char*
tls_certificate_uuid (tls_certificate_t);

#endif /* not _GVMD_MANAGE_TLS_CERTIFICATES_H */
