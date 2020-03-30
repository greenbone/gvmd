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
 * @file manage_sql_tls_certificates.h
 * @brief GVM management layer: TLS Certificates SQL headers
 *
 * Headers for TLS Certificates SQL for the GVM management layer.
 */

#ifndef _GVMD_MANAGE_SQL_TLS_CERTIFICATES_H
#define _GVMD_MANAGE_SQL_TLS_CERTIFICATES_H

const char**
tls_certificate_filter_columns ();

column_t*
tls_certificate_select_columns ();

gchar *
tls_certificate_extra_where (const char *);

int
delete_tls_certificate (const char *, int);

void
delete_tls_certificates_user (user_t);

void
inherit_tls_certificates (user_t, user_t);

int
user_has_tls_certificate (tls_certificate_t, user_t);

int
add_tls_certificates_from_report_host (report_host_t,
                                       const char*,
                                       const char*);

#endif /* not _GVMD_MANAGE_SQL_TLS_CERTIFICATES_H */
