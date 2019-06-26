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

#ifndef _GVMD_MANAGE_SQL_TLS_CERTIFICATES_H
#define _GVMD_MANAGE_SQL_TLS_CERTIFICATES_H

int
delete_tls_certificate (const char *, int);

void
delete_tls_certificates_user (user_t);

void
inherit_tls_certificates (user_t, user_t);

#endif /* not _GVMD_MANAGE_SQL_TLS_CERTIFICATES_H */
