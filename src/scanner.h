/* Copyright (C) 2014-2019 Greenbone Networks GmbH
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
 * @file scanner.h
 * @brief Module for Greenbone Vulnerability Manager: Scanner Connection API.
 */

#ifndef _GVMD_SCANNER_H
#define _GVMD_SCANNER_H

#include <gnutls/gnutls.h>

void
openvas_scanner_fork ();

void
openvas_scanner_free ();

int
openvas_scanner_set_address (const char *, int);

int
openvas_scanner_set_unix (const char *);

#endif /* not _GVMD_SCANNER_H */
