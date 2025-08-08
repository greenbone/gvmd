/* Copyright (C) 2021-2022 Greenbone AG
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

#include "gmp_base.h"

#include <glib.h>
#include <gvm/util/xmlutils.h>


/**
 * @file
 * @brief GVM GMP layer: License information headers
 *
 * Headers for GMP handling of license information.
 */

/* GET_LICENSE. */

void
get_license_start (gmp_parser_t *,
                   const gchar **,
                   const gchar **);

void
get_license_element_start (gmp_parser_t *,
                           const gchar *,
                           const gchar **,
                           const gchar **);

int
get_license_element_end (gmp_parser_t *,
                         GError **,
                         const gchar *);

void
get_license_element_text (const gchar *,
                          gsize);


/* MODIFY_LICENSE. */

void
modify_license_start (gmp_parser_t *,
                   const gchar **,
                   const gchar **);

void
modify_license_element_start (gmp_parser_t *,
                           const gchar *,
                           const gchar **,
                           const gchar **);

int
modify_license_element_end (gmp_parser_t *,
                         GError **,
                         const gchar *);

void
modify_license_element_text (const gchar *,
                          gsize);
