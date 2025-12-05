/* Copyright (C) 2021-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
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
