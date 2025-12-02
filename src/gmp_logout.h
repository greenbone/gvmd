/* Copyright (C) 2021-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gmp_base.h"

#include <glib.h>
#include <gvm/util/xmlutils.h>

void
logout_start (gmp_parser_t *,
              const gchar **,
              const gchar **);

void
logout_element_start (gmp_parser_t *, const gchar *,
                      const gchar **, const gchar **);

int
logout_element_end (gmp_parser_t *, GError **, const gchar *);
