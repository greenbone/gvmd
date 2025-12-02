/* Copyright (C) 2018-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_GMP_DELETE_H
#define _GVMD_GMP_DELETE_H

#include "gmp_base.h"

#include <glib.h>

void
delete_start (const gchar *, const gchar *, const gchar **, const gchar **);

void
delete_run (gmp_parser_t *, GError **);

#endif /* not _GVMD_GMP_DELETE_H */
