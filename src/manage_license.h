/* Copyright (C) 2020-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: License information headers.
 *
 * Headers for non-SQL license information code for the GVM management layer.
 */

#include <glib.h>

#ifdef HAS_LIBTHEIA
#include <theia/client.h>
#else
#include "theia_dummy.h"
#endif

/* Actions */

int
manage_update_license_file (const char *, char **);

int
manage_get_license (gchar **, theia_license_t **);
