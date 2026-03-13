/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Headers for Greenbone Vulnerability Manager runtime config handling.
 */

#ifndef _GVMD_GVMD_CONFIG_H
#define _GVMD_GVMD_CONFIG_H

#include <glib.h>

int
load_gvmd_config (const char *);

GKeyFile *
get_gvmd_config ();

void
gvmd_config_get_boolean (GKeyFile *, const char *, const char *,
                         int *, int *);

void
gvmd_config_resolve_boolean (const char *, gboolean, gboolean, gboolean*);

#endif /* _GVMD_GVMD_CONFIG_H */
