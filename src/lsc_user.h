/* Copyright (C) 2009-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/*
 * @file
 * @brief LSC user credentials package generation.
 */

#ifndef _GVMD_LSC_USER_H
#define _GVMD_LSC_USER_H

#include <glib.h>

int
lsc_user_keys_create (const gchar *, gchar **);

int
lsc_user_rpm_recreate (const gchar *, const gchar *,
                       void **, gsize *);

int
lsc_user_deb_recreate (const gchar *, const char *, const char *,
                       void **, gsize *);

int
lsc_user_exe_recreate (const gchar *, const gchar *, void **, gsize *);

#endif /* not _GVMD_LSC_USER_H */
