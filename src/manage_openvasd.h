/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Greenbone Vulnerability Manager OpenVASD scan handling.
 */

#if ENABLE_OPENVASD

#ifndef _GVMD_MANAGE_OPENVASD_H
#define _GVMD_MANAGE_OPENVASD_H

#include <glib.h>
#include "manage_resources_types.h"
#include <gvm/openvasd/openvasd.h>

int
handle_openvasd_scan_start (task_t, target_t, const char *,
                            int, gboolean, gboolean *);

int
handle_openvasd_scan (task_t, report_t, const char *, time_t);

int
handle_openvasd_scan_end (task_t, int, gboolean);

#endif /* not _GVMD_MANAGE_OPENVASD_H */
#endif /* ENABLE_OPENVASD */
