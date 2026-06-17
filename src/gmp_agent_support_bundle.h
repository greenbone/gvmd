/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Agent support bundle headers.
 *
 * Headers for GMP handlers for downloading agent support bundles.
 */

#ifndef _GVMD_GMP_AGENT_SUPPORT_BUNDLE_H
#define _GVMD_GMP_AGENT_SUPPORT_BUNDLE_H

#include "gmp_base.h"

void
get_agent_support_bundle_run (gmp_parser_t *, GError **);

void
get_agent_support_bundle_start (const gchar **, const gchar **);

#endif /* _GVMD_GMP_AGENT_SUPPORT_BUNDLE_H */
