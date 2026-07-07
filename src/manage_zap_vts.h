/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Extra vulnerability test data headers.
 *
 * Extra vulnerability test headers for the GVM management layer.
 */

#ifndef _GVMD_MANAGE_ZAP_VTS_H
#define _GVMD_MANAGE_ZAP_VTS_H

#include <cjson/cJSON.h>

double
zap_risk_to_cvss (const char *);

int
update_zap_vts_from_feed ();

#endif /* _GVMD_MANAGE_ZAP_VTS_H */
