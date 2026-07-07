/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: ZAP vulnerability test SQL headers.
 *
 * SQL ZAP vulnerability test headers for the GVM management layer.
 */

#ifndef _GVMD_MANAGE_SQL_ZAP_VTS_H
#define _GVMD_MANAGE_SQL_ZAP_VTS_H

#include <cjson/cJSON.h>

#include "manage_zap_vts.h"

int
insert_zap_vt_from_json (cJSON*);

void
update_zap_vt_severities_from_cves ();

void
update_zap_vt_group_severity_scores ();

#endif /* _GVMD_MANAGE_SQL_ZAP_VTS_H */
