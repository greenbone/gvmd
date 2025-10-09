/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief HTTP scanner management interface for GVMD.
 *
 * This header defines the interface functions used by GVMD to interact
 * with the HTTP-based scanner component.
 */

#if ENABLE_HTTP_SCANNER
#ifndef MANAGE_HTTP_SCANNER_H
#define MANAGE_HTTP_SCANNER_H

#include "manage_resources.h"

#include <gvm/http_scanner/http_scanner.h>

http_scanner_connector_t
http_scanner_connect(scanner_t scanner, const char* scan_id);

int
prepare_http_scanner_scan_for_resume (http_scanner_connector_t,
                                      char **);

int
handle_http_scanner_scan (http_scanner_connector_t,
                          task_t, report_t,
                          void (*)
                            (task_t, report_t, GSList *, time_t, time_t));

#endif //MANAGE_HTTP_SCANNER_H
#endif
