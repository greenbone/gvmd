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
http_scanner_set_connector_scan_id (http_scanner_connector_t connector,
                                    const char *scan_id);

#endif //MANAGE_HTTP_SCANNER_H
#endif
