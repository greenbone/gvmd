/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Web application scanner management.
 *
 * This header defines the interface functions used by GVMD to interact
 * with the web application scanner component.
 */

#if ENABLE_WEB_APPLICATION_SCANNING
#ifndef _GVMD_MANAGE_WEB_APPLICATION_SCANNER_H
#define _GVMD_MANAGE_WEB_APPLICATION_SCANNER_H

#include "manage_resources_types.h"
#include <gvm/http_scanner/http_scanner.h>

http_scanner_connector_t
web_application_scanner_connect (scanner_t,
                                 const char *);

int
run_web_application_task (task_t, int, char **);

int
stop_web_application_task (task_t);

#endif // not _GVMD_MANAGE_WEB_APPLICATION_SCANNER_H
#endif // ENABLE_WEB_APPLICATION_SCANNING
