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

#if ENABLE_CONTAINER_SCANNING
#ifndef _GVMD_MANAGE_CONTAINER_IMAGE_SCANNER_H
#define _GVMD_MANAGE_CONTAINER_IMAGE_SCANNER_H

#include "manage_resources.h"
#include <gvm/http_scanner/http_scanner.h>

http_scanner_connector_t
container_image_scanner_connect (scanner_t,
                                 const char *);

int
run_container_image_task (task_t, int, char **);

int
stop_container_image_task (task_t);

#endif // ENABLE_CONTAINER_SCANNING
#endif // not _GVMD_MANAGE_CONTAINER_IMAGE_SCANNER_H
