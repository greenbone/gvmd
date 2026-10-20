/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Client connection watcher helpers.
 */

#ifndef _GVMD_CLIENT_WATCHER_H
#define _GVMD_CLIENT_WATCHER_H

#include <sys/types.h>

/**
 * @brief Result of probing a client connection.
 */
typedef enum
{
  CLIENT_CONNECTION_LIVE,
  CLIENT_CONNECTION_CLOSED,
  CLIENT_CONNECTION_ERROR
} client_connection_state_t;

client_connection_state_t
client_connection_probe_result (ssize_t, int);

client_connection_state_t
client_connection_probe (int, int *);

#endif /* _GVMD_CLIENT_WATCHER_H */
