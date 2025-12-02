/* Copyright (C) 2009-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Headers for the GMP daemon.
 */

#ifndef _GVMD_GMPD_H
#define _GVMD_GMPD_H

#include "manage.h"
#include "types.h"

#include <glib.h>
#include <gnutls/gnutls.h>
#include <gvm/util/serverutils.h>
#include <netinet/in.h>

/**
 * @brief Maximum number of seconds spent trying to read the protocol.
 */
#ifndef READ_PROTOCOL_TIMEOUT
#define READ_PROTOCOL_TIMEOUT 300
#endif

/**
 * @brief Size of \ref from_client data buffers, in bytes.
 */
#define FROM_BUFFER_SIZE 1048576

int
init_gmpd (GSList *, const db_conn_info_t *, int, int, int, int,
           manage_connection_forker_t, int);

void
init_gmpd_process (const db_conn_info_t *, gchar **);

int
serve_gmp (gvm_connection_t *, const db_conn_info_t *, gchar **);

#endif /* not _GVMD_GMPD_H */
