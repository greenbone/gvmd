/* OpenVAS Manager
 * $Id$
 * Description: Module for OpenVAS Manager: common OMP and OTP code.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 *
 * Copyright:
 * Copyright (C) 2009 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * @file  oxpd.c
 * @brief Globals shared between the OpenVAS Manager OMP and OTP daemons.
 */

#include "oxpd.h"

#if 0
#include <sys/types.h>
#if FROM_BUFFER_SIZE > SSIZE_MAX
#error FROM_BUFFER_SIZE too big for `read'
#endif
#endif

/**
 * @brief Buffer of input from the client.
 */
char from_client[FROM_BUFFER_SIZE];

/**
 * @brief Buffer of input from the server.
 */
char from_server[FROM_BUFFER_SIZE];

/**
 * @brief Size of \ref from_client and \ref from_server data buffers, in bytes.
 */
buffer_size_t from_buffer_size = FROM_BUFFER_SIZE;

// FIX just make these pntrs?

/**
 * @brief The start of the data in the \ref from_client buffer.
 */
buffer_size_t from_client_start = 0;

/**
 * @brief The start of the data in the \ref from_server buffer.
 */
buffer_size_t from_server_start = 0;

/**
 * @brief The end of the data in the \ref from_client buffer.
 */
buffer_size_t from_client_end = 0;

/**
 * @brief The end of the data in the \ref from_server buffer.
 */
buffer_size_t from_server_end = 0;

/**
 * @brief The IP address of openvasd, "the server".
 */
struct sockaddr_in server_address;
