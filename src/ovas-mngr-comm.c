/* OpenVAS Manager
 * $Id$
 * Description: See below.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 * Jan-Oliver Wagner <jan-oliver.wagner@intevation.de>
 *
 * Copyright:
 * Copyright (C) 2009 Intevation GmbH
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

#include <string.h>
#include "tracef.h"

/**
 * @brief The size of the data buffers.
 *
 * When the client/server buffer is full `select' stops watching for input
 * from the client/server.
 */
#define BUFFER_SIZE 8192

/**
 * @brief Buffer of output to the server.
 */
char to_server[BUFFER_SIZE];

/**
 * @brief The end of the data in the \ref to_server buffer.
 */
int to_server_end = 0;

/**
 * @file ovas-mngr-comm.c
 * @brief API for communication between openvas-manger and openvas-server
 *
 * This file contains a API for communicating with an openvas-server
 * which uses OTP as protocol.
 */

/**
 * @brief Send a message to the server.
 *
 * @param[in]  msg  The message, a string.
 *
 * @return 0 for success, for any other values a failure happened.
 */
int send_to_server (char * msg)
{
  if (BUFFER_SIZE - to_server_end < strlen (msg))
    return 1;

  memcpy (to_server + to_server_end, msg, strlen (msg));
  tracef ("-> server: %s\n", msg);
  to_server_end += strlen (msg);

  return 0;
}
