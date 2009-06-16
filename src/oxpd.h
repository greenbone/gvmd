/* OpenVAS Manager
 * $Id$
 * Description: Headers for OpenVAS Manager: common OMP and OTP code.
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

#ifndef OPENVAS_MANAGER_OXPD_H
#define OPENVAS_MANAGER_OXPD_H

#include "types.h"
#include <netinet/in.h>

/**
 * @brief Size of \ref from_client and \ref from_server data buffers, in bytes.
 */
#define FROM_BUFFER_SIZE 1048576

buffer_size_t from_buffer_size;

extern char from_client[];
extern buffer_size_t from_client_start;
extern buffer_size_t from_client_end;
extern char from_server[];
extern buffer_size_t from_server_start;
extern buffer_size_t from_server_end;

/*@-exportlocal@*/
extern struct sockaddr_in server_address;
/*@=exportlocal@*/

#endif
