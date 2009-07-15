/* Test 0 of read_protocol.
 * $Id$
 * Description: Test read_protcol timing out.
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

#define TRACE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "../tracef.h"

int
main ()
{
  int socket;
  gnutls_session_t session;
  char* id;

  setup_test ();

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  /* FIX This must be more than the timeout, which is currently 300. */
  sleep (320);

  switch (env_authenticate (&session))
    {
      case 1:
        /* Manager closed connection. */
        close_manager_connection (socket, session);
        return EXIT_SUCCESS;
      default:
        /* Authentication failed. */
        break;
    }

  if (create_task_from_rc_file (&session,
                                "new_task_small_rc",
                                "Test for read_protocol_0",
                                "Simple test scan.",
                                &id))
    {
      close_manager_connection (socket, session);
      return EXIT_SUCCESS;
    }

  close_manager_connection (socket, session);
  return EXIT_FAILURE;
}
