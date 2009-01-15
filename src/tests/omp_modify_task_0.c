/* Test 0 of OMP MODIFY_TASK.
 * $Id$
 * Description: Test the OMP MODIFY_TASK command.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
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

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  /* Create a task. */

  if (send_to_manager (&session, "<new_task><task_file>base64 text</task_file><identifier>Scan Webserver</identifier><comment>Hourly scan of the webserver</comment></new_task>")
      == -1)
    {
      gnutls_bye (session, GNUTLS_SHUT_RDWR);
      close (socket);
      return EXIT_FAILURE;
    }

  char* entity = read_entity (&session);
  tracef ("new task entity: %s\n", entity);
  // FIX get id, assume 0 for now

  if (strcmp (entity, "new_task_response"))
    return EXIT_FAILURE;

  /* Send a modify_task request. */

  if (send_to_manager (&session, "<modify_task><task_id>0</task_id><parameter>task_file</parameter><value>Modified hourly scan of the webserver</value></modify_task>")
      == -1)
    {
      gnutls_bye (session, GNUTLS_SHUT_RDWR);
      close (socket);
      return EXIT_FAILURE;
    }

  /* Read the response. */

  entity = read_entity (&session);
  tracef ("entity: %s\n", entity);

  /* Cleanup. */

  gnutls_bye (session, GNUTLS_SHUT_RDWR);
  close (socket);

  /* Compare. */

  if (strcmp (entity, "modify_task_response") == 0)
    return EXIT_SUCCESS;

  return EXIT_FAILURE;
}
