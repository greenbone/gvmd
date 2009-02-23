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
  int socket, ret;
  gnutls_session_t session;
  unsigned int id;

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  if (authenticate (&session, "mattm", "mattm"))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Create a task. */

#define CONFIG "Task configuration."

  if (create_task (&session,
                   CONFIG,
                   strlen (CONFIG),
                   "Test for omp_modify_task",
                   "Comment.",
                   &id))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Send a modify_task request. */

#if 0
  if (authenticate (&session, "mattm", "mattm"))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }
#endif

  if (sendf_to_manager (&session,
                        "<modify_task>"
                        "<task_id>%u</task_id>"
                        "<parameter>comment</parameter>"
                        "<value>Modified comment.</value>"
                        "</modify_task>",
                        id)
      == -1)
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Read the response. */

  entity_t entity = NULL;
  read_entity (&session, &entity);

  /* Compare. */

  entity_t expected = add_entity (NULL, "modify_task_response", NULL);
  add_entity (&expected->entities, "status", "201");

  if (compare_entities (entity, expected))
    ret = EXIT_FAILURE;
  else
    ret = EXIT_SUCCESS;

  /* Cleanup. */

  close_manager_connection (socket, session);
  free_entity (entity);
  free_entity (expected);

  return ret;
}
