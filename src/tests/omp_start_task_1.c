/* Test 1 of OMP START_TASK.
 * $Id$
 * Description: Test running OMP START_TASK twice in one session.
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

#define TRACE 0

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
  unsigned int id;

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  if (env_authenticate (&session)) goto fail;

  /* Create a task. */

  if (create_task_from_rc_file (&session,
                                "new_task_empty_rc",
                                "Task for omp_start_task_0",
                                "Test omp_start_task_0 task.",
                                &id))
    goto fail;

  /* Start the task. */

  if (start_task (&session, id)) goto delete_fail;

  /* Wait for the task to finish on the server. */

  if (wait_for_task_end (&session, id)) goto delete_fail;

  /* Start the task again. */

  if (start_task (&session, id)) goto delete_fail;

  /* Wait for the task to finish on the server again. */

  if (wait_for_task_end (&session, id)) goto delete_fail;

  delete_task (&session, id);
  close_manager_connection (socket, session);
  return EXIT_SUCCESS;

 delete_fail:
  delete_task (&session, id);
 fail:
  close_manager_connection (socket, session);
  return EXIT_FAILURE;
}
