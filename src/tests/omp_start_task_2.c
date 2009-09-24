/* Test 2 of OMP START_TASK.
 * $Id$
 * Description: Test OMP START_TASK, exiting the session early.
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

  if (omp_authenticate_env (&session)) goto fail;

  /* Create a task. */

  if (omp_create_task_rc_file (&session,
                               "new_task_empty_rc",
                               "Task for omp_start_task_0",
                               "Test omp_start_task_0 task.",
                               &id))
    goto fail;

  /* Start the task. */

  if (omp_start_task (&session, id)) goto delete_fail;

  /* End the session. */

  if (close_manager_connection (socket, session)) goto delete_fail;

  /* Connect again. */

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  if (omp_authenticate_env (&session)) goto fail;

  /* Wait for the task to finish on the scanner. */

  if (omp_wait_for_task_end (&session, id)) goto delete_fail;

  /* Start the task again. */

  if (omp_start_task (&session, id)) goto delete_fail;

  /* Wait for the task to finish on the scanner again. */

  if (omp_wait_for_task_end (&session, id)) goto delete_fail;

  omp_delete_task (&session, id);
  free (id);
  close_manager_connection (socket, session);
  return EXIT_SUCCESS;

 delete_fail:
  omp_delete_task (&session, id);
  free (id);
 fail:
  close_manager_connection (socket, session);
  return EXIT_FAILURE;
}
