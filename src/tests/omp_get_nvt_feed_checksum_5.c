/* Test 4 of OMP GET_NVT_FEED_CHECKSUM.
 * $Id$
 * Description:
 * Test GET_NVT_FEED_CHECKSUM with a missing algorithm after starting a
 * task.
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

#include <ctype.h>
#include <glib.h>
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
  entity_t entity;

  setup_test ();

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  /* Create a task. */

  if (env_authenticate (&session))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  if (create_task_from_rc_file (&session,
                                "new_task_small_rc",
                                "Task for omp_get_nvt_feed_checksum_1",
                                "Test omp_get_nvt_feed_checksum_1 task.",
                                &id))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Start the task. */

  if (start_task (&session, id))
    {
      delete_task (&session, id);
      close_manager_connection (socket, session);
      free (id);
      return EXIT_FAILURE;
    }

  /* Wait for the task to start on the server. */

  if (wait_for_task_start (&session, id))
    {
      delete_task (&session, id);
      close_manager_connection (socket, session);
      free (id);
      return EXIT_FAILURE;
    }

  /* Request the task status. */

  if (env_authenticate (&session))
    {
      delete_task (&session, id);
      close_manager_connection (socket, session);
      free (id);
      return EXIT_FAILURE;
    }

  if (openvas_server_sendf (&session,
                            "<get_status task_id=\"%s\"/>",
                            id)
      == -1)
    {
      delete_task (&session, id);
      close_manager_connection (socket, session);
      free (id);
      return EXIT_FAILURE;
    }

  entity = NULL;
  if (read_entity (&session, &entity))
    {
      delete_task (&session, id);
      close_manager_connection (socket, session);
      free (id);
      return EXIT_FAILURE;
    }
  free_entity (entity);

  /* Get the feed checksum. */

  if (openvas_server_send (&session,
                           "<get_nvt_feed_checksum algorithm=\"xxx\"/>")
      == -1)
    {
      delete_task (&session, id);
      close_manager_connection (socket, session);
      free (id);
      return EXIT_FAILURE;
    }

  /* Read the response. */

  entity = NULL;
  read_entity (&session, &entity);

  /* Compare to expected response. */

  if (entity == NULL
      || entity_attribute (entity, "status") == NULL
      || strcmp (entity_attribute (entity, "status"), "400"))
    {
      free_entity (entity);
      delete_task (&session, id);
      close_manager_connection (socket, session);
      free (id);
      return EXIT_FAILURE;
    }

  free_entity (entity);
  delete_task (&session, id);
  close_manager_connection (socket, session);
  free (id);
  return EXIT_SUCCESS;
}
