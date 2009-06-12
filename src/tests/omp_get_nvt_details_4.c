/* Test 4 of OMP GET_NVT_DETAILS.
 * $Id$
 * Description: Test the OMP GET_NVT_DETAILS with a known ID.
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
  const char* status;
  const char* nvt_id;
  entity_t entity, entity2, nvt;

  setup_test ();

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  if (env_authenticate (&session))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Request feed information once, so manager requests it from server. */

  if (send_to_manager (&session, "<get_nvt_all/>") == -1)
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }
  entity = NULL;
  if (read_entity (&session, &entity))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }
  free_entity (entity);

  /* Create a task. */

  if (create_task_from_rc_file (&session,
                                "new_task_small_rc",
                                "Task for omp_get_nvt_details_1",
                                "Test omp_get_nvt_details_1 task.",
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

#if 0
  if (env_authenticate (&session))
    {
      delete_task (&session, id);
      close_manager_connection (socket, session);
      free (id);
      return EXIT_FAILURE;
    }
#endif

  if (sendf_to_manager (&session,
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

  delete_task (&session, id);
  free (id);

  /* Get summary of all NVTs, to get details of one NVT. */

  if (send_to_manager (&session, "<get_nvt_all/>") == -1)
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }
  entity = NULL;
  if (read_entity (&session, &entity))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }
  nvt = entity_child (entity, "nvt");
  if (nvt == NULL
      || (nvt_id = entity_attribute (nvt, "oid")) == NULL)
    {
      free_entity (entity);
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Request details of the NVT. */

  if (sendf_to_manager (&session,
                        "<get_nvt_details oid=\"%s\"/>",
                        nvt_id)
      == -1)
    {
      free_entity (entity);
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Read the response. */

  entity2 = NULL;
  if (read_entity (&session, &entity2))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Compare to expected response. */

  if (entity2 == NULL
      || strcmp (entity_name (entity2), "get_nvt_details_response")
      || (status = entity_attribute (entity2, "status")) == NULL
      || strcmp (status, "200")
      || compare_entities (entity_child (entity, "nvt"), nvt))
    {
      free_entity (entity);
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  free_entity (entity);
  close_manager_connection (socket, session);
  return EXIT_SUCCESS;
}
