/* Test 1 of OMP GET_CERTIFICATES.
 * $Id$
 * Description: Test the OMP GET_CERTIFICATES command after a task runs.
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
  entity_t entity;
  const char* status;

  setup_test ();

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  if (omp_authenticate_env (&session))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Request certificates, and give the server some time to send other
   * cruft first. */

  if (openvas_server_send (&session, "<get_certificates/>") == -1)
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

  sleep (10);

  /* Request certificates until the manager responds with OK or an error. */

  while (1)
    {
      if (openvas_server_send (&session, "<get_certificates/>") == -1)
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

      if (entity == NULL
          || strcmp (entity_name (entity), "get_certificates_response")
          || (status = entity_attribute (entity, "status")) == NULL
          || (strcmp (status, "200")
              && strcmp (status, "503")))
        {
          free_entity (entity);
          close_manager_connection (socket, session);
          return EXIT_FAILURE;
        }
      if (strcmp (status, "200") == 0)
        {
          free_entity (entity);
          close_manager_connection (socket, session);
          return EXIT_SUCCESS;
        }
      free_entity (entity);
      sleep (0.25);
    }

  close_manager_connection (socket, session);
  return EXIT_FAILURE;
}
