/* Test 2 of OMP GET_NVT_DETAILS.
 * $Id$
 * Description: Test OMP GET_NVT_DETAILS with a missing ID.
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

  setup_test ();

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  /* Repeatedly request the feed details until they are available. */

  if (env_authenticate (&session))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  while (1)
    {

      if (openvas_server_send (&session,
                               "<get_nvt_details oid=\"0.0.0.0.0.0.0.0.0.0\"/>")
          == -1)
        {
          close_manager_connection (socket, session);
          return EXIT_FAILURE;
        }

      /* Read the response. */

      entity = NULL;
      read_entity (&session, &entity);
      if (entity == NULL)
        {
          close_manager_connection (socket, session);
          return EXIT_FAILURE;
        }

      if (entity_attribute (entity, "status"))
        {
          if (strcmp (entity_attribute (entity, "status"), "503"))
            break;
        }
      else
        {
          free_entity (entity);
          close_manager_connection (socket, session);
          return EXIT_FAILURE;
        }

      free_entity (entity);
    }

  /* Compare to expected response. */

  entity_t expected = add_entity (NULL, "get_nvt_details_response", NULL);
  add_attribute (expected, "status", "404");
  add_attribute (expected,
                 "status_text",
                 "Failed to find NVT '0.0.0.0.0.0.0.0.0.0'");

  if (compare_entities (entity, expected))
    {
      free_entity (entity);
      free_entity (expected);
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  free_entity (expected);
  free_entity (entity);
  close_manager_connection (socket, session);
  return EXIT_SUCCESS;
}
