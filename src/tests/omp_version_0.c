/* Test 0 of OMP OMP_VERSION.
 * $Id$
 * Description: Test the OMP OMP_VERSION command.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TRACE 1

#include "common.h"
#include "../tracef.h"

int
main ()
{
  int socket, ret;
  gnutls_session_t session;

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  /* Send a version request. */

  if (authenticate (&session, "mattm", "mattm") == -1) // FIX
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  if (send_to_manager (&session, "<omp_version/>\n") == -1)
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Read the response. */

  entity_t entity = NULL;
  if (read_entity (&session, &entity))
    {
      fprintf (stderr, "Failed to read response.\n");
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Compare. */

  entity_t expected = add_entity (NULL, "omp_version_response", NULL);
  add_entity (&expected->entities, "status", "200");
  entity_t version = add_entity (&expected->entities, "version", "1.0");
  add_entity (&version->entities, "preferred", NULL);

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
