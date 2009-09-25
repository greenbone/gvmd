/* Test 0 of OMP CREATE_LSC_CREDENTIAL.
 * $Id$
 * Description: Test the OMP CREATE_LSC_CREDENTIAL command.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@intevation.de>
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
  int socket, ret;
  gnutls_session_t session;
  entity_t entity, expected;

  setup_test ();

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  /* Create LSC credential. */

  if (omp_authenticate_env (&session))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  omp_delete_lsc_credential (&session, "omp_create_lsc_credential_0");
  if (openvas_server_send (&session,
                           "<create_lsc_credential>"
                           "<name>omp_create_lsc_credential_0</name>"
                           "</create_lsc_credential>")
      == -1)
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Read the response. */

  entity = NULL;
  if (read_entity (&session, &entity))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Compare. */

  expected = add_entity (NULL, "create_lsc_credential_response", NULL);
  add_attribute (expected, "status", "201");
  add_attribute (expected, "status_text", "OK, resource created");

  if (compare_entities (entity, expected))
    ret = EXIT_FAILURE;
  else
    ret = EXIT_SUCCESS;

  /* Cleanup. */

  omp_delete_lsc_credential (&session, "omp_create_lsc_credential_0");
  close_manager_connection (socket, session);
  free_entity (entity);
  free_entity (expected);

  return ret;
}
