/* Test 0 of a bogus OMP command.
 * $Id$
 * Description: Test the manager with a bogus command before authenticating.
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
  entity_t entity, expected;

  setup_test ();

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  /* Send the XML. */

  if (openvas_server_send (&session, "<xxx_bogus_command_name_xxx/>") == -1)
    goto fail;

  /* Read the response. */

  entity = NULL;
  read_entity (&session, &entity);

  /* Compare to expected response. */

  expected = add_entity (NULL, "omp_response", NULL);
  add_attribute (expected, "status", "400");
  add_attribute (expected,
                 "status_text",
                 "First command must be AUTHENTICATE");

  if (compare_entities (entity, expected))
    {
      free_entity (entity);
      free_entity (expected);
 fail:
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  free_entity (entity);
  free_entity (expected);
  close_manager_connection (socket, session);
  return EXIT_SUCCESS;
}
