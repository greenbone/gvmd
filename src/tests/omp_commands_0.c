/* Test 0 of OMP COMMANDS.
 * $Id$
 * Description: Test OMP COMMANDS with two simple commands.
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
  entity_t entity, expected, version_response, version;

  setup_test ();

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  if (env_authenticate (&session))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Request the help text. */

  if (openvas_server_send (&session,
                           "<commands>"
                           "<get_version/>"
                           "<get_version/>"
                           "</commands>")
      == -1)
     {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Read the response. */

  entity = NULL;
  read_entity (&session, &entity);

  /* Compare to expected response. */

  expected = add_entity (NULL, "commands_response", NULL);
  add_attribute (expected, "status", "200");
  add_attribute (expected, "status_text", "OK");

  version_response = add_entity (&expected->entities, "get_version_response", NULL);
  add_attribute (version_response, "status", "200");
  add_attribute (version_response, "status_text", "OK");
  version = add_entity (&version_response->entities, "version", "1.0");
  add_attribute (version, "preferred", "yes");

  version_response = add_entity (&expected->entities, "get_version_response", NULL);
  add_attribute (version_response, "status", "200");
  add_attribute (version_response, "status_text", "OK");
  version = add_entity (&version_response->entities, "version", "1.0");
  add_attribute (version, "preferred", "yes");

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
