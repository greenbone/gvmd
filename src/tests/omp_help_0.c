/* Test 0 of OMP HELP.
 * $Id$
 * Description: Test the OMP HELP command.
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

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "../tracef.h"

static char* help_text = "\n"
"    ABORT_TASK             Abort a running task.\n"
"    AUTHENTICATE           Authenticate with the manager.\n"
"    CREATE_TASK            Create a new task.\n"
"    DELETE_REPORT          Delete an existing report.\n"
"    DELETE_TASK            Delete an existing task.\n"
"    GET_DEPENDENCIES       Get dependencies for all available NVTs.\n"
"    GET_NVT_ALL            Get IDs and names of all available NVTs.\n"
"    GET_NVT_DETAILS        Get all details for all available NVTs.\n"
"    GET_NVT_FEED_CHECKSUM  Get checksum for entire NVT collection.\n"
"    GET_PREFERENCES        Get preferences for all available NVTs.\n"
"    GET_REPORT             Get a report identified by its unique ID.\n"
"    GET_RULES              Get the rules for the authenticated user.\n"
"    GET_STATUS             Get task status information.\n"
"    GET_VERSION            Get the OpenVAS Manager Protocol version.\n"
"    HELP                   Get this help text.\n"
"    MODIFY_REPORT          Modify an existing report.\n"
"    MODIFY_TASK            Update an existing task.\n"
"    START_TASK             Manually start an existing task.\n";

int
main ()
{
  int socket;
  gnutls_session_t session;

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  /* Request the help text. */

  if (env_authenticate (&session))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  if (send_to_manager (&session, "<help/>") == -1)
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Read the response. */

  entity_t entity = NULL;
  read_entity (&session, &entity);

  /* Compare to expected response. */

  entity_t expected = add_entity (NULL, "help_response", help_text);
  add_entity (&expected->entities, "status", "200");

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
