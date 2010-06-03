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
"    COMMANDS               Run a list of commands.\n"
"    CREATE_AGENT           Create an agent.\n"
"    CREATE_CONFIG          Create a config.\n"
"    CREATE_ESCALATOR       Create an escalator.\n"
"    CREATE_LSC_CREDENTIAL  Create a local security check credential.\n"
"    CREATE_NOTE            Create a note.\n"
"    CREATE_SCHEDULE        Create a schedule.\n"
"    CREATE_TARGET          Create a target.\n"
"    CREATE_TASK            Create a task.\n"
"    DELETE_AGENT           Delete an agent.\n"
"    DELETE_CONFIG          Delete a config.\n"
"    DELETE_ESCALATOR       Delete an escalator.\n"
"    DELETE_LSC_CREDENTIAL  Delete a local security check credential.\n"
"    DELETE_NOTE            Delete a note.\n"
"    DELETE_REPORT          Delete a report.\n"
"    DELETE_SCHEDULE        Delete a schedule.\n"
"    DELETE_TARGET          Delete a target.\n"
"    DELETE_TASK            Delete a task.\n"
"    GET_AGENTS             Get all agents.\n"
"    GET_CERTIFICATES       Get all available certificates.\n"
"    GET_CONFIGS            Get all configs.\n"
"    GET_DEPENDENCIES       Get dependencies for all available NVTs.\n"
"    GET_ESCALATORS         Get all escalators.\n"
"    GET_LSC_CREDENTIALS    Get all local security check credentials.\n"
"    GET_NOTES              Get all notes.\n"
"    GET_NVT_ALL            Get IDs and names of all available NVTs.\n"
"    GET_NVT_DETAILS        Get all details for all available NVTs.\n"
"    GET_NVT_FAMILIES       Get a list of all NVT families.\n"
"    GET_NVT_FEED_CHECKSUM  Get checksum for entire NVT collection.\n"
"    GET_PREFERENCES        Get preferences for all available NVTs.\n"
"    GET_REPORT             Get a report identified by its unique ID.\n"
"    GET_RESULTS            Get results.\n"
"    GET_RULES              Get the rules for the authenticated user.\n"
"    GET_SCHEDULES          Get all schedules.\n"
"    GET_SOURCES            Get external sources for resources.\n"
"    GET_STATUS             Get task status information.\n"
"    GET_SYSTEM_REPORTS     Get all system reports.\n"
"    GET_TARGETS            Get all targets.\n"
"    GET_VERSION            Get the OpenVAS Manager Protocol version.\n"
"    HELP                   Get this help text.\n"
"    MODIFY_CONFIG          Update an existing config.\n"
"    MODIFY_NOTE            Modify an existing note.\n"
"    MODIFY_REPORT          Modify an existing report.\n"
"    MODIFY_TASK            Update an existing task.\n"
"    RESUME_OR_START_TASK   Resume task if stopped, else start task.\n"
"    RESUME_STOPPED_TASK    Resume a stopped task.\n"
"    TEST_ESCALATOR         Run an escalator.\n"
"    START_TASK             Manually start an existing task.\n";

int
main ()
{
  int socket;
  gnutls_session_t session;

  setup_test ();

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  /* Request the help text. */

  if (omp_authenticate_env (&session))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  if (openvas_server_send (&session, "<help/>") == -1)
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Read the response. */

  entity_t entity = NULL;
  read_entity (&session, &entity);

  /* Compare to expected response. */

  entity_t expected = add_entity (NULL, "help_response", help_text);
  add_attribute (expected, "status", "200");
  add_attribute (expected, "status_text", "OK");

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
