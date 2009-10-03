/* Test 1 of OMP GET_PREFERENCES.
 * $Id$
 * Description: Test the OMP GET_PREFERENCES command.
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
  entity_t preferences_1, preferences_2;

  setup_test ();

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  if (omp_authenticate_env (&session))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  if (omp_get_preferences_503 (&session, &preferences_1))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Get the preferences. */

  if (openvas_server_send (&session, "<get_preferences />") == -1)
    {
      free_entity (preferences_1);
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Read the response. */

  preferences_2 = NULL;
  read_entity (&session, &preferences_2);
  if (preferences_2) print_entity (stdout, preferences_2);

  /* Compare to expected response. */

  if (preferences_2
      && entity_attribute (preferences_2, "status")
      && (strcmp (entity_attribute (preferences_2, "status"), "200") == 0)
      && (strcmp (entity_attribute (preferences_2, "status_text"), "OK") == 0))
    {
      if (compare_entities (preferences_1, preferences_2) == 0)
        {
          free_entity (preferences_1);
          free_entity (preferences_2);
          close_manager_connection (socket, session);
          return EXIT_SUCCESS;
        }
      free_entity (preferences_1);
    }

  if (preferences_2) free_entity (preferences_2);
  close_manager_connection (socket, session);
  return EXIT_FAILURE;
}
