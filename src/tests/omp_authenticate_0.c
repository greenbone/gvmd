/* Test 0 of OMP AUTHENTICATE.
 * $Id$
 * Description: Test OMP AUTHENTICATE, where the username includes a quote.
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

#include "common.h"

#include <stdlib.h>

int
main ()
{
  int socket;
  gnutls_session_t session;
  entity_t entity, expected;

  setup_test ();

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  if (send_to_manager (&session,
                       "<authenticate><credentials>"
                       "<username>o'm</username>"
                       "<password>om</password>"
                       "</credentials></authenticate>")
      == -1)
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Read the response. */

  entity = NULL;
  read_entity (&session, &entity);

  /* Compare to expected response. */

  expected = add_entity (NULL, "authenticate_response", NULL);
  add_attribute (expected, "status", "400");
  add_attribute (expected, "status_text", "Authentication failed");

  if (compare_entities (entity, expected))
    {
      /* The test is just to see if the manager survives the quote, so
       * authentication success and failure are both OK. */

      free_entity (expected);
      expected = add_entity (NULL, "authenticate_response", NULL);
      add_attribute (expected, "status", "200");
      add_attribute (expected, "status_text", "OK");

      if (compare_entities (entity, expected))
        {
          free_entity (entity);
          close_manager_connection (socket, session);
          return EXIT_FAILURE;
        }
    }

  free_entity (expected);
  free_entity (entity);
  close_manager_connection (socket, session);
  return EXIT_SUCCESS;
}
