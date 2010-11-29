/* Test 1 of getting the lsc_credentials.
 * $Id$
 * Description: Test OMP get_lsc_credentials, naming a credential.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
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

#define NAME_1 "ompgetlsccredentials1name1"
#define NAME_2 "ompgetlsccredentials1name2"
#define COMMENT_1 "Test comment."

int
main ()
{
  int socket, found_1 = 0;
  gnutls_session_t session;
  entities_t lsc_credentials;
  entity_t entity, lsc_credential;

  setup_test ();

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  if (omp_authenticate_env (&session))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Ensure the lsc_credentials exist. */

  omp_delete_lsc_credential (&session, NAME_1);
  if (omp_create_lsc_credential (&session, NAME_1, NAME_1, COMMENT_1) == -1)
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  omp_delete_lsc_credential (&session, NAME_2);
  if (omp_create_lsc_credential (&session, NAME_2, NAME_2, NULL) == -1)
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Request the lsc_credentials. */

  if (openvas_server_sendf (&session,
                            "<get_lsc_credentials name=\"%s\"/>",
                            NAME_1)
      == -1)
    goto delete_fail;

  /* Check that the response includes the created entry. */

  entity = NULL;
  if (read_entity (&session, &entity))
    {
      fprintf (stderr, "Failed to read response.\n");
      goto delete_fail;
    }

  if (entity_attribute (entity, "status")
      && strcmp (entity_attribute (entity, "status"), "200") == 0)
    {
      lsc_credentials = entity->entities;
      if ((lsc_credential = first_entity (lsc_credentials)))
        {
          entity_t name = entity_child (lsc_credential, "name");
          entity_t comment = entity_child (lsc_credential, "comment");
          entity_t login = entity_child (lsc_credential, "login");
          if (name == NULL
              || login == NULL
              || comment == NULL)
            goto free_fail;
          if ((strcmp (entity_text (name), NAME_1) == 0)
              && (strcmp (entity_text (login), NAME_1) == 0)
              && (strcmp (entity_text (comment), COMMENT_1) == 0))
            found_1 = 1;
        }
    }

 free_fail:
  free_entity (entity);
 delete_fail:
  omp_delete_lsc_credential (&session, NAME_1);
  omp_delete_lsc_credential (&session, NAME_2);
  close_manager_connection (socket, session);
  return found_1 ? EXIT_SUCCESS : EXIT_FAILURE;
}
