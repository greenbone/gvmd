/* Test 3 of getting the configs.
 * $Id$
 * Description: Test OMP get_configs, waiting for the server NVT info.
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
#include "../string.h"

int
main ()
{
  int socket, found_1 = 0, found_2 = 0;
  gnutls_session_t session;
  entities_t configs;
  entity_t entity, config;

  setup_test ();

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  if (env_authenticate (&session))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Repeatedly request the feed details until they are available. */

  while (1)
    {
      if (send_to_manager (&session,
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

  /* Create a config. */

  if (omp_create_config_from_rc_file (&session,
                                      "omp_get_configs_1",
                                      NULL,
                                      "new_task_small_rc"))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Request the configs. */

  if (send_to_manager (&session, "<get_configs/>")
      == -1)
    goto delete_fail;

  /* Check that the response includes the standard configs. */

  entity = NULL;
  if (read_entity (&session, &entity))
    {
      fprintf (stderr, "Failed to read response.\n");
      goto delete_fail;
    }

  configs = entity->entities;
  while ((config = first_entity (configs)))
    {
      entity_t name = entity_child (config, "name");
      if (name == NULL) goto free_fail;
      if (strcmp (entity_text (name), "Full") == 0)
        {
          entity_t comment, count, growing;
          comment = entity_child (config, "comment");
          if (comment == NULL
              || strcmp (entity_text (comment), "All inclusive configuration."))
            break;
          count = entity_child (config, "family_count");
          if (count == NULL) break;
          growing = entity_child (count, "growing");
          if (growing == NULL || strcmp (entity_text (growing), "1"))
            break;
          count = entity_child (config, "nvt_count");
          if (count == NULL) break;
          growing = entity_child (count, "growing");
          if (growing == NULL || strcmp (entity_text (growing), "1"))
            break;
          found_1 = 1;
        }
      else if (strcmp (entity_text (name), "omp_get_configs_1") == 0)
        {
          entity_t comment, count, growing;
          comment = entity_child (config, "comment");
          if (comment == NULL
              || strcmp (entity_text (comment), ""))
            break;
          count = entity_child (config, "family_count");
          if (count == NULL || strcmp (entity_text (count), "2")) break;
          growing = entity_child (count, "growing");
          if (growing == NULL || strcmp (entity_text (growing), "0"))
            break;
          count = entity_child (config, "nvt_count");
          if (count == NULL || strcmp (entity_text (count), "4"))
            break;
          growing = entity_child (count, "growing");
          if (growing == NULL || strcmp (entity_text (growing), "0"))
            break;
          found_2 = 1;
        }
      configs = next_entities (configs);
    }

 free_fail:
  free_entity (entity);
 delete_fail:
  omp_delete_config (&session, "omp_get_configs_1");
  close_manager_connection (socket, session);
  return (found_1 && found_2) ? EXIT_SUCCESS : EXIT_FAILURE;
}
