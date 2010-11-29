/* Test 4 of OMP CREATE_TASK
 * $Id$
 * Description: Test CREATE_TASK with a real RC file.
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

int
main ()
{
  int socket, found = 0;
  gnutls_session_t session;
  char* id;
  entity_t entity, config;
  entities_t configs;
  gchar* target_name;

  setup_test ();

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  /* Create a task. */

  if (omp_authenticate_env (&session)) goto fail;

  if (omp_create_task_rc_file (&session,
                               "new_task_small__many_plugins_yes_rc",
                               "Test for omp_create_task_4 task",
                               "Task for manager test omp_create_task_4.",
                               &id))
    goto fail;

  /* Check that there is a target for the task. */

  if (omp_authenticate_env (&session)) goto delete_fail;

  if (openvas_server_send (&session, "<get_targets/>") == -1)
    goto delete_fail;

  entity = NULL;
  read_entity (&session, &entity);

  target_name = g_strdup_printf ("Imported target for task %s", id);
  configs = entity->entities;
  while ((config = first_entity (configs)))
    {
      entity_t name = entity_child (config, "name");
      if (name == NULL) goto free_fail;
      if (strcmp (entity_text (name), target_name) == 0)
        {
          entity_t comment, hosts;
          comment = entity_child (config, "comment");
          if (comment == NULL
              || strcmp (entity_text (comment), ""))
            break;
          hosts = entity_child (config, "hosts");
          if (hosts == NULL
              || strcmp (entity_text (hosts), "tomato4.rgb"))
            break;
          found = 1;
          break;
        }
      configs = next_entities (configs);
    }

 free_fail:
  g_free (target_name);
  free_entity (entity);
 delete_fail:
  omp_delete_task (&session, id);
  free (id);
 fail:
  close_manager_connection (socket, session);
  return found ? EXIT_SUCCESS : EXIT_FAILURE;
}
