/* Common test utilities header.
 * $Id$
 * Description: Header for common test utilities.
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
#include <gnutls/gnutls.h>
#include <stdio.h>

/* Communication. */

int
connect_to_manager_host_port (gnutls_session_t *, char*, int);

int
connect_to_manager (gnutls_session_t *);

int
close_manager_connection (int, gnutls_session_t);

int
send_to_manager (gnutls_session_t*, const char*);

int
sendf_to_manager (gnutls_session_t*, const char*, ...);

/* XML. */

typedef GSList* entities_t;

typedef struct
{
  char* name;
  char* text;
  //void* attributes;
  entities_t entities;
} * entity_t;

entity_t
add_entity (entities_t*, const char*, const char*);

int
compare_entities (entity_t, entity_t);

entity_t
entity_child (entity_t entity, char* name);

char*
entity_name (entity_t entity);

char*
entity_text (entity_t entity);

void
free_entity (entity_t);

void
print_entity (FILE*, entity_t);

void
print_entities (FILE*, entities_t);

int
read_entity (gnutls_session_t*, entity_t*);

/* OMP. */

// FIX temp export
/**
 * @brief Do something for each child of an entity.
 *
 * Calling "break" during body exits the loop.
 *
 * @param[in]  entity  The entity.
 * @param[in]  child   Name to use for child variable.
 * @param[in]  temp    Name to use for internal variable.
 * @param[in]  body    The code to run for each child.
 */
#define DO_CHILDREN(entity, child, temp, body)      \
  do                                                \
    {                                               \
      GSList* temp = entity->entities;              \
      while (temp)                                  \
        {                                           \
          entity_t child = temp->data;              \
          {                                         \
            body;                                   \
          }                                         \
          temp = g_slist_next (temp);               \
        }                                           \
    }                                               \
  while (0)

#if 0
/* Lisp version of DO_CHILDREN. */
(defmacro do-children ((entity child) &body body)
  "Do something for each child of an entity."
  (let ((temp (gensym)))
    `(while ((,temp (entity-entities ,entity) (rest ,temp)))
            (,temp)
       ,@body)))
#endif

int
authenticate (gnutls_session_t* session,
              const char* username,
              const char* password);

int
env_authenticate (gnutls_session_t* session);

int
create_task (gnutls_session_t*, char*, unsigned int, char*, char*,
             unsigned int*);

int
create_task_from_rc_file (gnutls_session_t*, char*, char*, char*,
                          unsigned int*);

int
delete_task (gnutls_session_t*, unsigned int);

int
start_task (gnutls_session_t* , unsigned int);

int
wait_for_task_end (gnutls_session_t*, unsigned int);

int
wait_for_task_start (gnutls_session_t*, unsigned int);
