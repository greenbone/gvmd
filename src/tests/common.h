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

#ifndef COMMON_H
#define COMMON_H

#include <glib.h>
#include <gnutls/gnutls.h>
#include <stdio.h>

/* Communication. */

int
connect_to_manager_host_port (gnutls_session_t *, const char*, int);

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
  GHashTable* attributes;
  entities_t entities;
} * entity_t;

entities_t
next_entities (entities_t);

entity_t
first_entity (entities_t);

entity_t
add_entity (entities_t*, const char*, const char*);

void
add_attribute (entity_t, const char*, const char*);

int
compare_entities (entity_t, entity_t);

entity_t
entity_child (entity_t, const char*);

const char*
entity_attribute (entity_t, const char*);

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
read_entity_and_text (gnutls_session_t*, entity_t*, char**);

int
read_entity (gnutls_session_t*, entity_t*);

/* OMP. */

const char*
task_status (entity_t status_response);

int
authenticate (gnutls_session_t* session,
              const char* username,
              const char* password);

int
env_authenticate (gnutls_session_t* session);

int
create_task (gnutls_session_t*, const char*, unsigned int,
             const char*, const char*, char**);

int
create_task_from_rc_file (gnutls_session_t*, const char*, const char*,
                          const char*, char**);

int
delete_task (gnutls_session_t*, const char*);

int
start_task (gnutls_session_t* , const char*);

int
wait_for_task_end (gnutls_session_t*, const char*);

int
wait_for_task_start (gnutls_session_t*, const char*);

int
wait_for_task_stop (gnutls_session_t*, const char*);

int
wait_for_task_delete (gnutls_session_t*, const char*);

int
omp_get_status (gnutls_session_t*, const char*, entity_t*);

int
omp_get_report (gnutls_session_t*, const char*, entity_t*);

int
omp_delete_report (gnutls_session_t*, const char*);

int
omp_delete_task (gnutls_session_t*, const char*);

int
omp_modify_task (gnutls_session_t*, const char*,
                 const char*, const char*, const char*);

int
omp_get_preferences (gnutls_session_t*, entity_t*);

int
omp_get_certificates (gnutls_session_t*, entity_t*);

int
omp_until_up (int (*) (gnutls_session_t*, entity_t*),
              gnutls_session_t*,
              entity_t*);

int
omp_create_target (gnutls_session_t*, const char*, const char*, const char*);

int
omp_delete_target (gnutls_session_t*, const char*);

int
omp_create_config (gnutls_session_t*, const char*, const char*, unsigned int);

int
omp_create_config_from_rc_file (gnutls_session_t*, const char*, const char*);

int
omp_delete_config (gnutls_session_t*, const char*);

/* Setup. */

void
setup_test ();

#endif /* not COMMON_H */
