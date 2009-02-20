/* Common test utilities header.
 * $Id$
 * Description: Header for common test utilities.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 *
 * Copyright:
 * Copyright (C) 2009 Intevation GmbH
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
connect_to_manager (gnutls_session_t *);

int
close_manager_connection (int, gnutls_session_t);

int
send_to_manager (gnutls_session_t*, const char*);

/* XML */

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
authenticate (gnutls_session_t* session,
              const char* username,
              const char* password);

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
