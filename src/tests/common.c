/* Common test utilities.
 * $Id$
 * Description: Common utilities for tests.
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

/**
 * @brief Manager (openvasmd) port.
 */
#define OPENVASMD_PORT 1242

/**
 * @brief Manager (openvasmd) address.
 */
#define OPENVASMD_ADDRESS "127.0.0.1"

/**
 * @brief Size of the buffer for reading from the manager.
 */
#define BUFFER_SIZE 2048

/**
 * @brief Trace flag.
 */
#define TRACE 1

#include <assert.h>
#include <arpa/inet.h>
#include <glib.h>             /* For XML parsing. */
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"
#include "../tracef.h"

struct sockaddr_in address;


/* Manager communication. */

/**
 * @brief Connect to the manager.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 *
 * @return 0 on success, -1 on error.
 */
int
connect_to_manager (gnutls_session_t * session)
{
  /* Initialize security library. */

  int ret = gnutls_global_init();
  if (ret < 0)
    {
      fprintf (stderr, "Failed to initialize GNUTLS.\n");
      return -1;
    }

  /* Setup address. */

  address.sin_family = AF_INET;

  struct servent *servent = getservbyname ("omp", "tcp");
  if (servent)
    // FIX free servent?
    address.sin_port = servent->s_port;
  else
    address.sin_port = htons (OPENVASMD_PORT);

  if (!inet_aton(OPENVASMD_ADDRESS, &address.sin_addr))
    {
      fprintf (stderr, "Failed to create server address %s.\n",
               OPENVASMD_ADDRESS);
      return -1;
    }

  tracef ("   Set to connect to address %s port %i\n",
          OPENVASMD_ADDRESS,
          ntohs (address.sin_port));

  /* Make manager socket. */

  int manager_socket = socket (PF_INET, SOCK_STREAM, 0);
  if (manager_socket == -1)
    {
      perror ("Failed to create manager socket");
      return -1;
    }

  /* Setup manager session. */

  gnutls_certificate_credentials_t credentials;
  if (gnutls_certificate_allocate_credentials (&credentials))
    {
      fprintf (stderr, "Failed to allocate manager credentials.\n");
      goto close_fail;
    }

  if (gnutls_init (session, GNUTLS_CLIENT))
    {
      fprintf (stderr, "Failed to initialise manager session.\n");
      goto manager_free_fail;
    }

  if (gnutls_set_default_priority (*session))
    {
      fprintf (stderr, "Failed to set manager session priority.\n");
      goto manager_fail;
    }

  const int kx_priority[] = { GNUTLS_KX_DHE_RSA,
                              GNUTLS_KX_RSA,
                              GNUTLS_KX_DHE_DSS,
                              0 };
  if (gnutls_kx_set_priority (*session, kx_priority))
    {
      fprintf (stderr, "Failed to set manager key exchange priority.\n");
      goto manager_fail;
    }

  if (gnutls_credentials_set (*session,
                              GNUTLS_CRD_CERTIFICATE,
                              credentials))
    {
      fprintf (stderr, "Failed to set manager credentials.\n");
      goto manager_fail;
    }

  /* Connect to manager. */

  if (connect (manager_socket,
               (struct sockaddr *) &address,
               sizeof (struct sockaddr_in))
      == -1)
    {
      perror ("Failed to connect to manager");
      return -1;
    }

  tracef ("connected to manager\n");

  /* Complete setup of manager session. */

  gnutls_transport_set_ptr (*session,
                            (gnutls_transport_ptr_t) manager_socket);

  while (1)
    {
      int ret = gnutls_handshake (*session);
      if (ret >= 0)
        break;
      if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED)
        continue;
      fprintf (stderr, "Failed to shake hands with manager.\n");
      gnutls_perror (ret);
      if (shutdown (manager_socket, SHUT_RDWR) == -1)
        perror ("Failed to shutdown manager socket");
      goto manager_fail;
    }
  tracef ("   Handshook with server.\n");

  return manager_socket;

 manager_fail:
  gnutls_deinit (*session);

 manager_free_fail:
  gnutls_certificate_free_credentials (credentials);

 close_fail:
  close (manager_socket);

  return -1;
}

/**
 * @brief Send a string to the manager.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  string   String to send.
 *
 * @return 0 on success, -1 on error.
 */
int
send_to_manager (gnutls_session_t* session, const char* string)
{
  size_t left = strlen (string);
  while (left)
    {
      ssize_t count;
      tracef ("send %i from %.*s[...]\n", left, left < 30 ? left : 30, string);
      count = gnutls_record_send (*session, string, left);
      if (count < 0)
        {
          if (count == GNUTLS_E_INTERRUPTED)
            /* Interrupted, try write again. */
            continue;
          if (count == GNUTLS_E_REHANDSHAKE)
            /* \todo Rehandshake. */
            continue;
          fprintf (stderr, "Failed to write to manager.\n");
          gnutls_perror (count);
          return -1;
        }
      tracef ("=> %.*s\n", count, string);
      string += count;
      left -= count;
    }
  tracef ("=> done\n");

  return 0;
}


/* XML. */

typedef struct
{
  GSList* first;
  GSList* current;
  gboolean done;
} context_data_t;

/**
 * @brief Create an entity.
 *
 * @param[in]  name  Name of the entity.  Copied, freed by free_entity.
 * @param[in]  text  Text of the entity.  Copied, freed by free_entity.
 *
 * @return A newly allocated entity.
 */
entity_t
make_entity (const char* name, const char* text)
{
  entity_t entity;
  entity = g_malloc (sizeof (*entity));
  entity->name = g_strdup (name ?: "");
  entity->text = g_strdup (text ?: "");
  entity->entities = NULL;
  return entity;
}

/**
 * @brief Add an XML entity to a tree of entities.
 *
 * @param[in]  entities  The tree of entities
 * @param[in]  name      Name of the entity.  Copied, freed by free_entity.
 * @param[in]  text      Text of the entity.  Copied, freed by free_entity.
 *
 * @return The new entity.
 */
entity_t
add_entity (entities_t* entities, const char* name, const char* text)
{
  entity_t entity = make_entity (name, text);
  if (entities)
    *entities = g_slist_append (entities ? *entities : NULL, entity);
  return entity;
}

/**
 * @brief Free an entity, recursively.
 *
 * @param[in]  entity  The entity.
 */
void
free_entity (entity_t entity)
{
  if (entity)
    {
      free (entity->name);
      free (entity->text);
      // FIX props
      if (entity->entities)
        {
          GSList* list = entity->entities;
          while (list)
            {
              free_entity (list->data);
              list = list->next;
            }
          g_slist_free (entity->entities);
        }
    }
}

/**
 * @brief Buffer for reading from the manager.
 */
char buffer_start[BUFFER_SIZE];

/**
 * @brief Current position in the manager reading buffer.
 */
char* buffer_point = buffer_start;

/**
 * @brief End of the manager reading buffer.
 */
char* buffer_end = buffer_start + BUFFER_SIZE;

/**
 * @brief Handle the start of an OMP XML element.
 *
 * @param[in]  context           Parser context.
 * @param[in]  element_name      XML element name.
 * @param[in]  attribute_names   XML attribute name.
 * @param[in]  attribute_values  XML attribute values.
 * @param[in]  user_data         Dummy parameter.
 * @param[in]  error             Error parameter.
 */
void
handle_start_element (GMarkupParseContext* context,
                      const gchar *element_name,
                      const gchar **attribute_names,
                      const gchar **attribute_values,
                      gpointer user_data,
                      GError **error)
{
  entity_t entity;
  tracef ("   handle_start_element %s\n", element_name);
  context_data_t* data = (context_data_t*) user_data;
  if (data->current)
    {
      entity_t current = (entity_t) data->current->data;
      entity = add_entity (&current->entities, element_name, NULL);
    }
  else
     entity = add_entity (NULL, element_name, NULL);

  /* "Push" the element. */
  if (data->first == NULL)
    data->current = data->first = g_slist_prepend (NULL, entity);
  else
    data->current = g_slist_prepend (data->current, entity);
}

/**
 * @brief Handle the end of an XML element.
 *
 * @param[in]  context           Parser context.
 * @param[in]  element_name      XML element name.
 * @param[in]  user_data         Dummy parameter.
 * @param[in]  error             Error parameter.
 */
void
handle_end_element (GMarkupParseContext* context,
                    const gchar *element_name,
                    gpointer user_data,
                    GError **error)
{
  tracef ("   handle_end_element %s\n", element_name);
  context_data_t* data = (context_data_t*) user_data;
  assert (data->current && data->first);
  if (data->current == data->first)
    {
      assert (strcmp (element_name,
                      /* The name of the very first entity. */
                      ((entity_t) (data->first->data))->name)
              == 0);
      data->done = TRUE;
    }
  /* "Pop" the element. */
  if (data->current) data->current = g_slist_next (data->current);
}

/**
 * @brief Handle additional text of an XML element.
 *
 * @param[in]  context           Parser context.
 * @param[in]  text              The text.
 * @param[in]  text_len          Length of the text.
 * @param[in]  user_data         Dummy parameter.
 * @param[in]  error             Error parameter.
 */
void
handle_text (GMarkupParseContext* context,
             const gchar *text,
             gsize text_len,
             gpointer user_data,
             GError **error)
{
  tracef ("   handle_text\n");
  context_data_t* data = (context_data_t*) user_data;
  entity_t current = (entity_t) data->current->data;
  current->text = current->text
                  ? g_strconcat (current->text, text, NULL)
                  : g_strdup (text);
}

/**
 * @brief Handle an OMP XML parsing error.
 *
 * @param[in]  context           Parser context.
 * @param[in]  error             The error.
 * @param[in]  user_data         Dummy parameter.
 */
void
handle_error (GMarkupParseContext* context,
              GError *error,
              gpointer user_data)
{
  tracef ("   handle_error\n");
  tracef ("   Error: %s\n", error->message);
}

/**
 * @brief Read an XML entity tree from the manager.
 *
 * @param[in]   session   Pointer to GNUTLS session.
 * @param[out]  entities  Pointer to an entity tree.
 *
 * @return 0 success, -1 read error, -2 parse error, -3 end of file.
 */
int
read_entity (gnutls_session_t* session, entity_t* entity)
{
  /* Create the XML parser. */
  GMarkupParser xml_parser;
  xml_parser.start_element = handle_start_element;
  xml_parser.end_element = handle_end_element;
  xml_parser.text = handle_text;
  xml_parser.passthrough = NULL;
  xml_parser.error = handle_error;

  context_data_t context_data;
  context_data.done = FALSE;
  context_data.first = NULL;
  context_data.current = NULL;

  /* Setup the XML context. */
  GError* error = NULL;
  GMarkupParseContext *xml_context;
  xml_context = g_markup_parse_context_new (&xml_parser,
                                            0,
                                            &context_data,
                                            NULL);

  /* Read and parse, until encountering end of file or error. */
  while (1)
    {
      ssize_t count;
      while (1)
        {
          tracef ("   asking for %i\n", buffer_end - buffer_start);
          count = gnutls_record_recv (*session,
                                      buffer_start,
                                      buffer_end - buffer_start);
          if (count < 0)
            {
              if (count == GNUTLS_E_INTERRUPTED)
                /* Interrupted, try read again. */
                continue;
              if (count == GNUTLS_E_REHANDSHAKE)
                /* Try again. TODO Rehandshake. */
                continue;
              fprintf (stderr, "Failed to read from manager (read_entity).\n");
              gnutls_perror (count);
              free_entity (context_data.first->data);
              return -1;
            }
          if (count == 0)
            {
              /* End of file. */
              g_markup_parse_context_end_parse (xml_context, &error);
              if (error)
                {
                  tracef ("   End error: %s\n", error->message);
                  g_error_free (error);
                }
              free_entity (context_data.first->data);
              return -3;
            }
          break;
        }

      tracef ("<= %.*s\n", count, buffer_start);

      g_markup_parse_context_parse (xml_context,
				    buffer_start,
				    count,
				    &error);
      if (error)
	{
	  fprintf (stderr, "Failed to parse client XML: %s\n", error->message);
	  g_error_free (error);
          free_entity (context_data.first->data);
	  return -2;
	}
      if (context_data.done)
        {
          g_markup_parse_context_end_parse (xml_context, &error);
          if (error)
            {
              tracef ("   End error: %s\n", error->message);
              g_error_free (error);
              free_entity (context_data.first->data);
              return -2;
            }
          *entity = (entity_t) context_data.first->data;
          return 0;
        }
    }
}

/**
 * @brief Print an XML entity for g_slist_foreach.
 *
 * @param[in]  entity  The entity, as a gpointer.
 * @param[in]  stream  The stream to which to print, as a gpointer.
 */
void
foreach_print_entity (gpointer entity, gpointer stream)
{
  print_entity ((FILE*) stream, (entity_t) entity);
}

/**
 * @brief Print an XML entity.
 *
 * @param[in]  entity  The entity.
 * @param[in]  stream  The stream to which to print.
 */
void
print_entity (FILE* stream, entity_t entity)
{
  fprintf (stream, "<%s>", entity->name);
  fprintf (stream, "%s", entity->text);
  g_slist_foreach (entity->entities, foreach_print_entity, stream);
  fprintf (stream, "</%s>", entity->name);
}

/**
 * @brief Print an XML entity tree.
 *
 * @param[in]  stream    The stream to which to print.
 * @param[in]  entities  The entities.
 */
void
print_entities (FILE* stream, entities_t entities)
{
  g_slist_foreach (entities, foreach_print_entity, stream);
}

/**
 * @brief Compare two XML entity.
 *
 * @param[in]  entity1  First entity.
 * @param[in]  entity2  First entity.
 *
 * @return 0 is equal, 1 otherwise.
 */
int
compare_entities (entity_t entity1, entity_t entity2)
{
  if (strcmp (entity1->name, entity2->name))
    {
      tracef ("  compare failed name: %s vs %s\n", entity1->name, entity2->name);
      return 1;
    }
  if (strcmp (entity1->text, entity2->text))
    {
      tracef ("  compare failed text %s vs %s (%s)\n",
              entity1->text, entity2->text, entity1->name);
      return 1;
    }
  // FIX props
  // FIX entities can be in any order
  GSList* list1 = entity1->entities;
  GSList* list2 = entity2->entities;
  while (list1 && list2)
    {
      if (compare_entities (list1->data, list2->data)) return 1;
      list1 = g_slist_next (list1);
      list2 = g_slist_next (list2);
    }
  if (list1 == list2) return 0;
  /* More entities in one of the two. */
  tracef ("  compare failed number of entities (%s)\n", entity1->name);
  return 1;
}
