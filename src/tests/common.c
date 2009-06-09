/* Common test utilities.
 * $Id$
 * Description: Common utilities for tests.
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

/**
 * @file common.c
 * @brief Common utilities for tests.
 *
 * There are three sets of utilities here.
 *
 * The first set provides lower level facilities for communicating with the
 * manager.  The functions are
 * \ref connect_to_manager,
 * \ref close_manager_connection,
 * \ref send_to_manager and
 * \ref sendf_to_manager.
 *
 * The second set is a generic XML interface.
 * The tests use the interface to read and handle the XML returned by
 * the manager.  The key function is \ref read_entity.
 *
 * The third set uses the other two to provide higher level, OMP-aware,
 * facilities for communicating with the manager.  The functions are
 * \ref authenticate,
 * \ref env_authenticate,
 * \ref create_task,
 * \ref create_task_from_rc_file,
 * \ref delete_task,
 * \ref start_task,
 * \ref wait_for_task_end and
 * \ref wait_for_task_start.
 *
 * There are examples of using this interface in the tests.
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

/**
 * @brief Verbose output flag.
 *
 * Only consulted if compiled with TRACE non-zero.
 */
int verbose = 0;

#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>             /* For XML parsing. */
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"
#include "../tracef.h"

/**
 * @brief Manager address.
 */
struct sockaddr_in address;


/* Low level manager communication. */

/**
 * @brief Connect to the manager using a given host and port.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  host     Host to connect to.
 * @param[in]  port     Port to connect to.
 *
 * @return 0 on success, -1 on error.
 */
int
connect_to_manager_host_port (gnutls_session_t * session,
                              char *host, int port)
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
    address.sin_port = htons (port);

  if (!inet_aton(host, &address.sin_addr))
    {
      fprintf (stderr, "Failed to create server address %s.\n",
               host);
      return -1;
    }

  tracef ("   Set to connect to address %s port %i\n",
          host,
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
  tracef ("   Shook hands with manager.\n");

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
 * @brief Connect to the manager.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 *
 * @return 0 on success, -1 on error.
 */
int
connect_to_manager (gnutls_session_t * session)
{
  return connect_to_manager_host_port (session, OPENVASMD_ADDRESS, OPENVASMD_PORT);
}

/**
 * @brief Close the connection to the manager.
 *
 * @param[in]  socket   Socket connected to manager (from \ref connect_to_manager).
 * @param[in]  session  GNUTLS session with manager.
 *
 * @return 0 on success, -1 on error.
 */
int
close_manager_connection (int socket, gnutls_session_t session)
{
  /* Turn off blocking. */
  if (fcntl (socket, F_SETFL, O_NONBLOCK) == -1) return -1;

  gnutls_bye (session, GNUTLS_SHUT_RDWR);
  close (socket);
  return 0;
}

/**
 * @brief Send a string to the manager.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  string   String to send.
 *
 * @return 0 on success, 1 if manager closed connection, -1 on error.
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
      tracef ("   count: %i\n", count);
      if (count < 0)
        {
          if (count == GNUTLS_E_INTERRUPTED)
            /* Interrupted, try write again. */
            continue;
          if (count == GNUTLS_E_REHANDSHAKE)
            {
              /* \todo Rehandshake. */
              tracef ("   send_to_manager rehandshake\n");
              continue;
            }
          fprintf (stderr, "Failed to write to manager.\n");
          gnutls_perror (count);
          return -1;
        }
      if (count == 0)
        {
          /* Manager closed connection. */
          tracef ("=  manager closed\n");
          return 1;
        }
      tracef ("=> %.*s\n", count, string);
      string += count;
      left -= count;
    }
  tracef ("=> done\n");

  return 0;
}

/**
 * @brief Format and send a string to the manager.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  format   printf-style format string for message.
 *
 * @return 0 on success, 1 if manager closed connection, -1 on error.
 */
int
sendf_to_manager (gnutls_session_t* session, const char* format, ...)
{
  va_list args;
  va_start (args, format);
  gchar* msg = g_strdup_vprintf (format, args);
  int ret = send_to_manager (session, msg);
  g_free (msg);
  va_end (args);
  return ret;
}


/* XML. */

/**
 * @brief XML context.
 *
 * This structure is used to pass data between XML event handlers and the
 * caller of the XML parser.
 */
typedef struct {
  GSList* first;    ///< The name of the very first entity.
  GSList* current;  ///< The element currently being parsed.
  gboolean done;    ///< Flag which is true when the first element is closed.
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
  entity->attributes = NULL;
  return entity;
}

/**
 * @brief Return all the entities from an entities_t after the first.
 *
 * @param[in]  entities  The list of entities.
 *
 * @return All the entities that follow the first.
 */
entities_t
next_entities (entities_t entities)
{
  return (entities_t) entities->next;
}

/**
 * @brief Return the first entity from an entities_t.
 *
 * @param[in]  entities  The list of entities.
 *
 * @return The first entity.
 */
entity_t
first_entity (entities_t entities)
{
  return (entity_t) entities->data;
}

/**
 * @brief Add an XML entity to a tree of entities.
 *
 * @param[in]  entities  The tree of entities
 * @param[in]  name      Name of the entity.  Copied, copy is freed by
 *                       free_entity.
 * @param[in]  text      Text of the entity.  Copied, copy is freed by
 *                       free_entity.
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
 * @brief Add an attribute to an XML entity.
 *
 * @param[in]  entity  The entity.
 * @param[in]  name    Name of the attribute.  Copied, copy is freed by
 *                     free_entity.
 * @param[in]  value   Text of the attribute.  Copied, copy is freed by
 *                     free_entity.
 *
 * @return The new entity.
 */
void
add_attribute (entity_t entity, const char* name, const char* value)
{
  if (entity->attributes == NULL)
    entity->attributes = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                g_free, g_free);
  g_hash_table_insert (entity->attributes, g_strdup (name), g_strdup (value));
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
      if (entity->attributes) g_hash_table_destroy (entity->attributes);
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
 * @brief Get the text an entity.
 *
 * @param[in]  entity  Entity.
 *
 * @return Entity text, which is freed by free_entity.
 */
char*
entity_text (entity_t entity)
{
  return entity->text;
}

/**
 * @brief Get the name an entity.
 *
 * @param[in]  entity  Entity.
 *
 * @return Entity name, which is freed by free_entity.
 */
char*
entity_name (entity_t entity)
{
  return entity->name;
}

/**
 * @brief Compare a given name with the name of a given entity.
 *
 * @param[in]  entity  Entity.
 * @param[in]  name    Name.
 *
 * @return Zero if entity name matches name, otherwise a positive or negative
 *         number as from strcmp.
 */
int
compare_entity_with_name (gconstpointer entity, gconstpointer name)
{
  return strcmp (entity_name ((entity_t) entity), (char*) name);
}

/**
 * @brief Get a child of an entity.
 *
 * @param[in]  entity  Entity.
 * @param[in]  name    Name of the child.
 *
 * @return Entity if found, else NULL.
 */
entity_t
entity_child (entity_t entity, const char* name)
{
  if (entity->entities)
    {
      entities_t match = g_slist_find_custom (entity->entities,
                                              name,
                                              compare_entity_with_name);
      return match ? (entity_t) match->data : NULL;
    }
  return NULL;
}

/**
 * @brief Get an attribute of an entity.
 *
 * @param[in]  entity  Entity.
 * @param[in]  name    Name of the attribute.
 *
 * @return Attribute if found, else NULL.
 */
const char*
entity_attribute (entity_t entity, const char* name)
{
  if (entity->attributes)
    return (const char*) g_hash_table_lookup (entity->attributes, name);
  return NULL;
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
 * @brief Add attributes from an XML callback to an entity.
 *
 * @param[in]  entity  The entity.
 * @param[in]  names   List of attribute names.
 * @param[in]  values  List of attribute values.
 */
void
add_attributes (entity_t entity, const gchar **names, const gchar **values)
{
  if (*names && *values)
    {
      if (entity->attributes == NULL)
        entity->attributes = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                    g_free, g_free);
      while (*names && *values)
        {
          if (*values)
            g_hash_table_insert (entity->attributes,
                                 g_strdup (*names),
                                 g_strdup (*values));
          names++;
          values++;
        }
    }
}

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
  //tracef ("   handle_start_element %s\n", element_name);
  context_data_t* data = (context_data_t*) user_data;
  if (data->current)
    {
      entity_t current = (entity_t) data->current->data;
      entity = add_entity (&current->entities, element_name, NULL);
    }
  else
     entity = add_entity (NULL, element_name, NULL);

  add_attributes (entity, attribute_names, attribute_values);

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
  //tracef ("   handle_end_element %s\n", element_name);
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
  //tracef ("   handle_text\n");
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
  //tracef ("   handle_error\n");
  tracef ("   Error: %s\n", error->message);
}

/**
 * @brief Read an XML entity tree from the manager.
 *
 * @param[in]   session   Pointer to GNUTLS session.
 * @param[out]  entity    Pointer to an entity tree.
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
              if (context_data.first && context_data.first->data)
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
              if (context_data.first && context_data.first->data)
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
          if (context_data.first && context_data.first->data)
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
              if (context_data.first && context_data.first->data)
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
  fflush (stream);
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
 * @brief Look for a key-value pair in a hash table.
 *
 * @param[in]  key          Key.
 * @param[in]  value        Value.
 * @param[in]  attributes2  The hash table.
 *
 * @return FALSE if found, TRUE otherwise.
 */
gboolean
compare_find_attribute (gpointer key, gpointer value, gpointer attributes2)
{
  gchar* value2 = g_hash_table_lookup (attributes2, key);
  if (value2 && strcmp (value, value2) == 0) return FALSE;
  tracef ("  compare failed attribute: %s\n", (char*) value);
  return TRUE;
}

/**
 * @brief Compare two XML entity.
 *
 * @param[in]  entity1  First entity.
 * @param[in]  entity2  First entity.
 *
 * @return 0 if equal, 1 otherwise.
 */
int
compare_entities (entity_t entity1, entity_t entity2)
{
  //tracef ("  compare %p vs %p\n", entity1, entity2);
  if (entity1 == NULL) return entity2 == NULL ? 0 : 1;
  if (entity2 == NULL) return 1;
  //tracef ("    attribs %p vs %p\n", entity1->attributes, entity2->attributes);
  if (entity1->attributes == NULL) return entity2->attributes == NULL ? 0 : 1;
  if (entity2->attributes == NULL) return 1;

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

  if (g_hash_table_find (entity1->attributes,
                         compare_find_attribute,
                         (gpointer) entity2->attributes))
    {
      tracef ("  compare failed attributes\n");
      return 1;
    }

  // FIX entities can be in any order
  GSList* list1 = entity1->entities;
  GSList* list2 = entity2->entities;
  while (list1 && list2)
    {
      if (compare_entities (list1->data, list2->data))
        {
          tracef ("  compare failed subentity\n");
          return 1;
        }
      list1 = g_slist_next (list1);
      list2 = g_slist_next (list2);
    }
  if (list1 == list2) return 0;
  /* More entities in one of the two. */
  tracef ("  compare failed number of entities (%s)\n", entity1->name);
  return 1;
}

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


/* OMP. */

/**
 * @brief Get the task status from an OMP STATUS response.
 *
 * @param[in]  response   STATUS response.
 *
 * @return The entity_text of the status entity if the entity is found, else
 *         NULL.
 */
const char*
task_status (entity_t response)
{
  entity_t status = entity_child (response, "status");
  if (status) return entity_text (status);
  return NULL;
}

/**
 * @brief Authenticate with the manager.
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  username  Username.
 * @param[in]  password  Password.
 *
 * @return 0 on success, 1 if manager closed connection, -1 on error.
 */
int
authenticate (gnutls_session_t* session,
              const char* username,
              const char* password)
{
  gchar* msg = g_strdup_printf ("<authenticate><credentials>"
                                "<username>%s</username>"
                                "<password>%s</password>"
                                "</credentials></authenticate>",
                                username,
                                password);
  int ret = send_to_manager (session, msg);
  g_free (msg);
  if (ret) return ret;

#if 1
  return 0;
#else
  /* What to do if OMP authenticate is changed to respond always. */

  entity_t entity = NULL;
  if (read_entity (session, &entity)) return -1;

  entity_t expected = add_entity (NULL, "authenticate_response", NULL);
  add_attribute (expected, "status", "201");

  ret = compare_entities (entity, expected);

  free_entity (expected);
  free_entity (entity);

  return ret ? -1 : 0;
#endif
}

/**
 * @brief Authenticate, getting credentials from the environment.
 *
 * Get the user name from environment variable OPENVAS_TEST_USER if that is
 * set, else from USER.  Get the password from OPENVAS_TEST_PASSWORD.
 *
 * @param[in]  session   Pointer to GNUTLS session.
 *
 * @return 0 on success, 1 if manager closed connection, -1 on error.
 */
int
env_authenticate (gnutls_session_t* session)
{
  char* user = getenv ("OPENVAS_TEST_USER");
  if (user == NULL)
    {
      user = getenv ("USER");
      if (user == NULL) return -1;
    }

  char* password = getenv ("OPENVAS_TEST_PASSWORD");
  if (password == NULL) return -1;

  return authenticate (session, user, password);
}

/**
 * @brief Create a task, given the task description as an RC file.
 *
 * @param[in]   session     Pointer to GNUTLS session.
 * @param[in]   config      Task configuration.
 * @param[in]   config_len  Length of config.
 * @param[in]   identifier  Task identifier.
 * @param[in]   comment     Task comment.
 * @param[out]  id          Pointer for newly allocated ID of new task.  Only
 *                          set on successful return.
 *
 * @return 0 on success, -1 on error.
 */
int
create_task (gnutls_session_t* session,
             char* config,
             unsigned int config_len,
             char* identifier,
             char* comment,
             char** id)
{
  /* Convert the file contents to base64. */

  gchar* new_task_file = g_base64_encode ((guchar*) config,
                                          config_len);

  /* Create the OMP request. */

  gchar* new_task_request;
  new_task_request = g_strdup_printf ("<create_task>"
                                      "<task_file>%s</task_file>"
                                      "<name>%s</name>"
                                      "<comment>%s</comment>"
                                      "</create_task>",
                                      new_task_file,
                                      identifier,
                                      comment);
  g_free (new_task_file);

  /* Send the request. */

  int ret = send_to_manager (session, new_task_request);
  g_free (new_task_request);
  if (ret) return -1;

  /* Read the response. */

  entity_t entity = NULL;
  if (read_entity (session, &entity)) return -1;

  /* Get the ID of the new task from the response. */

  entity_t id_entity = entity_child (entity, "task_id");
  if (id_entity == NULL)
    {
      free_entity (entity);
      return -1;
    }
  *id = g_strdup (entity_text (id_entity));
  return 0;
}

/**
 * @brief Create a task, given the task description as an RC file.
 *
 * @param[in]   session     Pointer to GNUTLS session.
 * @param[in]   file_name   Name of the RC file.
 * @param[in]   identifier  Task identifier.
 * @param[in]   comment     Task comment.
 * @param[out]  id          ID of new task.
 *
 * @return 0 on success, -1 on error.
 */
int
create_task_from_rc_file (gnutls_session_t* session,
                          char* file_name,
                          char* identifier,
                          char* comment,
                          char** id)
{
  gchar* new_task_rc = NULL;
  gsize new_task_rc_len;
  GError* error = NULL;

  /* Read in the RC file. */

  g_file_get_contents (file_name,
                       &new_task_rc,
                       &new_task_rc_len,
                       &error);
  if (error)
    {
      g_error_free (error);
      return -1;
    }

  int ret = create_task (session,
                         new_task_rc,
                         new_task_rc_len,
                         identifier,
                         comment,
                         id);
  g_free (new_task_rc);
  return ret;
}

/**
 * @brief Start a task and read the manager response.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  id       ID of task.
 *
 * @return 0 on success, -1 on error.
 */
int
start_task (gnutls_session_t* session,
            char* id)
{
  if (sendf_to_manager (session,
                        "<start_task><task_id>%s</task_id></start_task>",
                        id)
      == -1)
    return -1;

  /* Read the response. */

  entity_t entity = NULL;
  if (read_entity (session, &entity)) return -1;

  /* Check the response. */

  const char* status = entity_attribute (entity, "status");
  if (status == NULL)
    {
      free_entity (entity);
      return -1;
    }
  if (strlen (status) == 0)
    {
      free_entity (entity);
      return -1;
    }
  char first = status[0];
  free_entity (entity);
  if (first == '2') return 0;
  return -1;
}

/**
 * @brief Wait for a task to start running on the server.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  id       ID of task.
 *
 * @return 0 on success, -1 on error.
 */
int
wait_for_task_start (gnutls_session_t* session,
                     char* id)
{
  while (1)
    {
      if (sendf_to_manager (session, "<get_status/>") == -1)
        return -1;

      /* Read the response. */

      entity_t entity = NULL;
      if (read_entity (session, &entity)) return -1;

      /* Check the response. */

      const char* status = entity_attribute (entity, "status");
      if (status == NULL)
        {
          free_entity (entity);
          return -1;
        }
      if (strlen (status) == 0)
        {
          free_entity (entity);
          return -1;
        }
      if (status[0] == '2')
        {
          /* Check the running status of the given task. */

          char* run_state = NULL;

#if 0
          /* Lisp version. */
          (do-children (entity child)
            (when (string= (entity-type child) "task")
              (let ((task-id (entity-child child "task_id")))
                (fi* task-id
                  (free-entity entity)
                  (return-from wait-for-task-start -1))
                (when (string= (entity-text task-id) id)
                  (let ((status (entity-child child "status")))
                    (fi* status
                      (free-entity entity)
                      (return-from wait-for-task-start -1))
                    (setq run-state (entity-text status)))
                  (return)))))
#endif

          DO_CHILDREN (entity, child, temp,
                       if (strcasecmp (entity_name (child), "task") == 0)
                         {
                           entity_t task_id = entity_child (child, "task_id");
                           if (task_id == NULL)
                             {
                               free_entity (entity);
                               return -1;
                             }
                           if (strcasecmp (entity_text (task_id), id)
                               == 0)
                             {
                               entity_t status = entity_child (child, "status");
                               if (status == NULL)
                                 {
                                   free_entity (entity);
                                   return -1;
                                 }
                               run_state = entity_text (status);
                               break;
                             }
                         });

          if (run_state == NULL)
            {
              free_entity (entity);
              return -1;
            }

          if (strcmp (run_state, "Running") == 0
              || strcmp (run_state, "Done") == 0)
            {
              free_entity (entity);
              return 0;
            }
          free_entity (entity);
        }

      sleep (1);
    }
}

/**
 * @brief Wait for a task to finish running on the server.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  id       ID of task.
 *
 * @return 0 on success, -1 on error.
 */
int
wait_for_task_end (gnutls_session_t* session,
                   char* id)
{
  tracef ("wait_for_task_end\n");
  while (1)
    {
      if (sendf_to_manager (session, "<get_status/>") == -1)
        return -1;

      /* Read the response. */

      entity_t entity = NULL;
      if (read_entity (session, &entity)) return -1;

      /* Check the response. */

      const char* status = entity_attribute (entity, "status");
      if (status == NULL)
        {
          free_entity (entity);
          return -1;
        }
      if (strlen (status) == 0)
        {
          free_entity (entity);
          return -1;
        }
      if (status[0] == '2')
        {
          /* Check the running status of the given task. */

          char* run_state = NULL;

#if 0
          /* Lisp version. */
          (do-children (entity child)
            (when (string= (entity-type child) "task")
              (let ((task-id (entity-child child "task_id")))
                (fi* task-id
                  (free-entity entity)
                  (return-from wait-for-task-start -1))
                (when (string= (entity-text task-id) id)
                  (let ((status (entity-child child "status")))
                    (fi* status
                      (free-entity entity)
                      (return-from wait-for-task-start -1))
                    (setq run-state (entity-text status)))
                  (return)))))
#endif

          DO_CHILDREN (entity, child, temp,
                       if (strcasecmp (entity_name (child), "task") == 0)
                         {
                           entity_t task_id = entity_child (child, "task_id");
                           if (task_id == NULL)
                             {
                               free_entity (entity);
                               return -1;
                             }
                           if (strcasecmp (entity_text (task_id), id)
                               == 0)
                             {
                               entity_t status = entity_child (child, "status");
                               if (status == NULL)
                                 {
                                   free_entity (entity);
                                   return -1;
                                 }
                               run_state = entity_text (status);
                               break;
                             }
                         });

          if (run_state == NULL)
            {
              free_entity (entity);
              return -1;
            }

          if (strcmp (run_state, "Done") == 0)
            {
              free_entity (entity);
              return 0;
            }
          free_entity (entity);
        }

      sleep (1);
    }
}

/**
 * @brief Wait for the manager to actually remove a task.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  id       ID of task.
 *
 * @return 0 on success, -1 on error.
 */
int
wait_for_task_delete (gnutls_session_t* session,
                      const char* id)
{
  while (1)
    {
      entity_t entity;
      const char* status;

      if (sendf_to_manager (session,
                            "<get_status>"
                            "<task_id>%s</task_id>"
                            "</get_status>",
                            id)
          == -1)
        return -1;

      entity = NULL;
      if (read_entity (session, &entity)) return -1;

      status = task_status (entity);
      free_entity (entity);
      if (status == NULL) break;

      sleep (1);
    }
  return 0;
}

/**
 * @brief Delete a task and read the manager response.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  id       ID of task.
 *
 * @return 0 on success, -1 on error.
 */
int
delete_task (gnutls_session_t* session, char* id)
{
  if (sendf_to_manager (session,
                        "<delete_task><task_id>%s</task_id></delete_task>",
                        id)
      == -1)
    return -1;

  /* Read the response. */

  entity_t entity = NULL;
  if (read_entity (session, &entity)) return -1;

  /* Check the response. */

  const char* status = entity_attribute (entity, "status");
  if (status == NULL)
    {
      free_entity (entity);
      return -1;
    }
  if (strlen (status) == 0)
    {
      free_entity (entity);
      return -1;
    }
  char first = status[0];
  free_entity (entity);
  if (first == '2') return 0;
  return -1;
}

/**
 * @brief Get the status of a task.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  id       ID of task.
 * @param[out] status   Status return.
 *
 * @return 0 on success, -1 or OMP response code on error.
 */
int
omp_get_status (gnutls_session_t* session, const char* id, entity_t* status)
{
  const char* status_code;
  int ret;

  if (sendf_to_manager (session,
                        "<get_status>"
                        "<task_id>%s</task_id>"
                        "</get_status>",
                        id)
      == -1)
    return -1;

  /* Read the response. */

  *status = NULL;
  if (read_entity (session, status)) return -1;

  /* Check the response. */

  status_code = entity_attribute (*status, "status");
  if (status_code == NULL)
    {
      free_entity (*status);
      return -1;
    }
  if (strlen (status_code) == 0)
    {
      free_entity (*status);
      return -1;
    }
  if (status_code[0] == '2') return 0;
  ret = (int) strtol (status_code, NULL, 10);
  free_entity (*status);
  if (errno == ERANGE) return -1;
  return ret;
}


/* Setup. */

/**
 * @brief Setup a test.
 *
 * Set up the verbosity flag according the the OPENVAS_TEST_VERBOSE
 * environment variable and prepare signal handling.
 *
 * Each test should call this at the very beginning of the test.
 */
void
setup_test ()
{
  char* env_verbose = getenv ("OPENVAS_TEST_VERBOSE");
  if (env_verbose) verbose = strcmp (env_verbose, "0");
  signal (SIGPIPE, SIG_IGN);
}
