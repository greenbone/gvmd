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

  fprintf (stdout, "connected\n");

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
      fprintf (stderr, "send %i from %s\n", left, string);
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


/* Reading the XML. */

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
  tracef ("handle_start_element %s\n", element_name);
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
  tracef ("handle_end_element %s\n", element_name);
  *((const char**)user_data) = g_strdup (element_name);
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
  tracef ("handle_text\n");
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
  tracef ("handle_error\n");
  tracef ("Error: %s\n", error->message);
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
 * @brief Read an XML entity from the manager.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 *
 * @return Pointer to name of entity on success, NULL on error.
 */
char*
read_entity (gnutls_session_t* session)
{
  char* entity = NULL;

  /* Create the XML parser. */
  GMarkupParser xml_parser;
  xml_parser.start_element = handle_start_element;
  xml_parser.end_element = handle_end_element;
  xml_parser.text = handle_text;
  xml_parser.passthrough = NULL;
  xml_parser.error = handle_error;

  while (buffer_point < buffer_end)
    {
      ssize_t count;
 retry:
      tracef ("asking for %i\n", buffer_end - buffer_point);
      count = gnutls_record_recv (*session,
                                  buffer_point,
                                  buffer_end - buffer_point);
      if (count < 0)
        {
          if (count == GNUTLS_E_INTERRUPTED)
            /* Interrupted, try read again. */
            goto retry;
          if (count == GNUTLS_E_REHANDSHAKE)
            /* Try again. TODO Rehandshake. */
            goto retry;
          fprintf (stderr, "Failed to read from manager (read_entity).\n");
          gnutls_perror (count);
          break;
        }
      if (count == 0)
        {
          /* End of file. */
          return NULL;
        }
      tracef ("<= %.*s\n", count, buffer_point);
      buffer_point += count;

      GError* error = NULL;
      GMarkupParseContext *xml_context;
      xml_context = g_markup_parse_context_new (&xml_parser,
                                                0,
                                                &entity,
                                                NULL);
      g_markup_parse_context_parse (xml_context,
				    buffer_start,
				    buffer_point - buffer_start,
				    &error);
      if (error)
	{
	  fprintf (stderr, "Failed to parse client XML: %s\n", error->message);
	  g_error_free (error);
	  return NULL;
	}
      return entity;
    }
  return NULL;
}
