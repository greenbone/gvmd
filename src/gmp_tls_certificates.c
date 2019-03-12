/* Copyright (C) 2019 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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
 * @file gmp_tls_certificates.c
 * @brief GVM GMP layer: TLS certificates
 *
 * This includes function and variable definitions for GMP handling
 *  of TLS certificates.
 */

#include "gmp_tls_certificates.h"
#include "gmp_base.h"
#include "gmp_get.h"
#include "manage_tls_certificates.h"

#include <glib.h>
#include <stdlib.h>
#include <string.h>

#include <gvm/util/xmlutils.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"



/* GET_TLS_CERTIFICATES. */

/**
 * @brief The get_tls_certificates command.
 */
typedef struct
{
  get_data_t get;    ///< Get args.
} get_tls_certificates_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static get_tls_certificates_t get_tls_certificates_data;

/**
 * @brief Reset command data.
 */
static void
get_tls_certificates_reset ()
{
  get_data_reset (&get_tls_certificates_data.get);
  memset (&get_tls_certificates_data, 0, sizeof (get_tls_certificates_t));
}

/**
 * @brief Handle command start element.
 *
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
get_tls_certificates_start (const gchar **attribute_names,
                   const gchar **attribute_values)
{
  get_data_parse_attributes (&get_tls_certificates_data.get, "tls_certificate",
                             attribute_names,
                             attribute_values);
}

/**
 * @brief Handle end element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
void
get_tls_certificates_run (gmp_parser_t *gmp_parser, GError **error)
{
  iterator_t tls_certificates;
  int count, filtered, ret, first;

  count = 0;

  ret = init_get ("get_tls_certificates",
                  &get_tls_certificates_data.get,
                  "TLS Certificates",
                  &first);
  if (ret)
    {
      switch (ret)
        {
          case 99:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("get_tls_certificates",
                                "Permission denied"));
            break;
          default:
            internal_error_send_to_client (error);
            get_tls_certificates_reset ();
            return;
        }
      get_tls_certificates_reset ();
      return;
    }

  /* Setup the iterator. */

  ret = init_tls_certificate_iterator (&tls_certificates,
                                       &get_tls_certificates_data.get);
  if (ret)
    {
      switch (ret)
        {
          case 1:
            if (send_find_error_to_client ("get_tls_certificates",
                                           "tls_certificate",
                                           get_tls_certificates_data.get.id,
                                           gmp_parser))
              {
                error_send_to_client (error);
                get_tls_certificates_reset ();
                return;
              }
            break;
          case 2:
            if (send_find_error_to_client
                  ("get_tls_certificates", "filter",
                   get_tls_certificates_data.get.filt_id, gmp_parser))
              {
                error_send_to_client (error);
                get_tls_certificates_reset ();
                return;
              }
            break;
          case -1:
            SEND_TO_CLIENT_OR_FAIL
              (XML_INTERNAL_ERROR ("get_tls_certificates"));
            break;
        }
      get_tls_certificates_reset ();
      return;
    }

  /* Loop through tls_certificates, sending XML. */

  SEND_GET_START ("tls_certificate");
  while (1)
    {
      ret = get_next (&tls_certificates, &get_tls_certificates_data.get,
                      &first, &count, init_tls_certificate_iterator);
      if (ret == 1)
        break;
      if (ret == -1)
        {
          internal_error_send_to_client (error);
          get_tls_certificates_reset ();
          return;
        }

      /* Send generic GET command elements. */

      SEND_GET_COMMON (tls_certificate, &get_tls_certificates_data.get,
                       &tls_certificates);

      /* Send tls_certificate info. */
      SENDF_TO_CLIENT_OR_FAIL 
        ("<certificate>%s</certificate>"
         "<md5_fingerprint>%s</md5_fingerprint>"
         "<trust>%d</trust>"
         "<valid>%d</valid>"
         "<activation_time>%s</activation_time>"
         "<expiration_time>%s</expiration_time>"
         "<subject_dn>%s</subject_dn>"
         "<issuer_dn>%s</issuer_dn>"
         "</tls_certificate>",
         tls_certificate_iterator_certificate (&tls_certificates),
         tls_certificate_iterator_md5_fingerprint (&tls_certificates),
         tls_certificate_iterator_trust (&tls_certificates),
         tls_certificate_iterator_valid (&tls_certificates),
         tls_certificate_iterator_activation_time (&tls_certificates),
         tls_certificate_iterator_expiration_time (&tls_certificates),
         tls_certificate_iterator_subject_dn (&tls_certificates),
         tls_certificate_iterator_issuer_dn (&tls_certificates));
      count++;
    }
  cleanup_iterator (&tls_certificates);
  filtered = get_tls_certificates_data.get.id
              ? 1
              : tls_certificate_count (&get_tls_certificates_data.get);
  SEND_GET_END ("tls_certificate",
                &get_tls_certificates_data.get,
                count,
                filtered);

  get_tls_certificates_reset ();
}


/* CREATE_TLS_CERTIFICATE. */

/**
 * @brief The create_tls_certificate command.
 */
typedef struct
{
  context_data_t *context;     ///< XML parser context.
} create_tls_certificate_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static create_tls_certificate_t create_tls_certificate_data;

/**
 * @brief Reset command data.
 */
static void
create_tls_certificate_reset ()
{
  if (create_tls_certificate_data.context->first)
    {
      free_entity (create_tls_certificate_data.context->first->data);
      g_slist_free_1 (create_tls_certificate_data.context->first);
    }
  g_free (create_tls_certificate_data.context);
  memset (&create_tls_certificate_data, 0, sizeof (create_tls_certificate_t));
}

/**
 * @brief Start a command.
 *
 * @param[in]  gmp_parser        GMP parser.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
create_tls_certificate_start (gmp_parser_t *gmp_parser,
                     const gchar **attribute_names,
                     const gchar **attribute_values)
{
  memset (&create_tls_certificate_data, 0, sizeof (create_tls_certificate_t));
  create_tls_certificate_data.context = g_malloc0 (sizeof (context_data_t));
  create_tls_certificate_element_start (gmp_parser, "create_tls_certificate",
                                        attribute_names, attribute_values);
}

/**
 * @brief Start element.
 *
 * @param[in]  gmp_parser        GMP parser.
 * @param[in]  name              Element name.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
create_tls_certificate_element_start (gmp_parser_t *gmp_parser, const gchar *name,
                             const gchar **attribute_names,
                             const gchar **attribute_values)
{
  xml_handle_start_element (create_tls_certificate_data.context, name, attribute_names,
                            attribute_values);
}

/**
 * @brief Execute command.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
void
create_tls_certificate_run (gmp_parser_t *gmp_parser, GError **error)
{
  entity_t entity, copy, comment, name, certificate;
  tls_certificate_t new_tls_certificate;

  entity = (entity_t) create_tls_certificate_data.context->first->data;

  copy = entity_child (entity, "copy");

  if (copy)
    {
      /* Copy from an existing tls_certificate and exit. */

      name = entity_child (entity, "name");
      comment = entity_child (entity, "comment");
      switch (copy_tls_certificate (name ? entity_text (name) : NULL,
                                    comment ? entity_text (comment) : NULL,
                                    entity_text (copy), &new_tls_certificate))
        {
          case 0:
            {
              char *uuid;
              uuid = tls_certificate_uuid (new_tls_certificate);
              SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID
                                        ("create_tls_certificate"),
                                       uuid);
              log_event ("tls_certificate", "TLS Certificate", uuid, "created");
              free (uuid);
              break;
            }
          case 1:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_tls_certificate",
                                "TLS Certificate exists already"));
            log_event_fail ("tls_certificate", "TLS Certificate", NULL,
                            "created");
            break;
          case 2:
            if (send_find_error_to_client ("create_tls_certificate",
                                           "tls_certificate",
                                           entity_text (copy),
                                           gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            log_event_fail ("tls_certificate",
                            "TLS Certificate",
                            NULL,
                            "created");
            break;
          case 99:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_tls_certificate",
                                "Permission denied"));
            log_event_fail ("tls_certificate",
                            "TLS Certificate",
                            NULL,
                            "created");
            break;
          case -1:
          default:
            SEND_TO_CLIENT_OR_FAIL
             (XML_INTERNAL_ERROR ("create_tls_certificate"));
            log_event_fail ("tls_certificate",
                            "TLS Certificate",
                            NULL,
                            "created");
            break;
        }
      create_tls_certificate_reset ();
      return;
    }

  /* Check given info. */

  name = entity_child (entity, "name");
  comment = entity_child (entity, "comment");
  certificate = entity_child (entity, "certificate");

  switch (create_tls_certificate
                (name ? entity_text (comment) : NULL,
                 comment ? entity_text (comment) : "",
                 certificate ? entity_text (certificate) : NULL,
                 &new_tls_certificate))
    {
      case 0:
        {
          char *uuid = tls_certificate_uuid (new_tls_certificate);
          SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_tls_certificate"),
                                   uuid);
          log_event ("tls_certificate", "TLS Certificate", uuid, "created");
          free (uuid);
          break;
        }
      case 99:
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("create_tls_certificate",
                            "Permission denied"));
        log_event_fail ("tls_certificate", "TLS Certificate", NULL, "created");
        break;
      case -1:
      default:
        SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_tls_certificate"));
        log_event_fail ("tls_certificate", "TLS Certificate", NULL, "created");
        break;
    }

  create_tls_certificate_reset ();
}

/**
 * @brief End element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 * @param[in]  name         Element name.
 *
 * @return 0 success, 1 command finished.
 */
int
create_tls_certificate_element_end (gmp_parser_t *gmp_parser, GError **error,
                                    const gchar *name)
{
  xml_handle_end_element (create_tls_certificate_data.context, name);
  if (create_tls_certificate_data.context->done)
    {
      create_tls_certificate_run (gmp_parser, error);
      return 1;
    }
  return 0;
}

/**
 * @brief Add text to element.
 *
 * @param[in]  text         Text.
 * @param[in]  text_len     Text length.
 */
void
create_tls_certificate_element_text (const gchar *text, gsize text_len)
{
  xml_handle_text (create_tls_certificate_data.context, text, text_len);
}
