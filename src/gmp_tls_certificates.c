/* Copyright (C) 2019 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
  const gchar *include_certificate_data;

  get_data_parse_attributes (&get_tls_certificates_data.get, "tls_certificate",
                             attribute_names,
                             attribute_values);

  if (find_attribute (attribute_names, attribute_values,
                      "include_certificate_data", &include_certificate_data))
    {
       get_data_set_extra (&get_tls_certificates_data.get,
                           "include_certificate_data",
                           include_certificate_data);
    }
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
  int count, filtered, ret, first, include_certificate_data;
  const char *include_certificate_data_str;

  count = 0;

  include_certificate_data_str
    = get_data_get_extra (&get_tls_certificates_data.get,
                          "include_certificate_data");
  if (include_certificate_data_str
      && strcmp (include_certificate_data_str, "")
      && strcmp (include_certificate_data_str, "0"))
    include_certificate_data = 1;
  else
    include_certificate_data = 0;

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

  if (get_tls_certificates_data.get.trash)
    {
      SEND_TO_CLIENT_OR_FAIL
       (XML_ERROR_SYNTAX ("get_tls_certificates",
                          "TLS Certificates do not use the trashcan"));
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

      SEND_GET_COMMON_NO_TRASH (tls_certificate,
                                &get_tls_certificates_data.get,
                                &tls_certificates);

      /* Send tls_certificate info. */
      SENDF_TO_CLIENT_OR_FAIL
        ("<certificate format=\"%s\">%s</certificate>"
         "<sha256_fingerprint>%s</sha256_fingerprint>"
         "<md5_fingerprint>%s</md5_fingerprint>"
         "<trust>%d</trust>"
         "<valid>%d</valid>"
         "<time_status>%s</time_status>"
         "<activation_time>%s</activation_time>"
         "<expiration_time>%s</expiration_time>"
         "<subject_dn>%s</subject_dn>"
         "<issuer_dn>%s</issuer_dn>"
         "<serial>%s</serial>"
         "<last_seen>%s</last_seen>",
         tls_certificate_iterator_certificate_format (&tls_certificates)
            ? tls_certificate_iterator_certificate_format (&tls_certificates)
            : "unknown",
         (get_tls_certificates_data.get.details || include_certificate_data)
            ? tls_certificate_iterator_certificate (&tls_certificates)
            : "",
         tls_certificate_iterator_sha256_fingerprint (&tls_certificates),
         tls_certificate_iterator_md5_fingerprint (&tls_certificates),
         tls_certificate_iterator_trust (&tls_certificates),
         tls_certificate_iterator_valid (&tls_certificates),
         tls_certificate_iterator_time_status (&tls_certificates),
         tls_certificate_iterator_activation_time (&tls_certificates),
         tls_certificate_iterator_expiration_time (&tls_certificates),
         tls_certificate_iterator_subject_dn (&tls_certificates),
         tls_certificate_iterator_issuer_dn (&tls_certificates),
         tls_certificate_iterator_serial (&tls_certificates),
         tls_certificate_iterator_last_seen (&tls_certificates));

      if (get_tls_certificates_data.get.details)
        {
          iterator_t sources;
          SEND_TO_CLIENT_OR_FAIL ("<sources>");

          init_tls_certificate_source_iterator
             (&sources,
              get_iterator_resource (&tls_certificates));

          while (next (&sources))
            {
              const char *location_host_ip;
              const char *origin_type, *origin_id, *origin_data;

              location_host_ip
                = tls_certificate_source_iterator_location_host_ip (&sources);

              origin_type
                = tls_certificate_source_iterator_origin_type (&sources);
              origin_id
                = tls_certificate_source_iterator_origin_id (&sources);
              origin_data
                = tls_certificate_source_iterator_origin_data (&sources);

              SENDF_TO_CLIENT_OR_FAIL
                 ("<source id=\"%s\">"
                  "<timestamp>%s</timestamp>"
                  "<tls_versions>%s</tls_versions>",
                  tls_certificate_source_iterator_uuid (&sources),
                  tls_certificate_source_iterator_timestamp (&sources),
                  tls_certificate_source_iterator_tls_versions (&sources)
                    ? tls_certificate_source_iterator_tls_versions (&sources)
                    : "");

              if (tls_certificate_source_iterator_location_uuid (&sources))
                {
                  gchar *asset_id;

                  asset_id
                    = tls_certificate_host_asset_id (location_host_ip,
                                                     origin_id);

                  SENDF_TO_CLIENT_OR_FAIL
                     ("<location id=\"%s\">"
                      "<host>"
                      "<ip>%s</ip>"
                      "<asset id=\"%s\"/>"
                      "</host>"
                      "<port>%s</port>"
                      "</location>",
                      tls_certificate_source_iterator_location_uuid
                         (&sources),
                      location_host_ip,
                      asset_id ? asset_id : "",
                      tls_certificate_source_iterator_location_port
                         (&sources));

                  free (asset_id);
                }

              if (tls_certificate_source_iterator_origin_uuid (&sources))
                {

                  gchar *extra_xml;

                  SENDF_TO_CLIENT_OR_FAIL 
                     ("<origin id=\"%s\">"
                      "<origin_type>%s</origin_type>"
                      "<origin_id>%s</origin_id>"
                      "<origin_data>%s</origin_data>",
                      tls_certificate_source_iterator_origin_uuid (&sources),
                      origin_type,
                      origin_id,
                      origin_data);

                  extra_xml = tls_certificate_origin_extra_xml (origin_type,
                                                                origin_id,
                                                                origin_data);
                  if (extra_xml)
                    {
                      SEND_TO_CLIENT_OR_FAIL (extra_xml);
                    }

                  SENDF_TO_CLIENT_OR_FAIL
                     ("</origin>");

                  g_free (extra_xml);
                }

              SEND_TO_CLIENT_OR_FAIL ("</source>");
            }

          cleanup_iterator (&sources);

          SEND_TO_CLIENT_OR_FAIL ("</sources>");
        }

      SENDF_TO_CLIENT_OR_FAIL ("</tls_certificate>");
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
create_tls_certificate_element_start (gmp_parser_t *gmp_parser,
                                      const gchar *name,
                                      const gchar **attribute_names,
                                      const gchar **attribute_values)
{
  xml_handle_start_element (create_tls_certificate_data.context, name,
                            attribute_names, attribute_values);
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
  entity_t entity, copy, comment, name, certificate, trust;
  int trust_int;
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
  trust = entity_child (entity, "trust");

  if (certificate == NULL
      || strcmp (entity_text (certificate), "") == 0)
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("create_tls_certificate",
                           "CERTIFICATE is required and must not be empty."));
      log_event_fail ("tls_certificate",
                      "TLS Certificate",
                      NULL,
                      "created");
      return;
    }

  trust_int = 0;
  if (trust)
    {
      if (strcmp (entity_text (trust), "")
          && strcmp (entity_text (trust), "0"))
        trust_int = 1;
    }

  switch (create_tls_certificate
                (name ? entity_text (name) : NULL,
                 comment ? entity_text (comment) : "",
                 certificate ? entity_text (certificate) : NULL,
                 trust_int,
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
      case 1:
        {
          SEND_TO_CLIENT_OR_FAIL
            (XML_ERROR_SYNTAX ("create_tls_certificate",
                               "Invalid certificate content"));
          log_event_fail ("tls_certificate",
                          "TLS Certificate",
                          NULL,
                          "created");
          break;
        }
      case 2:
        {
          SEND_TO_CLIENT_OR_FAIL
            (XML_ERROR_SYNTAX ("create_tls_certificate",
                               "CERTIFICATE is not valid Base64."));
          log_event_fail ("tls_certificate",
                          "TLS Certificate",
                          NULL,
                          "created");
          break;
        }
      case 3:
        {
          SEND_TO_CLIENT_OR_FAIL
            (XML_ERROR_SYNTAX ("create_tls_certificate",
                              "TLS Certificate exists already"));
          log_event_fail ("tls_certificate", "TLS Certificate", NULL,
                          "created");
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


/* MODIFY_TLS_CERTIFICATE. */

/**
 * @brief The modify_tls_certificate command.
 */
typedef struct
{
  context_data_t *context;     ///< XML parser context.
} modify_tls_certificate_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static modify_tls_certificate_t modify_tls_certificate_data;

/**
 * @brief Reset command data.
 */
static void
modify_tls_certificate_reset ()
{
  if (modify_tls_certificate_data.context->first)
    {
      free_entity (modify_tls_certificate_data.context->first->data);
      g_slist_free_1 (modify_tls_certificate_data.context->first);
    }
  g_free (modify_tls_certificate_data.context);
  memset (&modify_tls_certificate_data, 0, sizeof (modify_tls_certificate_t));
}

/**
 * @brief Start a command.
 *
 * @param[in]  gmp_parser        GMP parser.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
modify_tls_certificate_start (gmp_parser_t *gmp_parser,
                              const gchar **attribute_names,
                              const gchar **attribute_values)
{
  memset (&modify_tls_certificate_data,
          0,
          sizeof (modify_tls_certificate_t));
  modify_tls_certificate_data.context = g_malloc0 (sizeof (context_data_t));
  modify_tls_certificate_element_start (gmp_parser,
                                        "modify_tls_certificate",
                                        attribute_names,
                                        attribute_values);
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
modify_tls_certificate_element_start (gmp_parser_t *gmp_parser,
                                      const gchar *name,
                                      const gchar **attribute_names,
                                      const gchar **attribute_values)
{
  xml_handle_start_element (modify_tls_certificate_data.context,
                            name,
                            attribute_names,
                            attribute_values);
}

/**
 * @brief Execute command.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
void
modify_tls_certificate_run (gmp_parser_t *gmp_parser, GError **error)
{
  entity_t entity, comment, name, trust;
  const char *tls_certificate_id;
  int trust_int;

  entity = (entity_t) modify_tls_certificate_data.context->first->data;

  tls_certificate_id = entity_attribute (entity, "tls_certificate_id");

  /* Check the given info. */

  comment = entity_child (entity, "comment");
  name = entity_child (entity, "name");
  trust = entity_child (entity, "trust");

  trust_int = -1;
  if (trust)
    {
      if (strcmp (entity_text (trust), "")
          && strcmp (entity_text (trust), "0"))
        trust_int = 1;
      else
        trust_int = 0;
    }

  /* Modify the tls_certificate. */

  if (tls_certificate_id == NULL)
    SEND_TO_CLIENT_OR_FAIL
     (XML_ERROR_SYNTAX ("modify_tls_certificate",
                        "MODIFY_TLS_CERTIFICATE requires a tls_certificate_id"
                        " attribute"));
  else switch (modify_tls_certificate
                (tls_certificate_id,
                 comment ? entity_text (comment) : NULL,
                 name ? entity_text (name) : NULL,
                 trust_int))
    {
      case 0:
        SENDF_TO_CLIENT_OR_FAIL (XML_OK ("modify_tls_certificate"));
        log_event ("tls_certificate",
                   "TLS Certificate",
                   tls_certificate_id,
                   "modified");
        break;
      case 1:
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("modify_tls_certificate",
                            "TLS Certificate exists already"));
        log_event_fail ("tls_certificate",
                        "TLS certificate",
                        tls_certificate_id,
                        "modified");
        break;
      case 2:
        log_event_fail ("tls_certificate",
                        "TLS Certificate",
                        tls_certificate_id,
                        "modified");
        if (send_find_error_to_client ("modify_tls_certificate",
                                       "TLS certificate",
                                       tls_certificate_id,
                                       gmp_parser))
          {
            error_send_to_client (error);
            return;
          }
        break;
      case 3:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_tls_certificate",
                             "Invalid certificate content"));

        log_event_fail ("tls_certificate",
                        "TLS Certificate",
                        tls_certificate_id,
                        "modified");
        break;
      case 4:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_tls_certificate",
                              "CERTIFICATE is not valid Base64."));
        log_event_fail ("tls_certificate",
                        "TLS Certificate",
                        NULL,
                        "modified");
        return;
      case 99:
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("modify_tls_certificate",
                            "Permission denied"));
        log_event_fail ("tls_certificate",
                        "TLS Certificate",
                        tls_certificate_id,
                        "modified");
        break;
      case -1:
      default:
        SEND_TO_CLIENT_OR_FAIL
         (XML_INTERNAL_ERROR ("modify_tls_certificate"));
        log_event_fail ("tls_certificate",
                        "TLS Certificate",
                        tls_certificate_id,
                        "modified");
        break;
    }

  modify_tls_certificate_reset ();
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
modify_tls_certificate_element_end (gmp_parser_t *gmp_parser, GError **error,
                                    const gchar *name)
{
  xml_handle_end_element (modify_tls_certificate_data.context, name);
  if (modify_tls_certificate_data.context->done)
    {
      modify_tls_certificate_run (gmp_parser, error);
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
modify_tls_certificate_element_text (const gchar *text, gsize text_len)
{
  xml_handle_text (modify_tls_certificate_data.context, text, text_len);
}

/**
 * @brief Generate extra XML for special TLS certificate origins like reports
 *
 * @param[in]  origin_type  The origin type (e.g. "Report")
 * @param[in]  origin_id    The id of the origin resource (e.g. report id)
 * @param[in]  origin_data  The extra origin data
 *
 * @return Newly allocated XML string or NULL.
 */
gchar *
tls_certificate_origin_extra_xml (const char *origin_type,
                                  const char *origin_id,
                                  const char *origin_data)
{
  gchar *ret;

  ret = NULL;

  if (strcasecmp (origin_type, "Report") == 0)
    {
      report_t report;

      report = 0;
      if (find_report_with_permission (origin_id, &report, "get_reports"))
        {
          g_warning ("%s : error getting report", __func__);
        }

      if (report)
        {
          task_t task;
          gchar *timestamp, *report_task_id, *report_task_name;

          timestamp = NULL;
          report_task_id = NULL;
          report_task_name = NULL;
          report_timestamp (origin_id, &timestamp);

          task = 0;
          if (report_task (report, &task))
            {
              g_warning ("%s : error getting report task", __func__);
            }

          if (task)
            {
              task_uuid (task, &report_task_id);
              report_task_name = task_name (task);
            }

          ret = g_strdup_printf ("<report id=\"%s\">"
                                 "<date>%s</date>"
                                 "<task id=\"%s\">"
                                 "<name>%s</name>"
                                 "</task>"
                                 "</report>",
                                 origin_id,
                                 timestamp ? timestamp : "",
                                 report_task_id ? report_task_id : "",
                                 report_task_name ? report_task_name : "");

          g_free (timestamp);
          g_free (report_task_id);
          g_free (report_task_name);
        }
    }

  return ret;
}
