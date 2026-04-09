/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gmp_report_tls_certificates.h"

#include "gmp_get.h"
#include "manage.h"
#include "manage_acl.h"
#include "manage_report_tls_certificates.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"

/**
 * @brief Command data for the get_report_tls_certificates command.
 */
typedef struct
{
  get_data_t get;  ///< Get args with filtering.
  char *report_id; ///< ID of single report to get.
} get_report_tls_certificates_data_t;

/**
 * @brief Parser callback data.
 */
static get_report_tls_certificates_data_t get_report_tls_certificates_data;

/**
 * @brief Reset the internal state of the <get_report_tls_certificates> command.
 */
static void
get_report_tls_certificates_reset ()
{
  get_data_reset (&get_report_tls_certificates_data.get);
  g_free (get_report_tls_certificates_data.report_id);
  memset (&get_report_tls_certificates_data,
          0,
          sizeof (get_report_tls_certificates_data));
}

/**
 * @brief Initialize the <get_report_tls_certificates> GMP command by parsing
 *        attributes.
 *
 * @param[in] attribute_names   Null-terminated array of attribute names.
 * @param[in] attribute_values  Null-terminated array of corresponding
 *                              attribute values.
 */
void
get_report_tls_certificates_start (const gchar **attribute_names,
                                   const gchar **attribute_values)
{
  const gchar *attribute;

  get_data_parse_attributes (&get_report_tls_certificates_data.get,
                             "tls_certificate",
                             attribute_names,
                             attribute_values);

  if (find_attribute (attribute_names, attribute_values,
                      "report_id", &attribute))
    {
      get_report_tls_certificates_data.report_id = g_strdup (attribute);

      get_data_set_extra (&get_report_tls_certificates_data.get,
                          "report_id",
                          g_strdup (attribute));
    }
}

/**
 * @brief Execute the <get_report_tls_certificates> GMP command.
 *
 * @param[in] gmp_parser  Pointer to the GMP parser handling the current
 *                        session.
 * @param[in] error       Location to store error information, if any occurs.
 */
void
get_report_tls_certificates_run (gmp_parser_t *gmp_parser, GError **error)
{
  report_t report;
  task_t task;
  gboolean is_container_scanning_report = FALSE;
  int ret, filtered, count;

  count = 0;

  if (get_report_tls_certificates_data.report_id == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL
      (XML_ERROR_SYNTAX ("get_report_tls_certificates",
        "Missing report_id attribute"));
      get_report_tls_certificates_reset ();
      return;
    }

  ret = init_get ("get_report_tls_certificates",
                  &get_report_tls_certificates_data.get,
                  "Report TLS Certificates",
                  NULL);
  if (ret)
    {
      switch (ret)
        {
        case 99:
          SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("get_report_tls_certificates",
            "Permission denied"));
          break;
        default:
          internal_error_send_to_client (error);
          get_report_tls_certificates_reset ();
          return;
        }
      get_report_tls_certificates_reset ();
      return;
    }

  if (find_report_with_permission (get_report_tls_certificates_data.report_id,
                                   &report,
                                   "get_reports"))
    {
      internal_error_send_to_client (error);
      get_report_tls_certificates_reset ();
      return;
    }

  if (report == 0)
    {
      if (send_find_error_to_client ("get_report_tls_certificates",
                                     "report",
                                     get_report_tls_certificates_data.report_id,
                                     gmp_parser))
        error_send_to_client (error);
      get_report_tls_certificates_reset ();
      return;
    }

  if (report_task (report, &task))
    {
      internal_error_send_to_client (error);
      get_report_tls_certificates_reset ();
      return;
    }

#if ENABLE_CONTAINER_SCANNING
  {
    oci_image_target_t oci_image_target = task_oci_image_target (task);
    if (oci_image_target)
      is_container_scanning_report = TRUE;
  }
#endif

  SEND_GET_START ("report_tls_certificate");

  ret = manage_send_report_tls_certificates (
    report,
    &get_report_tls_certificates_data.get,
    is_container_scanning_report,
    send_to_client,
    gmp_parser->client_writer,
    gmp_parser->client_writer_data);

  if (ret)
    {
      switch (ret)
        {
        case 2:
          if (send_find_error_to_client ("get_report_tls_certificates",
                                         "filter",
                                         get_report_tls_certificates_data.get.
                                         filt_id,
                                         gmp_parser))
            error_send_to_client (error);
          break;
        default:
          internal_error_send_to_client (error);
          break;
        }
      get_report_tls_certificates_reset ();
      return;
    }

  filtered = get_report_tls_certificates_data.get.id
               ? 1
               : report_ssl_cert_count (report);
  SEND_GET_END ("report_tls_certificate",
                &get_report_tls_certificates_data.get,
                count,
                filtered);

  get_report_tls_certificates_reset ();
}