/* Copyright (C) 2009-2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Active Directory.
 *
 * GMP Handlers for Active Directory.
 */

#include "gmp_active_directory.h"
#include "gmp_base.h"
#include "manage_active_directory.h"
#include "manage.h"

#include <string.h>

#include <gvm/util/xmlutils.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"

/* VERIFY_ACTIVE_DIRECTORY_CREDENTIAL */

typedef struct
{
  context_data_t *context;
} verify_active_directory_credential_data_t;

static verify_active_directory_credential_data_t
  verify_active_directory_credential_data;

/**
 * @brief Reset the verify_active_directory_credential data.
 */
static void
verify_active_directory_credential_reset (void)
{
  context_data_t *context = verify_active_directory_credential_data.context;

  if (context && context->first)
    {
      free_entity (context->first->data);
      g_slist_free_1 (context->first);
    }

  g_free (context);
  memset (&verify_active_directory_credential_data, 0,
          sizeof (verify_active_directory_credential_data));
}

/**
 * @brief Handle the start of the VERIFY_ACTIVE_DIRECTORY_CREDENTIAL element.
 *
 * @param[in]  gmp_parser        current instance of GMP parser.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
verify_active_directory_credential_start (gmp_parser_t *gmp_parser,
                                          const gchar **attribute_names,
                                          const gchar **attribute_values)
{
  (void) gmp_parser;

  memset (&verify_active_directory_credential_data, 0,
          sizeof (verify_active_directory_credential_data));

  verify_active_directory_credential_data.context
    = g_malloc0 (sizeof (context_data_t));

  verify_active_directory_credential_element_start (
    gmp_parser,
    "verify_active_directory_credential",
    attribute_names,
    attribute_values
  );
}

/**
 * @brief Start an element of verify_active_directory_credential command.
 *
 * @param[in]  gmp_parser        current instance of GMP parser.
 * @param[in]  name              the name of the element.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
verify_active_directory_credential_element_start (gmp_parser_t *gmp_parser,
                                                  const gchar *name,
                                                  const gchar **attribute_names,
                                                  const gchar **attribute_values)
{
  xml_handle_start_element (verify_active_directory_credential_data.context,
                            name,
                            attribute_names,
                            attribute_values);
}

/**
 * @brief Add text to element in verify_active_directory_credential command.
 *
 * @param[in]  text      the text content of the element.
 * @param[in]  text_len  the length of the text content.
 */
void
verify_active_directory_credential_element_text (const gchar *text,
                                                 gsize text_len)
{
  xml_handle_text (verify_active_directory_credential_data.context,
                   text, text_len);
}

/**
 * @brief End element in verify_active_directory_credential command
 *
 * @param[in] gmp_parser  current instance of GMP parser.
 * @param[in] error       the errors, if any.
 * @param[in] name        the name of the element.
 *
 * @return 1 if the element is fully processed, 0 otherwise.
 */
int
verify_active_directory_credential_element_end (gmp_parser_t *gmp_parser,
                                                GError **error,
                                                const gchar *name)
{
  context_data_t *context = verify_active_directory_credential_data.context;

  xml_handle_end_element (context, name);
  if (!context->done)
    return 0;

  verify_active_directory_credential_run (gmp_parser, error);
  return 1;
}

/**
 * @brief Get the text content of a child element.
 *
 * @param root  The parent entity.
 * @param name  The name of the child element.
 *
 * @return A newly allocated string containing the text content
 *         or NULL otherwise.
 */
static gchar *
ad_child_text (entity_t root, const gchar *name)
{
  entity_t child = entity_child (root, name);
  const gchar *text;

  if (child == NULL)
    return NULL;

  text = entity_text (child);
  return g_strdup (text ? text : "");
}

/**
 * @brief Run the verify_active_directory_credential command.
 *
 * @param[in] gmp_parser  Active GMP parser instance.
 * @param[in] error       the errors, if any.
 */
void
verify_active_directory_credential_run (gmp_parser_t *gmp_parser,
                                        GError **error)
{
  credential_data_t data = { 0 };
  ad_credential_data_t *ad = &data.ad_credential_data;
  context_data_t *context = verify_active_directory_credential_data.context;
  entity_t root = context && context->first
                    ? context->first->data : NULL;
  const gchar *credential_id;
  const gchar *response = XML_INTERNAL_ERROR ("verify_active_directory_credential");
  verify_ad_return_t result;

  if (root == NULL)
    goto cleanup;

  credential_id = entity_attribute (root, "credential_id");

  ad->host = ad_child_text (root, "host");
  ad->port = ad_child_text (root, "port");
  ad->bind_dn = ad_child_text (root, "bind_dn");
  ad->bind_password = ad_child_text (root, "bind_password");
  ad->base_dn = ad_child_text (root, "base_dn");
  ad->tls_mode = ad_child_text (root, "tls_mode");
  ad->ca_certificate = ad_child_text (root, "ca_certificate");

  result = verify_active_directory_credential (credential_id, ad);

  switch (result)
    {
    case VERIFY_AD_CREDENTIAL_OK:
      response = XML_OK ("verify_active_directory_credential");
      break;
    case VERIFY_AD_CREDENTIAL_INVALID_INPUT:
      response = XML_ERROR_SYNTAX (
        "verify_active_directory_credential",
        "Invalid AD credential settings");
      break;
    case VERIFY_AD_CREDENTIAL_NOT_FOUND:
      response = XML_ERROR_MISSING (
        "verify_active_directory_credential");
      break;
    case VERIFY_AD_CREDENTIAL_PERMISSION_DENIED:
      response = XML_ERROR_ACCESS (
        "verify_active_directory_credential");
      break;
    case VERIFY_AD_CREDENTIAL_INVALID_TYPE:
      response = XML_ERROR_SYNTAX (
        "verify_active_directory_credential",
        "Credential is not an Active Directory credential");
      break;
    case VERIFY_AD_CREDENTIAL_INVALID_STORED_CONFIGURATION:
      response = XML_ERROR_SYNTAX (
        "verify_active_directory_credential",
        "Stored Active Directory credential configuration is invalid");
      break;
    case VERIFY_AD_CREDENTIAL_HOST_REQUIRED:
      response = XML_ERROR_SYNTAX (
        "verify_active_directory_credential",
        "AD host is required");
      break;
    case VERIFY_AD_CREDENTIAL_BIND_DN_REQUIRED:
      response = XML_ERROR_SYNTAX (
        "verify_active_directory_credential",
        "AD bind DN is required");
      break;
    case VERIFY_AD_CREDENTIAL_BIND_PASSWORD_REQUIRED:
      response = XML_ERROR_SYNTAX (
        "verify_active_directory_credential",
        "AD bind password is required");
      break;
    case VERIFY_AD_CREDENTIAL_BASE_DN_REQUIRED:
      response = XML_ERROR_SYNTAX (
        "verify_active_directory_credential",
        "AD base DN is required");
      break;
    case VERIFY_AD_CREDENTIAL_TLS_MODE_REQUIRED:
      response = XML_ERROR_SYNTAX (
        "verify_active_directory_credential",
        "AD TLS mode is required");
      break;
    case VERIFY_AD_CREDENTIAL_INVALID_TLS_MODE:
      response = XML_ERROR_SYNTAX (
        "verify_active_directory_credential",
        "Invalid AD TLS mode");
      break;
    case VERIFY_AD_CREDENTIAL_INVALID_PORT:
      response = XML_ERROR_SYNTAX (
        "verify_active_directory_credential",
        "Invalid AD port");
      break;
    case VERIFY_AD_CREDENTIAL_INVALID_CA_CERTIFICATE:
      response = XML_ERROR_SYNTAX (
        "verify_active_directory_credential",
        "Invalid AD CA certificate");
      break;
    case VERIFY_AD_CREDENTIAL_CONNECTION_FAILED:
      response = XML_ERROR_UNAVAILABLE (
        "verify_active_directory_credential",
        "Could not connect to Active Directory");
      break;
    case VERIFY_AD_CREDENTIAL_BIND_FAILED:
      response = XML_ERROR_UNAVAILABLE (
        "verify_active_directory_credential",
        "Active Directory bind failed");
      break;
    case VERIFY_AD_CREDENTIAL_FEATURE_DISABLED:
      response = XML_ERROR_SYNTAX (
        "verify_active_directory_credential",
        "Active Directory integration is disabled");
      break;
    case VERIFY_AD_CREDENTIAL_INTERNAL_ERROR:
    default:
      break;
    }

cleanup:
  if (send_to_client (response, gmp_parser->client_writer,
                      gmp_parser->client_writer_data))
    error_send_to_client (error);

  credential_data_reset (&data);
  verify_active_directory_credential_reset ();
}
