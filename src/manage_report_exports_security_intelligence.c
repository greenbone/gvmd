/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_integration_configs.h"
#include "manage_report_exports.h"

#include <auth/gvm_auth.h>
#include <security_intelligence/security_intelligence.h>


#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief  Generates a Bearer access token
 *
 * @param  config  Integration config for report export
 *
 * @return Bearer access token, must be freed by caller.
 */
static gchar *
generate_bearer_token (integration_config_data_t config)
{
  gvm_oauth2_new_err_t new_err = GVM_OAUTH2_NEW_ERR_INTERNAL_ERROR;

  gvm_oauth2_token_provider_t token_provider = gvm_oauth2_token_provider_new (
    config->oidc_url, config->oidc_client_id, config->oidc_client_secret, "",
    30, &new_err);
  if (!token_provider)
    {
      g_debug ("%s: failed to initialize token_provider, error: %d", __func__,
               new_err);
      return NULL;
    }

  gvm_oauth2_get_token_err_t tok_err = GVM_OAUTH2_GET_TOKEN_ERR_INTERNAL_ERROR;
  char *access_token = gvm_oauth2_get_token (token_provider, &tok_err);
  if (!access_token)
    {
      g_debug ("%s: failed to retrieve access_token, error: %d", __func__,
               tok_err);
      return NULL;
    }

  gchar *bearer = g_strdup_printf ("Bearer %s", access_token);

  gvm_auth_str_free (access_token);
  gvm_oauth2_token_provider_free (token_provider);

  return bearer;
}

/**
 * @brief  Generates a Bearer access token and uses it to populate
 *         security intelligence connector configuration
 *
 * @param  conn    The security intelligence connector. Bearer token on the
 *                 connector will be modified
 * @param  config  Integration config for report export
 *
 * @return TRUE on success, FALSE on failure.
 */
static gboolean
refresh_connector_access_token (security_intelligence_connector_t conn,
                                integration_config_data_t config)
{
  gchar *bearer_token = generate_bearer_token (config);
  if (!bearer_token)
    {
      return FALSE;
    }

  security_intelligence_connector_builder (
    conn, SECURITY_INTELLIGENCE_BEARER_TOKEN, bearer_token);

  g_free (bearer_token);
  return TRUE;
}

/**
 * @brief  Register managed appliance with security intelligence
 *
 * @param  conn  The security intelligence connector
 * @param  appliance_id  The appliance ID to register with.
 *                       Defined to be the OIDC client ID
 * @return TRUE on success
 */
static gboolean
register_managed_appliance (security_intelligence_connector_t conn,
                            const gchar* appliance_id)
{
  security_intelligence_managed_appliance_t managed_appliance =
    security_intelligence_managed_appliance_new ();
  security_intelligence_managed_appliance_t created_appliance = NULL;

  managed_appliance->appliance_id = g_strdup (appliance_id);
  int result = security_intelligence_create_managed_appliance (conn, managed_appliance,
                                                  &created_appliance, NULL);

  if (result != SECURITY_INTELLIGENCE_RESP_OK)
    {
      g_warning ("%s: failed to register appliance with security intelligence",
                 __func__);
      return FALSE;
    }

  if (created_appliance)
    {
      // DEBUG
      g_warning ("appliance: %s %s %s\n", created_appliance->appliance_id,
                 created_appliance->ip,
                 created_appliance->https_certificate_fingerprint);
      security_intelligence_managed_appliance_free (created_appliance);
    }
  security_intelligence_managed_appliance_free (managed_appliance);

  return TRUE;
}

/**
 * @brief  Export a single report to security intelligence
 *
 * @param  report    The report to export
 * @param  config    Integration config for OpenVAS Security Intelligence
 *                   export
 *
 * @return EXPORT_REPORT_RESULT_SUCCESS on success
 *         EXPORT_REPORT_RESULT_TIMEOUT when the request has timed out
 *         EXPORT_REPORT_RESULT_TOKEN_GENERATION_FAILED when access_token could
 *            not be created with the given provider
 *         EXPORT_REPORT_RESULT_FAILURE on failure
 */
export_report_result_t
export_report_security_intelligence (report_t report,
                                     integration_config_data_t config)
{
  (void) report;
  g_debug ("%s: exporting report %lld", __func__, report);

  // Create connector
  security_intelligence_connector_t conn =
    security_intelligence_connector_new ();
  security_intelligence_connector_builder (conn, SECURITY_INTELLIGENCE_URL,
                                           config->service_url);
  security_intelligence_connector_builder (conn, SECURITY_INTELLIGENCE_CA_CERT,
                                           config->service_cacert);
  refresh_connector_access_token (conn, config);

  // Register appliance
  register_managed_appliance (conn, config->oidc_client_id);

  /**
   * - Connect to OpenVAS Security Intelligence, using libgvm
   *    - Use managed appliance and report ID to see if it is known already
   *      (with correct page size)
   *    - See if/how many "pages" already have been uploaded
   * - Figure out how many pages we need for the report
   * - Create diff between what OpenVAS Security Intelligence has, and how many
   *   pages the report needs
   * - Start generating & uploading "missing" pages
   */

  /**
   * To create a page:
   *    Create get_data_t and run print_report_xml_start (),
   *    then read the temp file and send using the token
   */

  security_intelligence_connector_free (conn);

  return EXPORT_REPORT_RESULT_FAILURE;
}
