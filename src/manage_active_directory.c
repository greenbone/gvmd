/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Active Directory.
 *
 * Non-SQL Active Directory management code for the GVM management layer.
 */

#if ENABLE_AD_INTEGRATION

#include "gvmd_config.h"
#include "manage_acl.h"
#include "manage_active_directory.h"
#include "manage_runtime_flags.h"
#include "manage_sql.h"
#include "manage_sql_resources.h"
#include "manage_sql_credentials.h"
#include "manage_credentials.h"
#include "lsc_user.h"

#include <arpa/inet.h>
#include <errno.h>
#include <gnutls/x509.h> /* for gnutls_x509_crt_... */

#include <gvm/ad_connector/ad_connector.h>
#include <gvm/base/hosts.h>
#include <gvm/util/tlsutils.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

#define AD_NETWORK_TIMEOUT_SECONDS_DEFAULT 10
#define AD_OPERATION_TIMEOUT_SECONDS_DEFAULT 30

#define ACTIVE_DIRECTORY_CONFIG_GROUP "active_directory"
#define AD_ALLOWED_HOSTS_DEFAULT ""
#define AD_ALLOWED_PORTS_DEFAULT "389,636,3268,3269"

/**
 * @brief DNS-free host comparison key, retaining the address family.
 */
typedef struct
{
  int type;
  union
  {
    gchar *name;
    struct in_addr ipv4;
    struct in6_addr ipv6;
  } value;
} ad_policy_host_t;

/**
 * @brief Array of allowed Active Directory hosts. Empty means allow all.
 */
static GPtrArray *ad_allowed_hosts;

/**
 * @brief Array of allowed Active Directory ports. Empty means allow all.
 */
static GArray *ad_allowed_ports;

/**
 * @brief Parse a required decimal port without trimming or fallback.
 *
 * @param[in]  text  Borrowed port string; NULL and empty input are invalid.
 * @param[out] port  Non-NULL caller-owned output, written only on success.
 *
 * @return TRUE if port is parsed successfully and valid, FALSE otherwise.
 */
static gboolean
parse_ad_port (const gchar *text, guint *port)
{
  gchar *end;
  guint64 number;

  if (text == NULL || !g_ascii_isdigit ((guchar) text[0]))
    return FALSE;

  errno = 0;
  number = g_ascii_strtoull (text, &end, 10);
  if (errno == ERANGE || *end != '\0' || number < 1 || number > 65535)
    return FALSE;

  *port = (guint) number;
  return TRUE;
}

/**
 * @brief Free an owned host comparison key.
 *
 * @param[in] data  Non-NULL host key whose ownership is transferred here.
 */
static void
ad_policy_host_free (gpointer data)
{
  ad_policy_host_t *host = data;

  if (host->type == HOST_TYPE_NAME)
    g_free (host->value.name);
  g_free (host);
}

/**
 * @brief Parse an individual host without DNS or fallback parsing.
 *
 * @param[in] text  Hostname or IP literal, without surrounding whitespace.
 *                 The input is not modified; NULL and empty input are invalid.
 *
 * @return Newly allocated normalized key, or NULL for invalid/unsupported
 *         syntax or failed address conversion. Free with ad_policy_host_free().
 */
static ad_policy_host_t *
parse_ad_policy_host (const gchar *text)
{
  ad_policy_host_t *host;
  int type = gvm_get_host_type (text);

  if (type != HOST_TYPE_NAME && type != HOST_TYPE_IPV4
      && type != HOST_TYPE_IPV6)
    return NULL;

  host = g_new0 (ad_policy_host_t, 1);
  host->type = type;
  if (type == HOST_TYPE_NAME)
    {
      gsize length;

      host->value.name = g_ascii_strdown (text, -1);
      length = strlen (host->value.name);
      if (length && host->value.name[length - 1] == '.')
        host->value.name[length - 1] = '\0';
    }
  else if ((type == HOST_TYPE_IPV4
            && inet_pton (AF_INET, text, &host->value.ipv4) != 1)
           || (type == HOST_TYPE_IPV6
               && inet_pton (AF_INET6, text, &host->value.ipv6) != 1))
    {
      ad_policy_host_free (host);
      return NULL;
    }

  return host;
}

/**
 * @brief Compare normalized names or binary addresses of the same family.
 *
 * @param[in] a  Non-NULL normalized host key.
 * @param[in] b  Non-NULL normalized host key.
 *
 * @return TRUE for equal keys of the same type, FALSE otherwise.
 */
static gboolean
ad_policy_hosts_equal (const ad_policy_host_t *a, const ad_policy_host_t *b)
{
  if (a->type != b->type)
    return FALSE;
  if (a->type == HOST_TYPE_NAME)
    return g_str_equal (a->value.name, b->value.name);
  if (a->type == HOST_TYPE_IPV4)
    return a->value.ipv4.s_addr == b->value.ipv4.s_addr;
  return memcmp (a->value.ipv6.s6_addr, b->value.ipv6.s6_addr,
                 sizeof (a->value.ipv6.s6_addr)) == 0;
}

/**
 * @brief Select one option independently, preserving explicit empty values.
 *
 * Use the shared getter without distinguishing sources. It logs string read
 * errors; any NULL result uses the built-in default.
 *
 * @param[in] kf             Parsed configuration, or NULL if unavailable.
 * @param[in] env_name       Non-NULL environment override name.
 * @param[in] key            Non-NULL key in the active_directory group.
 * @param[in] default_value  Non-NULL built-in default string.
 *
 * @return Newly allocated selected string, including explicit empty values.
 *         Missing/unreadable values use the default. Free with g_free().
 */
static gchar *
ad_policy_config_string (GKeyFile *kf, const gchar *env_name,
                         const gchar *key, const gchar *default_value)
{
  gchar *value = gvmd_get_env_or_config_string (
    env_name, kf, ACTIVE_DIRECTORY_CONFIG_GROUP, key);

  return value ? value : g_strdup (default_value);
}

/**
 * @brief Parse and deduplicate a host list, discarding partial invalid lists.
 *
 * @param[in,out] text  Non-NULL writable comma-separated list. Surrounding
 *                     whitespace is stripped in place; ownership is retained
 *                     by the caller.
 *
 * @return Owned array of normalized host keys, empty for an empty/whitespace-only
 *         list, or NULL if any entry is invalid. Release with g_ptr_array_unref().
 */
static GPtrArray *
parse_ad_allowed_hosts (gchar *text)
{
  GPtrArray *hosts = g_ptr_array_new_with_free_func (ad_policy_host_free);
  gchar **entries;

  if (*g_strstrip (text) == '\0')
    return hosts;

  entries = g_strsplit (text, ",", -1);
  for (gchar **entry = entries; *entry; entry++)
    {
      ad_policy_host_t *host;
      gboolean duplicate = FALSE;

      g_strstrip (*entry);
      host = **entry ? parse_ad_policy_host (*entry) : NULL;
      if (host == NULL)
        {
          g_strfreev (entries);
          g_ptr_array_unref (hosts);
          return NULL;
        }
      for (guint i = 0; i < hosts->len; i++)
        if (ad_policy_hosts_equal (host, g_ptr_array_index (hosts, i)))
          {
            duplicate = TRUE;
            break;
          }
      if (duplicate)
        ad_policy_host_free (host);
      else
        g_ptr_array_add (hosts, host);
    }
  g_strfreev (entries);
  return hosts;
}

/**
 * @brief Parse and deduplicate decimal ports, discarding partial invalid lists.
 *
 * @param[in,out] text  Non-NULL writable comma-separated list. Surrounding
 *                     whitespace is stripped in place; ownership is retained
 *                     by the caller.
 *
 * @return Owned array of guint ports, empty for an empty/whitespace-only list,
 *         or NULL if any entry is invalid. Release with g_array_unref().
 */
static GArray *
parse_ad_allowed_ports (gchar *text)
{
  GArray *ports = g_array_new (FALSE, FALSE, sizeof (guint));
  gchar **entries;

  if (*g_strstrip (text) == '\0')
    return ports;

  entries = g_strsplit (text, ",", -1);
  for (gchar **entry = entries; *entry; entry++)
    {
      guint port;
      gboolean duplicate = FALSE;

      g_strstrip (*entry);
      if (!parse_ad_port (*entry, &port))
        {
          g_strfreev (entries);
          g_array_unref (ports);
          return NULL;
        }
      for (guint i = 0; i < ports->len; i++)
        if (g_array_index (ports, guint, i) == port)
          {
            duplicate = TRUE;
            break;
          }
      if (!duplicate)
        g_array_append_val (ports, port);
    }
  g_strfreev (entries);
  return ports;
}

/**
 * @brief Load the startup AD connection policy, even if runtime AD is disabled.
 *
 * Invalid selected lists warn and use independent built-in defaults. Publish
 * only complete lists, freeing previous policy on repeated initialization.
 * This does not enforce the policy on any command or connector.
 */
void
load_active_directory_config (void)
{
  GKeyFile *kf = get_gvmd_config ();
  gchar *text;
  GPtrArray *hosts;
  GArray *ports;

  text = ad_policy_config_string (kf, "GVMD_AD_ALLOWED_HOSTS", "allowed_hosts",
                                  AD_ALLOWED_HOSTS_DEFAULT);
  hosts = parse_ad_allowed_hosts (text);
  g_free (text);
  if (hosts == NULL)
    {
      g_warning ("%s: active_directory.allowed_hosts: expected comma-separated "
                 "individual names or IP addresses with no empty entries; "
                 "using built-in default (all hosts)", __func__);
      text = g_strdup (AD_ALLOWED_HOSTS_DEFAULT);
      hosts = parse_ad_allowed_hosts (text);
      g_free (text);
    }

  text = ad_policy_config_string (kf, "GVMD_AD_ALLOWED_PORTS", "allowed_ports",
                                  AD_ALLOWED_PORTS_DEFAULT);
  ports = parse_ad_allowed_ports (text);
  g_free (text);
  if (ports == NULL)
    {
      g_warning ("%s: active_directory.allowed_ports: expected comma-separated "
                 "decimal ports in range 1-65535 with no empty entries; "
                 "using built-in default", __func__);
      text = g_strdup (AD_ALLOWED_PORTS_DEFAULT);
      ports = parse_ad_allowed_ports (text);
      g_free (text);
    }

  g_clear_pointer (&ad_allowed_hosts, g_ptr_array_unref);
  g_clear_pointer (&ad_allowed_ports, g_array_unref);
  ad_allowed_hosts = hosts;
  ad_allowed_ports = ports;
}

/**
 * @brief Reset the AD connector data structure.
 *
 * @param[in,out] ad  Pointer to the AD connector data structure to reset.
 *
 * This function frees all dynamically allocated fields within the
 * ad_credential_data_t structure and sets them to NULL.
 */
void
ad_credential_data_reset (ad_credential_data_t *ad)
{
  if (ad == NULL)
    return;

  g_free (ad->host);
  g_free (ad->port);
  g_free (ad->bind_dn);
  g_free (ad->bind_password);
  g_free (ad->base_dn);
  g_free (ad->tls_mode);
  g_free (ad->ca_certificate);

  memset (ad, 0, sizeof (*ad));
}

/**
 * @brief Validate an Active Directory port.
 *
 * @param[in] text  Borrowed port string, not modified. NULL means omitted;
 *                 empty strings are invalid. No ownership is transferred.
 *
 * @return TRUE for NULL or a fully consumed base-10 port in 1-65535 without
 *         overflow, FALSE otherwise.
 */
gboolean
valid_ad_port (const char *text)
{
  guint port;

  return text == NULL || parse_ad_port (text, &port);
}

/**
 * @brief Select the numeric AD port without consulting destination policy.
 *
 * @param[in] port_text       Borrowed explicit port, or NULL for the TLS default.
 *                           Empty/malformed explicit values never use a default.
 * @param[in] tls_mode        Borrowed exact mode: starttls or ldaps, required
 *                           even when an explicit port is supplied.
 * @param[out] effective_port Non-NULL caller-owned output, written only on
 *                           success: explicit port, 389 (starttls), or 636 (ldaps).
 *
 * @return AD_DESTINATION_OK, AD_DESTINATION_INVALID_PORT, or
 *         AD_DESTINATION_INVALID_TLS_MODE. Invalid explicit ports take
 *         precedence over invalid TLS modes. Inputs are not modified or retained.
 */
ad_destination_return_t
active_directory_effective_port (const gchar *port_text, const gchar *tls_mode,
                                 guint *effective_port)
{
  guint port;

  if (port_text && !parse_ad_port (port_text, &port))
    return AD_DESTINATION_INVALID_PORT;
  if (!tls_mode || (strcmp (tls_mode, "starttls") != 0
                    && strcmp (tls_mode, "ldaps") != 0))
    return AD_DESTINATION_INVALID_TLS_MODE;

  if (port_text == NULL)
    port = g_str_equal (tls_mode, "starttls") ? 389 : 636;
  *effective_port = port;
  return AD_DESTINATION_OK;
}

/**
 * @brief Check an initial AD destination against the loaded startup policy.
 *
 * Call after load_active_directory_config() and command-specific structural
 * validation, permission checks and resolution of stored/merged fields. This
 * DNS-free checker does not create a connector or resolve command input.
 * Empty lists remove membership restrictions, never syntax validation. The
 * startup snapshot is read only; environment/file changes are not consulted.
 *
 * @param[in] host           Borrowed unchanged hostname/IP literal. NULL, empty,
 *                          surrounding whitespace and unsupported syntax fail.
 * @param[in] port           Borrowed explicit decimal port, or NULL for default;
 *                          an empty string is invalid, not an omitted port.
 * @param[in] tls_mode       Borrowed exact required mode: starttls or ldaps.
 * @param[out] effective_port Optional caller-owned numeric output, written only
 *                          on success. No fallback port is selected on denial.
 *
 * @return Independent destination result. Invalid host, port, then TLS mode
 *         precede membership denial. Valid input is also denied if startup
 *         initialization has not occurred; no policy is loaded lazily.
 *         No input is modified, retained or owned;
 *         temporary normalization keys are freed before return.
 */
ad_destination_return_t
check_active_directory_destination (const gchar *host, const gchar *port,
                                    const gchar *tls_mode,
                                    guint *effective_port)
{
  ad_policy_host_t *key = parse_ad_policy_host (host);
  ad_destination_return_t result;
  guint number;
  gboolean host_allowed;
  gboolean port_allowed;

  if (key == NULL)
    return AD_DESTINATION_INVALID_HOST;

  result = active_directory_effective_port (port, tls_mode, &number);
  if (result != AD_DESTINATION_OK)
    {
      ad_policy_host_free (key);
      return result;
    }

  /* Initialization is a startup precondition, not implicit allow-all. */
  if (ad_allowed_hosts == NULL || ad_allowed_ports == NULL)
    {
      ad_policy_host_free (key);
      return AD_DESTINATION_NOT_ALLOWED;
    }

  host_allowed = ad_allowed_hosts->len == 0;
  for (guint i = 0; !host_allowed && i < ad_allowed_hosts->len; i++)
    host_allowed = ad_policy_hosts_equal (
      key, g_ptr_array_index (ad_allowed_hosts, i));
  ad_policy_host_free (key);

  port_allowed = ad_allowed_ports->len == 0;
  for (guint i = 0; !port_allowed && i < ad_allowed_ports->len; i++)
    port_allowed = g_array_index (ad_allowed_ports, guint, i) == number;

  if (!host_allowed || !port_allowed)
    return AD_DESTINATION_NOT_ALLOWED;
  if (effective_port)
    *effective_port = number;
  return AD_DESTINATION_OK;
}

/**
 * @brief Validate an Active Directory CA certificate.
 *
 * @param pem The CA certificate in PEM format.
 *
 * @return TRUE if the certificate is valid, FALSE otherwise.
 */
gboolean
valid_ad_ca_certificate (const char *pem)
{
  gnutls_x509_crt_t *certs = NULL;
  unsigned int count = 0;
  gnutls_datum_t input;
  gsize length;
  gboolean valid;
  int ret;

  if (pem == NULL || *pem == '\0')
    return FALSE;

  length = strlen (pem);
  if (length > G_MAXUINT)
    return FALSE;

  input.data = (unsigned char *) pem;
  input.size = (unsigned int) length;

  ret = gnutls_x509_crt_list_import2 (&certs, &count, &input,
                                      GNUTLS_X509_FMT_PEM, 0);

  valid = (ret == GNUTLS_E_SUCCESS && count > 0);
  gvm_x509_cert_list_free (certs, count);
  return valid;
}

/**
 * @brief Validate AD host syntax without DNS or policy membership checks.
 *
 * @param[in] host Borrowed unchanged host text; not retained or modified.
 *
 * @return TRUE for an individual name/IP literal, FALSE otherwise (including
 *         NULL/empty). Temporary comparison keys are freed before return.
 */
gboolean
valid_ad_host (const gchar *host)
{
  ad_policy_host_t *key = parse_ad_policy_host (host);
  gboolean valid = key != NULL;

  if (key)
    ad_policy_host_free (key);
  return valid;
}

/**
 * @brief Validate the supplied Active Directory connection data.
 *
 * @param[in] ad Borrowed connection data; not modified or retained.
 *
 * @return Structural validation result, including malformed host syntax after
 *         existing field checks. Does not check policy or transfer ownership.
 */
static verify_ad_return_t
validate_supplied_ad_connection_data (const ad_credential_data_t *ad)
{
  if (!ad || !ad->host || !*ad->host)
    return VERIFY_AD_CREDENTIAL_HOST_REQUIRED;
  if (!ad->bind_dn || !*ad->bind_dn)
    return VERIFY_AD_CREDENTIAL_BIND_DN_REQUIRED;
  if (!ad->base_dn || !*ad->base_dn)
    return VERIFY_AD_CREDENTIAL_BASE_DN_REQUIRED;
  if (!ad->bind_password || !*ad->bind_password)
    return VERIFY_AD_CREDENTIAL_BIND_PASSWORD_REQUIRED;
  if (!ad->tls_mode || !*ad->tls_mode)
    return VERIFY_AD_CREDENTIAL_TLS_MODE_REQUIRED;

  if (!valid_ad_port (ad->port))
    return VERIFY_AD_CREDENTIAL_INVALID_PORT;

  if (!valid_ad_host (ad->host))
    return VERIFY_AD_CREDENTIAL_INVALID_HOST;

  if (!g_str_equal (ad->tls_mode, "ldaps")
      && !g_str_equal (ad->tls_mode, "starttls"))
    return VERIFY_AD_CREDENTIAL_INVALID_TLS_MODE;

  if (ad->ca_certificate
      && !valid_ad_ca_certificate (ad->ca_certificate))
    return VERIFY_AD_CREDENTIAL_INVALID_CA_CERTIFICATE;

  return VERIFY_AD_CREDENTIAL_OK;
}

/**
 * @brief Configure an Active Directory connector with
 *        the provided connection data.
 *
 * Select the numeric port with active_directory_effective_port(). Verification
 * checks destination policy before connector creation; using the same helper
 * with unchanged port/TLS inputs gives the identical authorized port. This
 * function does not check policy or select a fallback port on invalid input.
 *
 * @param[in,out] connector           Borrowed connector to configure; not freed.
 * @param[in] ad                      Borrowed connection data, not modified or
 *                                   owned here; original host text is passed to
 *                                   the builder without normalization.
 * @param[in] network_timeout_seconds The network timeout in seconds.
 * @param[in] operation_timeout_seconds The operation timeout in seconds.
 *
 * @return AD_CONNECTOR_INVALID_VALUE for invalid input, otherwise the first
 *         builder error or AD_CONNECTOR_OK. No ownership is transferred here;
 *         the builder copies string and numeric option values into the connector.
 */
static ad_connector_return_t
configure_ad_connector (ad_connector_t connector,
                        const ad_credential_data_t *ad,
                        gint network_timeout_seconds,
                        gint operation_timeout_seconds)
{
  ad_connector_return_t rc;
  ad_connector_tls_mode_t tls_mode;
  guint effective_port;
  gint port;

  if (!connector || !ad
      || active_directory_effective_port (ad->port, ad->tls_mode,
                                          &effective_port)
           != AD_DESTINATION_OK)
    return AD_CONNECTOR_INVALID_VALUE;

  if (g_str_equal (ad->tls_mode, "ldaps"))
    tls_mode = AD_CONNECTOR_TLS_LDAPS;
  else
    tls_mode = AD_CONNECTOR_TLS_STARTTLS;
  port = (gint) effective_port;

  rc = ad_connector_builder (connector, AD_CONNECTOR_OPT_HOST, ad->host);
  if (rc != AD_CONNECTOR_OK)
    return rc;
  rc = ad_connector_builder (connector, AD_CONNECTOR_OPT_PORT, &port);
  if (rc != AD_CONNECTOR_OK)
    return rc;
  rc = ad_connector_builder (connector, AD_CONNECTOR_OPT_TLS_MODE, &tls_mode);
  if (rc != AD_CONNECTOR_OK)
    return rc;
  rc = ad_connector_builder (connector, AD_CONNECTOR_OPT_BIND_DN,
                             ad->bind_dn);
  if (rc != AD_CONNECTOR_OK)
    return rc;
  rc = ad_connector_builder (connector, AD_CONNECTOR_OPT_NETWORK_TIMEOUT,
                             &network_timeout_seconds);
  if (rc != AD_CONNECTOR_OK)
    return rc;
  rc = ad_connector_builder (connector, AD_CONNECTOR_OPT_OPERATION_TIMEOUT,
                             &operation_timeout_seconds);
  if (rc != AD_CONNECTOR_OK)
    return rc;

  if (ad->ca_certificate)
    return ad_connector_builder (connector,
                                 AD_CONNECTOR_OPT_CA_CERT,
                                 ad->ca_certificate);

  return AD_CONNECTOR_OK;
}

/**
 * @brief Check if any Active Directory connection fields are present.
 *
 * @param ad  The Active Directory connection data to check.
 *
 * @return TRUE if any fields are present, FALSE otherwise.
 */
static gboolean
ad_fields_present (const ad_credential_data_t *ad)
{
  return ad
         && (ad->host
             || ad->port
             || ad->bind_dn
             || ad->bind_password
             || ad->tls_mode
             || ad->base_dn
             || ad->ca_certificate);
}

/**
 * @brief Verify an Active Directory credential.
 *
 * Only the initial AD endpoint is checked, after permissions/validation.
 * Inputs are not modified/retained; loaded fields and connector are freed.
 *
 * @param[in] credential_id Borrowed stored ID, or NULL for inline fields.
 * @param[in] fields Borrowed inline data, or NULL for stored verification.
 *
 * @return A verify_ad_return_t indicating the result of the verification.
 */
verify_ad_return_t
verify_active_directory_credential (const gchar *credential_id,
                                    const ad_credential_data_t *fields)
{
  ad_credential_data_t saved = { 0 };
  const ad_credential_data_t *ad = fields;
  credential_t credential = 0;
  ad_connector_t connector = NULL;
  ad_connector_return_t connector_result;
  verify_ad_return_t result = VERIFY_AD_CREDENTIAL_INTERNAL_ERROR;
  gchar *type = NULL;
  gboolean supplied = ad_fields_present (fields);
  ad_destination_return_t destination_result;

  if ((credential_id && supplied)
      ||(!credential_id && !supplied)
      || (credential_id && !*credential_id))
    return VERIFY_AD_CREDENTIAL_INVALID_INPUT;

  if (!feature_enabled (FEATURE_ID_AD_INTEGRATION))
    return VERIFY_AD_CREDENTIAL_FEATURE_DISABLED;

  if (!acl_user_may ("verify_active_directory_credential"))
    return VERIFY_AD_CREDENTIAL_PERMISSION_DENIED;

  if (supplied)
    {
      result = validate_supplied_ad_connection_data (fields);
      if (result != VERIFY_AD_CREDENTIAL_OK)
        goto cleanup;
    }
  else
    {
      if (find_credential_with_permission (credential_id,
                                           &credential,
                                           "get_credentials"))
        {
          g_warning ("%s: Failed to find credential", __func__);
          goto cleanup;
        }

      if (!credential)
        {
          result = VERIFY_AD_CREDENTIAL_NOT_FOUND;
          goto cleanup;
        }

      type = credential_type (credential);
      if (!type)
        goto cleanup;
      if (strcmp (type, "ad") != 0)
        {
          result = VERIFY_AD_CREDENTIAL_INVALID_TYPE;
          goto cleanup;
        }

      saved.host = credential_value (credential, "ad_host");
      saved.port = credential_value (credential, "ad_port");
      saved.bind_dn = credential_value (credential, "ad_bind_dn");
      saved.bind_password
        = credential_encrypted_value (credential, "password");
      saved.base_dn = credential_value (credential, "ad_base_dn");
      saved.tls_mode = credential_value (credential, "ad_tls_mode");
      saved.ca_certificate
        = credential_value (credential, "ad_ca_certificate");
      ad = &saved;

      result = validate_supplied_ad_connection_data (ad);
      if (result != VERIFY_AD_CREDENTIAL_OK)
        {
          result = VERIFY_AD_CREDENTIAL_INVALID_STORED_CONFIGURATION;
          goto cleanup;
        }
    }

  destination_result = check_active_directory_destination (
    ad->host, ad->port, ad->tls_mode, NULL);
  if (destination_result != AD_DESTINATION_OK)
    {
      result = VERIFY_AD_CREDENTIAL_DESTINATION_NOT_ALLOWED;
      goto cleanup;
    }

  connector = ad_connector_new ();
  if (!connector)
    goto cleanup;

  connector_result = configure_ad_connector (connector,
                                             ad,
                                             AD_NETWORK_TIMEOUT_SECONDS_DEFAULT,
                                             AD_OPERATION_TIMEOUT_SECONDS_DEFAULT);
  if (connector_result != AD_CONNECTOR_OK)
    {
      result = !supplied && connector_result == AD_CONNECTOR_INVALID_VALUE
                 ? VERIFY_AD_CREDENTIAL_INVALID_STORED_CONFIGURATION
                 : VERIFY_AD_CREDENTIAL_INTERNAL_ERROR;
      goto cleanup;
    }

  connector_result = ad_connector_connect (connector, ad->bind_password);
  switch (connector_result)
    {
    case AD_CONNECTOR_OK:
      result = VERIFY_AD_CREDENTIAL_OK;
      break;
    case AD_CONNECTOR_BIND_ERROR:
      g_warning ("Active Directory bind failed");
      result = VERIFY_AD_CREDENTIAL_CONNECTION_FAILED;
      break;
    case AD_CONNECTOR_CONNECTION_ERROR:
      g_warning ("Could not connect to Active Directory");
      result = VERIFY_AD_CREDENTIAL_CONNECTION_FAILED;
      break;
    case AD_CONNECTOR_INVALID_VALUE:
      if (supplied)
        g_warning ("Internal error connecting to Active Directory");
      else
        g_warning ("Invalid stored Active Directory configuration");
      result = VERIFY_AD_CREDENTIAL_CONNECTION_FAILED;
      break;
    default:
      result = VERIFY_AD_CREDENTIAL_INTERNAL_ERROR;
      break;
    }

cleanup:
  ad_connector_free (connector);
  g_free (type);
  ad_credential_data_reset (&saved);
  return result;
}

#endif /* ENABLE_AD_INTEGRATION */
