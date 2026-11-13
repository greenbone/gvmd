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
#include "manage_configs.h"
#include "manage_targets.h"
#include "manage_utils.h"

#include <arpa/inet.h>
#include <errno.h>
#include <gnutls/x509.h> /* for gnutls_x509_crt_... */
#include <string.h>

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
typedef struct
{
  ad_object_type_t types;
  const gchar *name;
} ad_directory_attribute_t;

static const ad_directory_attribute_t ad_basic_attributes[] = {
  { AD_OBJECT_TYPE_ALL, "description" },
  { AD_OBJECT_TYPE_ALL, "cn" },
  { AD_OBJECT_TYPE_ALL, "objectcategory" },
  { AD_OBJECT_TYPE_OU, "ou" },
  { AD_OBJECT_TYPE_COMPUTER, "dnshostname" },
  { AD_OBJECT_TYPE_COMPUTER | AD_OBJECT_TYPE_GROUP, "samaccountname" },
  { AD_OBJECT_TYPE_COMPUTER, "operatingsystem" },
  { AD_OBJECT_TYPE_COMPUTER, "useraccountcontrol" },
  { AD_OBJECT_TYPE_GROUP, "displayname" },
  { AD_OBJECT_TYPE_GROUP, "grouptype" }
};

static const ad_directory_attribute_t ad_detail_attributes[] = {
  { AD_OBJECT_TYPE_COMPUTER, "operatingsystemversion" },
  { AD_OBJECT_TYPE_COMPUTER, "serviceprincipalname" }
};

typedef enum
{
  AD_CREDENTIAL_LOAD_OK,
  AD_CREDENTIAL_LOAD_NOT_FOUND,
  AD_CREDENTIAL_LOAD_INVALID_TYPE,
  AD_CREDENTIAL_LOAD_INTERNAL_ERROR
} ad_credential_load_return_t;

/**
 * @brief Owned startup host policy: empty allows all, NULL denies all.
 *
 * NULL means uninitialized or invalid/unreadable selected configuration.
 */
static GPtrArray *ad_allowed_hosts;

/**
 * @brief Owned startup port policy: empty allows all, NULL denies all.
 *
 * NULL means uninitialized or invalid/unreadable selected configuration.
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
 * The shared getter logs selected string read errors and distinguishes them
 * from absence. Only absence uses the built-in default; no source retry occurs.
 *
 * @param[in] kf             Parsed configuration, or NULL if unavailable.
 * @param[in] env_name       Non-NULL environment override name.
 * @param[in] key            Non-NULL key in the active_directory group.
 * @param[in] default_value  Non-NULL built-in default string.
 *
 * @return Newly allocated selected string, including explicit empty values.
 *         Missing values use the default; unreadable values return NULL.
 *         Free non-NULL results with g_free().
 */
static gchar *
ad_policy_config_string (GKeyFile *kf, const gchar *env_name,
                         const gchar *key, const gchar *default_value)
{
  gboolean read_error;
  gchar *value = gvmd_get_env_or_config_string_full (
    env_name, kf, ACTIVE_DIRECTORY_CONFIG_GROUP, key, &read_error);

  return value || read_error ? value : g_strdup (default_value);
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
 * Missing options use independent defaults; explicit empty lists allow all.
 * Invalid/unreadable selected lists warn and publish NULL (deny all), never a
 * default or lower-priority value. Publish complete lists or failure states,
 * freeing previous policy on repeated initialization, including valid-to-invalid
 * transitions. The checker reads only this snapshot; startup is not aborted.
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
  hosts = text ? parse_ad_allowed_hosts (text) : NULL;
  if (text && hosts == NULL)
    g_warning ("%s: active_directory.allowed_hosts: expected comma-separated "
               "individual names or IP addresses with no empty entries; "
               "AD destinations denied", __func__);
  g_free (text);

  text = ad_policy_config_string (kf, "GVMD_AD_ALLOWED_PORTS", "allowed_ports",
                                  AD_ALLOWED_PORTS_DEFAULT);
  ports = text ? parse_ad_allowed_ports (text) : NULL;
  if (text && ports == NULL)
    g_warning ("%s: active_directory.allowed_ports: expected comma-separated "
               "decimal ports in range 1-65535 with no empty entries; "
               "AD destinations denied", __func__);
  g_free (text);

  g_clear_pointer (&ad_allowed_hosts, g_ptr_array_unref);
  g_clear_pointer (&ad_allowed_ports, g_array_unref);
  ad_allowed_hosts = hosts;
  ad_allowed_ports = ports;
}

/**
 * @brief Free credential fields and reset the credential data.
 *
 * @param[in,out] ad Credential data whose owned fields to be freed.
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
 *         initialization has not occurred or either selected policy option was
 *         invalid/unreadable; no policy is loaded lazily or defaulted on failure.
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

  /* NULL is uninitialized/failed policy, never implicit allow-all. */
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
 * @brief Load a readable Active Directory credential.
 *
 * @param[in]  credential_id Credential UUID to look up with get_credentials
 *                           permission.
 * @param[out] data          Receives owned credential fields on success;
 *                           unchanged on failure. Release fields with
 *                           ad_credential_data_reset().
 *
 * @return AD_CREDENTIAL_LOAD_OK on success or an error code on failure.
 */
static ad_credential_load_return_t
load_ad_credential (const gchar *credential_id, ad_credential_data_t *data)
{
  credential_t credential = 0;
  gchar *type;
  gboolean is_ad;

  if (find_credential_with_permission (credential_id, &credential,
                                       "get_credentials"))
    {
      g_warning ("%s: Failed to find credential", __func__);
      return AD_CREDENTIAL_LOAD_INTERNAL_ERROR;
    }

  if (!credential)
    return AD_CREDENTIAL_LOAD_NOT_FOUND;

  type = credential_type (credential);
  if (!type)
    return AD_CREDENTIAL_LOAD_INTERNAL_ERROR;

  is_ad = g_str_equal (type, "ad");
  g_free (type);
  if (!is_ad)
    return AD_CREDENTIAL_LOAD_INVALID_TYPE;

  *data = (ad_credential_data_t) {
    .host = credential_value (credential, "ad_host"),
    .port = credential_value (credential, "ad_port"),
    .bind_dn = credential_value (credential, "ad_bind_dn"),
    .bind_password = credential_encrypted_value (credential, "password"),
    .tls_mode = credential_value (credential, "ad_tls_mode"),
    .base_dn = credential_value (credential, "ad_base_dn"),
    .ca_certificate = credential_value (credential, "ad_ca_certificate")
  };

  return AD_CREDENTIAL_LOAD_OK;
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
  ad_connector_t connector = NULL;
  ad_connector_return_t connector_result;
  verify_ad_return_t result = VERIFY_AD_CREDENTIAL_INTERNAL_ERROR;
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
      ad_credential_load_return_t load_result;
      load_result = load_ad_credential (credential_id, &saved);

      switch (load_result)
        {
        case AD_CREDENTIAL_LOAD_OK:
          break;
        case AD_CREDENTIAL_LOAD_NOT_FOUND:
          result = VERIFY_AD_CREDENTIAL_NOT_FOUND;
          goto cleanup;
        case AD_CREDENTIAL_LOAD_INVALID_TYPE:
          result = VERIFY_AD_CREDENTIAL_INVALID_TYPE;
          goto cleanup;
        case AD_CREDENTIAL_LOAD_INTERNAL_ERROR:
          goto cleanup;
        }
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
  ad_credential_data_reset (&saved);
  return result;
}

/**
 * @brief Find the attribute name for an object type.
 *
 * @param[in] attributes Attribute definitions to search.
 * @param[in] count      Number of definitions.
 * @param[in] type       Object type to match.
 * @param[in] name       Attribute name to compare without case sensitivity.
 *
 * @return A borrowed name from attributes, or NULL if no definition matches.
 */
static const gchar *
find_ad_attribute_name (const ad_directory_attribute_t *attributes,
                        gsize count,
                        ad_object_type_t type,
                        const gchar *name)
{
  for (gsize index = 0; index < count; index++)
    if ((attributes[index].types & type)
        && g_ascii_strcasecmp (name, attributes[index].name) == 0)
      return attributes[index].name;
  return NULL;
}

/**
 * @brief Append comma-separated attribute names for selected object types.
 *
 * @param[in,out] names      Buffer receiving attribute names.
 * @param[in]     attributes Available attribute definitions.
 * @param[in]     count      Number of definitions.
 * @param[in]     types      Bitmask of object types to include.
 */
static void
append_ad_attribute_names (GString *names,
                           const ad_directory_attribute_t *attributes,
                           gsize count,
                           ad_object_type_t types)
{
  for (gsize index = 0; index < count; index++)
    if (attributes[index].types & types)
      {
        if (names->len)
          g_string_append_c (names, ',');
        g_string_append (names, attributes[index].name);
      }
}

/**
 * @brief Get the attribute values for a given attribute name.
 *
 * @param[in] object Directory object to query.
 * @param[in] name   Attribute name.
 *
 * @return A borrowed array owned by object, or NULL if unavailable.
 */
const GPtrArray *
ad_object_attribute_values (const ad_directory_object_t *object,
                            const gchar *name)
{
  gchar *key;
  GPtrArray *values;

  if (!object || !object->attributes || !name)
    return NULL;

  key = g_ascii_strdown (name, -1);
  values = g_hash_table_lookup (object->attributes, key);
  g_free (key);
  return values;
}

/**
 * @brief Get the first attribute value for a given attribute name.
 *
 * @param[in] object Directory object to query.
 * @param[in] name   Attribute name.
 *
 * @return A borrowed value owned by object, or NULL if unavailable.
 */
const gchar *
ad_object_attribute_value (const ad_directory_object_t *object,
                           const gchar *name)
{
  const GPtrArray *values = ad_object_attribute_values (object, name);

  return values && values->len ? g_ptr_array_index (values, 0) : NULL;
}

/**
 * @brief Check the computer's userAccountControl disabled flag.
 *
 * @param[in] object Directory object to inspect.
 *
 * @return TRUE if a valid computer account-control value has the disabled bit
 *         set; FALSE for enabled accounts, invalid values, or other objects.
 */
static gboolean
ad_directory_object_is_disabled (const ad_directory_object_t *object)
{
  const gchar *account_control;
  gchar *end;
  guint64 value;

  if (!object || object->type != AD_OBJECT_TYPE_COMPUTER)
    return FALSE;

  account_control = ad_object_attribute_value (object, "useraccountcontrol");

  if (!account_control || !g_ascii_isdigit ((guchar) *account_control))
    return FALSE;

  value = g_ascii_strtoull (account_control, &end, 10);
  return *end == '\0' && value <= G_MAXUINT32 && (value & 0x0002);
}

/**
 * @brief Consume a search object and retain selected directory data.
 *
 * @param[in] object Owned search object; freed after selected strings and
 *                   attribute arrays are transferred.
 *
 * @return An owned directory object to release with ad_directory_object_free(),
 *         or NULL if object is NULL.
 */
static ad_directory_object_t *
ad_directory_object_from_search_object (ad_object_t *object)
{
  ad_directory_object_t *result;
  GHashTableIter iter;
  gpointer key, values;

  if (!object)
    return NULL;

  result = g_malloc0 (sizeof (*result));
  result->type = object->type;

  result->name = object->name;
  object->name = NULL;

  result->distinguished_name = object->distinguished_name;
  object->distinguished_name = NULL;

  result->parent_dn = object->parent_dn;
  object->parent_dn = NULL;

  result->attributes = g_hash_table_new_full (
    g_str_hash,
    g_str_equal,
    g_free,
    (GDestroyNotify) g_ptr_array_unref
  );

  if (object->attributes)
    {
      g_hash_table_iter_init (&iter, object->attributes);
      while (g_hash_table_iter_next (&iter, &key, &values))
        {
          const gchar *name = find_ad_attribute_name (
            ad_basic_attributes,
            G_N_ELEMENTS (ad_basic_attributes),
            object->type,
            key
          );

          if (!name)
            name = find_ad_attribute_name (
              ad_detail_attributes,
              G_N_ELEMENTS (ad_detail_attributes),
              object->type,
              key
            );

          if (!name || !values || !((GPtrArray *) values)->len)
            continue;

          g_hash_table_iter_steal (&iter);
          g_free (key);

          g_hash_table_insert (result->attributes, g_strdup (name), values);
        }
    }

  ad_object_free (object);
  return result;
}

/**
 * @brief Free a directory object and its owned fields.
 *
 * @param[in] object Directory object to free.
 */
void
ad_directory_object_free (ad_directory_object_t *object)
{
  if (!object)
    return;

  g_free (object->name);
  g_free (object->distinguished_name);
  g_free (object->parent_dn);
  g_clear_pointer (&object->attributes, g_hash_table_unref);
  g_clear_pointer (&object->target_matches, g_ptr_array_unref);
  g_free (object);
}

/**
 * @brief Normalize an AD hostname by trimming whitespace and lowercasing it.
 *
 * @param[in] value Hostname to normalize.
 *
 * @return A newly allocated hostname to free with g_free(), or NULL for missing
 *         or invalid hostnames, including IP address literals.
 */
static gchar *
normalize_ad_hostname (const gchar *value)
{
  gchar *hostname;

  if (!value)
    return NULL;

  hostname = g_ascii_strdown (value, -1);
  g_strstrip (hostname);

  if (gvm_get_host_type (hostname) != HOST_TYPE_NAME)
    {
      g_free (hostname);
      return NULL;
    }
  return hostname;
}

/**
 * @brief Free the UUID and name of a resource reference.
 *
 * @param[in,out] resource Reference whose strings are freed; the structure is
 *                         retained and its pointers are not reset.
 */
static void
ad_resource_ref_clear (ad_resource_ref_t *resource)
{
  g_free (resource->uuid);
  g_free (resource->name);
}

/**
 * @brief Free a task match and its optional configuration reference.
 *
 * @param[in] task Owned task match to release.
 */
static void
ad_task_match_free (ad_task_match_t *task)
{
  ad_resource_ref_clear (&task->resource);
  if (task->config)
    {
      ad_resource_ref_clear (task->config);
      g_free (task->config);
    }
  g_free (task);
}

/**
 * @brief Free a target match and release its task array reference.
 *
 * @param[in] target Owned target match to release; shared tasks remain alive
 *                   while other references exist.
 */
static void
ad_target_match_free (ad_target_match_t *target)
{
  ad_resource_ref_clear (&target->resource);
  g_clear_pointer (&target->tasks, g_ptr_array_unref);
  g_free (target);
}

/**
 * @brief Initialize target match arrays and index computers by hostname.
 *
 * @param[in,out] objects Borrowed directory objects; computers receive empty
 *                        target match arrays if none exist.
 *
 * @return A new table owning normalized hostname keys and arrays of borrowed
 *         computer pointers. Release with g_hash_table_unref().
 */
static GHashTable *
index_ad_computers_for_target_matching (GPtrArray *objects)
{
  GHashTable *computers_by_hostname;

  computers_by_hostname
    = g_hash_table_new_full (g_str_hash,
                             g_str_equal,
                             g_free,
                            (GDestroyNotify) g_ptr_array_unref);

  for (guint index = 0; index < objects->len; index++)
    {
      ad_directory_object_t *object = g_ptr_array_index (objects, index);
      gchar *hostname;
      GPtrArray *computers_with_hostname;

      if (!object || object->type != AD_OBJECT_TYPE_COMPUTER)
        continue;

      if (!object->target_matches)
        object->target_matches
          = g_ptr_array_new_with_free_func ((GDestroyNotify) ad_target_match_free);

      hostname = normalize_ad_hostname (
        ad_object_attribute_value (object, "dnshostname")
      );

      if (!hostname)
        continue;

      computers_with_hostname = g_hash_table_lookup (computers_by_hostname,
                                                     hostname);
      if (!computers_with_hostname)
        {
          computers_with_hostname = g_ptr_array_new ();
          g_hash_table_insert (computers_by_hostname,
                               hostname,
                               computers_with_hostname);
        }
      else
        g_free (hostname);

      g_ptr_array_add (computers_with_hostname, object);
    }

  return computers_by_hostname;
}

/**
 * @brief Load readable target tasks and their readable configurations.
 *
 * @param[in]  target Active target's internal database ID.
 * @param[out] result Receives an owned array of ad_task_match_t on success,
 *                    including an empty array if no tasks match; unchanged on
 *                    failure. Release with g_ptr_array_unref().
 *
 * @return GET_AD_OBJECTS_OK on success, or GET_AD_OBJECTS_INTERNAL_ERROR if a
 *         task or configuration lookup fails.
 */
static get_ad_objects_return_t
load_ad_target_tasks (target_t target, GPtrArray **result)
{
  iterator_t tasks;
  GPtrArray *matches = g_ptr_array_new_with_free_func (
    (GDestroyNotify) ad_task_match_free);

  init_target_task_iterator (&tasks, target);
  while (next (&tasks))
    {
      task_t task = 0;
      ad_task_match_t *match;
      const gchar *uuid;

      if (!target_task_iterator_readable (&tasks))
        continue;

      uuid = target_task_iterator_uuid (&tasks);
      if (!uuid || find_task_with_permission (uuid, &task, "get_tasks"))
        goto fail;

      if (!task || task_target_in_trash (task))
        continue;

      match = g_new0 (ad_task_match_t, 1);
      match->resource.uuid = g_strdup (uuid);
      match->resource.name = g_strdup (target_task_iterator_name (&tasks));
      g_ptr_array_add (matches, match);

      if (!task_config_in_trash (task) && acl_user_may ("get_configs"))
        {
          gchar *config_uuid = task_config_uuid (task);
          config_t config = 0;

          if (config_uuid
              && find_config_with_permission (config_uuid, &config,
                                               "get_configs"))
            {
              g_free (config_uuid);
              goto fail;
            }

          if (config)
            {
              match->config = g_new0 (ad_resource_ref_t, 1);
              match->config->uuid = config_uuid;
              match->config->name = task_config_name (task);
            }
          else
            g_free (config_uuid);
        }
    }
  cleanup_iterator (&tasks);
  *result = matches;
  return GET_AD_OBJECTS_OK;

fail:
  cleanup_iterator (&tasks);
  g_ptr_array_unref (matches);
  return GET_AD_OBJECTS_INTERNAL_ERROR;
}

/**
 * @brief Attach a target and shared tasks to matching computers.
 *
 * @param[in,out] computers Borrowed computers with initialized target match
 *                          arrays; supply each computer once per target and
 *                          attach each target only once.
 * @param[in]     uuid      Target UUID to copy.
 * @param[in]     name      Target name to copy.
 * @param[in]     tasks     Borrowed immutable task array when not
 *                          requested; each target match acquires a reference.
 */
static void
add_target_match_to_computers (GPtrArray *computers, const gchar *uuid,
                               const gchar *name, GPtrArray *tasks)
{
  for (guint index = 0; index < computers->len; index++)
    {
      ad_directory_object_t *computer = g_ptr_array_index (computers, index);
      ad_target_match_t *match = g_new0 (ad_target_match_t, 1);

      match->resource.uuid = g_strdup (uuid);
      match->resource.name = g_strdup (name);
      match->tasks = tasks ? g_ptr_array_ref (tasks) : NULL;
      g_ptr_array_add (computer->target_matches, match);
    }
}

/**
 * @brief Match a target's hostnames after exclusions and attach optional tasks.
 *
 * @param[in,out] computers_by_hostname Borrowed hostname index whose computer
 *                                     objects receive target matches.
 * @param[in]     target                Iterator positioned on a readable target.
 * @param[in]     include_tasks         Whether to load readable tasks and configs.
 *
 * @return GET_AD_OBJECTS_OK, including when nothing matches, or
 *         GET_AD_OBJECTS_INTERNAL_ERROR on parsing, exclusion, or lookup failure.
 */
static get_ad_objects_return_t
attach_target_to_matching_computers (GHashTable *computers_by_hostname,
                                     iterator_t *target,
                                     gboolean include_tasks)
{
  GPtrArray *tasks = NULL;
  gboolean tasks_loaded = FALSE;
  get_ad_objects_return_t ret = GET_AD_OBJECTS_INTERNAL_ERROR;
  gvm_host_t *host;
  const gchar *exclude_hosts = target_iterator_exclude_hosts (target);
  const gchar *uuid = get_iterator_uuid (target);
  const gchar *name = get_iterator_name (target);

  guint max_hosts = manage_max_hosts ();
  gchar *clean_hosts = clean_hosts_string (target_iterator_hosts (target));
  gvm_hosts_t *hosts = gvm_hosts_new_with_max (clean_hosts, max_hosts);
  g_free (clean_hosts);

  if (!hosts)
    return ret;

  if (exclude_hosts && *exclude_hosts)
    {
      gchar *clean_exclude = clean_hosts_string (exclude_hosts);
      int excluded = gvm_hosts_exclude_with_max (hosts, clean_exclude,
                                                  max_hosts);

      g_free (clean_exclude);
      if (excluded < 0)
        goto cleanup;
    }

  while ((host = gvm_hosts_next (hosts)))
    {
      gchar *hostname;
      GPtrArray *computers;

      if (gvm_host_type (host) != HOST_TYPE_NAME)
        continue;

      hostname = gvm_host_value_str (host);
      computers = g_hash_table_lookup (computers_by_hostname, hostname);
      g_free (hostname);

      if (!computers)
        continue;

      if (include_tasks && !tasks_loaded)
        {
          ret = load_ad_target_tasks (get_iterator_resource (target), &tasks);
          if (ret != GET_AD_OBJECTS_OK)
            goto cleanup;

          tasks_loaded = TRUE;
        }

      add_target_match_to_computers (computers, uuid, name, tasks);
    }

  ret = GET_AD_OBJECTS_OK;

cleanup:
  g_clear_pointer (&tasks, g_ptr_array_unref);
  gvm_hosts_free (hosts);
  return ret;
}

/**
 * @brief Enrich discovered computers with readable target and task matches.
 *
 * @param[in,out] objects       Borrowed directory objects to enrich; OUs and
 *                              groups are unchanged. Computers without matches
 *                              receive empty target match arrays.
 * @param[in]     include_tasks Whether to include readable tasks and configs.
 *
 * @return GET_AD_OBJECTS_OK on success or an appropriate error code on failure.
 */
static get_ad_objects_return_t
match_ad_objects_to_targets (GPtrArray *objects,
                             gboolean include_tasks)
{
  get_data_t get = {
    .type = "target",
    .filter = "first=1 rows=-1",
    .ignore_max_rows_per_page = 1
  };
  iterator_t targets;
  GHashTable *computers_by_hostname;

  if (!objects)
    return GET_AD_OBJECTS_INVALID_INPUT;

  if (!acl_user_may ("get_targets"))
    {
      g_warning ("%s: Target matching skipped: permission to read targets "
                 "is required.", __func__);
      return GET_AD_OBJECTS_OK;
    }

  if (include_tasks && !acl_user_may ("get_tasks"))
    {
      g_warning ("%s: Task enrichment skipped: permission to read tasks "
                 "is required.", __func__);
      include_tasks = FALSE;
    }

  if (include_tasks && !acl_user_may ("get_configs"))
    g_warning ("%s: Scan configuration enrichment skipped: permission to read "
               "configurations is required.", __func__);

  computers_by_hostname = index_ad_computers_for_target_matching (objects);
  if (g_hash_table_size (computers_by_hostname) == 0)
    {
      g_hash_table_unref (computers_by_hostname);
      return GET_AD_OBJECTS_OK;
    }

  if (init_ad_target_candidate_iterator_by_hostname (&targets,
                                                     &get,
                                                     computers_by_hostname))
    {
      g_hash_table_unref (computers_by_hostname);
      return GET_AD_OBJECTS_INTERNAL_ERROR;
    }

  while (next (&targets))
    {
      get_ad_objects_return_t ret;

      ret = attach_target_to_matching_computers (computers_by_hostname,
                                                 &targets,
                                                 include_tasks);

      if (ret != GET_AD_OBJECTS_OK)
        {
          cleanup_iterator (&targets);
          g_hash_table_unref (computers_by_hostname);
          return ret;
        }
    }

  cleanup_iterator (&targets);
  g_hash_table_unref (computers_by_hostname);
  return GET_AD_OBJECTS_OK;
}

/**
 * @brief Release owned search results and reset their metadata.
 *
 * @param[in,out] result Result whose objects are freed and fields zeroed,
 *                       or NULL.
 */
void
get_ad_objects_result_reset (get_ad_objects_result_t *result)
{
  if (!result)
    return;

  if (result->objects)
    {
      g_ptr_array_set_free_func (result->objects,
                                 (GDestroyNotify) ad_directory_object_free);
      g_ptr_array_free (result->objects, TRUE);
    }
  memset (result, 0, sizeof (*result));
}

/**
 * @brief Validate the parameters for an Active Directory object search.
 *
 * @param[in] params Search parameters to validate.
 *
 * @return TRUE for a nonempty credential ID, supported scope and object types,
 *         allowed result limit, and tasks requested only with targets;
 *         FALSE otherwise.
 */
static gboolean
valid_ad_object_search_params (const get_ad_objects_params_t *params)
{
  if (!params || !params->credential_id || !*params->credential_id)
    return FALSE;
  if (params->group_dn && !*params->group_dn)
    return FALSE;
  if (params->tasks && !params->targets)
    return FALSE;

  if (params->max_results < 1
      || params->max_results > GET_AD_OBJECTS_MAX_RESULTS)
    return FALSE;

  if (params->scope != AD_CONNECTOR_SEARCH_SCOPE_BASE
      && params->scope != AD_CONNECTOR_SEARCH_SCOPE_ONELEVEL
      && params->scope != AD_CONNECTOR_SEARCH_SCOPE_SUBTREE)
    return FALSE;

  if (!params->object_types
      || (params->object_types & ~AD_OBJECT_TYPE_ALL))
    return FALSE;

  return TRUE;
}

/**
 * @brief Configure an Active Directory search.
 *
 * @param[in,out] config  Search configuration to populate.
 * @param[in]     params Borrowed search options, including the attribute selection.
 * @param[in]     credential_base_dn Base DN from the saved AD credential.
 *
 * @return AD_CONNECTOR_OK on success, or the validation or builder error.
 *         The configuration may be partially populated on failure.
 */
static ad_connector_return_t
configure_ad_search (ad_search_config_t config,
                     const get_ad_objects_params_t *params,
                     const gchar *credential_base_dn)
{
  ad_connector_return_t rc;
  const gchar *base_dn;
  gint max_results;

  if (!config || !params)
    return AD_CONNECTOR_INVALID_VALUE;

  max_results = (gint) params->max_results;

  if (params->base_dn
      && !ad_search_base_dn_is_within (params->base_dn, credential_base_dn))
    return AD_CONNECTOR_INVALID_VALUE;

  if (params->group_dn
      && !ad_search_base_dn_is_within (params->group_dn,
                                       credential_base_dn))
    return AD_CONNECTOR_INVALID_VALUE;

  base_dn = params->base_dn ? params->base_dn : credential_base_dn;
  rc = ad_search_config_builder (config, AD_SEARCH_CONFIG_OPT_BASE_DN,
                                 base_dn);
  if (rc != AD_CONNECTOR_OK)
    return rc;

  rc = ad_search_config_builder (config, AD_SEARCH_CONFIG_OPT_SCOPE,
                                 &params->scope);
  if (rc != AD_CONNECTOR_OK)
    return rc;
  rc = ad_search_config_builder (config, AD_SEARCH_CONFIG_OPT_OBJECT_TYPES,
                                 &params->object_types);
  if (rc != AD_CONNECTOR_OK)
    return rc;
  rc = ad_search_config_builder (config, AD_SEARCH_CONFIG_OPT_MAX_RESULTS,
                                 &max_results);
  if (rc != AD_CONNECTOR_OK)
    return rc;

  if (params->group_dn)
    {
      rc = ad_search_config_builder (config, AD_SEARCH_CONFIG_OPT_GROUP_DN,
                                     params->group_dn);
      if (rc != AD_CONNECTOR_OK)
        return rc;
    }

  GString *attributes = g_string_new (NULL);
  append_ad_attribute_names (attributes, ad_basic_attributes,
                             G_N_ELEMENTS (ad_basic_attributes),
                             params->object_types);
  if (params->details)
    append_ad_attribute_names (attributes, ad_detail_attributes,
                               G_N_ELEMENTS (ad_detail_attributes),
                               params->object_types);
  rc = ad_search_config_builder (config, AD_SEARCH_CONFIG_OPT_EXTRA_ATTRIBUTES,
                                 attributes->str);
  g_string_free (attributes, TRUE);
  if (rc != AD_CONNECTOR_OK)
    return rc;

  return ad_search_config_builder (
    config, AD_SEARCH_CONFIG_OPT_INCLUDE_DISABLED_COMPUTERS,
    &params->include_disabled_computers);
}

/**
 * @brief Collect and count a connector search object.
 *
 * @param[in]     object    Owned connector object, consumed on success or failure.
 * @param[in,out] user_data get_ad_objects_result_t with an initialized owned
 *                          object array; receives the object and updated counts.
 *
 * @return AD_OBJECT_CALLBACK_CONTINUE after collection, or
 *         AD_OBJECT_CALLBACK_ERROR for missing required data or an unsupported
 *         object type.
 */
static ad_object_callback_result_t
collect_ad_object (ad_object_t *object, gpointer user_data)
{
  get_ad_objects_result_t *result = user_data;
  ad_directory_object_t *entry;

  if (!object || !object->name || !object->distinguished_name)
    goto reject;

  if (object->type != AD_OBJECT_TYPE_OU
      && object->type != AD_OBJECT_TYPE_CONTAINER
      && object->type != AD_OBJECT_TYPE_COMPUTER
      && object->type != AD_OBJECT_TYPE_GROUP)
    goto reject;

  entry = ad_directory_object_from_search_object (object);

  if (!entry)
    return AD_OBJECT_CALLBACK_ERROR;

  g_ptr_array_add (result->objects, entry);

  if (entry->type == AD_OBJECT_TYPE_OU)
    result->counts.ou++;
  else if (entry->type == AD_OBJECT_TYPE_CONTAINER)
    result->counts.container++;
  else if (entry->type == AD_OBJECT_TYPE_GROUP)
    result->counts.group++;
  else if (entry->type == AD_OBJECT_TYPE_COMPUTER)
    {
      result->counts.computer_total++;

      if (ad_directory_object_is_disabled (entry))
        result->counts.computer_disabled++;
    }

  return AD_OBJECT_CALLBACK_CONTINUE;

reject:
  ad_object_free (object);
  return AD_OBJECT_CALLBACK_ERROR;
}

/**
 * @brief Search AD objects and optionally enrich them with target and task matches.
 *
 * @param[in]     params Borrowed search parameters, with defaults supplied by
 *                       the caller.
 * @param[in,out] result Initially empty result; receives owned objects, counts,
 *                       and truncation status only on success. Unchanged on
 *                       failure. Release with get_ad_objects_result_reset().
 *
 * @return GET_AD_OBJECTS_OK on success, including empty or truncated results,
 *         or an input, feature, permission, credential, connection, search,
 *         result-processing, or internal error.
 */
get_ad_objects_return_t
get_active_directory_objects (const get_ad_objects_params_t *params,
                              get_ad_objects_result_t *result)
{
  ad_credential_data_t saved = {0};
  ad_object_search_result_t result_metadata = {0};
  get_ad_objects_result_t collected_result = {0};
  ad_connector_t connector = NULL;
  ad_search_config_t config = NULL;
  ad_connector_return_t connector_result;
  get_ad_objects_return_t ret = GET_AD_OBJECTS_INTERNAL_ERROR;
  ad_credential_load_return_t cred_ret;

  if (!result || result->objects
      || !valid_ad_object_search_params (params))
    return GET_AD_OBJECTS_INVALID_INPUT;

  if (!feature_enabled (FEATURE_ID_AD_INTEGRATION))
    return GET_AD_OBJECTS_FEATURE_DISABLED;

  if (!acl_user_may ("get_active_directory_objects"))
    return GET_AD_OBJECTS_PERMISSION_DENIED;

  cred_ret = load_ad_credential (params->credential_id, &saved);

  switch (cred_ret)
    {
    case AD_CREDENTIAL_LOAD_OK:
      break;
    case AD_CREDENTIAL_LOAD_NOT_FOUND:
      ret = GET_AD_OBJECTS_NOT_FOUND;
      goto cleanup;
    case AD_CREDENTIAL_LOAD_INVALID_TYPE:
      ret = GET_AD_OBJECTS_INVALID_TYPE;
      goto cleanup;
    case AD_CREDENTIAL_LOAD_INTERNAL_ERROR:
      goto cleanup;
    }

  connector = ad_connector_new ();

  connector_result = configure_ad_connector (connector,
                                             &saved,
                                             AD_NETWORK_TIMEOUT_SECONDS_DEFAULT,
                                             AD_OPERATION_TIMEOUT_SECONDS_DEFAULT);
  if (connector_result != AD_CONNECTOR_OK)
    {
      if (connector_result == AD_CONNECTOR_INVALID_VALUE)
        ret = GET_AD_OBJECTS_INVALID_STORED_CONFIGURATION;
      goto cleanup;
    }

  config = ad_search_config_new ();

  connector_result = configure_ad_search (config, params, saved.base_dn);
  if (connector_result != AD_CONNECTOR_OK)
    {
      if (connector_result == AD_CONNECTOR_INVALID_VALUE)
        ret = GET_AD_OBJECTS_INVALID_INPUT;
      goto cleanup;
    }

  connector_result = ad_connector_connect (connector, saved.bind_password);
  if (connector_result != AD_CONNECTOR_OK)
    {
      if (connector_result == AD_CONNECTOR_BIND_ERROR)
        ret = GET_AD_OBJECTS_BIND_FAILED;
      else if (connector_result == AD_CONNECTOR_CONNECTION_ERROR)
        ret = GET_AD_OBJECTS_CONNECTION_FAILED;
      else if (connector_result == AD_CONNECTOR_INVALID_VALUE)
        ret = GET_AD_OBJECTS_INVALID_STORED_CONFIGURATION;
      goto cleanup;
    }

  collected_result.objects = g_ptr_array_new_with_free_func (
    (GDestroyNotify) ad_directory_object_free
  );

  connector_result = ad_connector_search_objects (connector,
                                                  config,
                                                  collect_ad_object,
                                                  &collected_result,
                                                  &result_metadata);
  if (connector_result != AD_CONNECTOR_OK)
    {
      if (connector_result == AD_CONNECTOR_RESULT_ERROR)
        ret = GET_AD_OBJECTS_RESULT_FAILED;
      else if (connector_result == AD_CONNECTOR_CONNECTION_ERROR)
        ret = GET_AD_OBJECTS_CONNECTION_FAILED;
      else if (connector_result == AD_CONNECTOR_SEARCH_ERROR)
        ret = GET_AD_OBJECTS_SEARCH_FAILED;
      goto cleanup;
    }

  if (params->targets)
    {
      ret = match_ad_objects_to_targets (collected_result.objects,
                                         params->tasks);
      if (ret != GET_AD_OBJECTS_OK)
        goto cleanup;
    }

  collected_result.truncated = result_metadata.truncated;

  *result = collected_result;
  collected_result = (get_ad_objects_result_t) {0};

  ret = GET_AD_OBJECTS_OK;

cleanup:
  g_clear_pointer (&collected_result.objects, g_ptr_array_unref);
  ad_search_config_free (config);
  ad_connector_free (connector);
  ad_credential_data_reset (&saved);

  return ret;
}

#endif /* ENABLE_AD_INTEGRATION */
