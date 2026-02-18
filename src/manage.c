/* Copyright (C) 2009-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief The Greenbone Vulnerability Manager management layer.
 *
 * This file defines a management layer, for implementing
 * Managers such as the Greenbone Vulnerability Manager daemon.
 *
 * This layer provides facilities for storing and manipulating user
 * data (credentials, targets, tasks, reports, schedules, roles, etc)
 * and general security data (NVTs, CVEs, etc).
 * Task manipulation includes controlling external facilities such as
 * OSP scanners.
 *
 * Simply put, the daemon's GMP implementation uses this layer to do the work.
 */

/**
 * @brief Enable extra functions.
 *
 * time.h in glibc2 needs this for strptime.
 */
#define _XOPEN_SOURCE

/**
 * @brief Enable extra GNU functions.
 *
 * pthread_sigmask () needs this with glibc < 2.19
 */
#define _GNU_SOURCE

#include "debug_utils.h"
#include "gmp_base.h"
#include "ipc.h"
#include "manage_acl.h"
#include "manage_agent_installers.h"
#include "manage_assets.h"
#include "manage_configs.h"
#include "manage_nvts.h"
#include "manage_osp.h"
#include "manage_port_lists.h"
#include "manage_report_configs.h"
#include "manage_report_formats.h"
#include "manage_scan_queue.h"
#include "manage_oci_image_targets.h"
#include "manage_http_scanner.h"
#include "manage_runtime_flags.h"
#include "manage_sql.h"
#include "manage_sql_assets.h"
#include "manage_sql_resources.h"
#include "manage_sql_secinfo.h"
#include "manage_sql_targets.h"
#include "manage_sql_tickets.h"
#include "manage_sql_tls_certificates.h"
#include "sql.h"
#include "utils.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <glib.h>
#include <gnutls/x509.h> /* for gnutls_x509_crt_... */
#include <math.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <gvm/base/gvm_sentry.h>
#include <gvm/base/hosts.h>
#include <bsd/unistd.h>
#include <gvm/osp/osp.h>
#include <gvm/util/cpeutils.h>
#include <gvm/util/fileutils.h>
#include <gvm/util/serverutils.h>
#include <gvm/util/uuidutils.h>
#include <gvm/util/versionutils.h>
#include <gvm/gmp/gmp.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief CPE selection stylesheet location.
 */
#define CPE_GETBYNAME_XSL GVM_SCAP_RES_DIR "/cpe_getbyname.xsl"

/**
 * @brief CVE selection stylesheet location.
 */
#define CVE_GETBYNAME_XSL GVM_SCAP_RES_DIR "/cve_getbyname.xsl"

/**
 * @brief CERT_BUND_ADV selection stylesheet location.
 */
#define CERT_BUND_ADV_GETBYNAME_XSL GVM_CERT_RES_DIR "/cert_bund_getbyname.xsl"

/**
 * @brief DFN_CERT_ADV selection stylesheet location.
 */
#define DFN_CERT_ADV_GETBYNAME_XSL GVM_CERT_RES_DIR "/dfn_cert_getbyname.xsl"

/**
 * @brief CPE dictionary location.
 */
#define CPE_DICT_FILENAME GVM_SCAP_DATA_DIR "/official-cpe-dictionary_v2.2.xml"

/**
 * @brief CVE data files location format string.
 *
 * %d should be the year expressed as YYYY.
 */
#define CVE_FILENAME_FMT GVM_SCAP_DATA_DIR "/nvdcve-2.0-%d.xml"

/**
 * @brief CERT-Bund data files location format string.
 *
 * %d should be the year without the century (expressed as YY),
 */
#define CERT_BUND_ADV_FILENAME_FMT GVM_CERT_DATA_DIR "/CB-K%02d.xml"

/**
 * @brief DFN-CERT data files location format string.
 *
 * First %d should be the year expressed as YYYY,
 * second %d should be should be Month expressed as MM.
 */
#define DFN_CERT_ADV_FILENAME_FMT GVM_CERT_DATA_DIR "/dfn-cert-%04d.xml"

/**
 * @brief SCAP timestamp location.
 */
#define SCAP_TIMESTAMP_FILENAME GVM_SCAP_DATA_DIR "/timestamp"

/**
 * @brief CERT timestamp location.
 */
#define CERT_TIMESTAMP_FILENAME GVM_CERT_DATA_DIR "/timestamp"

/**
 * @brief Maximum number of reports to process every SCHEDULE_PERIOD.
 */
#define MAX_REPORTS_PER_TICK 10

/**
 * @brief Number of minutes until the authentication cache is deleted
 *        if the session is idle.
 */
static int auth_timeout = 0;

/**
 * @brief Address of the broker used for publish-subscribe messaging (MQTT).
 */
static gchar *broker_address = NULL;

/**
 * @brief Path to the feed lock file
 */
static gchar *feed_lock_path = NULL;

/**
 * @brief Number of seconds to wait for the feed lock to be released.
 */
static int feed_lock_timeout = 0;

/**
 * @brief Maximum number of concurrent scan updates.
 */
static int max_concurrent_scan_updates = 0;

/**
 * @brief Maximum number of database connections.
 */
static int max_database_connections = MAX_DATABASE_CONNECTIONS_DEFAULT;

/**
 * @brief Maximum number of imported reports processed concurrently.
 */
static int max_concurrent_report_processing = MAX_REPORT_PROCESSING_DEFAULT;

/**
 * @brief Retries for waiting for memory to be available.
 */
static int mem_wait_retries = 0;

/**
 * @brief Minimum available memory in MiB for running a feed update.
 */
static int min_mem_feed_update = 0;

/**
 * @brief Path to the relay mapper executable, NULL to disable relays.
 */
static gchar *relay_mapper_path = NULL;

/**
 * @brief Number of minutes before overdue tasks timeout.
 */
static int schedule_timeout = SCHEDULE_TIMEOUT_DEFAULT;

/**
 * @brief Default number of auto retries if scanner connection is
 *        lost in a running task.
 */
static int scanner_connection_retry = SCANNER_CONNECTION_RETRY_DEFAULT;


/* Certificate and key management. */

/**
 * @brief Truncate a certificate, removing extra data.
 *
 * @param[in]  certificate    The certificate.
 *
 * @return  The truncated certificate as a newly allocated string or NULL.
 */
gchar *
truncate_certificate (const gchar* certificate)
{
  GString *cert_buffer;
  gchar *current_pos, *cert_start, *cert_end;
  gboolean done = FALSE;
  cert_buffer = g_string_new ("");

  current_pos = (gchar *) certificate;
  while (done == FALSE && *current_pos != '\0')
    {
      cert_start = NULL;
      cert_end = NULL;
      if (g_str_has_prefix (current_pos,
                            "-----BEGIN CERTIFICATE-----"))
        {
          cert_start = current_pos;
          cert_end = strstr (cert_start,
                             "-----END CERTIFICATE-----");
          if (cert_end)
            cert_end += strlen ("-----END CERTIFICATE-----");
          else
            done = TRUE;
        }
      else if (g_str_has_prefix (current_pos,
                                 "-----BEGIN TRUSTED CERTIFICATE-----"))
        {
          cert_start = current_pos;
          cert_end = strstr (cert_start,
                             "-----END TRUSTED CERTIFICATE-----");
          if (cert_end)
            cert_end += strlen ("-----END TRUSTED CERTIFICATE-----");
          else
            done = TRUE;
        }
      else if (g_str_has_prefix (current_pos,
                                 "-----BEGIN PKCS7-----"))
        {
          cert_start = current_pos;
          cert_end = strstr (cert_start,
                             "-----END PKCS7-----");
          if (cert_end)
            cert_end += strlen ("-----END PKCS7-----");
          else
            done = TRUE;
        }

      if (cert_start && cert_end)
        {
          g_string_append_len (cert_buffer, cert_start, cert_end - cert_start);
          g_string_append_c (cert_buffer, '\n');
        }
      current_pos++;
    }

  return g_string_free (cert_buffer, cert_buffer->len == 0);
}

/**
 * @brief Truncate a private key, removing extra data.
 *
 * @param[in]  private_key    The private key.
 *
 * @return  The truncated private key as a newly allocated string or NULL.
 */
gchar *
truncate_private_key (const gchar* private_key)
{
  gchar *key_start, *key_end;
  key_end = NULL;
  key_start = strstr (private_key, "-----BEGIN RSA PRIVATE KEY-----");
  if (key_start)
    {
      key_end = strstr (key_start, "-----END RSA PRIVATE KEY-----");

      if (key_end)
        key_end += strlen ("-----END RSA PRIVATE KEY-----");
      else
        return NULL;
    }

  if (key_start == NULL)
    {
      key_start = strstr (private_key, "-----BEGIN DSA PRIVATE KEY-----");
      if (key_start)
        {
          key_end = strstr (key_start, "-----END DSA PRIVATE KEY-----");

          if (key_end)
            key_end += strlen ("-----END DSA PRIVATE KEY-----");
          else
            return NULL;
        }
    }

  if (key_start == NULL)
    {
      key_start = strstr (private_key, "-----BEGIN EC PRIVATE KEY-----");
      if (key_start)
        {
          key_end = strstr (key_start, "-----END EC PRIVATE KEY-----");

          if (key_end)
            key_end += strlen ("-----END EC PRIVATE KEY-----");
          else
            return NULL;
        }
    }

  if (key_start == NULL)
    {
      key_start = strstr (private_key, "-----BEGIN OPENSSH PRIVATE KEY-----");
      if (key_start)
        {
          key_end = strstr (key_start, "-----END OPENSSH PRIVATE KEY-----");

          if (key_end)
            key_end += strlen ("-----END OPENSSH PRIVATE KEY-----");
          else
            return NULL;
        }
    }

  if (key_end && key_end[0] == '\n')
    key_end++;

  if (key_start == NULL || key_end == NULL)
    return NULL;
  else
    return g_strndup (key_start, key_end - key_start);
}

/**
 * @brief Gathers info from a certificate.
 *
 * @param[in]  certificate        The certificate to get data from.
 * @param[in]  certificate_len    Length of certificate, -1: null-terminated
 * @param[in]  escape_dns         Whether to escape control characters in DNs.
 * @param[out] activation_time    Pointer to write activation time to.
 * @param[out] expiration_time    Pointer to write expiration time to.
 * @param[out] md5_fingerprint    Pointer for newly allocated MD5 fingerprint.
 * @param[out] sha256_fingerprint Pointer for newly allocated SHA-256
 *                                fingerprint.
 * @param[out] subject            Pointer for newly allocated subject DN.
 * @param[out] issuer             Pointer for newly allocated issuer DN.
 * @param[out] serial             Pointer for newly allocated serial.
 * @param[out] certificate_format Pointer to certificate format.
 *
 * @return 0 success, -1 error.
 */
int
get_certificate_info (const gchar* certificate, gssize certificate_len,
                      gboolean escape_dns,
                      time_t* activation_time, time_t* expiration_time,
                      gchar** md5_fingerprint, gchar **sha256_fingerprint,
                      gchar **subject, gchar** issuer, gchar **serial,
                      gnutls_x509_crt_fmt_t *certificate_format)
{
  gchar *cert_truncated;
  gnutls_x509_crt_fmt_t certificate_format_internal;

  cert_truncated = NULL;
  if (activation_time)
    *activation_time = -1;
  if (expiration_time)
    *expiration_time = -1;
  if (md5_fingerprint)
    *md5_fingerprint = NULL;
  if (sha256_fingerprint)
    *sha256_fingerprint = NULL;
  if (subject)
    *subject = NULL;
  if (issuer)
    *issuer = NULL;
  if (serial)
    *serial = NULL;
  if (certificate_format)
    *certificate_format = GNUTLS_X509_FMT_DER;

  if (certificate)
    {
      int err;
      gnutls_datum_t cert_datum;
      gnutls_x509_crt_t gnutls_cert;
      static const gchar* begin_str = "-----BEGIN ";

      if (g_strstr_len (certificate, certificate_len, begin_str))
        {
          cert_truncated = truncate_certificate (certificate);
          if (cert_truncated == NULL)
            {
              return -1;
            }
          certificate_format_internal = GNUTLS_X509_FMT_PEM;
        }
      else
        {
          if (certificate_len < 0)
            {
              g_warning ("%s: PEM encoded certificate expected if"
                         " certificate_length is negative",
                         __func__);
              return -1;
            }

#if GLIB_CHECK_VERSION(2, 68, 0)
          cert_truncated = g_memdup2 (certificate, certificate_len);
#else
          cert_truncated = g_memdup (certificate, certificate_len);
#endif
          certificate_format_internal = GNUTLS_X509_FMT_DER;
        }

      cert_datum.data = (unsigned char*) cert_truncated;
      if (certificate_len < 0)
        cert_datum.size = strlen (cert_truncated);
      else
        cert_datum.size = certificate_len;

      gnutls_x509_crt_init (&gnutls_cert);
      err = gnutls_x509_crt_import (gnutls_cert, &cert_datum,
                                    certificate_format_internal);
      if (err)
        {
          g_free (cert_truncated);
          return -1;
        }

      if (certificate_format)
        *certificate_format = certificate_format_internal;

      if (activation_time)
        {
          *activation_time
            = gnutls_x509_crt_get_activation_time (gnutls_cert);
        }

      if (expiration_time)
        {
          *expiration_time
            = gnutls_x509_crt_get_expiration_time (gnutls_cert);
        }

      if (md5_fingerprint)
        {
          int i;
          size_t buffer_size = 16;
          unsigned char buffer[buffer_size];
          GString *string;

          string = g_string_new ("");

          gnutls_x509_crt_get_fingerprint (gnutls_cert, GNUTLS_DIG_MD5,
                                           buffer, &buffer_size);

          for (i = 0; i < buffer_size; i++)
            {
              if (i != 0)
                {
                  g_string_append_c (string, ':');
                }
              g_string_append_printf (string, "%02x", buffer[i]);
            }

          *md5_fingerprint = g_string_free (string, FALSE);
        }

      if (sha256_fingerprint)
        {
          int i;
          size_t buffer_size = 32;
          unsigned char buffer[buffer_size];
          GString *string;

          string = g_string_new ("");

          gnutls_x509_crt_get_fingerprint (gnutls_cert, GNUTLS_DIG_SHA256,
                                           buffer, &buffer_size);

          for (i = 0; i < buffer_size; i++)
            {
              g_string_append_printf (string, "%02X", buffer[i]);
            }

          *sha256_fingerprint = g_string_free (string, FALSE);
        }

      if (subject)
        {
          size_t buffer_size = 0;
          gchar *buffer;
          gnutls_x509_crt_get_dn (gnutls_cert, NULL, &buffer_size);
          buffer = g_malloc (buffer_size);
          if (gnutls_x509_crt_get_dn (gnutls_cert, buffer, &buffer_size))
            {
              *subject = g_strdup ("");
              g_free (buffer);
            }
          else if (escape_dns)
            {
              *subject = strescape_check_utf8 (buffer, NULL);
              g_free (buffer);
            }
          else
            *subject = buffer;
        }

      if (issuer)
        {
          size_t buffer_size = 0;
          gchar *buffer;
          gnutls_x509_crt_get_issuer_dn (gnutls_cert, NULL, &buffer_size);
          buffer = g_malloc (buffer_size);
          if (gnutls_x509_crt_get_issuer_dn (gnutls_cert, buffer, &buffer_size))
            {
              *issuer = g_strdup ("");
              g_free (buffer);
            }
          else if (escape_dns)
            {
              *issuer = strescape_check_utf8 (buffer, NULL);
              g_free (buffer);
            }
          else
            *issuer = buffer;
        }

      if (serial)
        {
          int i;
          size_t buffer_size = 0;
          unsigned char *buffer;
          GString *string;

          string = g_string_new ("");

          gnutls_x509_crt_get_serial (gnutls_cert, NULL, &buffer_size);
          buffer = g_malloc (buffer_size);
          gnutls_x509_crt_get_serial (gnutls_cert, buffer, &buffer_size);

          for (i = 0; i < buffer_size; i++)
            {
              g_string_append_printf (string, "%02X", buffer[i]);
            }

          *serial = g_string_free (string, FALSE);
        }

      gnutls_x509_crt_deinit (gnutls_cert);
      g_free (cert_truncated);
    }
  return 0;
}

/**
 * @brief Converts a certificate time to an ISO time string.
 *
 * @param[in] time  The time as a time_t.
 *
 * @return Newly allocated string.
 */
gchar *
certificate_iso_time (time_t time)
{
  if (time == 0)
    return g_strdup ("unlimited");
  else if (time == -1)
    return g_strdup ("unknown");
  else
    return g_strdup (iso_time (&time));
}

/**
 * @brief Tests the activation and expiration time of a certificate.
 *
 * @param[in] activates  Activation time.
 * @param[in] expires    Expiration time.
 *
 * @return Static status string.
 */
const gchar *
certificate_time_status (time_t activates, time_t expires)
{
  time_t now;
  time (&now);

  if (activates == -1 || expires == -1)
    return "unknown";
  else if (activates > now)
    return "inactive";
  else if (expires != 0 && expires < now)
    return "expired";
  else
    return "valid";
}


/* Helpers. */

/**
 * @brief Truncates text to a maximum length, optionally appends a suffix.
 *
 * Note: The string is modified in place instead of allocating a new one.
 * With the xml option the function will avoid cutting the string in the middle
 *  of XML entities, but element tags will be ignored.
 *
 * @param[in,out] string   The string to truncate.
 * @param[in]     max_len  The maximum length in bytes.
 * @param[in]     xml      Whether to preserve XML entities.
 * @param[in]     suffix   The suffix to append when the string is shortened.
 */
static void
truncate_text (gchar *string, size_t max_len, gboolean xml, const char *suffix)
{
  if (string == NULL)
    return;

  if (strlen (string) <= max_len)
    return;
  else
    {
      size_t offset;
      offset = max_len;

      // Move offset according according to suffix length
      if (suffix && strlen (suffix) < max_len)
        offset = offset - strlen (suffix);

      // Go back to start of UTF-8 character
      if (offset > 0 && (string[offset] & 0x80) == 0x80)
        {
          offset = g_utf8_find_prev_char (string, string + offset) - string;
        }

      if (xml)
        {
          // If the offset is in the middle of an XML entity,
          //  move the offset to the start of that entity.
          ssize_t entity_start_offset = offset;

          while (entity_start_offset >= 0
                 && string[entity_start_offset] != '&')
            {
              entity_start_offset --;
            }

          if (entity_start_offset >= 0)
            {
              char *entity_end = strchr(string + entity_start_offset, ';');
              if (entity_end && (entity_end - string) >= offset)
                offset = entity_start_offset;
            }
        }

      // Truncate the string, inserting the suffix if applicable
      if (suffix && strlen (suffix) < max_len)
        sprintf (string + offset, "%s", suffix);
      else
        string[offset] = '\0';
    }
}

/**
 * @brief XML escapes text truncating to a maximum length with a suffix.
 *
 * Note: The function will avoid cutting the string in the middle of XML
 *  entities.
 *
 * @param[in]  string   The string to truncate.
 * @param[in]  max_len  The maximum length in bytes.
 * @param[in]  suffix   The suffix to append when the string is shortened.
 *
 * @return Newly allocated string with XML escaped, truncated text.
 */
gchar *
xml_escape_text_truncated (const char *string, size_t max_len,
                           const char *suffix)
{
  gchar *escaped;
  gssize orig_len;

  orig_len = strlen (string);
  if (orig_len <= max_len)
    escaped = g_markup_escape_text (string, -1);
  else
    {
      gchar *offset_next;
      ssize_t offset;

      offset_next = g_utf8_find_next_char (string + max_len,
                                           string + orig_len);
      offset = offset_next - string;
      escaped = g_markup_escape_text (string, offset);
    }

  truncate_text (escaped, max_len, TRUE, suffix);
  return escaped;
}

/**
 * @brief Check whether a resource is available.
 *
 * @param[in]   type        Type.
 * @param[out]  resource    Resource.
 * @param[out]  permission  Permission required for this operation.
 *
 * @return 0 success, -1 error, 99 permission denied.
 */
static int
check_available (const gchar *type, resource_t resource,
                 const gchar *permission)
{
  if (resource)
    {
      gchar *uuid;
      resource_t found;

      uuid = resource_uuid (type, resource);
      if (find_resource_with_permission (type, uuid, &found, permission, 0))
        {
          g_free (uuid);
          return -1;
        }
      g_free (uuid);
      if (found == 0)
        return 99;

      return 0;
    }

  return -1;
}

/**
 * @brief Check if a scanner type is valid.
 *
 * @param[in]  scanner_type  Scanner type.
 *
 * @return 1 if valid, else 0.
 */
int
scanner_type_valid (scanner_type_t scanner_type)
{
  if (scanner_type > SCANNER_TYPE_NONE
      && scanner_type < SCANNER_TYPE_MAX
      && scanner_type != 4
      && scanner_type != 1)
    return 1;
  return 0;
}

/**
 * @brief Check if required feature for a scanner type is enabled.
 *
 * @param scanner_type  Scanner type.
 *
 * @return SCANNER_FEATURE_OK
 *         if no feature is required, or the required feature is enabled.
 *
 *         Otherwise, the value indicating that the feature required
 *         for the given scanner type is disabled.
 */
scanner_feature_status_t
check_scanner_feature (scanner_type_t scanner_type)
{
  if (scanner_type == SCANNER_TYPE_OPENVASD
      || scanner_type == SCANNER_TYPE_OPENVASD_SENSOR)
    {
      if (!feature_enabled (FEATURE_ID_OPENVASD_SCANNER))
        return SCANNER_FEATURE_OPENVASD_DISABLED;
      return SCANNER_FEATURE_OK;
    }

  if (scanner_type == SCANNER_TYPE_AGENT_CONTROLLER
      || scanner_type == SCANNER_TYPE_AGENT_CONTROLLER_SENSOR)
    {
      if (!feature_enabled (FEATURE_ID_AGENTS))
        return SCANNER_FEATURE_AGENTS_DISABLED;
      return SCANNER_FEATURE_OK;
    }

  if (scanner_type == SCANNER_TYPE_CONTAINER_IMAGE)
    {
      if (!feature_enabled (FEATURE_ID_CONTAINER_SCANNING))
        return SCANNER_FEATURE_CONTAINER_DISABLED;
      return SCANNER_FEATURE_OK;
    }

  return SCANNER_FEATURE_OK;
}

/**
 * @brief Check if a scanner type supports UNIX sockets.
 *
 * @param[in]  scanner_type  Scanner type.
 *
 * @return 1 if unix sockets are supported, else 0.
 */
int
scanner_type_supports_unix_sockets (scanner_type_t scanner_type)
{
  if (scanner_type == SCANNER_TYPE_OPENVAS
      || scanner_type == SCANNER_TYPE_OSP_SENSOR)
    return 1;
  return 0;
}

/**
 * @brief Gets the type of a scanner given its uuid.
 *
 * @param[in]  scanner_id  UUID of the scanner
 *
 * @return The scanner type or SCANNER_TYPE_NONE if scanner could not be found.
 */
scanner_type_t
get_scanner_type_by_uuid (const char *scanner_id)
{
  scanner_t scanner;
  if (scanner_id == NULL)
    return SCANNER_TYPE_NONE;
  if (find_resource_no_acl ("scanner", scanner_id, &scanner))
    {
      g_warning ("%s: Error finding scanner %s", __func__, scanner_id);
      return SCANNER_TYPE_NONE;
    }
  return get_scanner_type (scanner);
}


/* Severity related functions. */

/**
 * @brief Get the message type of a threat.
 *
 * @param  threat  Threat.
 *
 * @return Static message type name if threat names a threat, else NULL.
 */
const char *
threat_message_type (const char *threat)
{
  if (strcasecmp (threat, "Critical") == 0)
    return "Alarm";
  if (strcasecmp (threat, "High") == 0)
    return "Alarm";
  if (strcasecmp (threat, "Medium") == 0)
    return "Alarm";
  if (strcasecmp (threat, "Low") == 0)
    return "Alarm";
  if (strcasecmp (threat, "Log") == 0)
    return "Log Message";
  if (strcasecmp (threat, "Error") == 0)
    return "Error Message";
  if (strcasecmp (threat, "False Positive") == 0)
    return "False Positive";
  return NULL;
}

/**
 * @brief Check whether a severity falls within a threat level.
 *
 * @param[in]  severity  Severity.
 * @param[in]  level     Threat level.
 *
 * @return 1 if in level, else 0.
 */
int
severity_in_level (double severity, const char *level)
{
  if (strcmp (level, "critical") == 0)
    return severity >= 9 && severity <= 10;
  else if (strcmp (level, "high") == 0)
    return severity >= 7 && severity < 9;
  else if (strcmp (level, "medium") == 0)
    return severity >= 4 && severity < 7;
  else if (strcmp (level, "low") == 0)
    return severity > 0 && severity < 4;
  else if (strcmp (level, "none") == 0  || strcmp (level, "log") == 0)
    return severity == 0;

  return 0;
}

/**
 * @brief Get the threat level matching a severity score.
 *
 * @param[in] severity  severity score
 * @param[in] mode      0 for normal levels, 1 to use "Alarm" for severity > 0.0
 *
 * @return the level as a static string
 */
const char*
severity_to_level (double severity, int mode)
{
  if (severity == SEVERITY_LOG)
    return "Log";
  else if (severity == SEVERITY_FP)
    return "False Positive";
  else if (severity == SEVERITY_ERROR)
    return "Error";
  else if (severity > 0.0 && severity <= 10.0)
    {
      if (mode == 1)
        return "Alarm";
      else if (severity_in_level (severity, "critical"))
        return "Critical";
      else if (severity_in_level (severity, "high"))
        return "High";
      else if (severity_in_level (severity, "medium"))
        return "Medium";
      else if (severity_in_level (severity, "low"))
        return "Low";
      else
        return "Log";
    }
  else
    {
      g_warning ("%s: Invalid severity score given: %f",
                 __func__, severity);
      return NULL;
    }
}

/**
 * @brief Get the message type matching a severity score.
 *
 * @param[in] severity  severity score
 *
 * @return the message type as a static string
 */
const char*
severity_to_type (double severity)
{
  if (severity == SEVERITY_LOG)
    return "Log Message";
  else if (severity == SEVERITY_FP)
    return "False Positive";
  else if (severity == SEVERITY_ERROR)
    return "Error Message";
  else if (severity > 0.0 && severity <= 10.0)
    return "Alarm";
  else
    {
      g_warning ("%s: Invalid severity score given: %f",
                 __func__, severity);
      return NULL;
    }
}


/* Encryption key management. */

/**
 * @brief Creates a new encryption key and sets it as the new default.
 *
 * @param[in]  log_config  Logging configuration list.
 * @param[in]  database    Connection info for manage database.
 *
 * @return 0 on success, -1 on failure.
 */
int
manage_create_encryption_key (GSList *log_config,
                              const db_conn_info_t *database)
{
  int ret = manage_option_setup (log_config, database,
                                 0 /* avoid_db_check_inserts */);
  if (ret)
    {
      printf ("Error setting up log config or database connection.");
      g_warning ("Error setting up log config or database connection.");
      return -1;
    }

  time_t now = time(NULL);
  gchar *generated_uid
    = g_strdup_printf (ENCRYPTION_KEY_UID_TEMPLATE, iso_time (&now));

  lsc_crypt_ctx_t ctx = lsc_crypt_new (generated_uid);
  switch (lsc_crypt_create_enckey (ctx))
    {
      case 0:
        break;
      case 1:
        printf ("Credential encryption key '%s' already exists\n",
                generated_uid);
        g_warning ("%s: Credential encryption key '%s' already exists",
                 __func__, generated_uid);

        lsc_crypt_flush(ctx);
        g_free (generated_uid);
        manage_option_cleanup ();
        return -1;
      default:
        printf ("Could not create credential encryption key '%s'\n",
                generated_uid);
        g_warning ("%s: Could not create credential encryption key '%s'",
                 __func__, generated_uid);

        lsc_crypt_flush(ctx);
        g_free (generated_uid);
        manage_option_cleanup ();
        return -1;
    }
  set_current_encryption_key_uid (generated_uid);
  printf ("Credential encryption key created: '%s'\n",
          generated_uid);
  g_message ("%s: Credential encryption key created: '%s'",
             __func__, generated_uid);

  lsc_crypt_flush(ctx);
  g_free (generated_uid);
  manage_option_cleanup ();
  return 0;
}

/**
 * @brief Sets the new default encryption key. The key must already exist.
 *
 * @param[in]  log_config  Logging configuration list.
 * @param[in]  database    Connection info for manage database.
 * @param[in]  uid         UID for key.
 *
 * @return 0 on success, -1 on failure.
 */
int
manage_set_encryption_key (GSList *log_config,
                           const db_conn_info_t *database,
                           const char *uid)
{
  int ret = manage_option_setup (log_config, database,
                                 0 /* avoid_db_check_inserts */);
  if (ret)
    {
      printf ("Error setting up log config or database connection.\n");
      g_warning ("Error setting up log config or database connection.");
      return -1;
    }

  lsc_crypt_ctx_t ctx = lsc_crypt_new (uid);
  if (! lsc_crypt_enckey_exists (ctx))
    {
      printf ("Credential encryption key '%s' not found\n", uid);
      g_warning ("%s: Credential encryption key '%s' not found", __func__, uid);
      lsc_crypt_flush(ctx);
      manage_option_cleanup ();
      return -1;
    }

  set_current_encryption_key_uid (uid);
  printf ("Credential encryption key set to '%s'\n", uid);
  g_message ("%s: Credential encryption key set to '%s'", __func__, uid);
  lsc_crypt_flush(ctx);
  manage_option_cleanup ();
  return 0;
}


/* Credentials. */

/**
 * @brief Current credentials during any GMP command.
 */
credentials_t current_credentials;


/* Reports. */

/**
 * @brief Delete all the reports for a task.
 *
 * It's up to the caller to ensure that this runs in a contention safe
 * context (for example within an SQL transaction).
 *
 * @param[in]  task  A task descriptor.
 *
 * @return 0 on success, -1 on error.
 */
int
delete_reports (task_t task)
{
  report_t report;
  iterator_t iterator;
  init_report_iterator_task (&iterator, task);
  while (next_report (&iterator, &report))
    if (delete_report_internal (report))
      {
        cleanup_iterator (&iterator);
        return -1;
      }
  cleanup_iterator (&iterator);
  return 0;
}

/**
 * @brief Create a basic filter term to get report results.
 *
 * @param[in]  first            First row.
 * @param[in]  rows             Number of rows.
 * @param[in]  apply_overrides  Whether to apply overrides.
 * @param[in]  min_qod          Minimum QOD.
 *
 * @return Filter term.
 */
static gchar *
report_results_filter_term (int first, int rows,
                            int apply_overrides, int min_qod)
{
  return g_strdup_printf ("first=%d rows=%d"
                          " apply_overrides=%d min_qod=%d",
                          first, rows, apply_overrides, min_qod);
}


/**
 * @brief Create a new basic get_data_t struct to get report results.
 *
 * @param[in]  first            First row.
 * @param[in]  rows             Number of rows.
 * @param[in]  apply_overrides  Whether to apply overrides.
 * @param[in]  min_qod          Minimum QOD.
 *
 * @return GET data struct.
 */
get_data_t*
report_results_get_data (int first, int rows,
                         int apply_overrides, int min_qod)
{
  get_data_t* get = g_malloc (sizeof (get_data_t));
  memset (get, 0, sizeof (get_data_t));
  get->type = g_strdup ("result");
  get->filter = report_results_filter_term (first, rows,
                                            apply_overrides, min_qod);

  return get;
}

/**
 * @brief Array index of severity 0.0 in the severity_data_t.counts array.
 */
#define ZERO_SEVERITY_INDEX 4

/**
 * @brief Convert a severity value into an index in the counts array.
 *
 * @param[in]   severity        Severity value.
 *
 * @return      The index, 0 for invalid severity scores.
 */
static int
severity_data_index (double severity)
{
  int ret;
  if (severity >= 0.0)
    ret = (int)(round (severity * SEVERITY_SUBDIVISIONS)) + ZERO_SEVERITY_INDEX;
  else if (severity == SEVERITY_FP || severity == SEVERITY_ERROR)
    ret = (int)(round (severity)) + ZERO_SEVERITY_INDEX;
  else
    ret = 0;

  return ret;
}

/**
 * @brief Convert an index in the counts array to a severity value.
 *
 * @param[in]   index   Index in the counts array.
 *
 * @return      The corresponding severity value.
 */
double
severity_data_value (int index)
{
  double ret;
  if (index <= ZERO_SEVERITY_INDEX && index > 0)
    ret = ((double) index) - ZERO_SEVERITY_INDEX;
  else if (index <= (ZERO_SEVERITY_INDEX
                     + (SEVERITY_SUBDIVISIONS * SEVERITY_MAX)))
    ret = (((double) (index - ZERO_SEVERITY_INDEX)) / SEVERITY_SUBDIVISIONS);
  else
    ret = SEVERITY_MISSING;

  return ret;
}

/**
 * @brief Initialize a severity data structure.
 *
 * @param[in] data  The data structure to initialize.
 */
void
init_severity_data (severity_data_t* data)
{
  int max_i;
  max_i = ZERO_SEVERITY_INDEX + (SEVERITY_SUBDIVISIONS * SEVERITY_MAX);

  data->counts = g_malloc0 (sizeof (int) * (max_i + 1));

  data->total = 0;
  data->max = SEVERITY_MISSING;
}

/**
 * @brief Clean up a severity data structure.
 *
 * @param[in] data  The data structure to initialize.
 */
void
cleanup_severity_data (severity_data_t* data)
{
  g_free (data->counts);
}

/**
 * @brief Add a severity occurrence to the counts of a severity_data_t.
 *
 * @param[in]   severity_data   The severity count struct to add to.
 * @param[in]   severity        The severity to add.
 */
void
severity_data_add (severity_data_t* severity_data, double severity)
{
  (severity_data->counts)[severity_data_index (severity)]++;

  if (severity_data->total == 0 || severity_data->max <= severity)
    severity_data->max = severity;

  (severity_data->total)++;
}

/**
 * @brief Add a multiple severity occurrences to the counts of a severity_data_t.
 *
 * @param[in]   severity_data   The severity count struct to add to.
 * @param[in]   severity        The severity to add.
 * @param[in]   count           The number of occurrences to add.
 */
void
severity_data_add_count (severity_data_t* severity_data, double severity,
                         int count)
{
  (severity_data->counts)[severity_data_index (severity)] += count;

  if (severity_data->total == 0 || severity_data->max <= severity)
    severity_data->max = severity;

  (severity_data->total) += count;
}

/**
 * @brief Calculate the total of severity counts in a range.
 *
 * @param[in]  severity_data   The severity data struct to get counts from.
 * @param[in]  min_severity    The minimum severity included in the range.
 * @param[in]  max_severity    The maximum severity included in the range.
 *
 * @return     The total of severity counts in the specified range.
 */
static int
severity_data_range_count (const severity_data_t* severity_data,
                           double min_severity, double max_severity)
{
  int i, i_max, count;

  i_max = severity_data_index (max_severity);
  count = 0;

  for (i = severity_data_index (min_severity);
       i <= i_max;
       i++)
    {
      count += (severity_data->counts)[i];
    }
  return count;
}

/**
 * @brief Count the occurrences of severities in the levels.
 *
 * @param[in] severity_data    The severity counts data to evaluate.
 * @param[out] errors          The number of error messages.
 * @param[out] false_positives The number of False Positives.
 * @param[out] logs            The number of Log messages.
 * @param[out] lows            The number of Low severity results.
 * @param[out] mediums         The number of Medium severity results.
 * @param[out] highs           The number of High severity results.
 * @param[out] criticals       The number of Critical severity results.
 */
void
severity_data_level_counts (const severity_data_t *severity_data,
                            int *errors,
                            int *false_positives,
                            int *logs,
                            int *lows,
                            int *mediums,
                            int *highs,
                            int* criticals
                           )
{
  if (errors)
    *errors
      = severity_data_range_count (severity_data,
                                   level_min_severity ("Error"),
                                   level_max_severity ("Error"));

  if (false_positives)
    *false_positives
      = severity_data_range_count (severity_data,
                                   level_min_severity ("False Positive"),
                                   level_max_severity ("False Positive"));

  if (logs)
    *logs
      = severity_data_range_count (severity_data,
                                   level_min_severity ("Log"),
                                   level_max_severity ("Log"));

  if (lows)
    *lows
      = severity_data_range_count (severity_data,
                                   level_min_severity ("low"),
                                   level_max_severity ("low"));

  if (mediums)
    *mediums
      = severity_data_range_count (severity_data,
                                   level_min_severity ("medium"),
                                   level_max_severity ("medium"));

  if (highs)
    *highs
      = severity_data_range_count (severity_data,
                                   level_min_severity ("high"),
                                   level_max_severity ("high"));

  if (criticals)
    *criticals
      = severity_data_range_count (severity_data,
                                   level_min_severity ("critical"),
                                   level_max_severity ("critical"));
}


/* Task globals. */

/**
 * @brief The task currently running on the scanner.
 */
task_t current_scanner_task = (task_t) 0;

/**
 * @brief The report of the current task.
 */
report_t global_current_report = (report_t) 0;


/* General task facilities. */

/**
 * @brief Get the name of a run status.
 *
 * @param[in]  status  Run status.
 *
 * @return The name of the status (for example, "Done" or "Running").
 */
const char*
run_status_name (task_status_t status)
{
  switch (status)
    {
      case TASK_STATUS_DELETE_REQUESTED:
      case TASK_STATUS_DELETE_WAITING:
        return "Delete Requested";
      case TASK_STATUS_DELETE_ULTIMATE_REQUESTED:
      case TASK_STATUS_DELETE_ULTIMATE_WAITING:
        return "Ultimate Delete Requested";
      case TASK_STATUS_DONE:             return "Done";
      case TASK_STATUS_NEW:              return "New";

      case TASK_STATUS_REQUESTED:        return "Requested";

      case TASK_STATUS_RUNNING:          return "Running";

      case TASK_STATUS_QUEUED:           return "Queued";

      case TASK_STATUS_STOP_REQUESTED:
      case TASK_STATUS_STOP_WAITING:
        return "Stop Requested";

      case TASK_STATUS_STOPPED:          return "Stopped";
      case TASK_STATUS_PROCESSING:       return "Processing";
      default:                           return "Interrupted";
    }
}

/**
 * @brief Get the unique name of a run status.
 *
 * @param[in]  status  Run status.
 *
 * @return The name of the status (for example, "Done" or "Running").
 */
const char*
run_status_name_internal (task_status_t status)
{
  switch (status)
    {
      case TASK_STATUS_DELETE_REQUESTED: return "Delete Requested";
      case TASK_STATUS_DELETE_ULTIMATE_REQUESTED:
        return "Ultimate Delete Requested";
      case TASK_STATUS_DELETE_ULTIMATE_WAITING:
        return "Ultimate Delete Waiting";
      case TASK_STATUS_DELETE_WAITING:   return "Delete Waiting";
      case TASK_STATUS_DONE:             return "Done";
      case TASK_STATUS_NEW:              return "New";

      case TASK_STATUS_REQUESTED:        return "Requested";

      case TASK_STATUS_RUNNING:          return "Running";

      case TASK_STATUS_QUEUED:           return "Queued";

      case TASK_STATUS_STOP_REQUESTED:
        return "Stop Requested";

      case TASK_STATUS_STOP_WAITING:
        return "Stop Waiting";

      case TASK_STATUS_STOPPED:          return "Stopped";
      case TASK_STATUS_PROCESSING:       return "Processing";
      default:                           return "Interrupted";
    }
}

/**
 * @brief Set a task to interrupted.
 *
 * Expects global_current_report to match the task.
 *
 * @param[in]   task     Task
 * @param[in]   message  Message for error result.
 */
void
set_task_interrupted (task_t task, const gchar *message)
{
  set_task_run_status (task, TASK_STATUS_INTERRUPTED);
  if (global_current_report)
    {
      result_t result;
      result = make_result (task, "", "", "", "", "Error Message", message,
                            NULL);
      report_add_result (global_current_report, result);
    }
}


/* OSP tasks. */

/**
 * @brief Fork a child to handle an OSP scan's fetching and inserting.
 *
 * @param[in]   task       The task.
 * @param[in]   target     The target.
 * @param[in]   start_from 0 start from beginning, 1 continue from stopped,
 *                         2 continue if stopped else start from beginning.
 * @param[out]  report_id_return   UUID of the report.
 *
 * @return Parent returns with 0 if success, -1 if failure. Child process
 *         doesn't return and simply exits.
 */
static int
fork_osp_scan_handler (task_t task, target_t target, int start_from,
                       char **report_id_return)
{
  char *report_id = NULL;
  gboolean discovery_scan = FALSE;
  int rc;

  assert (task);
  assert (target);

  if (report_id_return)
    *report_id_return = NULL;

  if (run_osp_scan_get_report (task, start_from, &report_id))
    return -1;

  current_scanner_task = task;
  set_task_run_status (task, TASK_STATUS_REQUESTED);

  switch (fork ())
    {
      case 0:
        init_sentry ();
        break;
      case -1:
        /* Parent, failed to fork. */
        global_current_report = 0;
        g_warning ("%s: Failed to fork: %s",
                   __func__,
                   strerror (errno));
        set_task_interrupted (task,
                              "Error forking scan handler."
                              "  Interrupting scan.");
        set_report_scan_run_status (global_current_report,
                                    TASK_STATUS_INTERRUPTED);
        global_current_report = (report_t) 0;
        current_scanner_task = 0;
        g_free (report_id);
        return -9;
      default:
        /* Parent, successfully forked. */
        global_current_report = 0;
        current_scanner_task = 0;
        if (report_id_return)
          *report_id_return = report_id;
        else
          g_free (report_id);
        return 0;
    }

  /* Child: Re-open DB after fork and periodically check scan progress.
   * If progress == 100%: Parse the report results and other info then exit(0).
   * Else, exit(1) in error cases like connection to scanner failure.
   */
  reinit_manage_process ();
  manage_session_init (current_credentials.uuid);

  if (handle_osp_scan_start (task, target, report_id, start_from, FALSE,
                             &discovery_scan))
    {
      g_free (report_id);
      gvm_close_sentry ();
      exit (-1);
    }

  setproctitle ("OSP: Handling scan %s", report_id);

  rc = handle_osp_scan (task, global_current_report, report_id, 0);
  g_free (report_id);
  rc = handle_osp_scan_end (task, rc, discovery_scan);
  gvm_close_sentry ();
  exit (rc);
}

/**
 * @brief Prepare an OSP scan and add it to the gvmd scan queue.
 *
 * @param[in]   task       The task.
 * @param[in]   start_from 0 start from beginning, 1 continue from stopped,
 *                         2 continue if stopped else start from beginning.
 * @param[out]  report_id_return   UUID of the report.
 *
 * @return 0 on success, -1 on failure.
 */
static int
queue_osp_task (task_t task, int start_from, char **report_id_return)
{
  char *report_id = NULL;
  report_t report = 0;

  if (report_id_return)
    *report_id_return = NULL;

  if (run_osp_scan_get_report (task, start_from, &report_id))
    return -1;

  if (find_resource_no_acl ("report", report_id, &report))
    {
      g_warning ("%s: error getting report '%s'",
                 __func__, report_id);
      g_free (report_id);
      return -1;
    }
  else if (report == 0)
    {
      g_warning ("%s: could not find report '%s'",
                 __func__, report_id);
      g_free (report_id);
      return -1;
    }

  scan_queue_add (report);
  set_task_run_status (task, TASK_STATUS_REQUESTED);
  set_report_scan_run_status (report, TASK_STATUS_REQUESTED);
  g_debug ("%s: report %s (%llu) added to scan queue",
           __func__, report_id, report);
  g_free (report_id);
  return 0;
}

/**
 * @brief Start a task on an OSP or OpenVAS via OSP scanner.
 *
 * @param[in]   task       The task.
 * @param[in]   from       0 start from beginning, 1 continue from stopped,
 *                         2 continue if stopped else start from beginning.
 * @param[out]  report_id  The report ID.
 *
 * @return 0 success, 99 permission denied, -1 error.
 */
static int
run_osp_task (task_t task, int from, char **report_id)
{
  target_t target;

  target = task_target (task);
  if (target)
    {
      char *uuid;
      target_t found;

      uuid = target_uuid (target);
      if (find_target_with_permission (uuid, &found, "get_targets"))
        {
          g_free (uuid);
          return -1;
        }
      g_free (uuid);
      if (found == 0)
        return 99;
    }

  if (get_use_scan_queue ())
    {
      if (queue_osp_task (task, from, report_id))
        {
          g_warning ("Couldn't queue OSP scan");
          return -1;
        }
    }
  else
    {
      if (fork_osp_scan_handler (task, target, from, report_id))
        {
          g_warning ("Couldn't fork OSP scan handler");
          return -1;
        }
    }

  return 0;
}

/**
 * @brief Get the number of retries on a scanner connection lost.
 *
 * @return The number of retries on a scanner connection lost.
 */
int
get_scanner_connection_retry ()
{
  return scanner_connection_retry;
}

/**
 * @brief Set the number of retries on a scanner connection lost.
 *
 * @param new_retry The number of retries on a scanner connection lost.
 */
void
set_scanner_connection_retry (int new_retry)
{
  if (new_retry >= 0)
    scanner_connection_retry = new_retry;
}


/* CVE tasks. */

/**
 * @brief Check if version is in a given range.
 *
 * @param  target      Target version.
 * @param  start_incl  Start of range (inclusive), or NULL.
 * @param  start_excl  Start of range (exclusive), or NULL.
 * @param  end_incl    End of range (inclusive), or NULL.
 * @param  end_excl    End of range (exclusive), or NULL.
 *
 * @return 0 target is within given range, 1 target is outside given range,
 *         -1 result is undefined.
 */
static int
check_version (const gchar *target, const gchar *start_incl, const gchar *start_excl, const gchar *end_incl, const gchar *end_excl)
{
  int result;

  if (start_incl != NULL)
    {
      result = cmp_versions (start_incl, target);
      if (result == -5)
        return -1;
      if (result > 0)
        {
          return 0;
        }
    }
  if (start_excl != NULL)
    {
      result = cmp_versions (start_excl, target);
      if (result == -5)
        return -1;
      if (result >= 0)
        {
          return 0;
        }
    }

  if (end_incl != NULL)
    {
      result = cmp_versions (end_incl, target);
      if (result == -5)
        return -1;
      if (result < 0)
        {
          return 0;
        }
    }

  if (end_excl != NULL)
    {
      result = cmp_versions (end_excl, target);
      if (result == -5)
        return -1;
      if (result <= 0)
        {
          return 0;
        }
    }

  return (1);
}

/**
 * @brief Check CPE rule match.
 *
 * @param[in]  node         CPE match node.
 * @param[out] match        TRUE if matched.
 * @param[out] vulnerable   TRUE if vulnerable.
 * @param[in]  report_host  Report host to get CPEs from.
 * @param[in]  host_cpe     CPE being checked.
 */
static void
check_cpe_match_rule (long long int node, gboolean *match, gboolean *vulnerable, report_host_t report_host, const char *host_cpe)
{
  iterator_t cpe_match_node_childs;
  gchar *operator;
  iterator_t cpe_match_ranges;

  operator = sql_string ("SELECT operator FROM scap.cpe_match_nodes WHERE id = %llu", node);
  init_cpe_match_node_childs_iterator (&cpe_match_node_childs, node);
  while (next (&cpe_match_node_childs))
    {
      long long int child_node;
      child_node = cpe_match_node_childs_iterator_id (&cpe_match_node_childs);
      check_cpe_match_rule (child_node, match, vulnerable, report_host, host_cpe);
      if (strcmp (operator, "AND") == 0 && !(*match))
        return;
      if (strcmp (operator, "OR") == 0 && (*match) && (*vulnerable))
        return;
    }

  init_cpe_match_string_iterator (&cpe_match_ranges, node);
  while (next (&cpe_match_ranges))
    {
      iterator_t cpe_host_details_products;
      gchar *range_uri_cpe;
      gchar *range_uri_product;
      gchar *vsi, *vse, *vei, *vee;
      range_uri_cpe = vsi = vse = vei = vee = NULL;
      range_uri_cpe = g_strdup (cpe_match_string_iterator_criteria (&cpe_match_ranges));
      vsi = g_strdup (cpe_match_string_iterator_version_start_incl (&cpe_match_ranges));
      vse = g_strdup (cpe_match_string_iterator_version_start_excl (&cpe_match_ranges));
      vei = g_strdup (cpe_match_string_iterator_version_end_incl (&cpe_match_ranges));
      vee = g_strdup (cpe_match_string_iterator_version_end_excl (&cpe_match_ranges));
      range_uri_product = uri_cpe_to_uri_product (range_uri_cpe);
      init_host_details_cpe_product_iterator (&cpe_host_details_products, range_uri_product, report_host);
      while (next (&cpe_host_details_products))
        {
          cpe_struct_t source, target;
          const char *host_details_cpe;
          gboolean matches;
          host_details_cpe = host_details_cpe_product_iterator_value (&cpe_host_details_products);
          cpe_struct_init (&source);
          cpe_struct_init (&target);
          uri_cpe_to_cpe_struct (range_uri_cpe, &source);
          uri_cpe_to_cpe_struct (host_details_cpe, &target);
          matches = cpe_struct_match (&source, &target);
          if (matches)
            {
              int result;
              result = check_version (target.version, vsi, vse, vei, vee);
              if (result == 1)
                *match = TRUE;
            }
          cpe_struct_free (&source);
          cpe_struct_free (&target);
        }
      if (*match && cpe_match_string_iterator_vulnerable (&cpe_match_ranges) == 1)
        {
          cpe_struct_t source, target;
          cpe_struct_init (&source);
          cpe_struct_init (&target);
          uri_cpe_to_cpe_struct (range_uri_cpe, &source);
          uri_cpe_to_cpe_struct (host_cpe, &target);
          if (cpe_struct_match (&source, &target))
            *vulnerable = TRUE;
          cpe_struct_free (&source);
          cpe_struct_free (&target);
        }
      g_free (range_uri_product);
      g_free (range_uri_cpe);
      g_free (vsi);
      g_free (vse);
      g_free (vei);
      g_free (vee);
      if (strcmp (operator, "AND") == 0 && !(*match))
        return;
      if (strcmp (operator, "OR") == 0 && (*match) && (*vulnerable))
        return;
    }
}

/**
 * @brief Perform the json CVE "scan" for the found report host.
 *
 * @param[in]  task        Task.
 * @param[in]  report      The report to add the host, results and details to.
 * @param[in]  report_host The report host.
 * @param[in]  ip          The ip of the report host.
 * @param[in]  start_time  The start time of the scan.
 *
 * @param[out] prognosis_report_host  The report_host with prognosis results
 *                                    and host details.
 * @param[out] results                The results of the scan.
 */
static void
cve_scan_report_host_json (task_t task,
                           report_t report,
                           report_host_t report_host,
                           gchar *ip,
                           int start_time,
                           int *prognosis_report_host,
                           GArray *results)
{
  iterator_t host_details_cpe;
  init_host_details_cpe_iterator (&host_details_cpe, report_host);
  while (next (&host_details_cpe))
    {
      iterator_t cpe_match_root_node;
      iterator_t locations_iter;
      result_t result;
      char *cpe_product;
      const char *host_cpe;
      double severity;

      host_cpe = host_details_cpe_iterator_cpe (&host_details_cpe);
      cpe_product = uri_cpe_to_uri_product (host_cpe);
      init_cpe_match_nodes_iterator (&cpe_match_root_node, cpe_product);
      while (next (&cpe_match_root_node))
        {
          result_t root_node;
          gboolean match, vulnerable;
          const char *app, *cve;

          vulnerable = FALSE;
          match = FALSE;
          root_node = cpe_match_nodes_iterator_root_id (&cpe_match_root_node);
          check_cpe_match_rule (root_node, &match, &vulnerable, report_host, host_cpe);
          if (match && vulnerable)
            {
              GString *locations;
              gchar *desc;

              if (*prognosis_report_host == 0)
                *prognosis_report_host = manage_report_host_add (report,
                                                                 ip,
                                                                 start_time,
                                                                 0);

              severity = sql_double ("SELECT severity FROM scap.cves, scap.cpe_match_nodes"
                                     " WHERE scap.cves.id = scap.cpe_match_nodes.cve_id"
                                     " AND scap.cpe_match_nodes.id = %llu;",
                                     root_node);

              app = host_cpe;
              cve = sql_string ("SELECT name FROM scap.cves, scap.cpe_match_nodes"
                                " WHERE scap.cves.id = cpe_match_nodes.cve_id"
                                " AND scap.cpe_match_nodes.id = %llu;",
                                root_node);
              locations = g_string_new ("");

              insert_report_host_detail (global_current_report, ip, "cve", cve,
                                         "CVE Scanner", "App", app, NULL);

              init_app_locations_iterator (&locations_iter, report_host, app);

              while (next (&locations_iter))
                {
                  const char *location;
                  location = app_locations_iterator_location (&locations_iter);

                  if (location == NULL)
                    {
                      g_warning ("%s: Location is null for ip %s, app %s",
                                 __func__, ip, app);
                      continue;
                    }

                  if (locations->len)
                    {
                      g_string_append (locations, ", ");
                    }
                  g_string_append (locations, location);

                  insert_report_host_detail (report, ip, "cve", cve,
                                             "CVE Scanner", app, location, NULL);

                  insert_report_host_detail (report, ip, "cve", cve,
                                             "CVE Scanner", "detected_at",
                                             location, NULL);

                  insert_report_host_detail (report, ip, "cve", cve,
                                             "CVE Scanner", "detected_by",
                                             /* Detected by itself. */
                                             cve, NULL);
                }

              const char *description;
              description = sql_string ("SELECT description FROM scap.cves, scap.cpe_match_nodes"
                                        " WHERE scap.cves.id = scap.cpe_match_nodes.cve_id"
                                        " AND scap.cpe_match_nodes.id = %llu;",
                                        root_node);

              desc = g_strdup_printf ("The host carries the product: %s\n"
                                      "It is vulnerable according to: %s.\n"
                                      "%s%s%s"
                                      "\n"
                                      "%s",
                                      app,
                                      cve,
                                      locations->len
                                       ? "The product was found at: "
                                       : "",
                                      locations->len ? locations->str : "",
                                      locations->len ? ".\n" : "",
                                      description);

              g_debug ("%s: making result with severity %1.1f desc [%s]",
                       __func__, severity, desc);

              result = make_cve_result (task, ip, cve, severity, desc);
              g_free (desc);

              g_array_append_val (results, result);

              g_string_free (locations, TRUE);

            }
        }
      g_free (cpe_product);
    }
  cleanup_iterator (&host_details_cpe);
}

/**
 * @brief Perform a CVE "scan" on a host.
 *
 * @param[in]  task      Task.
 * @param[in]  report    The report to add the host, results and details to.
 * @param[in]  gvm_host  Host.
 * @param[in]  matching_version  The CPE-CVE matching version (0 or 1) to use.
 *
 * With version 0 matching, CPEs are only compared to the affected products
 *  lists of CVEs.
 * With version 1 matching, CPEs are matched by evaluating the match criteria
 *  for the CVEs.
 *
 * @return 0 success, 1 failed to get nthlast report for a host.
 */
static int
cve_scan_host (task_t task, report_t report, gvm_host_t *gvm_host,
               int matching_version)
{
  report_host_t report_host;
  gchar *ip, *host;

  assert (task);
  assert (report);

  host = gvm_host_value_str (gvm_host);

  ip = report_host_ip (host);
  if (ip == NULL)
    ip = g_strdup (host);

  g_debug ("%s: ip: %s", __func__, ip);

  /* Get the last report host that applies to the host IP address. */

  if (host_nthlast_report_host (ip, &report_host, 1))
    {
      g_warning ("%s: Failed to get nthlast report", __func__);
      g_free (ip);
      return 1;
    }

  g_debug ("%s: report_host: %llu", __func__, report_host);

  if (report_host)
    {
      iterator_t report_hosts;

      /* Get the report_host for the host. */

      init_report_host_iterator (&report_hosts, 0, NULL, report_host);
      if (next (&report_hosts))
        {
          iterator_t prognosis;
          int prognosis_report_host, start_time;
          GArray *results;

          /* Add report_host with prognosis results and host details. */

          results = g_array_new (TRUE, TRUE, sizeof (result_t));
          start_time = time (NULL);
          prognosis_report_host = 0;

          if (matching_version == 1 &&
              sql_int64_0 ("SELECT count(1) FROM information_schema.tables"
                           " WHERE table_schema = 'scap'"
                           " AND table_name = 'cpe_match_nodes';") > 0)
            {
              // Use new JSON CVE scan
              cve_scan_report_host_json (task, report, report_host, ip,
                                         start_time, &prognosis_report_host,
                                         results);
            }
          else
            {
              // Use XML CVE scan
              init_host_prognosis_iterator (&prognosis, report_host);
              while (next (&prognosis))
                {
                  const char *app, *cve;
                  double severity;
                  gchar *desc;
                  iterator_t locations_iter;
                  GString *locations;
                  result_t result;

                  if (prognosis_report_host == 0)
                    prognosis_report_host = manage_report_host_add (report,
                                                                    ip,
                                                                    start_time,
                                                                    0);

                  severity = prognosis_iterator_cvss_double (&prognosis);

                  app = prognosis_iterator_cpe (&prognosis);
                  cve = prognosis_iterator_cve (&prognosis);
                  locations = g_string_new("");

                  insert_report_host_detail (global_current_report, ip, "cve", cve,
                                             "CVE Scanner", "App", app, NULL);

                  init_app_locations_iterator (&locations_iter, report_host, app);

                  while (next (&locations_iter))
                    {
                      const char *location;
                      location = app_locations_iterator_location (&locations_iter);

                      if (location == NULL)
                        {
                          g_warning ("%s: Location is null for ip %s, app %s",
                                     __func__, ip, app);
                          continue;
                        }

                      if (locations->len)
                        g_string_append (locations, ", ");
                      g_string_append (locations, location);

                      insert_report_host_detail (report, ip, "cve", cve,
                                                 "CVE Scanner", app, location, NULL);

                      insert_report_host_detail (report, ip, "cve", cve,
                                                 "CVE Scanner", "detected_at",
                                                 location, NULL);

                      insert_report_host_detail (report, ip, "cve", cve,
                                                 "CVE Scanner", "detected_by",
                                                 /* Detected by itself. */
                                                 cve, NULL);
                    }

                  desc = g_strdup_printf ("The host carries the product: %s\n"
                                          "It is vulnerable according to: %s.\n"
                                          "%s%s%s"
                                          "\n"
                                          "%s",
                                          app,
                                          cve,
                                          locations->len
                                           ? "The product was found at: "
                                           : "",
                                          locations->len ? locations->str : "",
                                          locations->len ? ".\n" : "",
                                          prognosis_iterator_description
                                           (&prognosis));

                  g_debug ("%s: making result with severity %1.1f desc [%s]",
                           __func__, severity, desc);

                  result = make_cve_result (task, ip, cve, severity, desc);
                  g_free (desc);

                  g_array_append_val (results, result);

                  g_string_free (locations, TRUE);
                }
              cleanup_iterator (&prognosis);
            }
          report_add_results_array (report, results);
          g_array_free (results, TRUE);

          if (prognosis_report_host)
            {
              gchar *hostname, *best;

              /* Complete the report_host. */

              report_host_set_end_time (prognosis_report_host, time (NULL));

              hostname = report_host_hostname (report_host);
              if (hostname) {
                insert_report_host_detail (report, ip, "cve", "",
                                           "CVE Scanner", "hostname", hostname,
                                           NULL);
                g_free(hostname);
              }

              best = report_host_best_os_cpe (report_host);
              if (best) {
                insert_report_host_detail (report, ip, "cve", "",
                                           "CVE Scanner", "best_os_cpe", best,
                                           NULL);
                g_free(best);
              }

              best = report_host_best_os_txt (report_host);
              if (best) {
                insert_report_host_detail (report, ip, "cve", "",
                                           "CVE Scanner", "best_os_txt", best,
                                           NULL);
                g_free(best);
              }

              insert_report_host_detail (report, ip, "cve", "",
                                         "CVE Scanner", "CVE Scan", "1", NULL);
              update_report_modification_time (report);
            }
        }
      cleanup_iterator (&report_hosts);
    }

  g_free (ip);
  return 0;
}

/**
 * @brief Fork a child to handle a CVE scan's calculating and inserting.
 *
 * A process is forked to run the task, but the forked process never returns.
 *
 * @param[in]   task        The task.
 * @param[in]   target      The target.
 *
 * @return 0 success, -1 error, -9 failed to fork.
 */
static int
fork_cve_scan_handler (task_t task, target_t target)
{
  int pid;
  char *report_id, *hosts, *exclude_hosts;
  gvm_hosts_t *gvm_hosts;
  gvm_host_t *gvm_host;

  assert (task);
  assert (target);

  if (create_current_report (task, &report_id, TASK_STATUS_REQUESTED))
    {
      g_debug ("   %s: failed to create report", __func__);
      return -1;
    }

  set_task_run_status (task, TASK_STATUS_REQUESTED);

  pid = fork ();
  switch (pid)
    {
      case 0:
        init_sentry ();
        break;
      case -1:
        /* Parent, failed to fork. */
        g_warning ("%s: Failed to fork: %s",
                   __func__,
                   strerror (errno));
        set_task_interrupted (task,
                              "Error forking scan handler."
                              "  Interrupting scan.");
        set_report_scan_run_status (global_current_report,
                                    TASK_STATUS_INTERRUPTED);
        global_current_report = (report_t) 0;
        current_scanner_task = 0;
        return -9;
      default:
        /* Parent, successfully forked. */
        global_current_report = 0;
        current_scanner_task = 0;
        g_debug ("%s: %i forked %i", __func__, getpid (), pid);
        return 0;
    }

  /* Child.
   *
   * Re-open DB and do prognostic calculation.  On success exit(0), else
   * exit(1). */
  reinit_manage_process ();
  manage_session_init (current_credentials.uuid);

  /* Setup the task. */

  set_task_run_status (task, TASK_STATUS_RUNNING);

  setproctitle ("CVE: Handling scan %s", report_id);
  g_free (report_id);

  hosts = target_hosts (target);
  if (hosts == NULL)
    {
      set_task_interrupted (task,
                            "Error in target host list."
                            "  Interrupting scan.");
      set_report_scan_run_status (global_current_report, TASK_STATUS_INTERRUPTED);
      gvm_close_sentry ();
      exit (1);
    }

  exclude_hosts = target_exclude_hosts (target);

  reset_task (task);
  set_task_start_time_epoch (task, time (NULL));
  set_scan_start_time_epoch (global_current_report, time (NULL));

  /* Add the results. */

  gvm_hosts = gvm_hosts_new (hosts);
  free (hosts);

  if (gvm_hosts_exclude (gvm_hosts, exclude_hosts ?: "") < 0)
    {
      set_task_interrupted (task,
                              "Failed to exclude hosts."
                              "  Interrupting scan.");
      set_report_scan_run_status (global_current_report, TASK_STATUS_INTERRUPTED);
      gvm_hosts_free (gvm_hosts);
      free (exclude_hosts);
      gvm_close_sentry ();
      exit(1);
    }
  free (exclude_hosts);

  int matching_version;
  setting_value_int(SETTING_UUID_CVE_CPE_MATCHING_VERSION, &matching_version);

  while ((gvm_host = gvm_hosts_next (gvm_hosts)))
    if (cve_scan_host (task, global_current_report, gvm_host, matching_version))
      {
        set_task_interrupted (task,
                              "Failed to get nthlast report."
                              "  Interrupting scan.");
        set_report_scan_run_status (global_current_report, TASK_STATUS_INTERRUPTED);
        gvm_hosts_free (gvm_hosts);
        gvm_close_sentry ();
        exit (1);
      }
  gvm_hosts_free (gvm_hosts);

  /* Set the end states. */

  set_scan_end_time_epoch (global_current_report, time (NULL));
  set_task_end_time_epoch (task, time (NULL));
  set_task_run_status (task, TASK_STATUS_DONE);
  set_report_scan_run_status (global_current_report, TASK_STATUS_DONE);
  global_current_report = 0;
  current_scanner_task = (task_t) 0;
  gvm_close_sentry ();
  exit (0);
}

/**
 * @brief Start a CVE task.
 *
 * @param[in]   task    The task.
 *
 * @return 0 success, 99 permission denied, -1 error, -9 failed to fork.
 */
static int
run_cve_task (task_t task)
{
  target_t target;

  target = task_target (task);
  if (target)
    {
      char *uuid;
      target_t found;

      uuid = target_uuid (target);
      if (find_target_with_permission (uuid, &found, "get_targets"))
        {
          g_free (uuid);
          return -1;
        }
      g_free (uuid);
      if (found == 0)
        return 99;
    }

  if (fork_cve_scan_handler (task, target))
    {
      g_warning ("Couldn't fork CVE scan handler");
      return -1;
    }
  return 0;
}


/* Tasks. */

/**
 * @brief Gets the current path of the relay mapper executable.
 *
 * @return The current relay mapper path.
 */
const char *
get_relay_mapper_path ()
{
  return relay_mapper_path;
}

/**
 * @brief Gets the current path of the relay mapper executable.
 *
 * @param[in]  new_path  The new relay mapper path.
 */
void
set_relay_mapper_path (const char *new_path)
{
  g_free (relay_mapper_path);
  relay_mapper_path = new_path ? g_strdup (new_path) : NULL;
}

/**
 * @brief Gets the info about a scanner relay as an XML entity_t.
 *
 * @param[in]  original_host    The original hostname or IP address.
 * @param[in]  original_port    The original port number.
 * @param[in]  protocol         The protocol to look for, e.g. "GMP" or "OSP".
 * @param[out] ret_entity       Return location for the parsed XML.
 *
 * @return 0: success, -1 error.
 */
static int
get_relay_info_entity (const char *original_host, int original_port,
                       const char *protocol, entity_t *ret_entity)
{
  gchar **cmd, *stdout_str, *stderr_str;
  int ret, exit_code;
  GError *err;
  entity_t relay_entity;

  if (ret_entity == NULL)
    return -1;

  *ret_entity = NULL;
  stdout_str = NULL;
  stderr_str = NULL;
  ret = -1;
  exit_code = -1;
  err = NULL;

  cmd = (gchar **) g_malloc (8 * sizeof (gchar *));
  cmd[0] = g_strdup (relay_mapper_path);
  cmd[1] = g_strdup ("--host");
  cmd[2] = g_strdup (original_host);
  cmd[3] = g_strdup ("--port");
  cmd[4] = g_strdup_printf ("%d", original_port);
  cmd[5] = g_strdup ("--protocol");
  cmd[6] = g_strdup (protocol);
  cmd[7] = NULL;

  if (g_spawn_sync (NULL,
                    cmd,
                    NULL,
                    G_SPAWN_SEARCH_PATH,
                    NULL,
                    NULL,
                    &stdout_str,
                    &stderr_str,
                    &exit_code,
                    &err) == FALSE)
    {
      g_warning ("%s: g_spawn_sync failed: %s",
                 __func__, err ? err->message : "");
      g_strfreev (cmd);
      g_free (stdout_str);
      g_free (stderr_str);
      return -1;
    }
  else if (exit_code)
    {
      g_warning ("%s: mapper exited with code %d",
                 __func__, exit_code);
      g_message ("%s: mapper stderr:\n%s", __func__, stderr_str);
      g_debug ("%s: mapper stdout:\n%s", __func__, stdout_str);
      g_strfreev (cmd);
      g_free (stdout_str);
      g_free (stderr_str);
      return -1;
    }

  relay_entity = NULL;
  if (parse_entity (stdout_str, &relay_entity))
    {
      g_warning ("%s: failed to parse mapper output",
                 __func__);
      g_message ("%s: mapper stdout:\n%s", __func__, stdout_str);
      g_message ("%s: mapper stderr:\n%s", __func__, stderr_str);
    }
  else
    {
      ret = 0;
      *ret_entity = relay_entity;
    }

  g_strfreev (cmd);
  g_free (stdout_str);
  g_free (stderr_str);

  return ret;
}

/**
 * @brief Gets a relay hostname and port for a sensor scanner.
 *
 * If no mapper is available, a copy of the original host, port and
 *  CA certificate are returned.
 *
 * @param[in]  original_host    The original hostname or IP address.
 * @param[in]  original_port    The original port number.
 * @param[in]  original_ca_cert The original CA certificate.
 * @param[in]  protocol         The protocol to look for, e.g. "GMP" or "OSP".
 * @param[out] new_host         The hostname or IP address of the relay.
 * @param[out] new_port         The port number of the relay.
 * @param[out] new_ca_cert      The CA certificate of the relay.
 *
 * @return 0 success, 1 relay not found, -1 error.
 */
int
slave_get_relay (const char *original_host,
                 int original_port,
                 const char *original_ca_cert,
                 const char *protocol,
                 gchar **new_host,
                 int *new_port,
                 gchar **new_ca_cert)
{
  int ret = -1;

  assert (new_host);
  assert (new_port);
  assert (new_ca_cert);

  if (relay_mapper_path == NULL)
    {
      *new_host = original_host ? g_strdup (original_host) : NULL;
      *new_port = original_port;
      *new_ca_cert = original_ca_cert ? g_strdup (original_ca_cert) : NULL;

      return 0;
    }
  else
    {
      entity_t relay_entity = NULL;

      if (get_relay_info_entity (original_host, original_port,
                                 protocol, &relay_entity) == 0)
        {
          entity_t host_entity, port_entity, ca_cert_entity;

          host_entity = entity_child (relay_entity, "host");
          port_entity = entity_child (relay_entity, "port");
          ca_cert_entity = entity_child (relay_entity, "ca_cert");

          if (host_entity && port_entity && ca_cert_entity)
            {
              if (entity_text (host_entity)
                  && entity_text (port_entity)
                  && strcmp (entity_text (host_entity), "")
                  && strcmp (entity_text (port_entity), ""))
                {
                  *new_host = g_strdup (entity_text (host_entity));
                  *new_port = atoi (entity_text (port_entity));

                  if (entity_text (ca_cert_entity)
                      && strcmp (entity_text (ca_cert_entity), ""))
                    {
                      *new_ca_cert = g_strdup (entity_text (ca_cert_entity));
                    }
                  else
                    {
                      *new_ca_cert = NULL;
                    }
                  ret = 0;
                }
              else
                {
                  // Consider relay not found if host or port is empty
                  ret = 1;
                }
            }
          else
            {
              g_warning ("%s: mapper output did not contain"
                         " HOST, PORT and CA_CERT",
                         __func__);
            }
          free_entity (relay_entity);
        }
    }

  return ret;
}

#if ENABLE_OPENVASD
/* Prototype */
static int
run_openvasd_task (task_t task, int from, char **report_id);
#endif

#if ENABLE_AGENTS
/* Prototype */
static int
run_agent_control_task (task_t task, char **report_id);
#endif

/**
 * @brief Start or resume a task.
 *
 * A process will be forked to handle the task, but the forked process will
 * never return.
 *
 * @param[in]   task_id     The task ID.
 * @param[out]  report_id   The report ID.
 * @param[in]   from        0 start from beginning, 1 continue from stopped, 2
 *                          continue if stopped else start from beginning.
 *
 * @return 1 task is active already,
 *         3 failed to find task,
 *         4 resuming task not supported,
 *         99 permission denied,
 *         -1 error,
 *         -2 task is missing a target,
 *         -3 creating the report failed,
 *         -4 target missing hosts,
 *         -6 already a task running in this process,
 *         -9 fork failed.
 */
static int
run_task (const char *task_id, char **report_id, int from)
{
  task_t task;
  scanner_t scanner;
  int ret;
  const char *permission;

  if (current_scanner_task)
    return -6;

  if (from == 0)
    permission = "start_task";
  else if (from == 1)
    permission = "resume_task";
  else
    {
      assert (0);
      permission = "internal_error";
    }

  task = 0;
  if (find_task_with_permission (task_id, &task, permission))
    return -1;
  if (task == 0)
    return 3;

  scanner = task_scanner (task);
  assert (scanner);
  ret = check_available ("scanner", scanner, "get_scanners");
  if (ret)
    return ret;

  if (scanner_type (scanner) == SCANNER_TYPE_CVE)
    return run_cve_task (task);

  if (scanner_type (scanner) == SCANNER_TYPE_OPENVAS
      || scanner_type (scanner) == SCANNER_TYPE_OSP_SENSOR)
    return run_osp_task (task, from, report_id);

#if ENABLE_OPENVASD
  if (scanner_type (scanner) == SCANNER_TYPE_OPENVASD
    || scanner_type (scanner) == SCANNER_TYPE_OPENVASD_SENSOR)
    return run_openvasd_task (task, from, report_id);
#endif

#if ENABLE_AGENTS
  if (scanner_type (scanner) == SCANNER_TYPE_AGENT_CONTROLLER
    || scanner_type (scanner) == SCANNER_TYPE_AGENT_CONTROLLER_SENSOR)
    {
      if (from == 1)
        // Resume task is not supported by agent controller
        return 4;
      return run_agent_control_task (task, report_id);
    }
#endif

#if ENABLE_CONTAINER_SCANNING
  if (scanner_type (scanner) == SCANNER_TYPE_CONTAINER_IMAGE)
    return run_container_image_task (task, from, report_id);
#endif

  return -1; // Unknown scanner type
}

/**
 * @brief Start a task.
 *
 * A process will be forked to handle the task, but the forked process will
 * never return.
 *
 * @param[in]   task_id    The task ID.
 * @param[out]  report_id  The report ID.
 *
 * @return 1 task is active already,
 *         3 failed to find task,
 *         4 resuming task not supported,
 *         99 permission denied,
 *         -1 error,
 *         -2 task is missing a target,
 *         -3 creating the report failed,
 *         -4 target missing hosts,
 *         -6 already a task running in this process,
 *         -9 fork failed.
 */
int
start_task (const char *task_id, char **report_id)
{
  if (acl_user_may ("start_task") == 0)
    return 99;

  return run_task (task_id, report_id, 0);
}

/**
 * @brief Stop an OSP task.
 *
 * @param[in]   task  The task.
 *
 * @return 0 on success, else -1.
 */
static int
stop_osp_task (task_t task)
{
  osp_connection_t *connection;
  int ret = -1;
  report_t scan_report;
  char *scan_id;
  task_t previous_task;
  report_t previous_report;

  scan_report = task_running_report (task);
  if (!scan_report)
    return 0;

  previous_task = current_scanner_task;
  previous_report = global_current_report;

  scan_id = report_uuid (scan_report);
  if (!scan_id)
    goto end_stop_osp;
  connection = osp_scanner_connect (task_scanner (task));
  if (!connection)
    goto end_stop_osp;

  current_scanner_task = task;
  global_current_report = task_running_report (task);
  set_task_run_status (task, TASK_STATUS_STOP_REQUESTED);
  ret = osp_stop_scan (connection, scan_id, NULL);
  osp_connection_close (connection);
  if (ret)
    {
      g_free (scan_id);
      goto end_stop_osp;
    }

  connection = osp_scanner_connect (task_scanner (task));
  if (!connection)
    goto end_stop_osp;
  ret = osp_delete_scan (connection, scan_id);
  osp_connection_close (connection);
  g_free (scan_id);

end_stop_osp:
  set_task_end_time_epoch (task, time (NULL));
  set_task_run_status (task, TASK_STATUS_STOPPED);
  if (scan_report)
    {
      set_scan_end_time_epoch (scan_report, time (NULL));
      set_report_scan_run_status (scan_report, TASK_STATUS_STOPPED);
    }
  current_scanner_task = previous_task;
  global_current_report = previous_report;
  if (ret)
    return -1;
  return 0;
}

/**
 * @brief Initiate stopping a task.
 *
 * @param[in]  task  Task.
 *
 * @return 0 on success, 1 if stop requested.
 */
int
stop_task_internal (task_t task)
{
  task_status_t run_status;
  task_t previous_task;
  report_t previous_report;

  previous_task = current_scanner_task;
  previous_report = global_current_report;

  run_status = task_run_status (task);
  if (run_status == TASK_STATUS_REQUESTED
      || run_status == TASK_STATUS_RUNNING
      || run_status == TASK_STATUS_QUEUED)
    {
      current_scanner_task = task;
      global_current_report = task_running_report (task);
      set_task_run_status (task, TASK_STATUS_STOP_REQUESTED);
      current_scanner_task = previous_task;
      global_current_report = previous_report;
      return 1;
    }

  return 0;
}

#if ENABLE_OPENVASD
static int
stop_openvasd_task (task_t task);
#endif

/**
 * @brief Initiate stopping a task.
 *
 * @param[in]  task_id  Task UUID.
 *
 * @return 0 on success, 1 if stop requested, 3 failed to find task,
 *         99 permission denied, -1 error.
 */
int
stop_task (const char *task_id)
{
  task_t task;

  if (acl_user_may ("stop_task") == 0)
    return 99;

  task = 0;
  if (find_task_with_permission (task_id, &task, "stop_task"))
    return -1;
  if (task == 0)
    return 3;

  if (scanner_type (task_scanner (task)) == SCANNER_TYPE_OPENVAS
      || scanner_type (task_scanner (task)) == SCANNER_TYPE_OSP_SENSOR)
    return stop_osp_task (task);

#if ENABLE_OPENVASD
  if (scanner_type (task_scanner (task)) == SCANNER_TYPE_OPENVASD
      || scanner_type (task_scanner (task)) == SCANNER_TYPE_OPENVASD_SENSOR)
    return stop_openvasd_task (task);
#endif

#if ENABLE_CONTAINER_SCANNING
  if (scanner_type (task_scanner (task)) == SCANNER_TYPE_CONTAINER_IMAGE)
    return stop_container_image_task (task);
#endif

  return stop_task_internal (task);
}

/**
 * @brief Resume a task.
 *
 * A process will be forked to handle the task, but the forked process will
 * never return.
 *
 * @param[in]   task_id    Task UUID.
 * @param[out]  report_id  If successful, ID of the resultant report.
 *
 * @return 1 task is active already,
 *         3 failed to find task,
 *         4 resuming task not supported,
 *         22 caller error (task must be in "stopped" or "interrupted" state),
 *         99 permission denied,
 *         -1 error,
 *         -2 task is missing a target,
 *         -3 creating the report failed,
 *         -4 target missing hosts,
 *         -6 already a task running in this process,
 *         -9 fork failed.
 */
int
resume_task (const char *task_id, char **report_id)
{
  task_t task;
  task_status_t run_status;

  if (acl_user_may ("resume_task") == 0)
    return 99;

  task = 0;
  if (find_task_with_permission (task_id, &task, "resume_task"))
    return -1;
  if (task == 0)
    return 3;

  run_status = task_run_status (task);
  if ((run_status == TASK_STATUS_STOPPED)
      || (run_status == TASK_STATUS_INTERRUPTED))
    return run_task (task_id, report_id, 1);
  return 22;
}

/**
 * @brief Reassign a task to another slave.
 *
 * @param[in]  task_id    UUID of task.
 * @param[in]  slave_id   UUID of slave.
 *
 * @return 0 success, 2 task not found,
 *         3 slave not found, 4 slaves not supported by scanner, 5 task cannot
 *         be stopped currently, 6 scanner does not allow stopping, 7 new
 *         scanner does not support slaves, 98 stop and resume permission
 *         denied, 99 permission denied, -1 error.
 */
int
move_task (const char *task_id, const char *slave_id)
{
  task_t task;
  int task_scanner_type, slave_scanner_type;
  scanner_t slave, scanner;
  task_status_t status;
  int should_resume_task = 0;

  if (task_id == NULL)
    return -1;
  if (slave_id == NULL)
    return -1;

  if (acl_user_may ("modify_task") == 0)
    return 99;

  /* Find the task. */

  if (find_task_with_permission (task_id, &task, "get_tasks"))
    return -1;
  if (task == 0)
    return 2;

  /* Make sure destination scanner supports slavery. */

  if (strcmp (slave_id, "") == 0)
    slave_id = SCANNER_UUID_DEFAULT;

  if (find_scanner_with_permission (slave_id, &slave, "get_scanners"))
    return -1;
  if (slave == 0)
    return 3;

  slave_scanner_type = scanner_type (slave);
  if (slave_scanner_type != SCANNER_TYPE_OPENVAS)
    return 7;

  /* Make sure current scanner supports slavery. */

  scanner = task_scanner (task);
  if (scanner == 0)
    return -1;

  task_scanner_type = scanner_type (scanner);
  if (task_scanner_type != SCANNER_TYPE_OPENVAS)
    return 4;

  /* Stop task if required. */

  status = task_run_status (task);

  switch (status)
    {
      case TASK_STATUS_DELETE_REQUESTED:
      case TASK_STATUS_DELETE_ULTIMATE_REQUESTED:
      case TASK_STATUS_DELETE_WAITING:
      case TASK_STATUS_DELETE_ULTIMATE_WAITING:
      case TASK_STATUS_REQUESTED:
      case TASK_STATUS_PROCESSING:
        // Task cannot be stopped now
        return 5;
        break;
      case TASK_STATUS_RUNNING:
      case TASK_STATUS_QUEUED:
        if (task_scanner_type == SCANNER_TYPE_CVE)
          return 6;
        // Check permissions to stop and resume task
        if (acl_user_has_access_uuid ("task", task_id, "stop_task", 0)
            && acl_user_has_access_uuid ("task", task_id, "resume_task", 0))
          {
            // Stop the task, wait and resume after changes
            stop_task_internal (task);
            should_resume_task = 1;

            status = task_run_status (task);
            while (status == TASK_STATUS_STOP_REQUESTED
                   || status == TASK_STATUS_STOP_WAITING)
              {
                sleep (5);
                status = task_run_status (task);
              }
          }
        else
          return 98;
        break;
      case TASK_STATUS_STOP_REQUESTED:
      case TASK_STATUS_STOP_WAITING:
        while (status == TASK_STATUS_STOP_REQUESTED
               || status == TASK_STATUS_STOP_WAITING)
          {
            sleep (5);
            status = task_run_status (task);
          }
        break;
      default:
        break;
    }

  /* Update scanner. */

  set_task_scanner (task, slave);

  /* Resume task if required. */

  if (should_resume_task)
    resume_task (task_id, NULL);

  return 0;
}


/* Credentials. */

/**
 * @brief Get the written-out name of an LSC Credential type.
 *
 * @param[in]  abbreviation  The type abbreviation.
 *
 * @return The written-out type name.
 */
const char*
credential_full_type (const char* abbreviation)
{
  if (abbreviation == NULL)
    return NULL;
  else if (strcasecmp (abbreviation, "cc") == 0)
    return "client certificate";
#if ENABLE_CREDENTIAL_STORES
  else if (strcasecmp (abbreviation, "cs_krb5") ==0)
    return "Credential store Kerberos 5";
  else if (strcasecmp (abbreviation, "cs_pw") == 0)
    return "Credential store password only";
  else if (strcasecmp (abbreviation, "cs_snmp") == 0)
    return "Credential store SNMP";
  else if (strcasecmp (abbreviation, "cs_up") == 0)
    return "Credential store username + password";
  else if (strcasecmp (abbreviation, "cs_usk") == 0)
    return "Credential store username + SSH key";
#endif
  else if (strcasecmp (abbreviation, "krb5") == 0)
    return "Kerberos 5";
  else if (strcasecmp (abbreviation, "pw") == 0)
    return "password only";
  else if (strcasecmp (abbreviation, "snmp") == 0)
    return "SNMP";
  else if (strcasecmp (abbreviation, "up") == 0)
    return "username + password";
  else if (strcasecmp (abbreviation, "usk") == 0)
    return "username + SSH key";
  else
    return abbreviation;
}


/* System reports. */

/**
 * @brief Get a performance report from an OSP scanner.
 *
 * @param[in]  scanner          The scanner to get the performance report from.
 * @param[in]  start            The start time of the performance report.
 * @param[in]  end              The end time of the performance report.
 * @param[in]  titles           The end titles for the performance report.
 * @param[in]  performance_str  The performance string.
 * @param[out] error            Error return.
 *
 * @return 0 if successful, 6 could not connect to scanner or failed to get
 *         performance report
 */
static int
get_osp_performance_string (scanner_t scanner, int start, int end,
                            const char *titles, gchar **performance_str,
                            gchar **error)
{
#if ENABLE_OPENVASD
  http_scanner_connector_t connector;
  int err;
  openvasd_get_performance_opts_t opts;

  connector = http_scanner_connect (scanner, NULL);
  if (!connector)
    {
      *error = g_strdup ("Could not connect to scanner");
      return 6;
    }

  opts.start = start;
  opts.end = end;
  opts.titles = titles;

  err = openvasd_parsed_performance (connector, opts, performance_str, error);
  if (err)
    {
      g_warning ("Error getting openvasd performance report: %s", *error);
      http_scanner_connector_free (connector);
      return 6;
    }

  http_scanner_connector_free (connector);
#else
  osp_connect_data_t *conn_data;
  int return_value;
  osp_connection_t *connection = NULL;
  int connection_retry;
  osp_get_performance_opts_t opts;

  conn_data = osp_connect_data_from_scanner (scanner);

  connection_retry = get_scanner_connection_retry ();
  connection = osp_connect_with_data (conn_data);
  while (connection == NULL && connection_retry > 0)
    {
      sleep(1);
      connection = osp_connect_with_data (conn_data);
      connection_retry--;
    }

  osp_connect_data_free (conn_data);

  if (connection == NULL)
    {
      *error = g_strdup("Could not connect to scanner");
      return 6;
    }

  opts.start = start;
  opts.end = end;
  opts.titles = g_strdup (titles);

  return_value = osp_get_performance_ext (connection, opts,
                                          performance_str, error);

  if (return_value)
    {
      osp_connection_close (connection);
      g_warning ("Error getting OSP performance report: %s", *error);
      g_free (opts.titles);
      return 6;
    }

  osp_connection_close (connection);
  g_free (opts.titles);
#endif

  return 0;
}

/**
 * @brief Header for fallback system report.
 */
#define FALLBACK_SYSTEM_REPORT_HEADER \
"This is the most basic, fallback report.  The system can be configured to\n" \
"produce more powerful reports.  Please contact your system administrator\n" \
"for more information.\n\n"

/**
 * @brief Get the fallback report as a string.
 *
 * @param[in]  fallback_report  The string for the fallback report.
 */
static void
get_fallback_report_string(GString *fallback_report)
{
  int ret;
  double load[3];
  GError *get_error;
  gchar *output;
  gsize output_len;

  g_string_append_printf (fallback_report, FALLBACK_SYSTEM_REPORT_HEADER);

  ret = getloadavg (load, 3);
  if (ret == 3)
    {
      g_string_append_printf (fallback_report,
                              "Load average for past minute:     %.1f\n",
                              load[0]);
      g_string_append_printf (fallback_report,
                              "Load average for past 5 minutes:  %.1f\n",
                              load[1]);
      g_string_append_printf (fallback_report,
                              "Load average for past 15 minutes: %.1f\n",
                              load[2]);
    }
  else
    g_string_append (fallback_report, "Error getting load averages.\n");

  get_error = NULL;
  g_file_get_contents ("/proc/meminfo",
                       &output,
                       &output_len,
                       &get_error);

  if (get_error)
    g_error_free (get_error);
  else
    {
      gchar *safe;
      g_string_append (fallback_report, "\n/proc/meminfo:\n\n");
      safe = g_markup_escape_text (output, strlen (output));
      g_free (output);
      g_string_append (fallback_report, safe);
      g_free (safe);
    }
}

/**
 * @brief Command called by get_system_report_types.
 *        gvmcg stands for gvm-create-graphs.
 */
#define COMMAND "gvmcg 0 titles"

/**
 * @brief Get system report types.
 *
 * @param[in]   required_type  Single type to limit types to.
 * @param[out]  types          Types on success.
 * @param[out]  start          Actual start of types, which caller must free.
 * @param[out]  slave_id       ID of slave.
 *
 * @return 0 if successful, 1 failed to find report type, 2 failed to find
 *         slave, 3 serving the fallback, 4 could not connect to slave,
 *         5 authentication failed, 6 failed to get system report,
 *         -1 otherwise.
 */
static int
get_system_report_types (const char *required_type, gchar ***start,
                         gchar ***types, const char *slave_id)
{
  gchar *astdout = NULL;
  gchar *astderr = NULL;
  gchar *slave_error = NULL;
  GError *err = NULL;
  gint exit_status;

  if (slave_id && strcmp (slave_id, "0"))
    {
      int ret;
      scanner_t slave;

      slave = 0;

      if (find_scanner_with_permission (slave_id, &slave, "get_scanners"))
        return -1;
      if (slave == 0)
        return 2;

      // Assume OSP scanner
      ret = get_osp_performance_string (slave, 0, 0, "titles",
                                        &astdout, &slave_error);

      if (ret)
        {
          g_free (slave_error);
          return ret;
        }
    }
  else
    {
      g_debug ("   command: " COMMAND);

      if ((g_spawn_command_line_sync (COMMAND,
                                      &astdout,
                                      &astderr,
                                      &exit_status,
                                      &err)
          == FALSE)
          || (WIFEXITED (exit_status) == 0)
          || WEXITSTATUS (exit_status))
        {
          g_debug ("%s: gvmcg failed with %d", __func__, exit_status);
          g_debug ("%s: stdout: %s", __func__, astdout);
          g_debug ("%s: stderr: %s", __func__, astderr);
          g_free (astdout);
          g_free (astderr);
          *start = *types = g_malloc0 (sizeof (gchar*) * 2);
          (*start)[0] = g_strdup ("fallback Fallback Report");
          (*start)[0][strlen ("fallback")] = '\0';
          return 3;
        }
    }

  if (astdout)
    {
      char **type;
      *start = *types = type = g_strsplit (g_strchomp (astdout), "\n", 0);
      while (*type)
        {
          char *space;
          space = strchr (*type, ' ');
          if (space == NULL)
            {
              g_strfreev (*types);
              *types = NULL;
              g_free (astdout);
              g_free (astderr);
              g_free (slave_error);
              return -1;
            }
          *space = '\0';
          if (required_type && (strcmp (*type, required_type) == 0))
            {
              char **next;
              /* Found the single given type. */
              next = type + 1;
              while (*next)
                {
                  free (*next);
                  next++;
                }
              next = type + 1;
              *next = NULL;
              *types = type;
              g_free (astdout);
              g_free (astderr);
              g_free (slave_error);
              return 0;
            }
          type++;
        }
      if (required_type)
        {
          /* Failed to find the single given type. */
          g_free (astdout);
          g_free (astderr);
          g_free (slave_error);
          g_strfreev (*types);
          return 1;
        }
    }
  else
    *start = *types = g_malloc0 (sizeof (gchar*));

  g_free (astdout);
  g_free (astderr);
  g_free (slave_error);
  return 0;
}

#undef COMMAND

/**
 * @brief Initialise a system report type iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  type        Single report type to iterate over, NULL for all.
 * @param[in]  slave_id    ID of slave to get reports from.  0 for local.
 *
 * @return 0 on success, 1 failed to find report type, 2 failed to find slave,
 *         3 used the fallback report,  4 could not connect to slave,
 *         5 authentication failed, 6 failed to get system report,
 *         99 permission denied, -1 on error.
 */
int
init_system_report_type_iterator (report_type_iterator_t* iterator,
                                  const char* type,
                                  const char* slave_id)
{
  int ret;

  if (acl_user_may ("get_system_reports") == 0)
    return 99;

  ret = get_system_report_types (type, &iterator->start, &iterator->current,
                                 slave_id);
  if (ret == 0 || ret == 3)
    {
      iterator->current--;
      return ret;
    }
  return ret;
}

/**
 * @brief Cleanup a report type iterator.
 *
 * @param[in]  iterator  Iterator.
 */
void
cleanup_report_type_iterator (report_type_iterator_t* iterator)
{
  g_strfreev (iterator->start);
}

/**
 * @brief Increment a report type iterator.
 *
 * The caller must stop using this after it returns FALSE.
 *
 * @param[in]  iterator  Task iterator.
 *
 * @return TRUE if there was a next item, else FALSE.
 */
gboolean
next_report_type (report_type_iterator_t* iterator)
{
  iterator->current++;
  if (*iterator->current == NULL) return FALSE;
  return TRUE;
}

/**
 * @brief Return the name from a report type iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name.
 */
const char*
report_type_iterator_name (report_type_iterator_t* iterator)
{
  return (const char*) *iterator->current;
}

/**
 * @brief Return the title from a report type iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Title.
 */
const char*
report_type_iterator_title (report_type_iterator_t* iterator)
{
  const char *name = *iterator->current;
  return name + strlen (name) + 1;
}

/**
 * @brief Default duration for system reports.
 */
#define DEFAULT_DURATION 86400L

/**
 * @brief Generate params for gvmcg or OSP get_performance.
 *
 * @param[in]  duration     The duration as a string
 * @param[in]  start_time   The start time as a string
 * @param[in]  end_time     The end time as a string
 * @param[out] param_1      Output of the first parameter (start or duration)
 * @param[out] param_2      Output of the second parameter (end time)
 * @param[out] params_count The number of valid parameters
 */
void
parse_performance_params (const char *duration,
                          const char *start_time,
                          const char *end_time,
                          time_t *param_1,
                          time_t *param_2,
                          int *params_count)
{
  time_t start_time_num, end_time_num, duration_num;
  start_time_num = 0;
  end_time_num = 0;
  duration_num = 0;

  *param_1 = 0;
  *param_2 = 0;
  *params_count = 0;

  if (duration && strcmp (duration, ""))
    {
      duration_num = atol (duration);
      if (duration_num == 0)
        return;
    }
  if (start_time && strcmp (start_time, ""))
    {
      start_time_num = parse_iso_time (start_time);
      if (start_time_num == 0)
        return;
    }
  if (end_time && strcmp (end_time, ""))
    {
      end_time_num = parse_iso_time (end_time);
      if (end_time_num == 0)
        return;
    }

  if (start_time && strcmp (start_time, ""))
    {
      if (end_time && strcmp (end_time, ""))
        {
          *param_1 = start_time_num;
          *param_2 = end_time_num;
          *params_count = 2;
        }
      else if (duration && strcmp (duration, ""))
        {
          *param_1 = start_time_num;
          *param_2 = start_time_num + duration_num;
          *params_count = 2;
        }
      else
        {
          *param_1 = start_time_num;
          *param_2 = start_time_num + DEFAULT_DURATION;
          *params_count = 2;
        }
    }
  else if (end_time && strcmp (end_time, ""))
    {
      if (duration && strcmp (duration, ""))
        {
          *param_1 = end_time_num - duration_num;
          *param_2 = end_time_num;
          *params_count = 2;
        }
      else
        {
          *param_1 = end_time_num - DEFAULT_DURATION,
          *param_1 = end_time_num,
          *params_count = 2;
        }
    }
  else
    {
      if (duration && strcmp (duration, ""))
        {
          *param_1 = duration_num;
          *params_count = 1;
        }
      else
        {
          *param_1 = DEFAULT_DURATION;
          *params_count = 1;
        }
    }
}

/**
 * @brief Get a system report.
 *
 * @param[in]  name       Name of report.
 * @param[in]  duration   Time range of report, in seconds.
 * @param[in]  start_time Time of first data point in report.
 * @param[in]  end_time   Time of last data point in report.
 * @param[in]  slave_id   ID of slave to get report from.  0 for local.
 * @param[out] report     On success, report in base64 if such a report exists
 *                        else NULL.  Arbitrary on error.
 *
 * @return 0 if successful (including failure to find report), -1 on error,
 *         2 could not find slave scanner,
 *         3 if used the fallback report or got an error message to print
 */
int
manage_system_report (const char *name, const char *duration,
                      const char *start_time, const char *end_time,
                      const char *slave_id, char **report)
{
  gchar *astdout = NULL;
  gchar *astderr = NULL;
  gchar *slave_error = NULL;
  GError *err = NULL;
  GString *buffer = NULL;
  gint exit_status;
  gint return_code = 0;
  gchar *command = NULL;
  time_t cmd_param_1, cmd_param_2;
  int params_count;

  assert (name);

  parse_performance_params (duration, start_time, end_time,
                            &cmd_param_1, &cmd_param_2, &params_count);

  *report = NULL;

  if (params_count == 0)
    return manage_system_report ("blank", NULL, NULL, NULL, NULL, report);

  if (slave_id && strcmp (slave_id, "0"))
    {
      scanner_t slave;

      slave = 0;

      if (find_scanner_with_permission (slave_id, &slave, "get_scanners"))
        return -1;
      if (slave == 0)
        return 2;

      if (params_count == 1)
        {
          // only duration
          time_t now;
          now = time (NULL);
          return_code = get_osp_performance_string (slave,
                                                    now - cmd_param_1,
                                                    now,
                                                    name,
                                                    report,
                                                    &slave_error);
        }
      else
        {
          // start and end time
          return_code = get_osp_performance_string (slave,
                                                    cmd_param_1,
                                                    cmd_param_2,
                                                    name,
                                                    report,
                                                    &slave_error);
        }
    }
  else
    {
      if (!g_find_program_in_path ("gvmcg"))
        {
          buffer = g_string_new ("");
          get_fallback_report_string(buffer);
          *report = g_string_free (buffer, FALSE);
          return_code = 7;
        }
      else
        {
          /* For simplicity, it's up to the command to do the base64
           * encoding.
           */
          if (params_count == 1)
            command = g_strdup_printf ("gvmcg %ld %s",
                                       cmd_param_1,
                                       name);
          else
            command = g_strdup_printf ("gvmcg %ld %ld %s",
                                       cmd_param_1,
                                       cmd_param_2,
                                       name);

          g_debug ("   command: %s", command);

          if ((g_spawn_command_line_sync (command,
                                          &astdout,
                                          &astderr,
                                          &exit_status,
                                          &err)
               == FALSE)
              || (WIFEXITED (exit_status) == 0)
              || WEXITSTATUS (exit_status))
            {
              return_code = 3;

              g_warning ("%s: Failed to create performance graph -- %s",
                         __func__, astderr);
              g_debug ("%s: gvmcg failed with %d", __func__, exit_status);
              g_debug ("%s: stdout: %s", __func__, astdout);
              g_debug ("%s: stderr: %s", __func__, astderr);
            }
          g_free (command);
        }
    }

  if (return_code == 3 || return_code == 6)
    {
      buffer = g_string_new ("");
      g_string_append_printf (buffer,
                              "Failed to create performance graph: %s",
                              (return_code == 3 ? astderr : slave_error));
      *report = g_string_free (buffer, FALSE);
    }

  g_free (astderr);
  g_free (slave_error);

  if (return_code == 6 || return_code == 7)
    return_code = 3;

  if ((astdout == NULL || strlen (astdout) == 0) &&
      *report == NULL)
    {
      g_free (astdout);
      if (strcmp (name, "blank") == 0)
        return -1;
      return manage_system_report ("blank", NULL, NULL, NULL,
                                   NULL, report);
    }
  else if (*report == NULL)
    *report = astdout;
  else
    g_free (astdout);

  return return_code;
}


/* Scheduling. */

/**
 * @brief Flag for manage_auth_allow_all.
 *
 * 1 if set via scheduler, 2 if set via event, else 0.
 */
int authenticate_allow_all = 0;

/**
 * @brief UUID of user whose scheduled task is to be started (in connection
 *        with authenticate_allow_all).
 */
static gchar* schedule_user_uuid = NULL;

/**
 * @brief Ensure that any subsequent authentications succeed.
 *
 * @param[in]  scheduled  Whether this is happening from the scheduler.
 */
void
manage_auth_allow_all (int scheduled)
{
  authenticate_allow_all = scheduled ? 1 : 2;
}

/**
 * @brief Access UUID of user that scheduled the current task.
 *
 * @return UUID of user that scheduled the current task.
 */
const gchar*
get_scheduled_user_uuid ()
{
  return schedule_user_uuid;
}

/**
 * @brief Set UUID of user that scheduled the current task.
 * The previous value is freed and a copy of the UUID is created.
 *
 * @param user_uuid UUID of user that scheduled the current task.
 */
void
set_scheduled_user_uuid (const gchar* user_uuid)
{
  gchar *user_uuid_copy = user_uuid ? g_strdup (user_uuid) : NULL;
  g_free (schedule_user_uuid);
  schedule_user_uuid = user_uuid_copy;
}

/**
 * @brief Task info, for scheduler.
 */
typedef struct
{
  gchar *owner_uuid;   ///< UUID of owner.
  gchar *owner_name;   ///< Name of owner.
  gchar *task_uuid;    ///< UUID of task.
} scheduled_task_t;

/**
 * @brief Create a schedule task structure.
 *
 * @param[in] task_uuid   UUID of task.
 * @param[in] owner_uuid  UUID of owner.
 * @param[in] owner_name  Name of owner.
 *
 * @return Scheduled task structure.
 */
static scheduled_task_t *
scheduled_task_new (const gchar* task_uuid, const gchar* owner_uuid,
                    const gchar* owner_name)
{
  scheduled_task_t *scheduled_task;

  scheduled_task = g_malloc (sizeof (*scheduled_task));
  scheduled_task->task_uuid = g_strdup (task_uuid);
  scheduled_task->owner_uuid = g_strdup (owner_uuid);
  scheduled_task->owner_name = g_strdup (owner_name);

  return scheduled_task;
}

/**
 * @brief Set UUID of user that scheduled the current task.
 *
 * @param[in] scheduled_task  Scheduled task.
 */
static void
scheduled_task_free (scheduled_task_t *scheduled_task)
{
  g_free (scheduled_task->task_uuid);
  g_free (scheduled_task->owner_uuid);
  g_free (scheduled_task->owner_name);
  g_free (scheduled_task);
}

/**
 * @brief Start a task, for the scheduler.
 *
 * @param[in]  scheduled_task   Scheduled task.
 * @param[in]  fork_connection  Function that forks a child which is connected
 *                              to the Manager.  Must return PID in parent, 0
 *                              in child, or -1 on error.
 * @param[in]  sigmask_current  Sigmask to restore in child.
 *
 * @return 0 success, -1 error.  Child does not return.
 */
static int
scheduled_task_start (scheduled_task_t *scheduled_task,
                      manage_connection_forker_t fork_connection,
                      sigset_t *sigmask_current)
{
  int pid;
  gvm_connection_t connection;
  gmp_authenticate_info_opts_t auth_opts;

  /* Fork a child to start the task and wait for the response, so that the
   * parent can return to the main loop.  Only the parent returns. */

  pid = fork ();
  switch (pid)
    {
      case 0:
        /* Child.  Carry on to start the task, reopen the database (required
         * after fork). */

        /* Restore the sigmask that was blanked for pselect. */
        pthread_sigmask (SIG_SETMASK, sigmask_current, NULL);

        init_sentry ();
        reinit_manage_process ();
        manage_session_init (current_credentials.uuid);
        break;

      case -1:
        /* Parent on error. */
        g_warning ("%s: fork failed", __func__);
        return -1;

      default:
        /* Parent.  Continue to next task. */
        g_debug ("%s: %i forked %i", __func__, getpid (), pid);
        return 0;
    }

  /* Run the callback to fork a child connected to the Manager. */

  pid = fork_connection (&connection, scheduled_task->owner_uuid);
  switch (pid)
    {
      case 0:
        /* Child.  Break, start task, exit. */
        break;

      case -1:
        /* Parent on error. */
        g_warning ("%s: fork_connection failed", __func__);
        reschedule_task (scheduled_task->task_uuid);
        scheduled_task_free (scheduled_task);
        gvm_close_sentry ();
        exit (EXIT_FAILURE);
        break;

      default:
        {
          int status;

          /* Parent.  Wait for child, to check return. */

          setproctitle ("scheduler: waiting for %i", pid);

          g_debug ("%s: %i fork_connectioned %i",
                   __func__, getpid (), pid);

          if (signal (SIGCHLD, SIG_DFL) == SIG_ERR)
            g_warning ("%s: failed to set SIGCHLD", __func__);
          while (waitpid (pid, &status, 0) < 0)
            {
              if (errno == ECHILD)
                {
                  g_warning ("%s: Failed to get child exit,"
                             " so task '%s' may not have been scheduled",
                             __func__,
                             scheduled_task->task_uuid);
                  scheduled_task_free (scheduled_task);
                  gvm_close_sentry ();
                  exit (EXIT_FAILURE);
                }
              if (errno == EINTR)
                continue;
              g_warning ("%s: waitpid: %s",
                         __func__,
                         strerror (errno));
              g_warning ("%s: As a result, task '%s' may not have been"
                         " scheduled",
                         __func__,
                         scheduled_task->task_uuid);
              scheduled_task_free (scheduled_task);
              gvm_close_sentry ();
              exit (EXIT_FAILURE);
            }
          if (WIFEXITED (status))
            switch (WEXITSTATUS (status))
              {
                case EXIT_SUCCESS:
                  {
                    schedule_t schedule;
                    int periods;
                    const gchar *task_uuid;

                    /* Child succeeded, so task successfully started. */

                    task_uuid = scheduled_task->task_uuid;
                    schedule = task_schedule_uuid (task_uuid);
                    if (schedule
                        && schedule_period (schedule) == 0
                        && schedule_duration (schedule) == 0
                        /* Check next time too, in case the user changed
                         * the schedule after this task was added to the
                         * "starts" list. */
                        && task_schedule_next_time_uuid (task_uuid) == 0)
                      /* A once-off schedule without a duration, remove
                       * it from the task.  If it has a duration it
                       * will be removed by manage_schedule via
                       * clear_duration_schedules, after the duration. */
                      set_task_schedule_uuid (task_uuid, 0, -1);
                    else if ((periods = task_schedule_periods_uuid
                                         (task_uuid)))
                      {
                        /* A task restricted to a certain number of
                         * scheduled runs. */
                        if (periods > 1)
                          {
                            set_task_schedule_periods (task_uuid,
                                                       periods - 1);
                          }
                        else if (periods == 1
                                 && schedule_duration (schedule) == 0)
                          {
                            /* Last run of a task restricted to a certain
                             * number of scheduled runs. */
                            set_task_schedule_uuid (task_uuid, 0, 1);
                          }
                        else if (periods == 1)
                          /* Flag that the task has started, for
                           * update_duration_schedule_periods. */
                          set_task_schedule_next_time_uuid (task_uuid, 0);
                      }
                  }
                  scheduled_task_free (scheduled_task);
                  gvm_close_sentry ();
                  exit (EXIT_SUCCESS);

                case EXIT_FAILURE:
                default:
                  break;
              }

          /* Child failed, reset task schedule time and exit. */

          g_warning ("%s: child failed", __func__);
          reschedule_task (scheduled_task->task_uuid);
          scheduled_task_free (scheduled_task);
          gvm_close_sentry ();
          exit (EXIT_FAILURE);
        }
    }

  /* Start the task. */

  setproctitle ("scheduler: starting %s", scheduled_task->task_uuid);

  auth_opts = gmp_authenticate_info_opts_defaults;
  auth_opts.username = scheduled_task->owner_name;
  if (gmp_authenticate_info_ext_c (&connection, auth_opts))
    {
      g_warning ("%s: gmp_authenticate failed", __func__);
      scheduled_task_free (scheduled_task);
      gvm_connection_free (&connection);
      gvm_close_sentry ();
      exit (EXIT_FAILURE);
    }

  if (gmp_resume_task_report_c (&connection,
                                scheduled_task->task_uuid,
                                NULL))
    {
      gmp_start_task_opts_t opts;

      opts = gmp_start_task_opts_defaults;
      opts.task_id = scheduled_task->task_uuid;

      switch (gmp_start_task_ext_c (&connection, opts))
        {
          case 0:
            break;

          case 99:
            g_warning ("%s: user denied permission to start task", __func__);
            scheduled_task_free (scheduled_task);
            gvm_connection_free (&connection);
            gvm_close_sentry ();
            /* Return success, so that parent stops trying to start the task. */
            exit (EXIT_SUCCESS);

          default:
            g_warning ("%s: gmp_start_task and gmp_resume_task failed", __func__);
            scheduled_task_free (scheduled_task);
            gvm_connection_free (&connection);
            gvm_close_sentry ();
            exit (EXIT_FAILURE);
        }
    }

  scheduled_task_free (scheduled_task);
  gvm_connection_free (&connection);
  gvm_close_sentry ();
  exit (EXIT_SUCCESS);
}

/**
 * @brief Stop a task, for the scheduler.
 *
 * @param[in]  scheduled_task   Scheduled task.
 * @param[in]  fork_connection  Function that forks a child which is connected
 *                              to the Manager.  Must return PID in parent, 0
 *                              in child, or -1 on error.
 * @param[in]  sigmask_current  Sigmask to restore in child.
 *
 * @return 0 success, -1 error.  Child does not return.
 */
static int
scheduled_task_stop (scheduled_task_t *scheduled_task,
                     manage_connection_forker_t fork_connection,
                     sigset_t *sigmask_current)
{
  gvm_connection_t connection;
  gmp_authenticate_info_opts_t auth_opts;

  /* TODO As with starts above, this should retry if the stop failed. */

  /* Run the callback to fork a child connected to the Manager. */

  switch (fork_connection (&connection, scheduled_task->owner_uuid))
    {
      case 0:
        /* Child.  Break, stop task, exit. */
        break;

      case -1:
        /* Parent on error. */
        g_warning ("%s: stop fork failed", __func__);
        return -1;

      default:
        /* Parent.  Continue to next task. */
        return 0;
    }

  /* Stop the task. */

  setproctitle ("scheduler: stopping %s",
            scheduled_task->task_uuid);

  auth_opts = gmp_authenticate_info_opts_defaults;
  auth_opts.username = scheduled_task->owner_name;
  if (gmp_authenticate_info_ext_c (&connection, auth_opts))
    {
      scheduled_task_free (scheduled_task);
      gvm_connection_free (&connection);
      gvm_close_sentry ();
      exit (EXIT_FAILURE);
    }

  if (gmp_stop_task_c (&connection, scheduled_task->task_uuid))
    {
      scheduled_task_free (scheduled_task);
      gvm_connection_free (&connection);
      gvm_close_sentry ();
      exit (EXIT_FAILURE);
    }

  scheduled_task_free (scheduled_task);
  gvm_connection_free (&connection);
  gvm_close_sentry ();
  exit (EXIT_SUCCESS);
}

/**
 * @brief Check if a feed sync is needed without acquiring the feed lock.
 *
 * @return TRUE if a feed sync is needed, FALSE otherwise.
 */
gboolean
feed_sync_required ()
{
  int feed_status_ret;

  feed_status_ret = secinfo_feed_version_status ("cert");
  switch (feed_status_ret)
    {
      case 1:
      case 2:
      case 3:
      case 4:
        g_debug ("%s: CERT database needs to be updated (status %d)",
                 __func__, feed_status_ret);
        return TRUE;
      default:
        break;
    }

  feed_status_ret = secinfo_feed_version_status ("scap");
  switch (feed_status_ret)
    {
      case 1:
      case 2:
      case 3:
      case 4:
        g_debug ("%s: SCAP database needs to be updated (status %d)",
                 __func__, feed_status_ret);
        return TRUE;
      default:
        break;
    }

  if (!feature_enabled (FEATURE_ID_VT_METADATA))
    {
      if (nvts_feed_version_status_from_scanner () == 1)
        {
          g_debug ("%s: NVTs need to be updated", __func__);
          return TRUE;
        }
    }
  else
    {
      feed_status_ret = nvts_feed_version_status_from_timestamp ();
      switch (feed_status_ret)
        {
        case 1:
        case 2:
        case 3:
          g_debug ("%s: NVTs need to be updated (status %d)",
                   __func__, feed_status_ret);
          return TRUE;
        default:
          break;
        }
    }

  return FALSE;
}

/**
 * @brief Wait for memory
 *
 * @param[in]  check_func  Function to check memory, should return 1 if enough.
 * @param[in]  retries     Number of retries.
 * @param[in]  min_mem     Minimum memory in MiB, for logging only
 * @param[in]  action      Short descriptor of action waiting for memory.
 *
 * @return 0 if enough memory is available, 1 gave up
 */
static int
wait_for_mem (int check_func(),
              int retries,
              int min_mem,
              const char *action)
{
  int retry_number = 0;
  while (check_func () == 0)
    {
      if (retry_number == 0)
        {
          g_info ("%s: not enough memory for %s"
                  " (%lld / %d) MiB",
                  __func__,
                  action,
                  phys_mem_available () / 1048576llu,
                  min_mem);
        }
      else
        {
          g_debug ("%s: waiting for memory for %s"
                   " (%lld / %d) MiB",
                   __func__,
                   action,
                   phys_mem_available () / 1048576llu,
                   min_mem);
        }

      retry_number ++;
      if (retry_number > retries)
        return 1;

      sleep (SCHEDULE_PERIOD);
    }
  return 0;
}

/**
 * @brief Perform any syncing that is due.
 *
 * In gvmd, periodically called from the main daemon loop.
 *
 * @param[in]  sigmask_current  Sigmask to restore in child.
 * @param[in]  fork_update_nvt_cache  Function that forks a child that syncs
 *                                    the NVTS.  Child does not return.
 * @param[in]  try_gvmd_data_sync  Whether to try to sync gvmd data objects.
 */
void
manage_sync (sigset_t *sigmask_current,
             int (*fork_update_nvt_cache) (pid_t*),
             gboolean try_gvmd_data_sync)
{
  lockfile_t lockfile;

  reinit_manage_process ();
  manage_session_init (current_credentials.uuid);

  if (feed_sync_required ())
    {
      if (wait_for_mem (check_min_mem_feed_update,
                        mem_wait_retries,
                        min_mem_feed_update,
                        "SecInfo feed sync") == 0
          && feed_lockfile_lock (&lockfile) == 0)
        {
          pid_t nvts_pid, scap_pid, cert_pid;
          nvts_pid = manage_sync_nvts (fork_update_nvt_cache);
          scap_pid = manage_sync_scap (sigmask_current);
          cert_pid = manage_sync_cert (sigmask_current);

          wait_for_pid (nvts_pid, "NVTs sync");
          wait_for_pid (scap_pid, "SCAP sync");
          wait_for_pid (cert_pid, "CERT sync");

          update_scap_extra ();

          lockfile_unlock (&lockfile);
        }
    }

  if (try_gvmd_data_sync
      && (should_sync_configs ()
          || should_sync_port_lists ()
          || should_sync_report_formats ()
#if ENABLE_AGENTS
          || should_sync_agent_installers ()
#endif /* ENABLE_AGENTS */
          ))
    {
      if (wait_for_mem (check_min_mem_feed_update,
                        mem_wait_retries,
                        min_mem_feed_update,
                        "data objects feed sync") == 0
          && feed_lockfile_lock (&lockfile) == 0)
        {
#if ENABLE_AGENTS
          if (feature_enabled (FEATURE_ID_AGENTS))
            {
              manage_sync_agent_installers ();
            }
          else
            {
              g_debug (
                "%s: AGENTS runtime flag is disabled; skipping agent installers sync",
                __func__);
            }
#endif /* ENABLE_AGENTS */
          manage_sync_configs ();
          /* After config sync, update discovery nvts */
          manage_discovery_nvts ();
          manage_sync_port_lists ();
          manage_sync_report_formats ();

          lockfile_unlock (&lockfile);
        }
    }
}

/**
 * @brief Handle queued task actions like the scan queue or report processing.
 */
void
manage_queued_task_actions ()
{
  reinit_manage_process ();
  manage_session_init (current_credentials.uuid);

  setproctitle ("Manage process report imports");
  manage_process_report_imports ();
  setproctitle ("Manage scan queue");
  manage_handle_scan_queue ();
}

/**
 * @brief Perform any processing of imported reports that is due.
 *
 * In gvmd, periodically called from the main daemon loop.
 */
void
manage_process_report_imports ()
{
  lockfile_t lockfile;
  iterator_t reports;
  report_t report;
  int pid, ret;
  struct sigaction action;

  init_report_awaiting_processing_iterator (&reports, MAX_REPORTS_PER_TICK);

  while (next (&reports))
    {
      report = iterator_int64 (&reports, 0);

      gchar *lockfile_path =
        g_build_filename (GVMD_STATE_DIR,
                          g_strdup_printf ("gvm-process-report-%llu", report),
                          NULL);
      ret = lockfile_lock_path_nb (&lockfile, lockfile_path);
      if (ret > 0)
        {
          g_debug ("%s: Report %llu is already being processed",
                   __func__,
                   report);
          continue;
        }
      if (ret < 0)
        {
          g_critical ("%s: Error getting lock for report %llu",
                      __func__,
                      report);
          cleanup_iterator (&reports);
          return;
        }

      pid = fork ();
      switch (pid)
        {
          case 0:
            /* Child.   */

            init_sentry ();
            setproctitle ("process report import");

            if (semaphore_op (SEMAPHORE_REPORTS_PROCESSING, -1, 1))
              {
                g_debug ("%s: Failed to signal reports processing semaphore",
                         __func__);
                exit (EXIT_SUCCESS);
              }

            // Reset SIGCHLD handler to default so the process can
            // use common functions to wait for its own child processes.
            memset (&action, '\0', sizeof (action));
            sigemptyset (&action.sa_mask);
            action.sa_handler = SIG_DFL;
            action.sa_flags = 0;
            if (sigaction (SIGCHLD, &action, NULL) == -1)
              {
                g_critical ("%s: failed to set SIGCHLD handler: %s",
                            __func__,
                            strerror (errno));
                gvm_close_sentry ();
                exit (EXIT_FAILURE);
              }

            /* Clean up the process. */
            cleanup_manage_process (FALSE);

            init_sentry ();
            reinit_manage_process ();

            if (process_report_import (report))
              {
                lockfile_unlock (&lockfile);
                if (unlink (lockfile_path))
                  g_warning ("%s: Failed to delete lock file %s: %s",
                            __func__,
                            lockfile_path,
                            strerror (errno));
                g_free (lockfile_path);
                set_report_scan_run_status (report, TASK_STATUS_INTERRUPTED);
                g_warning ("%s: failed to process imported report %llu",
                           __func__,
                           report);
                gvm_close_sentry ();
                semaphore_op (SEMAPHORE_REPORTS_PROCESSING, +1, 0);
                exit (EXIT_FAILURE);
              }

            lockfile_unlock (&lockfile);
            if (unlink (lockfile_path))
              g_warning ("%s: Failed to delete lock file %s: %s",
                         __func__,
                         lockfile_path,
                         strerror (errno));
            g_free (lockfile_path);
            semaphore_op (SEMAPHORE_REPORTS_PROCESSING, +1, 0);

            cleanup_manage_process (TRUE);
            gvm_close_sentry ();
            exit (EXIT_SUCCESS);

          case -1:
            /* Parent when error. */
            g_warning ("%s: fork: %s", __func__, strerror (errno));
            lockfile_unlock (&lockfile);
            if (unlink (lockfile_path))
              g_warning ("%s: Failed to delete lock file %s: %s",
                         __func__,
                         lockfile_path,
                         strerror (errno));
            g_free (lockfile_path);
            cleanup_iterator (&reports);
            return;

          default:
            /* Parent. */
            g_debug ("%s: %i forked %i", __func__, getpid (), pid);
            continue;
          }
    }
  cleanup_iterator (&reports);
}

/**
 * @brief Adds a switch statement for handling the return value of a
 *        gvmd data rebuild.
 * @param type  The type as a description string, e.g. "port lists"
 */
#define REBUILD_SWITCH(type) \
  switch (ret)                                                              \
    {                                                                       \
      case 0:                                                               \
        g_message ("Rebuilt %s from feed.", type);                          \
        break;                                                              \
      case 1:                                                               \
        if (error_msg)                                                      \
          *error_msg = g_strdup_printf ("No %s feed directory.",            \
                                        type);                              \
        return -1;                                                          \
      case 2:                                                               \
        if (error_msg)                                                      \
          *error_msg = g_strdup_printf ("Feed owner not set or invalid"     \
                                        " while rebuilding %s.",            \
                                        type);                              \
        return -1;                                                          \
      case 3:                                                               \
        if (error_msg)                                                      \
          *error_msg = g_strdup_printf ("NVTs must be available"            \
                                        " while rebuilding %s.",            \
                                        type);                              \
        return -1;                                                          \
      default:                                                              \
        if (error_msg)                                                      \
          *error_msg = g_strdup_printf ("Internal error"                    \
                                        " while rebuilding %s.",            \
                                        type);                              \
        return -1;                                                          \
    }

/**
 * @brief Rebuild configs, port lists and report formats from feed.
 *
 * @param[in]  types      Comma-separated lists of types to rebuild or "all".
 * @param[in]  log_config Logging configuration list.
 * @param[in]  database   Connection info for manage database.
 * @param[out] error_msg  Error message.
 *
 * @return 0 success, -1 failed.
 */
int
manage_rebuild_gvmd_data_from_feed (const char *types,
                                    GSList *log_config,
                                    const db_conn_info_t *database,
                                    gchar **error_msg)
{
  int ret;
  lockfile_t lockfile;
  gboolean sync_configs, sync_port_lists, sync_report_formats;

  sync_configs = sync_port_lists = sync_report_formats = FALSE;

  if (strcasecmp (types, "all") == 0)
    {
      sync_configs = TRUE;
      sync_port_lists = TRUE;
      sync_report_formats = TRUE;
    }
  else
    {
      gchar **split, **split_iter;
      split = g_strsplit (types, ",", -1);

      if (*split == NULL)
        {
          g_free (split);
          if (error_msg)
            *error_msg = g_strdup ("No types given.");
          return -1;
        }

      split_iter = split;
      while (*split_iter)
        {
          gchar *type = g_strstrip (*split_iter);

          if (strcasecmp (type, "configs") == 0)
            sync_configs = TRUE;
          else if (strcasecmp (type, "port_lists") == 0)
            sync_port_lists = TRUE;
          else if (strcasecmp (type, "report_formats") == 0)
            sync_report_formats = TRUE;
          else
            {
              if (error_msg)
                *error_msg = g_strdup_printf ("Invalid type \"%s\""
                                              " (must be \"configs\","
                                              " \"port_lists\","
                                              " \"report_formats\""
                                              " or \"all\")",
                                              type);
              g_strfreev (split);
              return -1;
            }
          split_iter ++;
        }
      g_strfreev (split);
    }

  ret = feed_lockfile_lock_timeout (&lockfile);
  if (ret == 1)
    {
      if (error_msg)
        *error_msg = g_strdup ("Feed locked.");
      return -1;
    }
  else if (ret)
    {
      if (error_msg)
        *error_msg = g_strdup ("Error acquiring feed lock.");
      return -1;
    }

  ret = manage_option_setup (log_config, database,
                             0 /* avoid_db_check_inserts */);
  if (ret)
    {
      if (error_msg)
        *error_msg = g_strdup ("Error setting up log config or"
                               " database connection.");
      return -1;
    }

  if (sync_configs)
    {
      g_message ("Rebuilding configs from feed...");
      ret = manage_rebuild_configs ();
      REBUILD_SWITCH ("configs")
    }

  if (sync_port_lists)
    {
      g_message ("Rebuilding port lists from feed...");
      ret = manage_rebuild_port_lists ();
      REBUILD_SWITCH ("port lists")
    }

  if (sync_report_formats)
    {
      g_message ("Rebuilding report formats from feed...");
      ret = manage_rebuild_report_formats ();
      REBUILD_SWITCH ("report formats")
    }

  feed_lockfile_unlock (&lockfile);
  return 0;
}

#undef REBUILD_SWITCH

/**
 * @brief Schedule any actions that are due.
 *
 * In gvmd, periodically called from the main daemon loop.
 *
 * @param[in]  fork_connection  Function that forks a child which is connected
 *                              to the Manager.  Must return PID in parent, 0
 *                              in child, or -1 on error.
 * @param[in]  run_tasks        Whether to run scheduled tasks.
 * @param[in]  sigmask_current  Sigmask to restore in child.
 *
 * @return 0 success, 1 failed to get lock, -1 error.
 */
int
manage_schedule (manage_connection_forker_t fork_connection,
                 gboolean run_tasks,
                 sigset_t *sigmask_current)
{
  iterator_t schedules;
  GSList *starts, *stops;
  int ret;
  task_t previous_start_task, previous_stop_task;

  starts = NULL;
  stops = NULL;
  previous_start_task = 0;
  previous_stop_task = 0;

  auto_delete_reports ();

  ret = manage_update_nvti_cache ();
  if (ret)
    {
      if (ret == -1)
        {
          g_warning ("%s: manage_update_nvti_cache error"
                     " (Perhaps the db went down?)",
                     __func__);
          /* Just ignore, in case the db went down temporarily. */
          return 0;
        }

      return ret;
    }

  if (run_tasks == 0)
    return 0;

  /* Assemble "starts" and "stops" list containing task uuid, owner name and
   * owner UUID for each (scheduled) task to start or stop. */

  ret = init_task_schedule_iterator (&schedules);
  if (ret)
    {
      if (ret == -1)
        {
          g_warning ("%s: iterator init error"
                     " (Perhaps the db went down?)",
                     __func__);
          /* Just ignore, in case the db went down temporarily. */
          return 0;
        }

      return ret;
    }
  /* This iterator runs in a transaction. */
  while (next (&schedules))
    if (task_schedule_iterator_start_due (&schedules))
      {
        const char *icalendar, *zone;
        int timed_out;

        /* Check if task schedule is timed out before updating next due time */
        timed_out = task_schedule_iterator_timed_out (&schedules);

        /* Update the task schedule info to prevent multiple schedules. */

        icalendar = task_schedule_iterator_icalendar (&schedules);
        zone = task_schedule_iterator_timezone (&schedules);

        g_debug ("%s: start due for %llu, setting next_time",
                 __func__,
                 task_schedule_iterator_task (&schedules));
        set_task_schedule_next_time
         (task_schedule_iterator_task (&schedules),
          icalendar_next_time_from_string (icalendar, time(NULL), zone, 0));

        /* Skip this task if it was already added to the starts list
         * to avoid conflicts between multiple users with permissions. */

        if (previous_start_task == task_schedule_iterator_task (&schedules))
          continue;

        if (timed_out)
          {
            g_message (" %s: Task timed out: %s",
                       __func__,
                       task_schedule_iterator_task_uuid (&schedules));
            continue;
          }

        previous_start_task = task_schedule_iterator_task (&schedules);

        /* Add task UUID and owner name and UUID to the list. */

        starts = g_slist_prepend
                  (starts,
                   scheduled_task_new
                    (task_schedule_iterator_task_uuid (&schedules),
                     task_schedule_iterator_owner_uuid (&schedules),
                     task_schedule_iterator_owner_name (&schedules)));
      }
    else if (task_schedule_iterator_stop_due (&schedules))
      {
        /* Skip this task if it was already added to the stops list
         * to avoid conflicts between multiple users with permissions. */

        if (previous_stop_task == task_schedule_iterator_task (&schedules))
          continue;
        previous_stop_task = task_schedule_iterator_task (&schedules);

        /* Add task UUID and owner name and UUID to the list. */

        stops = g_slist_prepend
                 (stops,
                  scheduled_task_new
                   (task_schedule_iterator_task_uuid (&schedules),
                    task_schedule_iterator_owner_uuid (&schedules),
                    task_schedule_iterator_owner_name (&schedules)));
      }
  cleanup_task_schedule_iterator (&schedules);

  /* Start tasks in forked processes, now that the SQL statement is closed. */

  while (starts)
    {
      scheduled_task_t *scheduled_task;
      GSList *head;

      scheduled_task = starts->data;

      head = starts;
      starts = starts->next;
      g_slist_free_1 (head);

      if (scheduled_task_start (scheduled_task,
                                fork_connection,
                                sigmask_current))
        /* Error.  Reschedule and continue to next task. */
        reschedule_task (scheduled_task->task_uuid);
      scheduled_task_free (scheduled_task);
    }

  /* Stop tasks in forked processes, now that the SQL statement is closed. */

  while (stops)
    {
      scheduled_task_t *scheduled_task;
      GSList *head;

      scheduled_task = stops->data;
      head = stops;
      stops = stops->next;
      g_slist_free_1 (head);

      if (scheduled_task_stop (scheduled_task,
                               fork_connection,
                               sigmask_current))
        {
          /* Error.  Exit. */
          scheduled_task_free (scheduled_task);
          while (stops)
            {
              scheduled_task_free (stops->data);
              stops = g_slist_delete_link (stops, stops);
            }
          return -1;
        }
      scheduled_task_free (scheduled_task);
    }

  clear_duration_schedules (0);
  update_duration_schedule_periods (0);

  return 0;
}

/**
 * @brief Get the current schedule timeout.
 *
 * @return The schedule timeout in minutes.
 */
int
get_schedule_timeout ()
{
  return schedule_timeout;
}

/**
 * @brief Set the schedule timeout.
 *
 * @param new_timeout The new schedule timeout in minutes.
 */
void
set_schedule_timeout (int new_timeout)
{
  if (new_timeout < 0)
    schedule_timeout = -1;
  else
    schedule_timeout = new_timeout;
}


/* SecInfo. */

/* Defined in gmp.c. */
void buffer_config_preference_xml (GString *, iterator_t *, config_t, int);

/**
 * @brief Compute the filename where a given CVE can be found.
 *
 * @param[in] item_id   Full CVE identifier ("CVE-YYYY-ZZZZ").
 *
 * @return A dynamically allocated string (to be g_free'd) containing the
 *         path to the desired file or NULL on error.
 */
static char *
get_cve_filename (char *item_id)
{
  int year;

  if (sscanf (item_id, "%*3s-%d-%*d", &year) == 1)
    {
      /* CVEs before 2002 are stored in the 2002 file. */
      if (year <= 2002)
        year = 2002;
      return g_strdup_printf (CVE_FILENAME_FMT, year);
    }
  return NULL;
}

/**
 * @brief Compute the filename where a given CERT-Bund Advisory can be found.
 *
 * @param[in] item_id   CERT-Bund identifier without version
 *                      ("CB-K??/????" or "WID-SEC-????-????")
 *
 * @return A dynamically allocated string (to be g_free'd) containing the
 *         path to the desired file or NULL on error.
 */
static char *
get_cert_bund_adv_filename (char *item_id)
{
  int year;

  if (sscanf (item_id, "CB-K%d-%*s", &year) == 1)
    {
      return g_strdup_printf (CERT_BUND_ADV_FILENAME_FMT, year);
    }
  if (sscanf (item_id, "WID-SEC-%d-%*s", &year) == 1)
    {
      // new year format is YYYY thus subtract 2000 from the int
      return g_strdup_printf (CERT_BUND_ADV_FILENAME_FMT, year - 2000);
    }
  return NULL;
}

/**
 * @brief Compute the filename where a given DFN-CERT Advisory can be found.
 *
 * @param[in] item_id   Full DFN-CERT identifier ("DFN-CERT-YYYY-ZZZZ").
 *
 * @return A dynamically allocated string (to be g_free'd) containing the
 *         path to the desired file or NULL on error.
 */
static char *
get_dfn_cert_adv_filename (char *item_id)
{
  int year;

  if (sscanf (item_id, "DFN-CERT-%d-%*s", &year) == 1)
    {
      return g_strdup_printf (DFN_CERT_ADV_FILENAME_FMT, year);
    }
  return NULL;
}

/**
 * @brief Run xsltproc in an external process.
 *
 * @param[in] stylesheet    XSL stylesheet to use.
 * @param[in] xmlfile       XML file to process.
 * @param[in] param_names   NULL terminated array of stringparam names (can
 *                          be NULL).
 * @param[in] param_values  NULL terminated array of stringparam values (can
 *                          be NULL).
 *
 * @return A dynamically allocated (to be g_free'd) string containing the
 *         result of the operation of NULL on failure.
 */
static gchar *
xsl_transform (gchar *stylesheet, gchar *xmlfile, gchar **param_names,
               gchar **param_values)
{
  int i, param_idx;
  gchar **cmd, *cmd_full;
  gint exit_status;
  gboolean success;
  gchar *standard_out = NULL, *standard_err = NULL;

  param_idx = 0;
  if (param_names && param_values)
    while (param_names[param_idx] && param_values[param_idx])
      param_idx++;

  cmd = (gchar **)g_malloc ((4 + param_idx * 3) * sizeof (gchar *));

  i = 0;
  cmd[i++] = "xsltproc";
  if (param_idx)
    {
      int j;

      for (j = 0; j < param_idx; j++)
        {
          cmd[i++] = "--stringparam";
          cmd[i++] = param_names[j];
          cmd[i++] = param_values[j];
        }
    }
  cmd[i++] = stylesheet;
  cmd[i++] = xmlfile;
  cmd[i] = NULL;


  /* DEBUG: display the final command line. */
  cmd_full = g_strjoinv (" ", cmd);
  g_debug ("%s: Spawning in parent dir: %s",
           __func__, cmd_full);
  g_free (cmd_full);
  /* --- */

  if ((g_spawn_sync (NULL,
                     cmd,
                     NULL,                  /* Environment. */
                     G_SPAWN_SEARCH_PATH,
                     NULL,                  /* Setup function. */
                     NULL,
                     &standard_out,
                     &standard_err,
                     &exit_status,
                     NULL)
       == FALSE)
      || (WIFEXITED (exit_status) == 0)
      || WEXITSTATUS (exit_status))
    {
      g_warning ("%s: failed to transform the xml: %d (WIF %i, WEX %i)",
                 __func__,
                 exit_status,
                 WIFEXITED (exit_status),
                 WEXITSTATUS (exit_status));
      g_debug ("%s: stderr: %s", __func__, standard_err);
      g_debug ("%s: stdout: %s", __func__, standard_out);
      success = FALSE;
    }
  else if (strlen (standard_out) == 0)
    success = FALSE; /* execution succeeded but nothing was found */
  else
    success = TRUE; /* execution succeeded and we have a result */

  /* Cleanup. */
  g_free (cmd);
  g_free (standard_err);

  if (success)
    return standard_out;

  g_free (standard_out);
  return NULL;
}

/**
 * @brief Define a code snippet for get_nvti_xml.
 *
 * @param  x  Prefix for names in snippet.
 */
#define DEF(x)                                                    \
      const char* x = nvt_iterator_ ## x (nvts);                  \
      gchar* x ## _text = x                                       \
                          ? g_markup_escape_text (x, -1)          \
                          : g_strdup ("");

/**
 * @brief Create and return XML description for an NVT.
 *
 * @param[in]  nvts        The NVT.
 * @param[in]  details     If true, detailed XML, else simple XML.
 * @param[in]  pref_count  Preference count.  Used if details is true.
 * @param[in]  preferences If true, included preferences.
 * @param[in]  timeout     Timeout.  Used if details is true.
 * @param[in]  config      Config, used if preferences is true.
 * @param[in]  close_tag   Whether to close the NVT tag or not.
 * @param[in]  skip_cert_refs  Whether to exclude the CERT REFs.
 * @param[in]  skip_tags       Whether to exclude the tags.
 * @param[in]  lean            Whether to send fewer details.
 *
 * @return A dynamically allocated string containing the XML description.
 */
gchar *
get_nvt_xml (iterator_t *nvts, int details, int pref_count,
             int preferences, const char *timeout, config_t config,
             int close_tag, int skip_cert_refs, int skip_tags, int lean)
{
  const char* oid = nvt_iterator_oid (nvts);
  const char* name = nvt_iterator_name (nvts);
  gchar *msg, *name_text;

  name_text = name
               ? g_markup_escape_text (name, strlen (name))
               : g_strdup ("");
  if (details)
    {
      int tag_count;
      GString *refs_str, *tags_str, *buffer;
      iterator_t cert_refs_iterator, tags;
      gchar *tag_name_esc, *tag_value_esc, *tag_comment_esc;

      DEF (family);

      refs_str = g_string_new ("");

      if (skip_cert_refs)
        {
          // Faster.
        }
      else if (manage_cert_loaded())
        {
          init_nvt_cert_bund_adv_iterator (&cert_refs_iterator, oid);
          while (next (&cert_refs_iterator))
            {
              xml_string_append (refs_str,
                                 "<ref type=\"cert-bund\" id=\"%s\"/>",
                                 nvt_cert_bund_adv_iterator_name
                                  (&cert_refs_iterator));
            }
          cleanup_iterator (&cert_refs_iterator);

          init_nvt_dfn_cert_adv_iterator (&cert_refs_iterator, oid);
          while (next (&cert_refs_iterator))
            {
              xml_string_append (refs_str,
                                 "<ref type=\"dfn-cert\" id=\"%s\"/>",
                                 nvt_dfn_cert_adv_iterator_name
                                  (&cert_refs_iterator));
            }
          cleanup_iterator (&cert_refs_iterator);
        }
      else
        {
          g_string_append (refs_str,
                           "<warning>database not available</warning>");
        }

      xml_append_nvt_refs (refs_str, oid, NULL);

      if (skip_tags)
        tags_str = NULL;
      else
        {
          tags_str = g_string_new ("");
          tag_count = resource_tag_count ("nvt",
                                          get_iterator_resource (nvts),
                                          1);
        }

      if (tags_str && tag_count)
        {
          g_string_append_printf (tags_str,
                                  "<user_tags>"
                                  "<count>%i</count>",
                                  tag_count);

          init_resource_tag_iterator (&tags, "nvt",
                                      get_iterator_resource (nvts),
                                      1, NULL, 1);
          while (next (&tags))
            {
              tag_name_esc = g_markup_escape_text (resource_tag_iterator_name
                                                    (&tags),
                                                  -1);
              tag_value_esc = g_markup_escape_text (resource_tag_iterator_value
                                                      (&tags),
                                                    -1);
              tag_comment_esc = g_markup_escape_text (resource_tag_iterator_comment
                                                        (&tags),
                                                      -1);
              g_string_append_printf (tags_str,
                                      "<tag id=\"%s\">"
                                      "<name>%s</name>"
                                      "<value>%s</value>"
                                      "<comment>%s</comment>"
                                      "</tag>",
                                      resource_tag_iterator_uuid (&tags),
                                      tag_name_esc,
                                      tag_value_esc,
                                      tag_comment_esc);
              g_free (tag_name_esc);
              g_free (tag_value_esc);
              g_free (tag_comment_esc);
            }
          cleanup_iterator (&tags);
          g_string_append_printf (tags_str,
                                  "</user_tags>");
        }

      buffer = g_string_new ("");

      g_string_append_printf (buffer,
                              "<nvt oid=\"%s\">"
                              "<name>%s</name>"
                              "%s" // user_tags
                              "<preference_count>%i</preference_count>"
                              "<timeout>%s</timeout>",
                              oid,
                              name_text,
                              tags_str ? tags_str->str : "",
                              pref_count,
                              timeout ? timeout : "");

      if (lean == 0)
        {
          char *default_timeout;
          GString *nvt_tags;

          DEF (tag);

#undef DEF

          nvt_tags = g_string_new (tag_text);
          g_free (tag_text);

          /* Add the elements that are expected as part of the pipe-separated tag list
           * via API although internally already explicitly stored. Once the API is
           * extended to have these elements explicitly, they do not need to be
           * added to this tag string anymore. */
          if (nvt_iterator_summary (nvts) && nvt_iterator_summary (nvts)[0])
            {
              if (nvt_tags->str)
                xml_string_append (nvt_tags, "|summary=%s",
                                   nvt_iterator_summary (nvts));
              else
                xml_string_append (nvt_tags, "summary=%s",
                                   nvt_iterator_summary (nvts));
            }
          if (nvt_iterator_insight (nvts) && nvt_iterator_insight (nvts)[0])
            {
              if (nvt_tags->str)
                xml_string_append (nvt_tags, "|insight=%s",
                                   nvt_iterator_insight (nvts));
              else
                xml_string_append (nvt_tags, "insight=%s",
                                   nvt_iterator_insight (nvts));
            }
          if (nvt_iterator_affected (nvts) && nvt_iterator_affected (nvts)[0])
            {
              if (nvt_tags->str)
                xml_string_append (nvt_tags, "|affected=%s",
                                   nvt_iterator_affected (nvts));
              else
                xml_string_append (nvt_tags, "affected=%s",
                                   nvt_iterator_affected (nvts));
            }
          if (nvt_iterator_impact (nvts) && nvt_iterator_impact (nvts)[0])
            {
              if (nvt_tags->str)
                xml_string_append (nvt_tags, "|impact=%s",
                                   nvt_iterator_impact (nvts));
              else
                xml_string_append (nvt_tags, "impact=%s",
                                   nvt_iterator_impact (nvts));
            }
          if (nvt_iterator_detection (nvts) && nvt_iterator_detection (nvts)[0])
            {
              if (nvt_tags->str)
                xml_string_append (nvt_tags, "|vuldetect=%s",
                                   nvt_iterator_detection (nvts));
              else
                xml_string_append (nvt_tags, "vuldetect=%s",
                                   nvt_iterator_detection (nvts));
            }

          g_string_append_printf (buffer,
                                  "<creation_time>%s</creation_time>",
                                  iso_if_time (get_iterator_creation_time (nvts)));

          g_string_append_printf (buffer,
                                  "<modification_time>%s</modification_time>",
                                  iso_if_time (get_iterator_modification_time (nvts)));

          default_timeout = nvt_default_timeout (oid);

          g_string_append_printf (buffer,
                                  "<default_timeout>%s</default_timeout>"
                                  "<category>%d</category>"
                                  "<family>%s</family>"
                                  "<qod>"
                                  "<value>%s</value>"
                                  "<type>%s</type>"
                                  "</qod>"
                                  "<refs>%s</refs>"
                                  "<tags>%s</tags>",
                                  default_timeout ? default_timeout : "",
                                  nvt_iterator_category (nvts),
                                  family_text,
                                  nvt_iterator_qod (nvts),
                                  nvt_iterator_qod_type (nvts),
                                  refs_str->str,
                                  nvt_tags->str);

          free (default_timeout);

          g_string_free (nvt_tags, 1);
        }

      g_string_append_printf (buffer,
                              "<cvss_base>%s</cvss_base>",
                              nvt_iterator_cvss_base (nvts)
                              ? nvt_iterator_cvss_base (nvts)
                              : "");

      if (lean == 0)
        {
          iterator_t severities;

          g_string_append_printf (buffer,
                                  "<severities score=\"%s\">",
                                  nvt_iterator_cvss_base (nvts)
                                  ? nvt_iterator_cvss_base (nvts)
                                  : "");

          init_nvt_severity_iterator (&severities, oid);
          while (next (&severities))
            {
              buffer_xml_append_printf
                (buffer,
                 "<severity type=\"%s\">"
                 "<origin>%s</origin>"
                 "<date>%s</date>"
                 "<score>%0.1f</score>"
                 "<value>%s</value>"
                 "</severity>",
                 nvt_severity_iterator_type (&severities),
                 nvt_severity_iterator_origin (&severities),
                 nvt_severity_iterator_date (&severities),
                 nvt_severity_iterator_score (&severities),
                 nvt_severity_iterator_value (&severities));
            }
          cleanup_iterator (&severities);

          g_string_append_printf (buffer,
                                  "</severities>");
        }

      g_free (family_text);
      g_string_free (refs_str, 1);
      if (tags_str)
        g_string_free (tags_str, 1);

      if (lean == 0
          && (nvt_iterator_solution (nvts)
              || nvt_iterator_solution_type (nvts)
              || nvt_iterator_solution_method (nvts)))
        {
          buffer_xml_append_printf (buffer, "<solution");

          if (nvt_iterator_solution_type (nvts))
            buffer_xml_append_printf (buffer, " type='%s'",
              nvt_iterator_solution_type (nvts));

          if (nvt_iterator_solution_method (nvts))
            buffer_xml_append_printf (buffer, " method='%s'",
              nvt_iterator_solution_method (nvts));

          if (nvt_iterator_solution (nvts))
            buffer_xml_append_printf (buffer, ">%s</solution>",
              nvt_iterator_solution (nvts));
          else
            buffer_xml_append_printf (buffer, "/>");
        }

      if (preferences)
        {
          iterator_t prefs;
          char *default_timeout;
          const char *nvt_oid;

          default_timeout = nvt_default_timeout (oid);
          nvt_oid = nvt_iterator_oid (nvts);

          /* Send the preferences for the NVT. */

          xml_string_append (buffer,
                             "<preferences>"
                             "<timeout>%s</timeout>"
                             "<default_timeout>%s</default_timeout>",
                             timeout ? timeout : "",
                             default_timeout ? default_timeout : "");

          init_nvt_preference_iterator (&prefs, nvt_oid, FALSE);
          while (next (&prefs))
            buffer_config_preference_xml (buffer, &prefs, config, 1);
          cleanup_iterator (&prefs);

          xml_string_append (buffer, "</preferences>");
          free (default_timeout);
        }

      if (nvt_iterator_epss_cve (nvts))
        {
          buffer_xml_append_printf
             (buffer,
              "<epss>"
              "<max_severity>"
              "<score>%0.5f</score>"
              "<percentile>%0.5f</percentile>"
              "<cve id=\"%s\">",
              nvt_iterator_epss_score (nvts),
              nvt_iterator_epss_percentile (nvts),
              nvt_iterator_epss_cve (nvts));

          if (nvt_iterator_has_epss_severity (nvts))
            {
              buffer_xml_append_printf
                 (buffer,
                  "<severity>%0.1f</severity>",
                  nvt_iterator_epss_severity (nvts));
            }

          buffer_xml_append_printf
             (buffer,
              "</cve>"
              "</max_severity>"
              "<max_epss>"
              "<score>%0.5f</score>"
              "<percentile>%0.5f</percentile>"
              "<cve id=\"%s\">",
              nvt_iterator_max_epss_score (nvts),
              nvt_iterator_max_epss_percentile (nvts),
              nvt_iterator_max_epss_cve (nvts));

          if (nvt_iterator_has_max_epss_severity (nvts))
            {
              buffer_xml_append_printf
                 (buffer,
                  "<severity>%0.1f</severity>",
                  nvt_iterator_max_epss_severity (nvts));
            }

          buffer_xml_append_printf
             (buffer,
              "</cve>"
              "</max_epss>"
              "</epss>");
        }

      /* add discovery value */
      buffer_xml_append_printf
        (buffer,
         "<discovery>%d</discovery>",
         nvt_iterator_discovery (nvts));

      xml_string_append (buffer, close_tag ? "</nvt>" : "");
      msg = g_string_free (buffer, FALSE);
    }
  else
    {
      int tag_count;
      tag_count = resource_tag_count ("nvt",
                                      get_iterator_resource (nvts),
                                      1);

      GString *buffer = g_string_new (NULL);

      buffer_xml_append_printf (buffer,
                                "<nvt oid=\"%s\"><name>%s</name>",
                                oid, name_text);

      /* optional tags */
      if (tag_count)
        buffer_xml_append_printf (buffer,
                                  "<user_tags><count>%i</count></user_tags>",
                                  tag_count);

      /* add discovery value */
      buffer_xml_append_printf (buffer,
                                "<discovery>%d</discovery>",
                                nvt_iterator_discovery (nvts));

      /* close */
      xml_string_append (buffer, close_tag ? "</nvt>" : "");
      msg = g_string_free (buffer, FALSE);
    }
  g_free (name_text);
  return msg;
}

/**
 * @brief GET SCAP update time, as a string.
 *
 * @return Last update time as a static string, or "" on error.
 */
const char *
manage_scap_update_time ()
{
  gchar *content;
  GError *error;
  gsize content_size;
  struct tm update_time;

  /* Read in the contents. */

  error = NULL;
  if (g_file_get_contents (SCAP_TIMESTAMP_FILENAME,
                           &content,
                           &content_size,
                           &error)
      == FALSE)
    {
      if (error)
        {
          g_debug ("%s: failed to read %s: %s",
                   __func__, SCAP_TIMESTAMP_FILENAME, error->message);
          g_error_free (error);
        }
      return "";
    }

  memset (&update_time, 0, sizeof (struct tm));
  if (strptime (content, "%Y%m%d%H%M", &update_time))
    {
      static char time_string[100];
      #if !defined(__GLIBC__)
        strftime (time_string, 99, "%Y-%m-%dT%T.000", &update_time);
      #else
        strftime (time_string, 99, "%FT%T.000%z", &update_time);
      #endif
      return time_string;
    }
  return "";
}

/**
 * @brief Read raw information.
 *
 * @param[in]   type    Type of the requested information.
 * @param[in]   uid     Unique identifier of the requested information
 * @param[in]   name    Name or identifier of the requested information.
 * @param[out]  result  Pointer to the read information location. Will point
 *                      to NULL on error.
 *
 * @return 1 success, -1 error.
 */
int
manage_read_info (gchar *type, gchar *uid, gchar *name, gchar **result)
{
  gchar *fname;
  gchar *pnames[2] = { "refname", NULL };
  gchar *pvalues[2] = { name, NULL };

  assert (result != NULL);
  *result = NULL;

  if (g_ascii_strcasecmp ("CPE", type) == 0)
    {
      *result = cpe_details_xml(uid);
    }
  else if (g_ascii_strcasecmp ("CVE", type) == 0)
    {
      fname = get_cve_filename (uid);
      if (fname)
        {
          gchar *cve;
          cve = xsl_transform (CVE_GETBYNAME_XSL, fname, pnames, pvalues);
          g_free (fname);
          if (cve)
            *result = cve;
        }
    }
  else if (g_ascii_strcasecmp ("NVT", type) == 0)
    {
      iterator_t nvts;
      nvt_t nvt;

      if (!find_nvt (uid ? uid : name, &nvt) && nvt)
        {
          init_nvt_iterator (&nvts, nvt, 0, NULL, NULL, 0, NULL);

          if (next (&nvts))
            *result = get_nvt_xml (&nvts,
                                   1,    /* Include details. */
                                   0,    /* Preference count. */
                                   1,    /* Include preferences. */
                                   NULL, /* Timeout. */
                                   0,    /* Config. */
                                   1,    /* Close tag. */
                                   0,    /* Skip CERT refs. */
                                   0,    /* Skip tags. */
                                   0);   /* Lean. */

          cleanup_iterator (&nvts);
        }
    }
  else if (g_ascii_strcasecmp ("CERT_BUND_ADV", type) == 0)
    {
      fname = get_cert_bund_adv_filename (uid);
      if (fname)
        {
          gchar *adv;
          adv = xsl_transform (CERT_BUND_ADV_GETBYNAME_XSL, fname,
                               pnames, pvalues);
          g_free (fname);
          if (adv)
            *result = adv;
        }
    }
  else if (g_ascii_strcasecmp ("DFN_CERT_ADV", type) == 0)
    {
      fname = get_dfn_cert_adv_filename (uid);
      if (fname)
        {
          gchar *adv;
          adv = xsl_transform (DFN_CERT_ADV_GETBYNAME_XSL, fname,
                               pnames, pvalues);
          g_free (fname);
          if (adv)
            *result = adv;
        }
    }

  if (*result == NULL)
    return -1;

  return 1;
}


/* Users. */


/* Resource aggregates. */

/**
 * @brief Free a sort_data_t struct and its related resources.
 *
 * @param[in] sort_data  The sort_data struct to free.
 */
void
sort_data_free (sort_data_t *sort_data)
{
  g_free (sort_data->field);
  g_free (sort_data->stat);
  g_free (sort_data);
}


/* Feeds. */

/**
 * @brief Tests if the gvmd data feed directory and its subdirectories exist.
 *
 * @return TRUE if the directory exists.
 */
gboolean
manage_gvmd_data_feed_dirs_exist ()
{
  return gvm_file_is_readable (GVMD_FEED_DIR)
#if ENABLE_AGENTS
// TODO: Add this check once the agent installers are added to the feed
//         && agent_installers_feed_metadata_file_exists ()
#endif
         && configs_feed_dir_exists ()
         && port_lists_feed_dir_exists ()
         && report_formats_feed_dir_exists ();
}

/**
 * @brief Get the authentication cache timeout.
 *
 * @return The current timeout in minutes.
 */
int
get_auth_timeout ()
{
  return auth_timeout;
}

/**
 * @brief Set the authentication cache timeout.
 *
 * @param new_timeout The new timeout in minutes.
 */
void
set_auth_timeout (int new_timeout)
{
  if (new_timeout < 1)
    auth_timeout = 1;
  else
    auth_timeout = new_timeout;
}

/**
 * @brief Get the publish-subscribe messaging (MQTT) broker address.
 *
 * @return The current broker address.
 */
const gchar *
get_broker_address ()
{
  return broker_address;
}

/**
 * @brief Set the publish-subscribe messaging (MQTT) broker address.
 *
 * @param new_address The new broker address.
 */
void
set_broker_address (const char *new_address)
{
  g_free (broker_address);
  if (new_address && strcmp (new_address, ""))
    broker_address = g_strdup (new_address);
  else
    broker_address = NULL;
}

/**
 * @brief Get the feed lock file path.
 *
 * @return The current path to the lock file.
 */
const gchar *
get_feed_lock_path ()
{
  return feed_lock_path;
}

/**
 * @brief Set the feed lock file path.
 *
 * @param new_path The new path to the lock file.
 */
void
set_feed_lock_path (const char *new_path)
{
  g_free (feed_lock_path);
  if (new_path && strcmp (new_path, ""))
    feed_lock_path = g_strdup (new_path);
  else
    feed_lock_path = g_strdup (GVM_FEED_LOCK_PATH);
}

/**
 * @brief Get the feed lock timeout.
 *
 * @return The current timeout in seconds.
 */
int
get_feed_lock_timeout ()
{
  return feed_lock_timeout;
}

/**
 * @brief Set the feed lock timeout.
 *
 * @param new_timeout The new timeout in seconds.
 */
void
set_feed_lock_timeout (int new_timeout)
{
  if (new_timeout < 0)
    feed_lock_timeout = 0;
  else
    feed_lock_timeout = new_timeout;
}

/**
 * @brief Get the number of retries when waiting for memory to be available.
 *
 * @return The current number of retries.
 */
int
get_mem_wait_retries()
{
  return mem_wait_retries;
}

/**
 * @brief Set the number of retries when waiting for memory to be available.
 *
 * @param[in]  new_retries The new number of retries.
 */
void
set_mem_wait_retries (int new_retries)
{
  if (new_retries < 0)
    min_mem_feed_update = 0;
  else
    min_mem_feed_update = new_retries;
}

/**
 * @brief Check if the minimum memory for feed updates is available
 *
 * @return 1 if minimum memory amount is available, 0 if not
 */
int
check_min_mem_feed_update ()
{
  if (min_mem_feed_update)
    {
      guint64 min_mem_bytes = (guint64)min_mem_feed_update * 1048576llu;
      return phys_mem_available () >= min_mem_bytes ? 1 : 0;
    }
  return 1;
}

/**
 * @brief Get the minimum memory for feed updates.
 *
 * @return The current minimum memory for feed updates in MiB.
 */
int
get_min_mem_feed_update ()
{
  return min_mem_feed_update;
}

/**
 * @brief Get the minimum memory for feed updates.
 *
 * @param[in]  new_min_mem The new minimum memory for feed updates in MiB.
 */
void
set_min_mem_feed_update (int new_min_mem)
{
  guint64 min_mem_bytes = (guint64)new_min_mem * 1048576llu;
  if (new_min_mem < 0)
    min_mem_feed_update = 0;
  else if (min_mem_bytes > phys_mem_total ())
    {
      g_warning ("%s: requested feed minimum memory limit (%d MiB)"
                 " exceeds total physical memory (%lld MiB)."
                 " The setting is ignored.",
                 __func__,
                 new_min_mem,
                 phys_mem_total () / 1048576llu);
    }
  else
    min_mem_feed_update = new_min_mem;
}

/**
 * @brief Get the maximum number of concurrent scan updates.
 *
 * @return The current maximum number of concurrent scan updates.
 */
int
get_max_concurrent_scan_updates ()
{
  return max_concurrent_scan_updates;
}

/**
 * @brief Get the maximum number of database connections.
 *
 * @return The current maximum number of database connections.
 */
int
get_max_database_connections ()
{
  return max_database_connections;
}

/**
 * @brief Get the maximum number of reports to be processed concurrently.
 *
 * @return The current maximum number of reports to be processed concurrently.
 */
int
get_max_concurrent_report_processing ()
{
  return max_concurrent_report_processing;
}

/**
 * @brief Set the maximum number of concurrent scan updates.
 *
 * @param new_max The new maximum number of concurrent scan updates.
 */
void
set_max_concurrent_scan_updates (int new_max)
{
  if (new_max < 0)
    max_concurrent_scan_updates = 0;
  else
    max_concurrent_scan_updates = new_max;
}

/**
 * @brief Set the maximum number of database connections.
 *
 * @param new_max The current maximum number of database connections.
 */
void
set_max_database_connections (int new_max)
{
  if (new_max <= 0)
    max_database_connections = MAX_DATABASE_CONNECTIONS_DEFAULT;
  else
    max_database_connections = new_max;
}

/**
 * @brief Set the maximum number of concurrent imported report processing.
 *
 * @param new_max The current maximum number of concurrent report processing.
 */
void
set_max_concurrent_report_processing (int new_max)
{
  if (new_max <= 0)
  max_concurrent_report_processing = MAX_REPORT_PROCESSING_DEFAULT;
  else
  max_concurrent_report_processing = new_max;
}

/**
 * @brief Write start time to sync lock file.
 *
 * @param[in]  lockfile_fd  File descriptor of the lock file.
 */
void
write_sync_start (int lockfile_fd)
{
  time_t now;
  char now_string[26];
  char *now_string_ptr = now_string;

  now = time (NULL);
  ctime_r (&now, now_string);
  while (*now_string_ptr)
    {
      ssize_t count;
      count = write (lockfile_fd,
                     now_string,
                     strlen (now_string));
      if (count < 0)
        {
          if (errno == EAGAIN || errno == EINTR)
            /* Interrupted, try write again. */
            continue;
          g_warning ("%s: failed to write to lockfile: %s",
                     __func__,
                     strerror (errno));
          break;
        }
      now_string_ptr += count;
    }
}

/**
 * @brief Acquires the feed lock and writes the current time to the lockfile.
 *
 * @param[out] lockfile   Lockfile data struct.
 *
 * @return 0 success, 1 already locked, -1 error
 */
int
feed_lockfile_lock (lockfile_t *lockfile)
{
  int ret;

  /* Try to lock the file */
  ret = lockfile_lock_path_nb (lockfile, get_feed_lock_path ());
  if (ret)
    {
      return ret;
    }

  /* Write the file contents (timestamp) */
  write_sync_start (lockfile->fd);

  return 0;
}

/**
 * @brief Acquires the feed lock and writes the current time to the lockfile.
 *
 * @param[out] lockfile   Lockfile data struct.
 *
 * @return 0 success, 1 already locked, -1 error
 */
int
feed_lockfile_lock_timeout (lockfile_t *lockfile)
{
  int lock_status;
  gboolean log_timeout;
  time_t timeout_end;

  /* Try to lock the file */

  log_timeout = TRUE;
  timeout_end = time (NULL) + feed_lock_timeout;
  do
    {
      lock_status = feed_lockfile_lock (lockfile);
      if (lock_status == 1 /* already locked, but no error */
          && timeout_end > time (NULL))
        {
          if (log_timeout)
            {
              log_timeout = FALSE;
              g_message ("%s: Feed is currently locked by another process,"
                         " will retry until %s.",
                         __func__, iso_time (&timeout_end));
            }
          gvm_sleep (1);
        }
      else if (lock_status) /* error */
        {
          return lock_status;
        }
    } while (lock_status); /* lock is acquired when lock_status is 0 */

  return 0;
}

/**
 * @brief Releases the feed lock and clears the contents.
 *
 * @param[in] lockfile   Lockfile data struct.
 *
 * @return 0 success, -1 error
 */
int
feed_lockfile_unlock (lockfile_t *lockfile)
{
  int ret;

  /* Clear timestamp from lock file. */
  if (ftruncate (lockfile->fd, 0))
    g_warning ("%s: failed to ftruncate lockfile: %s",
               __func__,
               strerror (errno));

  /* Unlock the lockfile */
  ret = lockfile_unlock (lockfile);
  if (ret)
    {
      g_critical ("%s: Error releasing checking lock", __func__);
      return -1;
    }

  return 0;
}

/**
 * @brief Get VTs feed information from a scanner.
 *
 * @param[in]  update_socket  Socket to use to contact ospd-openvas scanner.
 * @param[out] vts_version    Output of scanner feed version.
 * @param[out] feed_name      Output of feed name.
 * @param[out] feed_vendor    Output of feed vendor.
 * @param[out] feed_home      Output of feed name home URL.
 *
 * @return 0 success, 1 connection to scanner failed, 2 scanner still starting,
 *         -1 other error.
 */
static int
nvts_feed_info_internal (const gchar *update_socket,
                         gchar **vts_version,
                         gchar **feed_name,
                         gchar **feed_vendor,
                         gchar **feed_home)
{
  osp_connection_t *connection;
  gchar *error;

  connection = osp_connection_new (update_socket, 0, NULL, NULL, NULL);
  if (!connection)
    {
      g_warning ("%s: failed to connect to %s", __func__, update_socket);
      return 1;
    }

  error = NULL;
  if (osp_get_vts_feed_info (connection,
                             vts_version,
                             feed_name,
                             feed_vendor,
                             feed_home,
                             &error))
    {
      if (error && strcmp (error, "OSPd OpenVAS is still starting") == 0)
        {
          g_free (error);
          osp_connection_close (connection);
          return 2;
        }
      g_warning ("%s: failed to get VT feed info. %s",
                 __func__, error ? : "");
      g_free (error);
      osp_connection_close (connection);
      return -1;
    }

  osp_connection_close (connection);

  return 0;
}

/**
 * @brief Get VTs feed information from the scanner using VT update socket.
 *
 * @param[out] vts_version  Output of scanner feed version.
 * @param[out] feed_name    Output of feed name.
 * @param[out] feed_vendor  Output of feed vendor.
 * @param[out] feed_home    Output of feed name home URL.
 *
 * @return 0 success, 1 connection to scanner failed, 2 scanner still starting,
 *         -1 other error.
 */
int
nvts_feed_info (gchar **vts_version, gchar **feed_name, gchar **feed_vendor,
                gchar **feed_home)
{
  scanner_type_t sc_type = get_scanner_type_by_uuid (SCANNER_UUID_DEFAULT);
  switch (sc_type)
  {
    case SCANNER_TYPE_OPENVAS:
      return nvts_feed_info_internal (get_osp_vt_update_socket (),
                                      vts_version,
                                      feed_name,
                                      feed_vendor,
                                      feed_home);
    case SCANNER_TYPE_OPENVASD:
      if (feature_enabled (FEATURE_ID_OPENVASD_SCANNER))
        {
          return nvts_feed_info_internal_from_openvasd (SCANNER_UUID_DEFAULT,
            vts_version);
        }
      else
        {
          if (feature_compiled_in (FEATURE_ID_OPENVASD_SCANNER))
            g_critical ("%s: Default scanner is an openvasd one,"
                      " but openvasd runtime flag is disabled.",
                      __func__);
          else
            g_critical ("%s: Default scanner is an openvasd one,"
                      " but gvmd is not built to support this.",
                      __func__);
          return -1;
        }
    default:
      g_critical ("%s: scanner type %d is not supported as default",
                  __func__, sc_type);
      return -1;
  }
}

/**
 * @brief Check the VTs feed sync for information using a OSP socket.
 *
 * @param[in]  update_socket  Socket to use to contact ospd-openvas scanner.
 * @param[out] lockfile_in_use       Whether the lockfile is in use.
 * @param[out] self_test_exit_error  Whether the sync script self check failed.
 * @param[out] self_test_error_msg   Self check error message if failed.
 *
 * @return 0 success, 1 connection to scanner failed, -1 other error.
 */
static int
nvts_check_feed_internal (const char *update_socket,
                         int *lockfile_in_use,
                         int *self_test_exit_error,
                         char **self_test_error_msg)
{
  osp_connection_t *connection;
  gchar *error;

  connection = osp_connection_new (update_socket, 0, NULL, NULL, NULL);
  if (!connection)
    {
      g_warning ("%s: failed to connect to %s", __func__, update_socket);
      return 1;
    }

  error = NULL;
  if (osp_check_feed (connection,
                      lockfile_in_use, self_test_exit_error,
                      self_test_error_msg, &error))
    {
      g_warning ("%s: failed to get VT feed info. %s",
                 __func__, error ? : "");
      g_free (error);
      osp_connection_close (connection);
      return -1;
    }

  osp_connection_close (connection);

  return 0;
}

/**
 * @brief Check the VTs feed sync for information using the default OSP socket.
 *
 * @param[out] lockfile_in_use       Whether the lockfile is in use.
 * @param[out] self_test_exit_error  Whether the sync script self check failed.
 * @param[out] self_test_error_msg   Self check error message if failed.
 *
 * @return 0 success, 1 connection to scanner failed, -1 other error.
 */
int
nvts_check_feed (int *lockfile_in_use,
                 int *self_test_exit_error,
                 char **self_test_error_msg)
{
  scanner_type_t sc_type = get_scanner_type_by_uuid (SCANNER_UUID_DEFAULT);
  switch (sc_type)
  {
    case SCANNER_TYPE_OPENVAS:
      return nvts_check_feed_internal (get_osp_vt_update_socket (),
                                       lockfile_in_use,
                                       self_test_exit_error,
                                       self_test_error_msg);
    case SCANNER_TYPE_OPENVASD:
      if (feature_enabled (FEATURE_ID_OPENVASD_SCANNER))
        {
          int ret = 0;
          char *vts_version = NULL;

          ret = nvts_feed_info_internal_from_openvasd (SCANNER_UUID_DEFAULT,
            &vts_version);
          self_test_exit_error = 0;
          *self_test_error_msg = NULL;
          if (ret == 0 && vts_version)
            lockfile_in_use = 0;
          else if (ret == 2)
            {
              ret = 0;
              *lockfile_in_use = 1;
            }

          return ret;
        }
      else
        {
          if (feature_compiled_in (FEATURE_ID_OPENVASD_SCANNER))
            g_critical ("%s: Default scanner is an openvasd one,"
                      " but openvasd runtime flag is disabled.",
                      __func__);
          else
            g_critical ("%s: Default scanner is an openvasd one,"
                      " but gvmd is not built to support this.",
                      __func__);
          return -1;
        }
    default:
      g_critical ("%s: scanner type %d is not supported as default",
                  __func__, sc_type);
      return -1;
  }
}

/**
 * @brief Migrates SCAP or CERT database, waiting until migration terminates.
 *
 * Calls a sync script to migrate the SCAP or CERT database.
 *
 * @param[in]  feed_type     Could be SCAP_FEED or CERT_FEED.
 *
 * @return 0 sync complete, 1 sync already in progress, -1 error
 */
int
gvm_migrate_secinfo (int feed_type)
{
  lockfile_t lockfile;
  int ret;

  if (feed_type != SCAP_FEED && feed_type != CERT_FEED)
    {
      g_warning ("%s: unsupported feed_type", __func__);
      return -1;
    }

  ret = feed_lockfile_lock_timeout (&lockfile);
  if (ret == 1)
    return 1;
  else if (ret)
    return -1;

  if (feed_type == SCAP_FEED)
    ret = check_scap_db_version ();
  else
    ret = check_cert_db_version ();

  feed_lockfile_unlock (&lockfile);

  return ret;
}


/* Time zone info. */

/**
 * @brief Get a list of all supported timezones
 *
 * @return An array of supported timezones. Caller must free.
 */
array_t *
manage_get_timezones ()
{
  array_t *tzs_out = make_array ();
  iterator_t pg_iterator;

  init_pg_timezones_iterator (&pg_iterator);
  while (next (&pg_iterator))
    {
      const char *pg_tz_name = pg_timezones_iterator_name (&pg_iterator);

      icaltimezone *ical_tz = icalendar_timezone_from_string (pg_tz_name);
      if (ical_tz)
        array_add_new_string (tzs_out, pg_tz_name);
    }

  return tzs_out;
}

/**
 * @brief Check if a timezone is supported
 *
 * @param[in]  zone  Name of the timezone to check.
 *
 * @return TRUE if the timezone is supported, FALSE otherwise
 */
gboolean
manage_timezone_supported (const char *zone)
{
  if (icalendar_timezone_from_string (zone) == NULL)
    return FALSE;
  return pg_timezone_supported (zone);
}


/* Wizards. */

/**
 * @brief Run a wizard.
 *
 * @param[in]  wizard_name       Wizard name.
 * @param[in]  run_command       Function to run GMP command.
 * @param[in]  run_command_data  Argument for run_command.
 * @param[in]  params            Wizard params.  Array of name_value_t.
 * @param[in]  read_only         Whether to only allow wizards marked as
 *                               read only.
 * @param[in]  mode              Name of the mode to run the wizard in.
 * @param[out] command_error     Either NULL or an address for an error message
 *                               when return is 0, 4 or 6.
 * @param[out] command_error_code  Either NULL or an address for a status code
 *                                 from the failed command when return is 0
 *                                 or 4.
 * @param[out] ret_response      Address for response string of last command.
 *
 * @return 0 success,
 *         1 name error,
 *         4 command in wizard failed,
 *         5 wizard not read only,
 *         6 Parameter validation failed,
 *         -1 internal error,
 *         99 permission denied.
 */
int
manage_run_wizard (const gchar *wizard_name,
                   int (*run_command) (void*, gchar*, gchar**),
                   void *run_command_data,
                   array_t *params,
                   int read_only,
                   const char *mode,
                   gchar **command_error,
                   gchar **command_error_code,
                   gchar **ret_response)
{
  GString *params_xml;
  gchar *file, *file_name, *response, *extra, *extra_wrapped, *wizard;
  gsize wizard_len;
  GError *get_error;
  entity_t entity, mode_entity, params_entity, read_only_entity;
  entity_t param_def, step;
  entities_t modes, steps, param_defs;
  int ret;
  const gchar *point;

  if (acl_user_may ("run_wizard") == 0)
    return 99;

  if (command_error)
    *command_error = NULL;

  if (command_error_code)
    *command_error_code = NULL;

  if (ret_response)
    *ret_response = NULL;

  point = wizard_name;
  while (*point && (isalnum (*point) || *point == '_')) point++;
  if (*point)
    return 1;

  /* Read wizard from file. */

  file_name = g_strdup_printf ("%s.xml", wizard_name);
  file = g_build_filename (GVMD_DATA_DIR,
                           "wizards",
                           file_name,
                           NULL);
  g_free (file_name);

  get_error = NULL;
  g_file_get_contents (file,
                       &wizard,
                       &wizard_len,
                       &get_error);
  g_free (file);
  if (get_error)
    {
      g_warning ("%s: Failed to read wizard: %s",
                 __func__,
                 get_error->message);
      g_error_free (get_error);
      return -1;
    }

  /* Parse wizard. */

  entity = NULL;
  if (parse_entity (wizard, &entity))
    {
      g_warning ("%s: Failed to parse wizard", __func__);
      g_free (wizard);
      return -1;
    }
  g_free (wizard);

  /* Select mode */
  if (mode && strcmp (mode, ""))
    {
      modes = entity->entities;
      int mode_found = 0;
      while (mode_found == 0 && (mode_entity = first_entity (modes)))
        {
          if (strcasecmp (entity_name (mode_entity), "mode") == 0)
            {
              entity_t name_entity;
              name_entity = entity_child (mode_entity, "name");

              if (strcmp (entity_text (name_entity), mode) == 0)
                mode_found = 1;
            }
          modes = next_entities (modes);
        }

      if (mode_found == 0)
        {
          free_entity (entity);
          if (ret_response)
            *ret_response = g_strdup ("");

          return 0;
        }
    }
  else
    {
      mode_entity = entity;
    }

  /* If needed, check if wizard is marked as read only.
   * This does not check the actual commands.
   */
  if (read_only)
    {
      read_only_entity = entity_child (mode_entity, "read_only");
      if (read_only_entity == NULL)
        {
          free_entity (entity);
          return 5;
        }
    }

  /* Check params */
  params_xml = g_string_new ("");
  params_entity = entity_child (mode_entity, "params");
  if (params_entity)
    param_defs = params_entity->entities;

  while (params_entity && (param_def = first_entity (param_defs)))
    {
      if (strcasecmp (entity_name (param_def), "param") == 0)
        {
          entity_t name_entity, regex_entity, optional_entity;
          const char *name, *regex;
          int optional;
          int param_found = 0;

          name_entity = entity_child (param_def, "name");
          if ((name_entity == NULL)
              || (strcmp (entity_text (name_entity), "") == 0))
            {
              g_warning ("%s: Wizard PARAM missing NAME",
                         __func__);
              free_entity (entity);
              return -1;
            }
          else
            name = entity_text (name_entity);

          regex_entity = entity_child (param_def, "regex");
          if ((regex_entity == NULL)
              || (strcmp (entity_text (regex_entity), "") == 0))
            {
              g_warning ("%s: Wizard PARAM missing REGEX",
                         __func__);
              free_entity (entity);
              return -1;
            }
          else
            regex = entity_text (regex_entity);

          optional_entity = entity_child (param_def, "optional");
          optional = (optional_entity
                      && strcmp (entity_text (optional_entity), "")
                      && strcmp (entity_text (optional_entity), "0"));

          if (params)
            {
              guint index = params->len;
              while (index--)
                {
                  name_value_t *pair;

                  pair = (name_value_t*) g_ptr_array_index (params, index);

                  if (pair == NULL)
                    continue;

                  if ((pair->name)
                      && (pair->value)
                      && (strcmp (pair->name, name) == 0))
                    {
                      index = 0; // end loop;
                      param_found = 1;

                      if (g_regex_match_simple (regex, pair->value, 0, 0) == 0)
                        {
                          if (command_error)
                            {
                              *command_error
                                = g_strdup_printf ("Value '%s' is not valid for"
                                                  " parameter '%s'.",
                                                  pair->value, name);
                            }
                          free_entity (entity);
                          g_string_free (params_xml, TRUE);
                          return 6;
                        }
                    }
                }
            }

          if (optional == 0 && param_found == 0)
            {
              if (command_error)
                {
                  *command_error = g_strdup_printf ("Mandatory wizard param '%s'"
                                                    " missing",
                                                    name);
                }
              free_entity (entity);
              return 6;
            }


        }
      param_defs = next_entities (param_defs);
    }

  /* Buffer params */
  if (params)
    {
      guint index = params->len;
      while (index--)
        {
          name_value_t *pair;

          pair = (name_value_t*) g_ptr_array_index (params, index);
          xml_string_append (params_xml,
                             "<param>"
                             "<name>%s</name>"
                             "<value>%s</value>"
                             "</param>",
                             pair->name ? pair->name : "",
                             pair->value ? pair->value : "");
        }
    }

  /* Run each step of the wizard. */

  response = NULL;
  extra = NULL;
  steps = mode_entity->entities;
  while ((step = first_entity (steps)))
    {
      if (strcasecmp (entity_name (step), "step") == 0)
        {
          entity_t command, extra_xsl;
          gchar *gmp;
          int xsl_fd, xml_fd;
          char xsl_file_name[] = "/tmp/gvmd-xsl-XXXXXX";
          FILE *xsl_file, *xml_file;
          char xml_file_name[] = "/tmp/gvmd-xml-XXXXXX";
          char extra_xsl_file_name[] = "/tmp/gvmd-extra-xsl-XXXXXX";
          char extra_xml_file_name[] = "/tmp/gvmd-extra-xml-XXXXXX";

          /* Get the command element. */

          command = entity_child (step, "command");
          if (command == NULL)
            {
              g_warning ("%s: Wizard STEP missing COMMAND",
                         __func__);
              free_entity (entity);
              g_free (response);
              g_free (extra);
              g_string_free (params_xml, TRUE);
              return -1;
            }

          /* Save the command XSL from the element to a file. */

          xsl_fd = mkstemp (xsl_file_name);
          if (xsl_fd == -1)
            {
              g_warning ("%s: Wizard XSL file create failed",
                         __func__);
              free_entity (entity);
              g_free (response);
              g_free (extra);
              g_string_free (params_xml, TRUE);
              return -1;
            }

          xsl_file = fdopen (xsl_fd, "w");
          if (xsl_file == NULL)
            {
              g_warning ("%s: Wizard XSL file open failed",
                         __func__);
              close (xsl_fd);
              free_entity (entity);
              g_free (response);
              g_free (extra);
              g_string_free (params_xml, TRUE);
              return -1;
            }

          if (first_entity (command->entities))
            print_entity (xsl_file, first_entity (command->entities));

          /* Write the params as XML to a file. */

          xml_fd = mkstemp (xml_file_name);
          if (xml_fd == -1)
            {
              g_warning ("%s: Wizard XML file create failed",
                         __func__);
              fclose (xsl_file);
              unlink (xsl_file_name);
              free_entity (entity);
              g_free (response);
              g_free (extra);
              g_string_free (params_xml, TRUE);
              return -1;
            }

          xml_file = fdopen (xml_fd, "w");
          if (xml_file == NULL)
            {
              g_warning ("%s: Wizard XML file open failed",
                         __func__);
              fclose (xsl_file);
              unlink (xsl_file_name);
              close (xml_fd);
              free_entity (entity);
              g_free (response);
              g_free (extra);
              g_string_free (params_xml, TRUE);
              return -1;
            }

          if (fprintf (xml_file,
                       "<wizard>"
                       "<params>%s</params>"
                       "<previous>"
                       "<response>%s</response>"
                       "<extra_data>%s</extra_data>"
                       "</previous>"
                       "</wizard>\n",
                       params_xml->str ? params_xml->str : "",
                       response ? response : "",
                       extra ? extra : "")
              < 0)
            {
              fclose (xsl_file);
              unlink (xsl_file_name);
              fclose (xml_file);
              unlink (xml_file_name);
              free_entity (entity);
              g_warning ("%s: Wizard failed to write XML",
                         __func__);
              g_free (response);
              g_free (extra);
              g_string_free (params_xml, TRUE);
              return -1;
            }

          fflush (xml_file);

          /* Combine XSL and XML to get the GMP command. */

          gmp = xsl_transform (xsl_file_name, xml_file_name, NULL,
                               NULL);
          fclose (xsl_file);
          unlink (xsl_file_name);
          fclose (xml_file);
          unlink (xml_file_name);
          if (gmp == NULL)
            {
              g_warning ("%s: Wizard XSL transform failed",
                         __func__);
              free_entity (entity);
              g_free (response);
              g_free (extra);
              g_string_free (params_xml, TRUE);
              return -1;
            }

          /* Run the GMP command. */

          g_free (response);
          response = NULL;
          ret = run_command (run_command_data, gmp, &response);
          if (ret == 0)
            {
              /* Command succeeded. */
            }
          else
            {
              free_entity (entity);
              g_free (response);
              g_free (extra);
              g_string_free (params_xml, TRUE);
              return -1;
            }

          /* Exit if the command failed. */

          if (response)
            {
              const char *status;
              entity_t response_entity;

              response_entity = NULL;
              if (parse_entity (response, &response_entity))
                {
                  g_warning ("%s: Wizard failed to parse response",
                             __func__);
                  free_entity (entity);
                  g_free (response);
                  g_free (extra);
                  g_string_free (params_xml, TRUE);
                  return -1;
                }

              status = entity_attribute (response_entity, "status");
              if ((status == NULL)
                  || (strlen (status) == 0)
                  || (status[0] != '2'))
                {
                  g_debug ("response was %s", response);
                  if (command_error)
                    {
                      const char *text;
                      text = entity_attribute (response_entity, "status_text");
                      if (text)
                        *command_error = g_strdup (text);
                    }
                  if (command_error_code)
                    {
                      *command_error_code = g_strdup (status);
                    }
                  free_entity (response_entity);
                  free_entity (entity);
                  g_free (response);
                  g_free (extra);
                  g_string_free (params_xml, TRUE);
                  return 4;
                }

              free_entity (response_entity);
            }

          /* Get the extra_data element. */

          extra_xsl = entity_child (step, "extra_data");
          if (extra_xsl)
            {
              /* Save the extra_data XSL from the element to a file. */

              xsl_fd = mkstemp (extra_xsl_file_name);
              if (xsl_fd == -1)
                {
                  g_warning ("%s: Wizard extra_data XSL file create failed",
                            __func__);
                  free_entity (entity);
                  g_free (response);
                  g_free (extra);
                  g_string_free (params_xml, TRUE);
                  return -1;
                }

              xsl_file = fdopen (xsl_fd, "w");
              if (xsl_file == NULL)
                {
                  g_warning ("%s: Wizard extra_data XSL file open failed",
                            __func__);
                  close (xsl_fd);
                  free_entity (entity);
                  g_free (response);
                  g_free (extra);
                  g_string_free (params_xml, TRUE);
                  return -1;
                }

              if (first_entity (extra_xsl->entities))
                print_entity (xsl_file, first_entity (extra_xsl->entities));

              /* Write the params as XML to a file. */

              xml_fd = mkstemp (extra_xml_file_name);
              if (xml_fd == -1)
                {
                  g_warning ("%s: Wizard XML file create failed",
                            __func__);
                  fclose (xsl_file);
                  unlink (xsl_file_name);
                  free_entity (entity);
                  g_free (response);
                  g_free (extra);
                  g_string_free (params_xml, TRUE);
                  return -1;
                }

              xml_file = fdopen (xml_fd, "w");
              if (xml_file == NULL)
                {
                  g_warning ("%s: Wizard XML file open failed",
                            __func__);
                  fclose (xsl_file);
                  unlink (xsl_file_name);
                  close (xml_fd);
                  free_entity (entity);
                  g_free (response);
                  g_free (extra);
                  g_string_free (params_xml, TRUE);
                  return -1;
                }

              if (fprintf (xml_file,
                           "<wizard>"
                           "<params>%s</params>"
                           "<current>"
                           "<response>%s</response>"
                           "</current>"
                           "<previous>"
                           "<extra_data>%s</extra_data>"
                           "</previous>"
                           "</wizard>\n",
                           params_xml->str ? params_xml->str : "",
                           response ? response : "",
                           extra ? extra : "")
                  < 0)
                {
                  fclose (xsl_file);
                  unlink (extra_xsl_file_name);
                  fclose (xml_file);
                  unlink (extra_xml_file_name);
                  free_entity (entity);
                  g_warning ("%s: Wizard failed to write XML",
                            __func__);
                  g_free (response);
                  g_free (extra);
                  g_string_free (params_xml, TRUE);
                  return -1;
                }

              fflush (xml_file);

              g_free (extra);
              extra = xsl_transform (extra_xsl_file_name, extra_xml_file_name,
                                     NULL, NULL);
              fclose (xsl_file);
              unlink (extra_xsl_file_name);
              fclose (xml_file);
              unlink (extra_xml_file_name);
            }
        }
      steps = next_entities (steps);
    }

  if (extra)
    extra_wrapped = g_strdup_printf ("<extra_data>%s</extra_data>",
                                     extra);
  else
    extra_wrapped = NULL;
  g_free (extra);

  if (ret_response)
    *ret_response = response;

  if (extra_wrapped)
    {
      entity_t extra_entity, status_entity, status_text_entity;
      ret = parse_entity (extra_wrapped, &extra_entity);
      if (ret == 0)
        {
          status_entity = entity_child (extra_entity, "status");
          status_text_entity = entity_child (extra_entity, "status_text");

          if (status_text_entity && command_error)
            {
              *command_error = g_strdup (entity_text (status_text_entity));
            }

          if (status_entity && command_error_code)
            {
              *command_error_code = g_strdup (entity_text (status_entity));
            }
          free_entity (extra_entity);
        }
      else
        {
          g_warning ("%s: failed to parse extra data", __func__);
          free_entity (entity);
          g_string_free (params_xml, TRUE);
          return -1;
        }
    }

  free_entity (entity);
  g_string_free (params_xml, TRUE);

  /* All the steps succeeded. */

  return 0;
}


/* Resources. */

/**
 * @brief Delete a resource.
 *
 * @param[in]  type         Type of resource.
 * @param[in]  resource_id  UUID of resource.
 * @param[in]  ultimate     Whether to remove entirely, or to trashcan.
 *
 * @return 0 success, 1 resource in use, 2 failed to find resource,
 *         99 permission denied, -1 error.
 */
int
delete_resource (const char *type, const char *resource_id, int ultimate)
{
#if ENABLE_CONTAINER_SCANNING
  if (strcasecmp (type, "oci_image_target") == 0)
    return delete_oci_image_target (resource_id, ultimate);
#endif /* ENABLE_CONTAINER_SCANNING */
  if (strcasecmp (type, "report_config") == 0)
    return delete_report_config (resource_id, ultimate);
  if (strcasecmp (type, "ticket") == 0)
    return delete_ticket (resource_id, ultimate);
#if ENABLE_AGENTS
  if (strcasecmp (type, "agent_group") == 0)
    return delete_agent_group (resource_id, ultimate);
#endif
  if (strcasecmp (type, "tls_certificate") == 0)
    return delete_tls_certificate (resource_id, ultimate);
  assert (0);
  return -1;
}

#if ENABLE_OPENVASD
/* openvasd */

/**
 * @brief Stop an openvasd task.
 *
 * @param[in]   task  The task.
 *
 * @return 0 on success, else -1.
 */
static int
stop_openvasd_task (task_t task)
{
  if (!feature_enabled (FEATURE_ID_OPENVASD_SCANNER))
    {
      g_warning ("%s: openvasd runtime flag is disabled", __func__);
      return -1;
    }
  int ret = 0;
  report_t scan_report;
  char *scan_id;
  task_t previous_task;
  report_t previous_report;

  scanner_t scanner;
  http_scanner_resp_t response;
  http_scanner_connector_t connector = NULL;

  scan_report = task_running_report (task);
  if (!scan_report)
    return 0;

  previous_task = current_scanner_task;
  previous_report = global_current_report;

  scan_id = report_uuid (scan_report);
  if (!scan_id)
    {
      ret = -1;
      goto end_stop_openvasd;
    }
  scanner = task_scanner (task);
  connector = http_scanner_connect (scanner, scan_id);
  if (!connector)
    {
      ret = -1;
      goto end_stop_openvasd;
    }

  current_scanner_task = task;
  global_current_report = task_running_report (task);
  set_task_run_status (task, TASK_STATUS_STOP_REQUESTED);
  response = http_scanner_stop_scan (connector);
  if (response->code < 0)
    {
      ret = -1;
      http_scanner_response_cleanup (response);
      g_free (scan_id);
      goto end_stop_openvasd;
    }
  http_scanner_response_cleanup (response);
  response = http_scanner_delete_scan (connector);
  http_scanner_response_cleanup (response);
  g_free (scan_id);
end_stop_openvasd:
  http_scanner_connector_free (connector);
  set_task_end_time_epoch (task, time (NULL));
  set_task_run_status (task, TASK_STATUS_STOPPED);
  if (scan_report)
    {
      set_scan_end_time_epoch (scan_report, time (NULL));
      set_report_scan_run_status (scan_report, TASK_STATUS_STOPPED);
    }
  current_scanner_task = previous_task;
  global_current_report = previous_report;

  return ret;
}

/**
 * @brief Prepare a report for resuming an OSP scan
 *
 * @param[in]  task     The task of the scan.
 * @param[in]  scan_id  The scan uuid.
 * @param[out] error    Error return.
 *
 * @return 0 scan finished or still running,
 *         1 scan must be started,
 *         -1 error
 */
static int
prepare_openvasd_scan_for_resume (task_t task, const char *scan_id,
                                  char **error)
{
  http_scanner_connector_t connection;
  int ret;

  assert (task);
  assert (scan_id);
  assert (global_current_report);
  assert (error);

  connection = http_scanner_connect (task_scanner (task), scan_id);
  if (!connection)
    {
      *error = g_strdup ("Could not connect to openvasd Scanner");
      return -1;
    }

  g_debug ("%s: Preparing scan %s for resume", __func__, scan_id);

  ret = prepare_http_scanner_scan_for_resume (connection, error);

  if (ret == 1)
    trim_partial_report (global_current_report);

  return ret;
}

/**
 * @brief Launch an OpenVAS via openvasd task.
 *
 * @param[in]   task           The task.
 * @param[in]   target         The target.
 * @param[in]   scan_id        The scan uuid.
 * @param[in]   from           0 start from beginning, 1 continue from stopped,
 *                             2 continue if stopped else start from beginning.
 * @param[out]  error          Error return.
 * @param[out]  discovery_out  Returns TRUE if all OIDs are labeled
 *                             as discovery in the used scan config.
 *
 * @return An http code on success, -1 if error.
 */
static int
launch_openvasd_openvas_task (task_t task, target_t target, const char *scan_id,
                         int from, char **error, gboolean *discovery_out)
{
  http_scanner_connector_t connection;
  char *hosts_str, *ports_str, *exclude_hosts_str, *finished_hosts_str;
  gchar *clean_hosts, *clean_exclude_hosts, *clean_finished_hosts_str;
  int alive_test, reverse_lookup_only, reverse_lookup_unify;
  int arp = 0, icmp = 0, tcp_ack = 0, tcp_syn = 0, consider_alive = 0;
  openvasd_target_t *openvasd_target;
  GSList *openvasd_targets, *vts;
  GHashTable *vts_hash_table;
  gchar *max_checks, *max_hosts;
  GHashTable *scanner_options;
  http_scanner_resp_t response;
  int ret, empty;
  config_t config;
  iterator_t scanner_prefs_iter, families, prefs;

  connection = NULL;
  config = task_config (task);

  alive_test = 0;
  reverse_lookup_unify = 0;
  reverse_lookup_only = 0;

  /* Prepare the report */
  if (from)
    {
      ret = prepare_openvasd_scan_for_resume (task, scan_id, error);
      if (ret == 0)
        return 0;
      else if (ret == -1)
        return -1;
      finished_hosts_str = report_finished_hosts_str (global_current_report);
      clean_finished_hosts_str = clean_hosts_string (finished_hosts_str);
    }
  else
    {
      finished_hosts_str = NULL;
      clean_finished_hosts_str = NULL;
    }

  /* Set up target(s) */
  hosts_str = target_hosts (target);
  ports_str = target_port_range (target);
  exclude_hosts_str = target_exclude_hosts (target);

  clean_hosts = clean_hosts_string (hosts_str);
  clean_exclude_hosts = clean_hosts_string (exclude_hosts_str);

  alive_test = 0;
  if (target_alive_tests (target) > 0)
    alive_test = target_alive_tests (target);

  if (target_reverse_lookup_only (target) != NULL)
    reverse_lookup_only = atoi (target_reverse_lookup_only (target));

  if (target_reverse_lookup_unify (target) != NULL)
    reverse_lookup_unify = atoi (target_reverse_lookup_unify (target));

  if (finished_hosts_str)
    {
      gchar *new_exclude_hosts;

      new_exclude_hosts = g_strdup_printf ("%s,%s",
                                           clean_exclude_hosts,
                                           clean_finished_hosts_str);
      free (clean_exclude_hosts);
      clean_exclude_hosts = new_exclude_hosts;
    }

  openvasd_target = openvasd_target_new (scan_id, clean_hosts, ports_str,
                                         clean_exclude_hosts,
                                         reverse_lookup_unify,
                                         reverse_lookup_only);
  if (finished_hosts_str)
    openvasd_target_set_finished_hosts (openvasd_target, finished_hosts_str);

  if (alive_test & ALIVE_TEST_ARP)
    arp = 1;
  if (alive_test & ALIVE_TEST_ICMP)
    icmp = 1;
  if (alive_test & ALIVE_TEST_TCP_ACK_SERVICE)
    tcp_ack = 1;
  if (alive_test & ALIVE_TEST_TCP_SYN_SERVICE)
    tcp_syn = 1;
  if (alive_test & ALIVE_TEST_CONSIDER_ALIVE)
    consider_alive = 1;

  openvasd_target_add_alive_test_methods (openvasd_target, icmp, tcp_syn,
                                          tcp_ack, arp, consider_alive);

  free (hosts_str);
  free (ports_str);
  free (exclude_hosts_str);
  free (finished_hosts_str);
  g_free (clean_hosts);
  g_free (clean_exclude_hosts);
  g_free (clean_finished_hosts_str);
  openvasd_targets = g_slist_append (NULL, openvasd_target);

#if ENABLE_CREDENTIAL_STORES == 0

  openvasd_credential_t *ssh_credential, *smb_credential, *esxi_credential;
  openvasd_credential_t *snmp_credential;

  ssh_credential = (openvasd_credential_t *) target_osp_ssh_credential_db (target);
  if (ssh_credential)
    openvasd_target_add_credential (openvasd_target, ssh_credential);

  smb_credential = (openvasd_credential_t *) target_osp_smb_credential_db (target);
  if (smb_credential)
    openvasd_target_add_credential (openvasd_target, smb_credential);

  esxi_credential =
    (openvasd_credential_t *) target_osp_esxi_credential_db (target);
  if (esxi_credential)
    openvasd_target_add_credential (openvasd_target, esxi_credential);

  snmp_credential =
    (openvasd_credential_t *) target_osp_snmp_credential_db (target);
  if (snmp_credential)
    openvasd_target_add_credential (openvasd_target, snmp_credential);

#endif

  /* Initialize vts table for vulnerability tests and their preferences */
  vts = NULL;
  vts_hash_table
    = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
                             /* Value is freed in vts list. */
                             NULL);

  /*  Setup of vulnerability tests (without preferences) */
  init_family_iterator (&families, 0, NULL, 1);
  GSList *oids = NULL;
  empty = 1;
  while (next (&families))
    {
      const char *family = family_iterator_name (&families);
      if (family)
        {
          iterator_t nvts;
          init_nvt_iterator (&nvts, 0, config, family, NULL, 1, NULL);
          while (next (&nvts))
            {
              const char *oid;
              openvasd_vt_single_t *new_vt;

              empty = 0;
              oid = nvt_iterator_oid (&nvts);
              new_vt = openvasd_vt_single_new (oid);
              oids = g_slist_prepend (oids, g_strdup (oid));

              vts = g_slist_prepend (vts, new_vt);
              g_hash_table_replace (vts_hash_table, g_strdup (oid), new_vt);
            }
          cleanup_iterator (&nvts);
        }
    }
  cleanup_iterator (&families);

  /* check oids are discovery or not */
  *discovery_out = nvts_oids_all_discovery_cached (oids);
  /* clean up oids list */
  g_slist_free_full (oids, g_free);

  if (empty) {
    if (error)
      *error = g_strdup ("Exiting because VT list is empty "
                         "(e.g. feed not synced yet)");
    g_slist_free_full (openvasd_targets, (GDestroyNotify) openvasd_target_free);
    // Credentials are freed with target
    g_slist_free_full (vts, (GDestroyNotify) openvasd_vt_single_free);
    return -1;
  }

  /* Setup general scanner preferences */
  scanner_options
    = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
  init_preference_iterator (&scanner_prefs_iter, config, "SERVER_PREFS");
  while (next (&scanner_prefs_iter))
    {
      const char *name, *value;
      name = preference_iterator_name (&scanner_prefs_iter);
      value = preference_iterator_value (&scanner_prefs_iter);
      if (name && value && !g_str_has_prefix (name, "timeout."))
        {
          const char *openvasd_value;

          // Workaround for boolean scanner preferences
          if (strcmp (value, "no") == 0)
            openvasd_value = "0";
          else if (strcmp (value, "yes") == 0)
            openvasd_value = "1";
          else
            openvasd_value = value;
          g_hash_table_replace (scanner_options, g_strdup (name),
                                g_strdup (openvasd_value));
        }
      /* Timeouts are stored as SERVER_PREFS, but are actually
         script preferences. This prefs is converted into a
         script preference to be sent to the scanner. */
      else if (name && value && g_str_has_prefix (name, "timeout."))
        {
          char **oid = NULL;
          openvasd_vt_single_t *openvasd_vt = NULL;

          oid = g_strsplit (name, ".", 2);
          openvasd_vt = g_hash_table_lookup (vts_hash_table, oid[1]);
          if (openvasd_vt)
            openvasd_vt_single_add_value (openvasd_vt, "0", value);
          g_strfreev (oid);
        }
    }
  cleanup_iterator (&scanner_prefs_iter);

  /* Setup user-specific scanner preference */
  add_user_scan_preferences (scanner_options);

  /* Setup general task preferences */
  max_checks = task_preference_value (task, "max_checks");
  g_hash_table_insert (scanner_options, g_strdup ("max_checks"),
                       max_checks ? max_checks : g_strdup (MAX_CHECKS_DEFAULT));

  max_hosts = task_preference_value (task, "max_hosts");
  g_hash_table_insert (scanner_options, g_strdup ("max_hosts"),
                       max_hosts ? max_hosts : g_strdup (MAX_HOSTS_DEFAULT));

  /* Setup VT preferences */
  init_preference_iterator (&prefs, config, "PLUGINS_PREFS");
  while (next (&prefs))
    {
      const char *full_name, *value;
      openvasd_vt_single_t *openvasd_vt;
      gchar **split_name;

      full_name = preference_iterator_name (&prefs);
      value = preference_iterator_value (&prefs);
      split_name = g_strsplit (full_name, ":", 4);

      openvasd_vt = NULL;
      if (split_name && split_name[0] && split_name[1] && split_name[2])
        {
          const char *oid = split_name[0];
          const char *pref_id = split_name[1];
          const char *type = split_name[2];
          gchar *openvasd_value = NULL;

          if (strcmp (type, "checkbox") == 0)
            {
              if (strcmp (value, "yes") == 0)
                openvasd_value = g_strdup ("1");
              else
                openvasd_value = g_strdup ("0");
            }
          else if (strcmp (type, "radio") == 0)
            {
              gchar** split_value;
              split_value = g_strsplit (value, ";", 2);
              openvasd_value = g_strdup (split_value[0]);
              g_strfreev (split_value);
            }
          else if (strcmp (type, "file") == 0)
            openvasd_value = g_base64_encode ((guchar*) value, strlen (value));

          openvasd_vt = g_hash_table_lookup (vts_hash_table, oid);
          if (openvasd_vt)
            openvasd_vt_single_add_value (openvasd_vt, pref_id,
                                     openvasd_value ? openvasd_value : value);
          g_free (openvasd_value);
        }

      g_strfreev (split_name);
    }
  cleanup_iterator (&prefs);
  g_hash_table_destroy (vts_hash_table);

  /* Start the scan */
  connection = http_scanner_connect (task_scanner (task), scan_id);
  if (!connection)
    {
      if (error)
        *error = g_strdup ("Could not connect to Scanner");
      g_slist_free_full (openvasd_targets,
                         (GDestroyNotify) openvasd_target_free);
      // Credentials are freed with target
      g_slist_free_full (vts, (GDestroyNotify) openvasd_vt_single_free);
      g_hash_table_destroy (scanner_options);
      return -1;
    }

  gchar *scan_config = NULL;
  scan_config =
    openvasd_build_scan_config_json(openvasd_target, scanner_options, vts);

  response = http_scanner_create_scan (connection, scan_config);
  if (response->code == 201)
    {
      http_scanner_response_cleanup (response);
      response = http_scanner_start_scan (connection);
    }
  else
    g_warning ("%s: Failed to create scan: %ld", __func__, response->code);

  openvasd_target_free(openvasd_target);
  // Credentials are freed with target
  g_slist_free_full (vts, (GDestroyNotify) openvasd_vt_single_free);
  g_hash_table_destroy (scanner_options);
  ret = response->code;
  http_scanner_response_cleanup (response);

  return ret;
}

/**
 * @brief Handle an ongoing openvasd scan, until success or failure.
 *
 * @param[in]   task      The task.
 * @param[in]   report    The report.
 * @param[in]   scan_id   The UUID of the scan on the scanner.
 *
 * @return 0 if success, -1 if error, -2 if scan was stopped,
 *         -3 if the scan was interrupted, -4 already stopped.
 */
static int
handle_openvasd_scan (task_t task, report_t report, const char *scan_id)
{
  scanner_t scanner;
  http_scanner_connector_t connector;
  int ret;

  scanner = task_scanner (task);
  connector = http_scanner_connect (scanner, scan_id);

  if (!connector)
    {
      g_warning ("%s: Could not connect to openvasd scanner", __func__);
      return -1;
    }

  ret = handle_http_scanner_scan (connector, task, report,
                                  parse_http_scanner_report);

  http_scanner_connector_free (connector);

  return ret;

}

/**
 * @brief Fork a child to handle an openvasd scan's fetching and inserting.
 *
 * @param[in]   task       The task.
 * @param[in]   target     The target.
 * @param[in]   from       0 start from beginning, 1 continue from stopped,
 *                         2 continue if stopped else start from beginning.
 * @param[out]  report_id_return   UUID of the report.
 *
 * @return Parent returns with 0 if success, -1 if failure. Child process
 *         doesn't return and simply exits.
 */
static int
fork_openvasd_scan_handler (task_t task, target_t target, int from,
                       char **report_id_return)
{
  char *report_id, *error = NULL;
  gboolean discovery_scan = FALSE;
  int rc;

  assert (task);
  assert (target);

  if (report_id_return)
    *report_id_return = NULL;

  if (run_osp_scan_get_report (task, from, &report_id))
    return -1;

  current_scanner_task = task;
  set_task_run_status (task, TASK_STATUS_REQUESTED);

  switch (fork ())
    {
      case 0:
        init_sentry ();
        break;
      case -1:
        /* Parent, failed to fork. */
        global_current_report = 0;
        g_warning ("%s: Failed to fork: %s",
                   __func__,
                   strerror (errno));
        set_task_interrupted (task,
                              "Error forking scan handler."
                              "  Interrupting scan.");
        set_report_scan_run_status (global_current_report,
                                    TASK_STATUS_INTERRUPTED);
        global_current_report = (report_t) 0;
        current_scanner_task = 0;
        g_free (report_id);
        return -9;
      default:
        /* Parent, successfully forked. */
        global_current_report = 0;
        current_scanner_task = 0;
        if (report_id_return)
          *report_id_return = report_id;
        else
          g_free (report_id);
        return 0;
    }

  /* Child: Re-open DB after fork and periodically check scan progress.
   * If progress == 100%: Parse the report results and other info then exit(0).
   * Else, exit(1) in error cases like connection to scanner failure.
   */
  reinit_manage_process ();
  manage_session_init (current_credentials.uuid);

  rc = launch_openvasd_openvas_task (task, target, report_id, from, &error,
                                     &discovery_scan);

  if (rc < 0)
    {
      result_t result;

      g_warning ("openvasd start_scan %s: %s", report_id, error);
      result = make_osp_result (task, "", "", "",
                                threat_message_type ("Error"),
                                error, "", "", QOD_DEFAULT, NULL, NULL);
      report_add_result (global_current_report, result);
      set_task_run_status (task, TASK_STATUS_DONE);
      set_report_scan_run_status (global_current_report, TASK_STATUS_DONE);
      set_task_end_time_epoch (task, time (NULL));
      set_scan_end_time_epoch (global_current_report, time (NULL));

      g_free (error);
      g_free (report_id);
      gvm_close_sentry ();
      exit (-1);
    }

  setproctitle ("openvasd: Handling scan %s", report_id);

  rc = handle_openvasd_scan (task, global_current_report, report_id);
  g_free (report_id);

  if (rc >= 0)
    {
      set_task_run_status (task, TASK_STATUS_PROCESSING);
      set_report_scan_run_status (global_current_report,
                                  TASK_STATUS_PROCESSING);
      asset_snapshots_target (global_current_report, task, discovery_scan);
      hosts_set_identifiers (global_current_report);
      hosts_set_max_severity (global_current_report, NULL, NULL);
      hosts_set_details (global_current_report);
      set_task_run_status (task, TASK_STATUS_DONE);
      set_report_scan_run_status (global_current_report, TASK_STATUS_DONE);
    }
  else if (rc == -1 || rc == -2)
    {
      set_task_run_status (task, TASK_STATUS_STOPPED);
      set_report_scan_run_status (global_current_report, TASK_STATUS_STOPPED);
    }
  else if (rc == -3)
    {
      set_task_run_status (task, TASK_STATUS_INTERRUPTED);
      set_report_scan_run_status (global_current_report,
                                  TASK_STATUS_INTERRUPTED);
    }

  set_task_end_time_epoch (task, time (NULL));
  set_scan_end_time_epoch (global_current_report, time (NULL));
  global_current_report = 0;
  current_scanner_task = (task_t) 0;
  gvm_close_sentry ();
  exit (rc);
}

/**
 * @brief Start a task on an openvasd scanner.
 *
 * @param[in]   task       The task.
 * @param[in]   from       0 start from beginning, 1 continue from stopped,
 *                         2 continue if stopped else start from beginning.
 * @param[out]  report_id  The report ID.
 *
 * @return 0 success, 99 permission denied, -1 error.
 */
static int
run_openvasd_task (task_t task, int from, char **report_id)
{
  if (!feature_enabled (FEATURE_ID_OPENVASD_SCANNER))
    {
      g_warning ("%s: openvasd runtime flag is disabled", __func__);
      return -1;
    }
  target_t target;

  target = task_target (task);
  if (target)
    {
      char *uuid;
      target_t found;

      uuid = target_uuid (target);
      if (find_target_with_permission (uuid, &found, "get_targets"))
        {
          g_free (uuid);
          return -1;
        }
      g_free (uuid);
      if (found == 0)
        return 99;
    }

  if (fork_openvasd_scan_handler (task, target, from, report_id))
    {
      g_warning ("Couldn't fork openvasd scan handler");
      return -1;
    }
  return 0;
}
#endif

#if ENABLE_AGENTS

/**
 * @brief Handle an agent controller scan, retrieving the scan result.
 *
 * @param[in]  task     The task.
 * @param[in]  report   The report.
 * @param[in]  scan_id  The UUID of the scan on the scanner.
 *
 * @return 0 on success, -1 on error.
 */
static int
handle_agent_controller_scan (task_t task, report_t report, const char *scan_id)
{
  scanner_t scanner = 0;
  http_scanner_connector_t connector = NULL;
  GSList *results = NULL;

  if (!task || !report || !scan_id || !*scan_id)
    return -1;

  scanner = task_scanner (task);
  if (scanner == 0)
    {
      result_t r = make_osp_result (
          task, "", "", "",
          threat_message_type ("Error"),
          "Agent Controller: no scanner associated with task", "", "",
          QOD_DEFAULT, NULL, NULL);
      report_add_result (report, r);
      return -1;
    }

  connector = http_scanner_connect (scanner, scan_id);
  if (!connector)
    {
      result_t r = make_osp_result (
          task, "", "", "",
          threat_message_type ("Error"),
          "Agent Controller: failed to connect to scanner", "", "",
          QOD_DEFAULT, NULL, NULL);
      report_add_result (report, r);
      return -1;
    }

  int http_status = http_scanner_parsed_results (connector, 0, 0, &results);
  if (http_status != 200)
    {
      gchar *msg = g_strdup_printf (
          "Agent Controller: failed to fetch results (HTTP %d)", http_status);
      result_t r = make_osp_result (
          task, "", "", "",
          threat_message_type ("Error"),
          msg, "", "",
          QOD_DEFAULT, NULL, NULL);
      report_add_result (report, r);
      g_free (msg);

      http_scanner_connector_free (connector);
      return -1;
    }

  /* Parse and import into the report */
  // Expect: agent controller results should be the same as openvasd result
  parse_http_scanner_report (task, report, results, time (NULL), time (NULL));

  if (results)
    g_slist_free_full (results, (GDestroyNotify) http_scanner_result_free);

  http_scanner_connector_free (connector);
  return 0;
}

/**
 * @brief Launch an agent controller scan for the given task/group.
 *        Initialize the new report with the scan_id
 *
 * @param[in]  task        Task handle for which the scan should be launched.
 * @param[in]  agent_group Agent group containing the agents to scan.
 * @param[out] report_id   On success, set to newly allocated report ID string.
 *                         Caller must free with g_free. Set to NULL on failure.
 * @param[out] error       On failure, optionally set to a newly allocated error
 *                         string (caller must g_free). Ignored if NULL.
 *
 * @return 0 on success, -1 on failure.
 */
static int
launch_agent_control_task (task_t task,
                           agent_group_t agent_group,
                           char **report_id,
                           gchar **error)
{
  http_scanner_connector_t connection = NULL;
  agent_controller_agent_list_t agent_control_list = NULL;
  agent_uuid_list_t agent_uuids = NULL;
  http_scanner_resp_t http_scanner_resp = NULL;
  gchar *payload = NULL;
  scanner_t scanner = 0;
  int ret = -1;

  if (report_id) *report_id = NULL;

  // Get scanner
  scanner = task_scanner (task);
  if (scanner == 0)
    {
      if (error) *error = g_strdup ("Scanner is not found");
      goto make_report;
    }

  // Connect HTTP scanner
  connection = http_scanner_connect (scanner, NULL);
  if (!connection)
    {
      if (error) *error = g_strdup ("Could not connect to Scanner");
      goto make_report;
    }

  // Build agent UUID list from group
  agent_uuids = agent_uuid_list_from_group (agent_group);
  if (!agent_uuids || agent_uuids->count <= 0)
    {
      if (error) *error = g_strdup ("No Agents found");
      goto make_report;
    }

  // Map UUIDs to agent controller entries
  agent_control_list = agent_controller_agent_list_new (agent_uuids->count);
  if (!agent_control_list)
    {
      if (error) *error = g_strdup ("Allocation failure (agent list)");
      goto make_report;
    }

  if (get_agent_controller_agents_from_uuids (scanner, agent_uuids, agent_control_list) != 0)
    {
      if (error) *error = g_strdup ("Could not get Agents from database");
      goto make_report;
    }

  // Build create-scan payload
  payload = agent_controller_build_create_scan_payload (agent_control_list);
  if (!payload)
    {
      if (error) *error = g_strdup ("Could not create scan payload");
      goto make_report;
    }

  // Create scan
  http_scanner_resp = http_scanner_create_scan (connection, payload);
  if (!http_scanner_resp || http_scanner_resp->code != 201)
    {
      if (error) *error = g_strdup ("Scanner failed to create the scan");
      goto make_report;
    }

  // Extract scan id
  {
    gchar *scan_id = agent_controller_get_scan_id (http_scanner_resp->body);
    if (!scan_id)
      {
        if (error) *error = g_strdup ("Could not get scan id from response");
        goto make_report;
      }

    if (report_id) *report_id = g_strdup (scan_id);
    g_free (scan_id);
  }

  /* success */
  ret = 0;

make_report:
  // Always create a report with TASK_STATUS_REQUESTED
  {
    int report_resp = create_agent_task_current_report (
      task, *report_id, TASK_STATUS_REQUESTED);
    if (report_resp != 0)
      {
        if (error && !*error) *error = g_strdup ("Could not create current report");
        ret = -1;
      }
    goto cleanUp;
  }

cleanUp:
  if (http_scanner_resp)
    http_scanner_response_cleanup (http_scanner_resp);
  if (agent_control_list)
    agent_controller_agent_list_free (agent_control_list);
  if (agent_uuids)
    agent_uuid_list_free (agent_uuids);
  if (connection)
    http_scanner_connector_free (connection);

  g_free (payload);

  return ret;
}

/**
 * @brief Fork a child to handle an agent controller scan's fetching and inserting.
 *
 * @param[in]   task       The task.
 * @param[in]   agent_group     The Agent group.
 * @param[out]  report_id_return   UUID of the report.
 *
 * @return Parent returns with 0 if success, -1 if failure. Child process
 *         doesn't return and simply exits.
 */
static int
fork_agent_controller_scan_handler (task_t task, agent_group_t agent_group,
                       char **report_id_return)
{
  char *report_id, *error = NULL;
  int rc;

  assert (task);
  assert (agent_group);

  if (report_id_return)
    *report_id_return = NULL;

  current_scanner_task = task;
  set_task_run_status (task, TASK_STATUS_REQUESTED);

  switch (fork ())
    {
      case 0:
        init_sentry ();
        break;
      case -1:
        /* Parent, failed to fork. */
        global_current_report = 0;
        g_warning ("%s: Failed to fork: %s",
                   __func__,
                   strerror (errno));
        set_task_interrupted (task,
                              "Error forking scan handler."
                              "  Interrupting scan.");
        set_report_scan_run_status (global_current_report,
                                    TASK_STATUS_INTERRUPTED);
        global_current_report = (report_t) 0;
        current_scanner_task = 0;
        return -9;
      default:
        /* Parent, successfully forked. */
        global_current_report = 0;
        current_scanner_task = 0;
        return 0;
    }

  /* Child: Re-open DB after fork and periodically check scan progress.
   * If progress == 100%: Parse the report results and other info then exit(0).
   * Else, exit(1) in error cases like connection to scanner failure.
   */
  reinit_manage_process ();
  manage_session_init (current_credentials.uuid);

  rc = launch_agent_control_task (task, agent_group, &report_id , &error);

  if (rc < 0)
    {
      result_t result;

      g_warning ("Agent Controller start_scan %s: %s", report_id, error);
      result = make_osp_result (task, "", "", "",
                                threat_message_type ("Error"),
                                error, "", "", QOD_DEFAULT, NULL, NULL);
      report_add_result (global_current_report, result);
      set_task_run_status (task, TASK_STATUS_DONE);
      set_report_scan_run_status (global_current_report, TASK_STATUS_DONE);
      set_task_end_time_epoch (task, time (NULL));
      set_scan_end_time_epoch (global_current_report, time (NULL));

      g_free (error);
      g_free (report_id);
      gvm_close_sentry ();
      exit (-1);
    }

  setproctitle ("Agent Controller: Handling scan %s", report_id);

  rc = handle_agent_controller_scan (task, global_current_report, report_id);
  g_free (report_id);

  if (rc >= 0)
    {
      set_task_run_status (task, TASK_STATUS_PROCESSING);
      set_report_scan_run_status (global_current_report,
                                  TASK_STATUS_PROCESSING);
      hosts_set_identifiers (global_current_report);
      hosts_set_max_severity (global_current_report, NULL, NULL);
      hosts_set_details (global_current_report);
      asset_snapshots_agent (global_current_report, task, agent_group);
      set_task_run_status (task, TASK_STATUS_DONE);
      set_report_scan_run_status (global_current_report, TASK_STATUS_DONE);
    }
  else if (rc == -1)
    {
      set_task_run_status (task, TASK_STATUS_INTERRUPTED);
      set_report_scan_run_status (global_current_report,
                                  TASK_STATUS_INTERRUPTED);
    }

  set_task_end_time_epoch (task, time (NULL));
  set_scan_end_time_epoch (global_current_report, time (NULL));
  global_current_report = 0;
  current_scanner_task = (task_t) 0;
  gvm_close_sentry ();
  exit (rc);
}

/**
 * @brief Start a task on an agent control scanner.
 *
 * @param[in]   task       The task.
 * @param[out]  report_id  The report ID.
 *
 * @return 0 success, 99 permission denied, -1 error.
 */
static int
run_agent_control_task (task_t task, char **report_id)
{
  if (!feature_enabled (FEATURE_ID_AGENTS))
    {
      g_warning ("%s: Agent runtime flag is disabled", __func__);
      return -1;
    }
  agent_group_t agent_group;

  agent_group = task_agent_group (task);
  if (agent_group)
    {
      char *uuid;
      target_t found;

      uuid = agent_group_uuid (agent_group);
      if (find_resource_with_permission ("agent_group", uuid, &found,
                                         "get_agent_groups", 0))
        {
          g_free (uuid);
          return -1;
        }

      g_free (uuid);

      if (found == 0)
        return 99;
    }

  if (fork_agent_controller_scan_handler (task, agent_group, report_id))
    {
      g_warning ("Couldn't fork agent-controller scan handler");
      return -1;
    }
  return 0;
}

#endif
