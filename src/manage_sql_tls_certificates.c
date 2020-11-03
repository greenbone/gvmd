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
 * @file manage_sql_tls_certificates.c
 * @brief GVM management layer: TLS Certificates SQL
 *
 * The TLS Certificates SQL for the GVM management layer.
 */

#include "manage_tls_certificates.h"
#include "manage_acl.h"
#include "manage_sql_tls_certificates.h"
#include "manage_sql.h"
#include "utils.h"
#include "sql.h"

#include <stdlib.h>
#include <string.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

// Static function prototypes

static tls_certificate_t
user_tls_certificate_match_internal (tls_certificate_t,
                                     user_t,
                                     const char *,
                                     const char *);

// Iterator for GMP get_tls_certificates

/**
 * @brief Filter columns for tls_certificate iterator.
 */
#define TLS_CERTIFICATE_ITERATOR_FILTER_COLUMNS                               \
 { GET_ITERATOR_FILTER_COLUMNS, "subject_dn", "issuer_dn", "md5_fingerprint", \
   "activates", "expires", "valid", "certificate_format", "last_seen",        \
   "sha256_fingerprint", "serial", "time_status", NULL }

/**
 * @brief TLS Certificate iterator columns.
 */
#define TLS_CERTIFICATE_ITERATOR_COLUMNS                                      \
 {                                                                            \
   GET_ITERATOR_COLUMNS (tls_certificates),                                   \
   {                                                                          \
     "certificate",                                                           \
     NULL,                                                                    \
     KEYWORD_TYPE_STRING                                                      \
   },                                                                         \
   {                                                                          \
     "subject_dn",                                                            \
     NULL,                                                                    \
     KEYWORD_TYPE_STRING                                                      \
   },                                                                         \
   {                                                                          \
     "issuer_dn",                                                             \
     NULL,                                                                    \
     KEYWORD_TYPE_STRING                                                      \
   },                                                                         \
   {                                                                          \
     "trust",                                                                 \
     NULL,                                                                    \
     KEYWORD_TYPE_INTEGER                                                     \
   },                                                                         \
   {                                                                          \
     "md5_fingerprint",                                                       \
     NULL,                                                                    \
     KEYWORD_TYPE_STRING                                                      \
   },                                                                         \
   {                                                                          \
     "certificate_iso_time (activation_time)",                                \
     "activation_time",                                                       \
     KEYWORD_TYPE_INTEGER                                                     \
   },                                                                         \
   {                                                                          \
     "certificate_iso_time (expiration_time)",                                \
     "expiration_time",                                                       \
     KEYWORD_TYPE_INTEGER                                                     \
   },                                                                         \
   {                                                                          \
     "(CASE WHEN (expiration_time >= m_now() OR expiration_time = -1)"        \
     "       AND (activation_time <= m_now() OR activation_time = -1)"        \
     "      THEN 1 ELSE 0 END)",                                              \
     "valid",                                                                 \
     KEYWORD_TYPE_INTEGER                                                     \
   },                                                                         \
   {                                                                          \
     "certificate_format",                                                    \
     NULL,                                                                    \
     KEYWORD_TYPE_STRING                                                      \
   },                                                                         \
   {                                                                          \
     "sha256_fingerprint",                                                    \
     NULL,                                                                    \
     KEYWORD_TYPE_STRING                                                      \
   },                                                                         \
   {                                                                          \
     "serial",                                                                \
     NULL,                                                                    \
     KEYWORD_TYPE_STRING                                                      \
   },                                                                         \
   {                                                                          \
     "(SELECT iso_time(max(timestamp)) FROM tls_certificate_sources"          \
     " WHERE tls_certificate = tls_certificates.id)",                         \
     NULL,                                                                    \
     KEYWORD_TYPE_STRING                                                      \
   },                                                                         \
   {                                                                          \
     "(CASE WHEN (activation_time = -1) OR (expiration_time = 1)"             \
     "      THEN 'unknown'"                                                   \
     "      WHEN (expiration_time < m_now() AND expiration_time != 0)"        \
     "      THEN 'expired'"                                                   \
     "      WHEN (activation_time > m_now())"                                 \
     "      THEN 'inactive'"                                                  \
     "      ELSE 'valid' END)",                                               \
     "time_status",                                                           \
     KEYWORD_TYPE_INTEGER                                                     \
   },                                                                         \
   {                                                                          \
     "activation_time",                                                       \
     "activates",                                                             \
     KEYWORD_TYPE_INTEGER                                                     \
   },                                                                         \
   {                                                                          \
     "expiration_time",                                                       \
     "expires",                                                               \
     KEYWORD_TYPE_INTEGER                                                     \
   },                                                                         \
   {                                                                          \
     "(SELECT max(timestamp) FROM tls_certificate_sources"                    \
     " WHERE tls_certificate = tls_certificates.id)",                         \
     "last_seen",                                                             \
     KEYWORD_TYPE_INTEGER                                                     \
   },                                                                         \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                       \
 }

/**
 * @brief Gets the filter columns for TLS certificates.
 *
 * @return Constant array of filter columns.
 */
const char**
tls_certificate_filter_columns ()
{
  static const char *columns[] = TLS_CERTIFICATE_ITERATOR_FILTER_COLUMNS;
  return columns;
}

/**
 * @brief Gets the select columns for TLS certificates.
 *
 * @return Constant array of select columns.
 */
column_t*
tls_certificate_select_columns ()
{
  static column_t columns[] = TLS_CERTIFICATE_ITERATOR_COLUMNS;
  return columns;
}

/**
 * @brief Get extra_where string for a TLS certificate iterator or count.
 *
 * @param[in]  filter           Filter string.
 *
 * @return     Newly allocated extra_where string.
 */
gchar *
tls_certificate_extra_where (const char *filter)
{
  GString *ret;
  gchar *host_id, *report_id;

  ret = g_string_new ("");

  host_id = filter_term_value (filter, "host_id");
  report_id = filter_term_value (filter, "report_id");

  if (host_id)
    {
      gchar *quoted_id;
      quoted_id = sql_quote (host_id);
      g_string_append_printf
         (ret,
          " AND (tls_certificates.id IN"
          " (WITH host_idents AS"
          "   (SELECT source_id AS ident_report_id, value AS ident_ip"
          "      FROM host_identifiers"
          "     WHERE host = (SELECT id FROM hosts"
          "                   WHERE uuid='%s')"
          "       AND name = 'ip')"
          "  SELECT tls_certificate"
          "    FROM tls_certificate_sources AS sources"
          "    JOIN tls_certificate_origins AS origins"
          "      ON origins.id = sources.origin"
          "    JOIN tls_certificate_locations AS locations"
          "      ON locations.id = sources.location"
          "    JOIN host_idents"
          "      ON origins.origin_id = host_idents.ident_report_id"
          "         AND locations.host_ip = host_idents.ident_ip)"
          " )",
          quoted_id);
      g_free (quoted_id);
    }

  if (report_id)
    {
      gchar *quoted_id;
      quoted_id = sql_quote (report_id);
      g_string_append_printf (ret,
                              " AND"
                              " (EXISTS"
                              "   (SELECT * FROM"
                              "    tls_certificate_source_origins AS src_orig"
                              "    WHERE tls_certificate = tls_certificates.id"
                              "      AND origin_type = 'Report'"
                              "      AND origin_id = '%s'))",
                              quoted_id);
      g_free (quoted_id);
    }

  g_free (host_id);
  g_free (report_id);

  return g_string_free (ret, FALSE);
}

/**
 * @brief Count number of tls_certificates.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of tls_certificates in filtered set.
 */
int
tls_certificate_count (const get_data_t *get)
{
  static const char *filter_columns[] = TLS_CERTIFICATE_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = TLS_CERTIFICATE_ITERATOR_COLUMNS;
  gchar *filter;
  char *extra_where;
  int ret;

  if (get->filt_id && strcmp (get->filt_id, FILT_ID_NONE))
    {
      if (get->filter_replacement)
        /* Replace the filter term with one given by the caller.  This is
         * used by GET_REPORTS to use the default filter with any task (when
         * given the special value of -3 in filt_id). */
        filter = g_strdup (get->filter_replacement);
      else
        filter = filter_term (get->filt_id);
      if (filter == NULL)
        return 2;
    }
  else
    filter = NULL;

  extra_where
    = tls_certificate_extra_where (filter ? filter : get->filter);

  ret = count ("tls_certificate", get, columns, NULL, filter_columns,
               0, 0, extra_where, TRUE);

  g_free (extra_where);
  return ret;
}

/**
 * @brief Initialise a tls_certificate iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 *
 * @return 0 success, 1 failed to find tls_certificate,
 *         2 failed to find filter, -1 error.
 */
int
init_tls_certificate_iterator (iterator_t *iterator, const get_data_t *get)
{
  static const char *filter_columns[] = TLS_CERTIFICATE_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = TLS_CERTIFICATE_ITERATOR_COLUMNS;
  gchar *filter;
  char *extra_where;
  int ret;

  if (get->filt_id && strcmp (get->filt_id, FILT_ID_NONE))
    {
      if (get->filter_replacement)
        /* Replace the filter term with one given by the caller.  This is
         * used by GET_REPORTS to use the default filter with any task (when
         * given the special value of -3 in filt_id). */
        filter = g_strdup (get->filter_replacement);
      else
        filter = filter_term (get->filt_id);
      if (filter == NULL)
        return 2;
    }
  else
    filter = NULL;

  extra_where
    = tls_certificate_extra_where (filter ? filter : get->filter);

  ret = init_get_iterator (iterator,
                           "tls_certificate",
                           get,
                           columns,
                           NULL,
                           filter_columns,
                           0,
                           NULL,
                           extra_where,
                           TRUE);

  g_free (extra_where);
  return ret;
}

/**
 * @brief Get a column value from a tls_certificate iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (tls_certificate_iterator_certificate, GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Get a column value from a tls_certificate iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (tls_certificate_iterator_subject_dn,
            GET_ITERATOR_COLUMN_COUNT + 1);

/**
 * @brief Get a column value from a tls_certificate iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (tls_certificate_iterator_issuer_dn,
            GET_ITERATOR_COLUMN_COUNT + 2);

/**
 * @brief Get a column value from a tls_certificate iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
int
tls_certificate_iterator_trust (iterator_t *iterator)
{
  if (iterator->done)
    return 0;

  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 3);
}

/**
 * @brief Get a column value from a tls_certificate iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (tls_certificate_iterator_md5_fingerprint,
            GET_ITERATOR_COLUMN_COUNT + 4);

/**
 * @brief Get a column value from a tls_certificate iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (tls_certificate_iterator_activation_time,
            GET_ITERATOR_COLUMN_COUNT + 5);

/**
 * @brief Get a column value from a tls_certificate iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (tls_certificate_iterator_expiration_time,
            GET_ITERATOR_COLUMN_COUNT + 6);

/**
 * @brief Get a column value from a tls_certificate iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
int
tls_certificate_iterator_valid (iterator_t *iterator)
{
  if (iterator->done)
    return 0;

  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 7);
}

/**
 * @brief Get a column value from a tls_certificate iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (tls_certificate_iterator_certificate_format,
            GET_ITERATOR_COLUMN_COUNT + 8);

/**
 * @brief Get a column value from a tls_certificate iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (tls_certificate_iterator_sha256_fingerprint,
            GET_ITERATOR_COLUMN_COUNT + 9);

/**
 * @brief Get a column value from a tls_certificate iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (tls_certificate_iterator_serial,
            GET_ITERATOR_COLUMN_COUNT + 10);

/**
 * @brief Get a column value from a tls_certificate iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (tls_certificate_iterator_last_seen,
            GET_ITERATOR_COLUMN_COUNT + 11);

/**
 * @brief Get a column value from a tls_certificate iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (tls_certificate_iterator_time_status,
            GET_ITERATOR_COLUMN_COUNT + 12);


/**
 * @brief Return whether a tls_certificate is in use.
 *
 * @param[in]  tls_certificate  TLS Certificate.
 *
 * @return 1 if in use, else 0.
 */
int
tls_certificate_in_use (tls_certificate_t tls_certificate)
{
  return 0;
}

/**
 * @brief Return whether a tls_certificate is writable.
 *
 * @param[in]  tls_certificate  TLS Certificate.
 *
 * @return 1 if writable, else 0.
 */
int
tls_certificate_writable (tls_certificate_t tls_certificate)
{
  return 1;
}

/**
 * @brief Create or update a TLS certificate from collected data
 *
 * @param[in]  name               Optional name for the certificate.
 * @param[in]  comment            Optional comment for the certificate.
 * @param[in]  certificate_b64    Base64 encoded certificate.
 * @param[in]  activation_time    Activation time of the certificate.
 * @param[in]  expiration_time    Expiration time of the certificate
 * @param[in]  md5_fingerprint    MD5 fingerprint of the certificate.
 * @param[in]  sha256_fingerprint SHA-256 fingerprint of the certificate.
 * @param[in]  subject_dn         Subject DN of the certificate.
 * @param[in]  issuer_dn          Issuer DN of the certificate.
 * @param[in]  serial             Serial of the certificate.
 * @param[in]  certificate_format Certificate format (0 = DER, 1 = PEM).
 * @param[in]  trust              Whether to trust the certificate.
 * @param[in]  update             Whether/how to update if certificate exists.
 *                                0: reject, 1: update missing.
 * @param[out] tls_certificate    Created TLS certificate.
 *
 * @return 0 success, -1 error, 3 certificate already exists.
 */
static int
make_tls_certificate (const char *name,
                      const char *comment,
                      const char *certificate_b64,
                      time_t activation_time,
                      time_t expiration_time,
                      const char *md5_fingerprint,
                      const char *sha256_fingerprint,
                      const char *subject_dn,
                      const char *issuer_dn,
                      const char *serial,
                      gnutls_x509_crt_fmt_t certificate_format,
                      int trust,
                      int update,
                      tls_certificate_t *tls_certificate)
{
  gchar *quoted_name, *quoted_comment, *quoted_certificate_b64;
  gchar *quoted_md5_fingerprint, *quoted_sha256_fingerprint;
  gchar *quoted_subject_dn, *quoted_issuer_dn, *quoted_serial;

  user_t current_user = 0;
  tls_certificate_t old_tls_certificate, new_tls_certificate;

  if (sha256_fingerprint == NULL || strcmp (sha256_fingerprint, "") == 0)
    {
      g_warning ("%s: Missing/empty sha256_fingerprint", __func__);
      return -1;
    }

  sql_int64 (&current_user,
             "SELECT id FROM users WHERE uuid = '%s'",
             current_credentials.uuid);

  old_tls_certificate
    = user_tls_certificate_match_internal (0,
                                           current_user,
                                           sha256_fingerprint,
                                           md5_fingerprint);

  if (old_tls_certificate && update != 1)
    {
      return 3;
    }

  if (name && strcmp (name, ""))
    quoted_name = sql_quote (name);
  else
    quoted_name = sql_quote (sha256_fingerprint);
  quoted_comment
    = sql_quote (comment ? comment : "");
  quoted_certificate_b64
    = sql_quote (certificate_b64 ? certificate_b64 : "");
  quoted_md5_fingerprint
    = sql_quote (md5_fingerprint ? md5_fingerprint : "");
  quoted_sha256_fingerprint
    = sql_quote (sha256_fingerprint ? sha256_fingerprint : "");
  quoted_subject_dn
    = sql_quote (subject_dn ? subject_dn : "");
  quoted_issuer_dn
    = sql_quote (issuer_dn ? issuer_dn : "");
  quoted_serial
    = sql_quote (serial ? serial : "");

  if (old_tls_certificate)
    {
      if (update == 1)
        {
          /*
           * Update any columns that are NULL or empty.
           *
           * (activation_time and expiration_time are updated if unknown (-1),
           *  certificate_format is updated if certificate is updated)
           */
          sql ("UPDATE tls_certificates SET"
               " certificate"
               "   = coalesce (nullif (certificate, ''), '%s'),"
               " activation_time"
               "   = coalesce (nullif (activation_time, -1), %ld),"
               " expiration_time"
               "   = coalesce (nullif (expiration_time, -1), %ld),"
               " md5_fingerprint"
               "   = coalesce (nullif (md5_fingerprint, ''), '%s'),"
               " sha256_fingerprint"
               "   = coalesce (nullif (sha256_fingerprint, ''), '%s'),"
               " subject_dn"
               "   = coalesce (nullif (subject_dn, ''), '%s'),"
               " issuer_dn"
               "   = coalesce (nullif (issuer_dn, ''), '%s'),"
               " serial"
               "   = coalesce (nullif (serial, ''), '%s'),"
               " certificate_format"
               "   = (CASE"
               "      WHEN (certificate IS NULL) OR (certificate = '')"
               "      THEN '%s'"
               "      ELSE certificate_format"
               "      END),"
               " modification_time = m_now ()"
               " WHERE id = %llu",
               quoted_certificate_b64,
               activation_time,
               expiration_time,
               quoted_md5_fingerprint,
               quoted_sha256_fingerprint,
               quoted_subject_dn,
               quoted_issuer_dn,
               quoted_serial,
               tls_certificate_format_str (certificate_format),
               old_tls_certificate);
        }

      new_tls_certificate = old_tls_certificate;
    }
  else
    {
      sql ("INSERT INTO tls_certificates"
           " (uuid, owner, name, comment, creation_time, modification_time,"
           "  certificate, subject_dn, issuer_dn, trust,"
           "  activation_time, expiration_time,"
           "  md5_fingerprint, sha256_fingerprint, serial, certificate_format)"
           " SELECT make_uuid(),"
           "        (SELECT id FROM users WHERE users.uuid = '%s'),"
           "        '%s', '%s', m_now(), m_now(), '%s', '%s', '%s', %d,"
           "        %ld, %ld,"
           "        '%s', '%s', '%s', '%s';",
           current_credentials.uuid,
           quoted_name,
           quoted_comment,
           quoted_certificate_b64,
           quoted_subject_dn,
           quoted_issuer_dn,
           trust,
           activation_time,
           expiration_time,
           quoted_md5_fingerprint,
           quoted_sha256_fingerprint,
           quoted_serial,
           tls_certificate_format_str (certificate_format));

      new_tls_certificate = sql_last_insert_id ();
    }

  g_free (quoted_name);
  g_free (quoted_comment);
  g_free (quoted_certificate_b64);
  g_free (quoted_subject_dn);
  g_free (quoted_issuer_dn);
  g_free (quoted_md5_fingerprint);
  g_free (quoted_sha256_fingerprint);
  g_free (quoted_serial);

  if (tls_certificate)
    *tls_certificate = new_tls_certificate;

  return 0;
}

/**
 * @brief Create or update a TLS certificate from Base64 encoded file content.
 *
 * @param[in]   name              Name of new TLS certificate.
 * @param[in]   comment           Comment of TLS certificate.
 * @param[in]   certificate_b64   Base64 certificate file content.
 * @param[in]   fallback_fpr      Fallback fingerprint if getting data fails.
 * @param[in]   trust             Whether to trust the certificate.
 * @param[in]   allow_failed_info Whether to use if get_certificate_info fails.
 * @param[in]   update            Whether/how to update if certificate exists.
 *                                0: reject, 1: update missing.
 * @param[out]  tls_certificate Created TLS certificate.
 *
 * @return 0 success, 1 invalid certificate content, 2 certificate not Base64,
 *         3 certificate already exists, 99 permission denied, -1 error.
 */
int
make_tls_certificate_from_base64 (const char *name,
                                  const char *comment,
                                  const char *certificate_b64,
                                  const char *fallback_fpr,
                                  int trust,
                                  int allow_failed_info,
                                  int update,
                                  tls_certificate_t *tls_certificate)
{
  int ret;
  gchar *certificate_decoded;
  gsize certificate_len;
  char *md5_fingerprint, *sha256_fingerprint, *subject_dn, *issuer_dn, *serial;
  time_t activation_time, expiration_time;
  gnutls_x509_crt_fmt_t certificate_format;

  certificate_decoded
      = (gchar*) g_base64_decode (certificate_b64, &certificate_len);

  if (certificate_decoded == NULL || certificate_len == 0)
    return 2;

  ret = get_certificate_info (certificate_decoded,
                              certificate_len,
                              &activation_time,
                              &expiration_time,
                              &md5_fingerprint,
                              &sha256_fingerprint,
                              &subject_dn,
                              &issuer_dn,
                              &serial,
                              &certificate_format);

  if (ret)
    {
      if (allow_failed_info == 0 || fallback_fpr == NULL)
        {
          g_free (certificate_decoded);
          return 1;
        }
      sha256_fingerprint = g_strdup (fallback_fpr);
    }

  ret = make_tls_certificate (name,
                              comment,
                              certificate_b64,
                              activation_time,
                              expiration_time,
                              md5_fingerprint,
                              sha256_fingerprint,
                              subject_dn,
                              issuer_dn,
                              serial,
                              certificate_format,
                              trust,
                              update,
                              tls_certificate);

  g_free (certificate_decoded);
  g_free (md5_fingerprint);
  g_free (sha256_fingerprint);
  g_free (subject_dn);
  g_free (issuer_dn);
  g_free (serial);

  return ret;
}

/**
 * @brief Create a TLS certificate.
 *
 * @param[in]   name            Name of new TLS certificate.
 * @param[in]   comment         Comment of TLS certificate.
 * @param[in]   certificate_b64 Base64 certificate file content.
 * @param[in]   trust           Whether to trust the certificate.
 * @param[out]  tls_certificate Created TLS certificate.
 *
 * @return 0 success, 1 invalid certificate content, 2 certificate not Base64,
 *         3 certificate already exists, 99 permission denied, -1 error.
 */
int
create_tls_certificate (const char *name,
                        const char *comment,
                        const char *certificate_b64,
                        int trust,
                        tls_certificate_t *tls_certificate)
{
  int ret;
  tls_certificate_t new_tls_certificate;

  ret = make_tls_certificate_from_base64 (name,
                                          comment,
                                          certificate_b64,
                                          NULL, /* fallback_fpr */
                                          trust,
                                          0, /* allow_failed_info */
                                          0, /* update */
                                          &new_tls_certificate);

  if (ret)
    return ret;

  get_or_make_tls_certificate_source (new_tls_certificate,
                                      NULL,   /* host_ip */
                                      NULL,   /* port */
                                      "Import",
                                      NULL,   /* origin_id */
                                      NULL);  /* origin_data */

  if (tls_certificate)
    *tls_certificate = new_tls_certificate;

  return 0;
}

/**
 * @brief Create a TLS certificate from an existing TLS certificate.
 *
 * @param[in]  name        Name. NULL to copy from existing TLS certificate.
 * @param[in]  comment     Comment. NULL to copy from existing TLS certificate.
 * @param[in]  tls_certificate_id   UUID of existing TLS certificate.
 * @param[out] new_tls_certificate  New TLS certificate.
 *
 * @return 0 success,
 *         1 TLS certificate exists already,
 *         2 failed to find existing TLS certificate,
 *         99 permission denied,
 *         -1 error.
 */
int
copy_tls_certificate (const char *name,
                      const char *comment,
                      const char *tls_certificate_id,
                      tls_certificate_t *new_tls_certificate)
{
  int ret;
  tls_certificate_t old_tls_certificate;

  assert (new_tls_certificate);

  ret = copy_resource ("tls_certificate", name, comment, tls_certificate_id,
                       "certificate, subject_dn, issuer_dn, trust,"
                       "activation_time, expiration_time, md5_fingerprint,"
                       "certificate_format, sha256_fingerprint, serial",
                       0, new_tls_certificate, &old_tls_certificate);
  if (ret)
    return ret;

  return 0;
}

/**
 * @brief Delete a tls_certificate.
 *
 * TLS certificates do not use the trashcan, so the "ultimate" param is ignored
 *  and the resource is always removed completely.
 *
 * @param[in]  tls_certificate_id  UUID of tls_certificate.
 * @param[in]  ultimate   Dummy for consistency with other delete commands.
 *
 * @return 0 success, 1 fail because tls_certificate is in use,
 *         2 failed to find tls_certificate, 99 permission denied, -1 error.
 */
int
delete_tls_certificate (const char *tls_certificate_id, int ultimate)
{
  tls_certificate_t tls_certificate = 0;

  sql_begin_immediate ();

  if (acl_user_may ("delete_tls_certificate") == 0)
    {
      sql_rollback ();
      return 99;
    }

  /* Search in the regular table. */

  if (find_resource_with_permission ("tls_certificate",
                                     tls_certificate_id,
                                     &tls_certificate,
                                     "delete_tls_certificate",
                                     0))
    {
      sql_rollback ();
      return -1;
    }

  if (tls_certificate == 0)
    {
      /* No such tls_certificate */
      sql_rollback ();
      return 2;
    }

  sql ("DELETE FROM permissions"
        " WHERE resource_type = 'tls_certificate'"
        " AND resource_location = %i"
        " AND resource = %llu;",
        LOCATION_TABLE,
        tls_certificate);

  tags_remove_resource ("tls_certificate",
                        tls_certificate,
                        LOCATION_TABLE);

  sql ("DELETE FROM tls_certificate_sources"
       " WHERE tls_certificate = %llu",
       tls_certificate);

  sql ("DELETE FROM tls_certificate_locations"
       " WHERE NOT EXISTS"
       "   (SELECT * FROM tls_certificate_sources"
       "     WHERE location = tls_certificate_locations.id);");

  sql ("DELETE FROM tls_certificate_origins"
       " WHERE NOT EXISTS"
       "   (SELECT * FROM tls_certificate_sources"
       "     WHERE origin = tls_certificate_origins.id);");

  sql ("DELETE FROM tls_certificates WHERE id = %llu;",
       tls_certificate);

  sql_commit ();
  return 0;
}

/**
 * @brief Delete all TLS certificate owned by a user.
 *
 * Also delete trash TLS certificates.
 *
 * @param[in]  user  The user.
 */
void
delete_tls_certificates_user (user_t user)
{
  /* Regular tls_certificate. */

  sql ("DELETE FROM tls_certificate_sources"
       " WHERE tls_certificate IN"
       " (SELECT id FROM tls_certificates WHERE owner = %llu)",
       user);

  sql ("DELETE FROM tls_certificate_locations"
       " WHERE NOT EXISTS"
       "   (SELECT * FROM tls_certificate_sources"
       "     WHERE location = tls_certificate_locations.id);");

  sql ("DELETE FROM tls_certificate_origins"
       " WHERE NOT EXISTS"
       "   (SELECT * FROM tls_certificate_sources"
       "     WHERE origin = tls_certificate_origins.id);");

  sql ("DELETE FROM tls_certificates WHERE owner = %llu;", user);
}

/**
 * @brief Change ownership of tls_certificate, for user deletion.
 *
 * Also assign tls_certificate that are assigned to the user to the inheritor.
 *
 * @param[in]  user       Current owner.
 * @param[in]  inheritor  New owner.
 */
void
inherit_tls_certificates (user_t user, user_t inheritor)
{
  /* Regular tls_certificate. */

  sql ("UPDATE tls_certificates SET owner = %llu WHERE owner = %llu;",
       inheritor, user);
}

/**
 * @brief Modify a TLS certificate.
 *
 * @param[in]   tls_certificate_id  UUID of TLS certificate.
 * @param[in]   comment             New comment on TLS certificate.
 * @param[in]   name                New name of TLS certificate.
 * @param[in]   trust               New trust value or -1 to keep old value.
 *
 * @return 0 success, 1 TLS certificate exists already,
 *         2 failed to find TLS certificate,
 *         3 invalid certificate content, 4 certificate is not valid Base64,
 *         99 permission denied, -1 error.
 */
int
modify_tls_certificate (const gchar *tls_certificate_id,
                        const gchar *comment,
                        const gchar *name,
                        int trust)
{
  tls_certificate_t tls_certificate;

  assert (tls_certificate_id);
  assert (current_credentials.uuid);

  sql_begin_immediate ();

  /* Check permissions and get a handle on the TLS certificate. */

  if (acl_user_may ("modify_tls_certificate") == 0)
    {
      sql_rollback ();
      return 99;
    }

  tls_certificate = 0;
  if (find_resource_with_permission ("tls_certificate",
                                     tls_certificate_id,
                                     &tls_certificate,
                                     "modify_tls_certificate",
                                     0))
    {
      sql_rollback ();
      return -1;
    }

  if (tls_certificate == 0)
    {
      sql_rollback ();
      return 2;
    }

  /* Update comment if requested. */

  if (comment)
    {
      gchar *quoted_comment;

      quoted_comment = sql_quote (comment);
      sql ("UPDATE tls_certificates SET"
           " comment = '%s',"
           " modification_time = m_now ()"
           " WHERE id = %llu;",
           quoted_comment,
           tls_certificate);
      g_free (quoted_comment);
    }

  /* Update name if requested. */

  if (name)
    {
      gchar *quoted_name;

      quoted_name = sql_quote (name);
      sql ("UPDATE tls_certificates SET"
           " name = '%s',"
           " modification_time = m_now ()"
           " WHERE id = %llu;",
           quoted_name,
           tls_certificate);
      g_free (quoted_name);
    }

  /* Update trust if requested */

  if (trust != -1)
    {
      sql ("UPDATE tls_certificates SET"
           " trust = %d,"
           " modification_time = m_now ()"
           " WHERE id = %llu;",
           trust,
           tls_certificate);
    }

  sql_commit ();

  return 0;
}

/**
 * @brief Return the UUID of a TLS certificate.
 *
 * @param[in]  tls_certificate  TLS certificate.
 *
 * @return Newly allocated UUID if available, else NULL.
 */
char*
tls_certificate_uuid (tls_certificate_t tls_certificate)
{
  return sql_string ("SELECT uuid FROM tls_certificates WHERE id = %llu;",
                     tls_certificate);
}

/**
 * @brief Initialise an iterator of TLS certificate sources
 *
 * @param[in]  iterator         Iterator to initialise.
 * @param[in]  tls_certificate  TLS certificate to get sources for.
 *
 * @return 0 success, -1 error.
 */
int
init_tls_certificate_source_iterator (iterator_t *iterator,
                                      tls_certificate_t tls_certificate)
{
  init_iterator (iterator,
                 "SELECT tls_certificate_sources.uuid,"
                 "       iso_time(timestamp) AS iso_timestamp,"
                 "       tls_versions,"
                 "       tls_certificate_locations.uuid,"
                 "       host_ip, port,"
                 "       tls_certificate_origins.uuid,"
                 "       origin_type, origin_id, origin_data"
                 " FROM tls_certificate_sources"
                 " LEFT OUTER JOIN tls_certificate_origins"
                 "   ON tls_certificate_origins.id = origin"
                 " LEFT OUTER JOIN tls_certificate_locations"
                 "   ON tls_certificate_locations.id = location"
                 " WHERE tls_certificate = %llu"
                 " ORDER BY timestamp DESC",
                 tls_certificate);

  return 0;
}

/**
 * @brief Get a column value from a tls_certificate iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (tls_certificate_source_iterator_uuid, 0);

/**
 * @brief Get a column value from a tls_certificate iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (tls_certificate_source_iterator_timestamp, 1);

/**
 * @brief Get a column value from a tls_certificate iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (tls_certificate_source_iterator_tls_versions, 2);

/**
 * @brief Get a column value from a tls_certificate iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (tls_certificate_source_iterator_location_uuid, 3);

/**
 * @brief Get a column value from a tls_certificate iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (tls_certificate_source_iterator_location_host_ip, 4);

/**
 * @brief Get a column value from a tls_certificate iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (tls_certificate_source_iterator_location_port, 5);

/**
 * @brief Get a column value from a tls_certificate iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (tls_certificate_source_iterator_origin_uuid, 6);

/**
 * @brief Get a column value from a tls_certificate iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (tls_certificate_source_iterator_origin_type, 7);

/**
 * @brief Get a column value from a tls_certificate iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (tls_certificate_source_iterator_origin_id, 8);

/**
 * @brief Get a column value from a tls_certificate iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (tls_certificate_source_iterator_origin_data, 9);

/**
 * @brief Gets or creates a tls_certificate_location.
 *
 * If a location with matching host_ip and port exists its id is returned,
 *  otherwise a new one is created and its id is returned.
 *
 * @param[in]  host_ip  IP address of the location
 * @param[in]  port     Port number of the location
 *
 * @return Row id of the tls_certificate_location
 */
resource_t
get_or_make_tls_certificate_location (const char *host_ip,
                                      const char *port)
{
  resource_t location = 0;
  char *quoted_host_ip, *quoted_port;
  quoted_host_ip = host_ip ? sql_quote (host_ip) : g_strdup ("");
  quoted_port = port ? sql_quote (port) : g_strdup ("");

  sql_int64 (&location,
             "SELECT id"
             " FROM tls_certificate_locations"
             " WHERE host_ip = '%s'"
             "   AND port = '%s'",
             quoted_host_ip,
             quoted_port);

  if (location)
    {
      g_free (quoted_host_ip);
      g_free (quoted_port);
      return location;
    }

  sql ("INSERT INTO tls_certificate_locations"
       "  (uuid, host_ip, port)"
       " VALUES (make_uuid (), '%s', '%s')",
       quoted_host_ip,
       quoted_port);

  location = sql_last_insert_id ();

  g_free (quoted_host_ip);
  g_free (quoted_port);

  return location;
}

/**
 * @brief Gets or creates a tls_certificate_origin.
 *
 * If an origin with matching type, id and data exists its id is returned,
 *  otherwise a new one is created and its id is returned.
 *
 * @param[in]  origin_type  Origin type, e.g. "GMP" or "Report"
 * @param[in]  origin_id    Origin resource id, e.g. a report UUID.
 * @param[in]  origin_data  Origin extra data, e.g. OID of generating NVT.
 *
 * @return Row id of the tls_certificate_origin
 */
resource_t
get_or_make_tls_certificate_origin (const char *origin_type,
                                    const char *origin_id,
                                    const char *origin_data)
{
  resource_t origin = 0;
  char *quoted_origin_type, *quoted_origin_id, *quoted_origin_data;
  quoted_origin_type = origin_type ? sql_quote (origin_type) : g_strdup ("");
  quoted_origin_id = origin_id ? sql_quote (origin_id) : g_strdup ("");
  quoted_origin_data = origin_data ? sql_quote (origin_data) : g_strdup ("");

  sql_int64 (&origin,
             "SELECT id"
             " FROM tls_certificate_origins"
             " WHERE origin_type = '%s'"
             "   AND origin_id = '%s'"
             "   AND origin_data = '%s'",
             quoted_origin_type,
             quoted_origin_id,
             quoted_origin_data);

  if (origin)
    {
      g_free (quoted_origin_type);
      g_free (quoted_origin_id);
      g_free (quoted_origin_data);
      return origin;
    }

  sql ("INSERT INTO tls_certificate_origins"
       "  (uuid, origin_type, origin_id, origin_data)"
       " VALUES (make_uuid (), '%s', '%s', '%s')",
       quoted_origin_type,
       quoted_origin_id,
       quoted_origin_data);

  origin = sql_last_insert_id ();

  g_free (quoted_origin_type);
  g_free (quoted_origin_id);
  g_free (quoted_origin_data);

  return origin;
}

/**
 * @brief Gets or creates a tls_certificate_source.
 *
 * If a source with matching location and origin data exists its id is
 *  returned, otherwise a new one is created and its id is returned.
 *
 * If all the location data is NULL a NULL location is fetched / created.
 *
 * @param[in]  tls_certificate  The TLS certificate of the source
 * @param[in]  host_ip          IP address of the location
 * @param[in]  port             Port number of the location
 * @param[in]  origin_type      Origin type, e.g. "GMP" or "Report"
 * @param[in]  origin_id        Origin resource id, e.g. a report UUID.
 * @param[in]  origin_data      Origin extra data, e.g. OID of generating NVT.
 *
 * @return Row id of the tls_certificate_origin
 */
resource_t
get_or_make_tls_certificate_source (tls_certificate_t tls_certificate,
                                    const char *host_ip,
                                    const char *port,
                                    const char *origin_type,
                                    const char *origin_id,
                                    const char *origin_data)
{
  resource_t location, origin, source;

  if (tls_certificate == 0)
    {
      g_warning ("%s: No TLS certificate given", __func__);
      return 0;
    }

  if (host_ip || port)
    location = get_or_make_tls_certificate_location (host_ip, port);
  else
    location = 0;

  origin = get_or_make_tls_certificate_origin (origin_type,
                                               origin_id,
                                               origin_data);

  source = 0;
  if (location)
    {
      sql_int64 (&source,
                 "SELECT id FROM tls_certificate_sources"
                 " WHERE tls_certificate = %llu"
                 "   AND location = %llu"
                 "   AND origin = %llu",
                 tls_certificate,
                 location,
                 origin);
    }
  else
    {
      sql_int64 (&source,
                 "SELECT id FROM tls_certificate_sources"
                 " WHERE tls_certificate = %llu"
                 "   AND location IS NULL"
                 "   AND origin = %llu",
                 tls_certificate,
                 origin);
    }

  if (source == 0)
    {
      sql ("INSERT INTO tls_certificate_sources"
           " (uuid, tls_certificate, location, origin, timestamp)"
           " VALUES"
           "  (make_uuid(), %llu, nullif(%llu, 0), %llu, m_now());",
           tls_certificate,
           location,
           origin);
      source = sql_last_insert_id ();
    }

  return source;
}

/**
 * @brief Tries to find a matching certificate for a given user
 *
 * @param[in]  tls_certificate    The certificate to check
 * @param[in]  user               The user to check
 * @param[in]  sha256_fingerprint The SHA256 fingerprint to match
 * @param[in]  md5_fingerprint    The MD5 fingerprint to match
 *
 * @return The matching certificate or 0 if none is found.
 */
static tls_certificate_t
user_tls_certificate_match_internal (tls_certificate_t tls_certificate,
                                     user_t user,
                                     const char *sha256_fingerprint,
                                     const char *md5_fingerprint)
{
  gchar *quoted_sha256_fingerprint, *quoted_md5_fingerprint;
  tls_certificate_t ret_tls_certificate = 0;

  quoted_sha256_fingerprint
    = sql_quote (sha256_fingerprint ? sha256_fingerprint : "");
  quoted_md5_fingerprint
    = sql_quote (md5_fingerprint ? md5_fingerprint : "");

  sql_int64 (&ret_tls_certificate,
             "SELECT id FROM tls_certificates"
             "   WHERE (id = %llu"
             "          OR sha256_fingerprint = '%s'"
             "          OR md5_fingerprint = '%s')"
             "     AND owner = %llu",
             tls_certificate,
             quoted_sha256_fingerprint,
             quoted_md5_fingerprint,
             user);

  g_free (quoted_sha256_fingerprint);
  g_free (quoted_md5_fingerprint);

  return ret_tls_certificate;
}

/**
 * @brief Checks if user owns a certificate or one with the same fingerprints.
 *
 * @param[in]  tls_certificate  The certificate to check
 * @param[in]  user             The user to check
 *
 * @return 1 matching certificate found, 0 no matching certificate
 */
int
user_has_tls_certificate (tls_certificate_t tls_certificate,
                          user_t user)
{
  gchar *sha256_fingerprint, *md5_fingerprint;

  sql_int64 (&user,
             "SELECT id FROM users WHERE uuid = '%s'",
             current_credentials.uuid);

  sha256_fingerprint
    = sql_string ("SELECT sha256_fingerprint FROM tls_certificates"
                  " WHERE id = %llu",
                  tls_certificate);
  md5_fingerprint
    = sql_string ("SELECT md5_fingerprint FROM tls_certificates"
                  " WHERE id = %llu",
                  tls_certificate);

  if (user_tls_certificate_match_internal (tls_certificate,
                                           user,
                                           sha256_fingerprint,
                                           md5_fingerprint))
    {
      g_free (sha256_fingerprint);
      g_free (md5_fingerprint);
      return 1;
    }

  g_free (sha256_fingerprint);
  g_free (md5_fingerprint);

  return 0;
}

/**
 * @brief Collects and add TLS certificates from the details of a report host.
 *
 * @param[in] report_host  The report host to get certificates from.
 * @param[in] report_id    UUID of the report
 * @param[in] host_ip      The IP address of the report host.
 *
 * @return 0: success, -1: error
 */
int
add_tls_certificates_from_report_host (report_host_t report_host,
                                       const char *report_id,
                                       const char *host_ip)
{
  iterator_t tls_certs;
  time_t activation_time, expiration_time;
  gchar *md5_fingerprint, *sha256_fingerprint, *subject, *issuer, *serial;
  gnutls_x509_crt_fmt_t certificate_format;

  /* host_ip and report_id are expected to avoid possibly redundant
   *  SQL queries to get them */
  if (report_host == 0
      || host_ip == NULL
      || report_id == NULL
      || strcmp (host_ip, "") == 0
      || strcmp (report_id, "") == 0)
    return -1;

  init_iterator (&tls_certs,
                 "SELECT rhd.value, rhd.name, rhd.source_name"
                 " FROM report_host_details AS rhd"
                 " WHERE rhd.report_host = %llu"
                 "   AND (source_description = 'SSL/TLS Certificate'"
                 "        OR source_description = 'SSL Certificate')",
                 report_host);

  while (next (&tls_certs))
    {
      const char *certificate_prefixed, *certificate_b64;
      gsize certificate_size;
      unsigned char *certificate;
      const char *scanner_fpr_prefixed, *scanner_fpr;
      gchar *quoted_scanner_fpr;
      const char *source_name;
      char *ssldetails;
      tls_certificate_t tls_certificate;

      iterator_t ports;
      gboolean has_ports;

      certificate_prefixed = iterator_string (&tls_certs, 0);
      certificate_b64 = g_strrstr (certificate_prefixed, ":") + 1;

      certificate = g_base64_decode (certificate_b64, &certificate_size);

      scanner_fpr_prefixed = iterator_string (&tls_certs, 1);
      scanner_fpr = g_strrstr (scanner_fpr_prefixed, ":") + 1;

      quoted_scanner_fpr = sql_quote (scanner_fpr);

      source_name = iterator_string (&tls_certs, 2);

      g_debug ("%s: Handling certificate %s on %s in report %s",
               __func__, scanner_fpr, host_ip, report_id);

      tls_certificate = 0;
      activation_time = -1;
      expiration_time = -1;
      md5_fingerprint = NULL;
      sha256_fingerprint = NULL;
      subject = NULL;
      issuer = NULL;
      serial = NULL;
      certificate_format = 0;

      get_certificate_info ((gchar*)certificate,
                            certificate_size,
                            &activation_time,
                            &expiration_time,
                            &md5_fingerprint,
                            &sha256_fingerprint,
                            &subject,
                            &issuer,
                            &serial,
                            &certificate_format);

      if (sha256_fingerprint == NULL)
        sha256_fingerprint = g_strdup (scanner_fpr);

      ssldetails
        = sql_string ("SELECT rhd.value"
                      " FROM report_host_details AS rhd"
                      " WHERE report_host = %llu"
                      "   AND name = 'SSLDetails:%s'"
                      " LIMIT 1;",
                      report_host,
                      quoted_scanner_fpr);

      if (ssldetails)
        parse_ssldetails (ssldetails,
                          &activation_time,
                          &expiration_time,
                          &issuer,
                          &serial);
      else
        g_warning ("%s: No SSLDetails found for fingerprint %s",
                   __func__,
                   scanner_fpr);

      free (ssldetails);

      if (make_tls_certificate (sha256_fingerprint, /* name */
                                "", /* comment */
                                certificate_b64,
                                activation_time,
                                expiration_time,
                                md5_fingerprint,
                                sha256_fingerprint,
                                subject,
                                issuer,
                                serial,
                                certificate_format,
                                0,
                                1,
                                &tls_certificate)
          || tls_certificate == 0)
        {
          g_warning ("%s: Could not create TLS certificate"
                     " or get existing one for fingerprint '%s'.",
                     __func__, scanner_fpr);

          g_free (certificate);
          g_free (md5_fingerprint);
          g_free (sha256_fingerprint);
          g_free (subject);
          g_free (issuer);
          g_free (serial);
          continue;
        }

      init_iterator (&ports,
                     "SELECT value FROM report_host_details"
                     " WHERE report_host = %llu"
                     "   AND name = 'SSLInfo'"
                     "   AND value LIKE '%%:%%:%s'",
                     report_host,
                     quoted_scanner_fpr);

      has_ports = FALSE;
      while (next (&ports))
        {
          const char *value;
          gchar *port, *quoted_port;
          GString *versions;
          iterator_t versions_iter;

          value = iterator_string (&ports, 0);
          port = g_strndup (value, g_strrstr (value, ":") - value - 1);
          quoted_port = sql_quote (port);

          has_ports = TRUE;

          versions = g_string_new ("");
          init_iterator (&versions_iter,
                         "SELECT value FROM report_host_details"
                         " WHERE report_host = %llu"
                         "   AND name = 'TLS/%s'",
                         report_host,
                         quoted_port);
          while (next (&versions_iter))
            {
              gchar *quoted_version;
              quoted_version = sql_quote (iterator_string (&versions_iter, 0));

              if (versions->len)
                g_string_append (versions, ", ");
              g_string_append (versions, quoted_version);
            }
          cleanup_iterator (&versions_iter);

          get_or_make_tls_certificate_source (tls_certificate,
                                              host_ip,
                                              port,
                                              "Report",
                                              report_id,
                                              source_name);

          g_free (port);
          g_free (quoted_port);
          g_string_free (versions, TRUE);
        }

      if (has_ports == FALSE)
        g_warning ("Certificate without ports: %s report:%s host:%s",
                   quoted_scanner_fpr, report_id, host_ip);

      cleanup_iterator (&ports);

      g_free (certificate);
      g_free (md5_fingerprint);
      g_free (sha256_fingerprint);
      g_free (subject);
      g_free (issuer);
      g_free (serial);
    }
  cleanup_iterator (&tls_certs);

  return 0;
}

/**
 * @brief Get the host asset UUID of a TLS certificate location.
 *
 * @param[in]  host_ip    IP address of the host.
 * @param[in]  origin_id  UUID of the origin report.
 *
 * @return The newly allocated host asset UUID.
 */
char *
tls_certificate_host_asset_id (const char *host_ip, const char *origin_id)
{
  return sql_string ("SELECT hosts.uuid"
                    " FROM host_identifiers"
                    " JOIN hosts ON hosts.id = host_identifiers.host"
                    " WHERE host_identifiers.name='ip'"
                    "   AND host_identifiers.value='%s'"
                    "   AND host_identifiers.source_id='%s'"
                    " ORDER BY host_identifiers.modification_time DESC"
                    " LIMIT 1;",
                    host_ip,
                    origin_id);
}
