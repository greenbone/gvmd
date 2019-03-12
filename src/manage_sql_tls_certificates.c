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
 * @file manage_sql_tls_certificates.c
 * @brief GVM management layer: TLS Certificates SQL
 *
 * The TLS Certificates SQL for the GVM management layer.
 */

#include "manage_tls_certificates.h"
#include "manage_acl.h"
#include "manage_sql_tls_certificates.h"
#include "manage_sql.h"
#include "sql.h"

#include <stdlib.h>
#include <string.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Filter columns for tls_certificate iterator.
 */
#define TLS_CERTIFICATE_ITERATOR_FILTER_COLUMNS                               \
 { GET_ITERATOR_FILTER_COLUMNS, "subject_dn", "issuer_dn", "md5_fingerprint", \
   "activates", "expires", "valid", NULL }

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
     "iso_time (activation_time)",                                            \
     "activation_time",                                                       \
     KEYWORD_TYPE_INTEGER                                                     \
   },                                                                         \
   {                                                                          \
     "iso_time (expiration_time)",                                            \
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
     "activation_time",                                                       \
     "activates",                                                             \
     KEYWORD_TYPE_INTEGER                                                     \
   },                                                                         \
   {                                                                          \
     "expiration_time",                                                       \
     "expires",                                                               \
     KEYWORD_TYPE_INTEGER                                                     \
   },                                                                         \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                       \
 }

/**
 * @brief TLS Certificate iterator columns for trash case.
 */
#define TLS_CERTIFICATE_ITERATOR_TRASH_COLUMNS                                \
 {                                                                            \
   GET_ITERATOR_COLUMNS (tls_certificates_trash),                             \
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
     "iso_time (activation_time)",                                            \
     "activation_time",                                                       \
     KEYWORD_TYPE_INTEGER                                                     \
   },                                                                         \
   {                                                                          \
     "iso_time (expiration_time)",                                            \
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
     "activation_time",                                                       \
     "activates",                                                             \
     KEYWORD_TYPE_INTEGER                                                     \
   },                                                                         \
   {                                                                          \
     "expiration_time",                                                       \
     "expires",                                                               \
     KEYWORD_TYPE_INTEGER                                                     \
   },                                                                         \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                       \
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
  static const char *extra_columns[] = TLS_CERTIFICATE_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = TLS_CERTIFICATE_ITERATOR_COLUMNS;
  static column_t trash_columns[] = TLS_CERTIFICATE_ITERATOR_TRASH_COLUMNS;

  return count ("tls_certificate", get, columns, trash_columns, extra_columns,
                0, 0, 0, TRUE);
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
  static column_t trash_columns[] = TLS_CERTIFICATE_ITERATOR_TRASH_COLUMNS;

  return init_get_iterator (iterator,
                            "tls_certificate",
                            get,
                            columns,
                            trash_columns,
                            filter_columns,
                            0,
                            NULL,
                            NULL,
                            TRUE);
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
 * @brief Return whether a trashcan tls_certificate is in use.
 *
 * @param[in]  tls_certificate  TLS Certificate.
 *
 * @return 1 if in use, else 0.
 */
int
trash_tls_certificate_in_use (tls_certificate_t tls_certificate)
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
 * @brief Return whether a trashcan tls_certificate is writable.
 *
 * @param[in]  tls_certificate  TLS Certificate.
 *
 * @return 1 if writable, else 0.
 */
int
trash_tls_certificate_writable (tls_certificate_t tls_certificate)
{
  return trash_tls_certificate_in_use (tls_certificate) == 0;
}

/**
 * @brief Create a TLS certificate.
 *
 * @param[in]   name            Name of new TLS certificate.
 * @param[in]   comment         Comment of TLS certificate.
 * @param[in]   base64_data     Base64 encoded certificate file content.
 * @param[out]  ticket          Created TLS certificate.
 *
 * @return 0 success, 1 invalid certificate, 99 permission denied, -1 error.
 */
int
create_tls_certificate (const char *name,
                        const char *comment,
                        const char *certificate,
                        tls_certificate_t *tls_certificate)
{
  int ret;
  char *md5_fingerprint, *subject_dn, *issuer_dn;
  time_t activation_time, expiration_time;

  subject_dn = NULL; // TODO add to get_certificate_info

  ret = get_certificate_info (certificate,
                              &activation_time,
                              &expiration_time,
                              &md5_fingerprint,
                              &subject_dn,
                              &issuer_dn);

  if (ret)
    return 1;

  sql ("INSERT INTO tls_certificates"
       " (uuid, owner, name, comment, creation_time, modification_time,"
       "  certificate, subject_dn, issuer_dn, trust,"
       "  activation_time, expiration_time, md5_fingerprint)"
       " SELECT make_uuid(), (SELECT id FROM users WHERE users.uuid = '%s'),"
       "        '%s', '%s', m_now(), m_now(), '%s', '%s', '%s', 0,"
       "        %ld, %ld, '%s';",
       current_credentials.uuid,
       name ? name : md5_fingerprint,
       comment ? comment : "",
       certificate ? certificate : "",
       subject_dn ? subject_dn : "",
       issuer_dn ? issuer_dn : "",
       activation_time,
       expiration_time,
       md5_fingerprint);

  if (tls_certificate)
    *tls_certificate = sql_last_insert_id ();

  return 0;
}

/**
 * @brief Create a TLS certificate from an existing TLS certificate.
 *
 * @param[in]  name        Name. NULL to copy from existing TLS certificate.
 * @param[in]  comment     Comment. NULL to copy from existing TLS certificate.
 * @param[in]  ticket_id   UUID of existing TLS certificate.
 * @param[out] new_ticket  New TLS certificate.
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
                       "activation_time, expiration_time, md5_fingerprint",
                       0, new_tls_certificate, &old_tls_certificate);
  if (ret)
    return ret;

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
