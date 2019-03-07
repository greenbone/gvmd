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

/**
 * @brief Filter columns for tls_certificate iterator.
 */
#define TLS_CERTIFICATE_ITERATOR_FILTER_COLUMNS                               \
 { GET_ITERATOR_FILTER_COLUMNS, "subject_dn", "issuer_dn", NULL }

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
