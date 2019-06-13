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
 * @param[in]   certificate     Plain certificate file content.
 * @param[in]   trust           Whether to trust the certificate.
 * @param[out]  tls_certificate Created TLS certificate.
 *
 * @return 0 success, 1 invalid certificate, 99 permission denied, -1 error.
 */
int
create_tls_certificate (const char *name,
                        const char *comment,
                        const char *certificate,
                        int trust,
                        tls_certificate_t *tls_certificate)
{
  int ret;
  char *md5_fingerprint, *subject_dn, *issuer_dn;
  time_t activation_time, expiration_time;

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
       "        '%s', '%s', m_now(), m_now(), '%s', '%s', '%s', %d,"
       "        %ld, %ld, '%s';",
       current_credentials.uuid,
       name ? name : md5_fingerprint,
       comment ? comment : "",
       certificate ? certificate : "",
       subject_dn ? subject_dn : "",
       issuer_dn ? issuer_dn : "",
       trust,
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
                       "activation_time, expiration_time, md5_fingerprint",
                       0, new_tls_certificate, &old_tls_certificate);
  if (ret)
    return ret;

  return 0;
}

/**
 * @brief Delete a tls_certificate.
 *
 * @param[in]  tls_certificate_id  UUID of tls_certificate.
 * @param[in]  ultimate   Whether to remove entirely, or to trashcan.
 *
 * @return 0 success, 1 fail because tls_certificate is in use,
 *         2 failed to find tls_certificate,
 *         3 predefined tls_certificate, 99 permission denied, -1 error.
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
      /* No such tls_certificate, check the trashcan. */

      if (find_trash ("tls_certificate",
                      tls_certificate_id,
                      &tls_certificate))
        {
          sql_rollback ();
          return -1;
        }
      if (tls_certificate == 0)
        {
          sql_rollback ();
          return 2;
        }
      if (ultimate == 0)
        {
          /* It's already in the trashcan. */
          sql_commit ();
          return 0;
        }

      sql ("DELETE FROM permissions"
           " WHERE resource_type = 'tls_certificate'"
           " AND resource_location = %i"
           " AND resource = %llu;",
           LOCATION_TRASH,
           tls_certificate);

      tags_remove_resource ("tls_certificate",
                            tls_certificate,
                            LOCATION_TRASH);

      sql ("DELETE FROM tls_certificates_trash WHERE id = %llu;",
           tls_certificate);

      sql_commit ();
      return 0;
    }

  /* Ticket was found in regular table. */

  if (ultimate == 0)
    {
      tls_certificate_t trash_tls_certificate;

      /* Move to trash. */

      sql ("INSERT INTO tls_certificates_trash"
           " (uuid, owner, name, comment, creation_time, modification_time,"
           "  certificate, subject_dn, issuer_dn, trust,"
           "  activation_time, expiration_time, md5_fingerprint)"
           " SELECT"
           "  uuid, owner, name, comment, creation_time, modification_time,"
           "  certificate, subject_dn, issuer_dn, trust,"
           "  activation_time, expiration_time, md5_fingerprint"
           " FROM tls_certificates WHERE id = %llu;",
           tls_certificate);

      trash_tls_certificate = sql_last_insert_id ();

      permissions_set_locations ("tls_certificate",
                                 tls_certificate,
                                 trash_tls_certificate,
                                 LOCATION_TRASH);
      tags_set_locations ("tls_certificate",
                          tls_certificate,
                          trash_tls_certificate,
                          LOCATION_TRASH);
    }
  else
    {
      /* Delete entirely. */

      sql ("DELETE FROM permissions"
           " WHERE resource_type = 'tls_certificate'"
           " AND resource_location = %i"
           " AND resource = %llu;",
           LOCATION_TABLE,
           tls_certificate);

      tags_remove_resource ("tls_certificate",
                            tls_certificate,
                            LOCATION_TABLE);
    }

  sql ("DELETE FROM tls_certificates WHERE id = %llu;",
       tls_certificate);

  sql_commit ();
  return 0;
}

/**
 * @brief Try restore a tls_certificate.
 *
 * If success, ends transaction for caller before exiting.
 *
 * @param[in]  tls_certificate_id  UUID of resource.
 *
 * @return 0 success, 1 fail because tls_certificate is in use,
 *         2 failed to find tls_certificate, -1 error.
 */
int
restore_tls_certificate (const char *tls_certificate_id)
{
  tls_certificate_t trash_tls_certificate, tls_certificate;

  if (find_trash ("tls_certificate",
                  tls_certificate_id,
                  &trash_tls_certificate))
    {
      sql_rollback ();
      return -1;
    }

  if (trash_tls_certificate == 0)
    return 2;

  /* Move the tls_certificate back to the regular table. */

  sql ("INSERT INTO tls_certificates"
       " (uuid, owner, name, comment, creation_time, modification_time,"
       "  certificate, subject_dn, issuer_dn, trust,"
       "  activation_time, expiration_time, md5_fingerprint)"
       " SELECT"
       "  uuid, owner, name, comment, creation_time, modification_time,"
       "  certificate, subject_dn, issuer_dn, trust,"
       "  activation_time, expiration_time, md5_fingerprint"
       " FROM tls_certificates_trash WHERE id = %llu;",
       trash_tls_certificate);

  tls_certificate = sql_last_insert_id ();

  /* Adjust references to the tls_certificate. */

  permissions_set_locations ("tls_certificate",
                             trash_tls_certificate,
                             tls_certificate,
                             LOCATION_TABLE);
  tags_set_locations ("tls_certificate",
                      trash_tls_certificate,
                      tls_certificate,
                      LOCATION_TABLE);

  /* Clear out the trashcan tls_certificate. */

  sql ("DELETE FROM tls_certificates_trash WHERE id = %llu;",
       trash_tls_certificate);

  sql_commit ();
  return 0;
}

/**
 * @brief Empty TLS certificate trashcans.
 */
void
empty_trashcan_tls_certificates ()
{
  sql ("DELETE FROM permissions"
       " WHERE resource_type = 'tls_certificate'"
       " AND resource_location = %i"
       " AND resource IN (SELECT id FROM tls_certificates_trash"
       "                  WHERE owner = (SELECT id FROM users"
       "                                 WHERE uuid = '%s'));",
       LOCATION_TRASH,
       current_credentials.uuid);

  sql ("DELETE FROM tickets_trash"
       " WHERE owner = (SELECT id FROM users WHERE uuid = '%s');",
       current_credentials.uuid);
}

/**
 * @brief Delete all TLS certificate owner by a user.
 *
 * Also delete trash TLS certificates.
 *
 * @param[in]  user  The user.
 */
void
delete_tls_certificates_user (user_t user)
{
  /* Regular tls_certificate. */

  sql ("DELETE FROM tls_certificate WHERE owner = %llu;", user);

  /* Trash tls_certificate. */

  sql ("DELETE FROM tls_certificate_trash WHERE owner = %llu;", user);
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

  sql ("UPDATE tls_certificate SET owner = %llu WHERE owner = %llu;",
       inheritor, user);

  /* Trash tickets. */

  sql ("UPDATE tls_certificate_trash SET owner = %llu WHERE owner = %llu;",
       inheritor, user);
}

/**
 * @brief Modify a TLS certificate.
 *
 * @param[in]   tls_certificate_id  UUID of TLS certificate.
 * @param[in]   comment             New comment on TLS certificate.
 * @param[in]   name                New name of TLS certificate.
 * @param[in]   certificate         New certificate file content.
 * @param[in]   trust               New trust value or -1 to keep old value.
 *
 * @return 0 success, 1 TLS certificate exists already,
 *         2 failed to find TLS certificate,
 *         3 invalid certificate content, 99 permission denied, -1 error.
 */
int
modify_tls_certificate (const gchar *tls_certificate_id,
                        const gchar *comment,
                        const gchar *name,
                        const gchar *certificate,
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

  /* Update certificate if requested. */

  if (certificate)
    {
      gchar *quoted_certificate;
      int ret;
      char *md5_fingerprint, *subject_dn, *issuer_dn;
      time_t activation_time, expiration_time;

      ret = get_certificate_info (certificate,
                                  &activation_time,
                                  &expiration_time,
                                  &md5_fingerprint,
                                  &subject_dn,
                                  &issuer_dn);

      if (ret)
        return 3;

      quoted_certificate = sql_quote (certificate);
      sql ("UPDATE tls_certificates SET"
           " certificate = '%s',"
           " activation_time = %llu,"
           " expiration_time = %llu,"
           " md5_fingerprint = '%s',"
           " subject_dn = '%s',"
           " issuer_dn = '%s',"
           " modification_time = m_now ()"
           " WHERE id = %llu;",
           quoted_certificate,
           activation_time,
           expiration_time,
           md5_fingerprint,
           subject_dn,
           issuer_dn,
           tls_certificate);
      g_free (quoted_certificate);
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
