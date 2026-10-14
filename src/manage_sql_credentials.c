/* Copyright (C) 2009-2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Credential SQL
 *
 * The Credential SQL for the GVM management layer.
 */

#include "manage_sql_credentials.h"
#include "manage_acl.h"
#include "manage_sql.h"
#include "manage_sql_resources.h"
#include "sql.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Set the name of a Credential.
 *
 * @param[in]  credential      The Credential.
 * @param[in]  name            Name.
 *
 * @return 0 on success, -1 on failure.
 */
int
set_credential_name (credential_t credential, const char *name)
{

  if (credential == 0 || name == NULL)
    return -1;

  sql_ps ("UPDATE credentials"
          " SET name = $1,"
          "     modification_time = m_now()"
          " WHERE id = $2;",
          SQL_STR_PARAM (name),
          SQL_RESOURCE_PARAM (credential),
          NULL);

  return 0;
}

/**
 * @brief Set the comment of a Credential.
 *
 * @param[in]  credential      The Credential.
 * @param[in]  comment         Comment.
 *
 * @return 0 on success, -1 on failure.
 */
int
set_credential_comment (credential_t credential,
                        const char *comment)
{
  if (credential == 0 || comment == NULL)
    return -1;

  sql_ps ("UPDATE credentials"
          " SET comment = $1,"
          "     modification_time = m_now()"
          " WHERE id = $2;",
          SQL_STR_PARAM (comment),
          SQL_RESOURCE_PARAM (credential),
          NULL);
  return 0;
}

/**
 * @brief Set the allow_insecure flag of a Credential.
 *
 * @param[in]  credential      The Credential.
 * @param[in]  allow_insecure  Allow insecure flag.
 *
 * @return 0 on success, -1 on failure.
 */
int
set_credential_allow_insecure (credential_t credential,
                               int allow_insecure)
{
  if (credential == 0
      || (allow_insecure != 0 && allow_insecure != 1))
    return -1;

  sql_ps ("UPDATE credentials"
          " SET allow_insecure = $1,"
          "     modification_time = m_now()"
          " WHERE id = $2;",
          SQL_INT_PARAM (allow_insecure),
          SQL_RESOURCE_PARAM (credential),
          NULL);

  return 0;
}

/**
 * @brief Update the modification time of a credential.
 *
 * @param[in]  credential  The credential.
 *
 */
void
update_credential_modification_time (credential_t credential)
{
  sql_ps ("UPDATE credentials SET"
          " modification_time = m_now ()"
          " WHERE id = $1;",
          SQL_RESOURCE_PARAM (credential),
          NULL);
}

/**
 * @brief Insert base fields for a new credential into the database.
 *
 * @param[in]   data           Credential data to insert.
 * @param[in]   database_type  Credential database type.
 * @param[out]  credential     Pointer to store the created credential.
 *
 * @return A credential_return_t return code.
 */
credential_return_t
insert_credential_base (const credential_data_t  *data,
                        const gchar *database_type,
                        credential_t *credential)
{
  gint allow_insecure;

  if (data == NULL
      || data->name == NULL
      || database_type == NULL
      || credential == NULL)
    return CREDENTIAL_INTERNAL_ERROR;

  *credential = 0;

  if (current_credentials.uuid == NULL)
    return CREDENTIAL_INTERNAL_ERROR;

  allow_insecure = data->allow_insecure
                   && data->allow_insecure[0]
                   && !g_str_equal (data->allow_insecure, "0");

  sql_ps ("INSERT INTO credentials"
          " (uuid, name, owner, comment, creation_time, modification_time,"
          "  type, allow_insecure)"
          " VALUES"
          " (make_uuid (), $1,"
          "  (SELECT id FROM users WHERE users.uuid = $2),"
          "  $3, m_now (), m_now (), $4, $5);",
          SQL_STR_PARAM (data->name),
          SQL_STR_PARAM (current_credentials.uuid),
          SQL_STR_PARAM (data->comment ? data->comment : ""),
          SQL_STR_PARAM (database_type),
          SQL_INT_PARAM (allow_insecure),
          NULL);

  *credential = sql_last_insert_id ();

  if (*credential == 0)
    return CREDENTIAL_INTERNAL_ERROR;

  return CREDENTIAL_OK;
}

/**
 * @brief Set data for a credential.
 *
 * @param[in]  credential     The credential.
 * @param[in]  type           The data type (e.g. "username" or "secret").
 * @param[in]  value          The value to set or NULL to remove data entry.
 *
 * @return  0 on success, -1 on error, 99 permission denied.
 */
int
set_credential_data (credential_t credential,
                     const char *type,
                     const char *value)
{
  if (current_credentials.uuid
      && (acl_user_may ("modify_credential") == 0))
    return 99;

  if (type == NULL || credential == 0)
    return -1;

  if (sql_int_ps ("SELECT count (*) FROM credentials_data"
                  " WHERE credential = $1 AND type = $2;",
                  SQL_RESOURCE_PARAM (credential),
                  SQL_STR_PARAM (type),
                  NULL))
    {
      if (value == NULL)
        {
          sql_ps ("DELETE FROM credentials_data"
                  " WHERE credential = $1 AND type = $2;",
                  SQL_RESOURCE_PARAM (credential),
                  SQL_STR_PARAM (type),
                  NULL);
        }
      else
        {
          sql_ps ("UPDATE credentials_data SET value = $1"
                  " WHERE credential = $2 AND type = $3;",
                  SQL_STR_PARAM (value),
                  SQL_RESOURCE_PARAM (credential),
                  SQL_STR_PARAM (type),
                  NULL);
        }
    }
  else if (value != NULL)
    {
      sql_ps ("INSERT INTO credentials_data (credential, type, value)"
              " VALUES ($1, $2, $3)",
              SQL_RESOURCE_PARAM (credential),
              SQL_STR_PARAM (type),
              SQL_STR_PARAM (value),
              NULL);
    }
  return 0;
}

/**
 * @brief Copy a credential and its associated data rows.
 *
 * The caller owns the surrounding transaction.
 *
 * @param[in]  name                 Name of new Credential. NULL to copy
 *                                  from existing.
 * @param[in]  comment              Comment on new Credential. NULL to copy
 *                                  from existing.
 * @param[in]  credential_id        UUID of existing Credential.
 * @param[out] new_credential       New Credential.
 *
 * @return 0 success, 1 resource exists already, 2 failed to find existing
 *         resource, 99 permission denied, -1 error.
 */
int
copy_credential_rows (const char *name,
                     const char *comment,
                     const char *credential_id,
                     credential_t *new_credential)
{
  credential_t source_credential;
  int ret;

  if (credential_id == NULL || new_credential == NULL)
    return -1;

  *new_credential = 0;

  ret = copy_resource_lock ("credential",
                            name,
                            comment,
                            credential_id,
                            "type",
                            1,
                            new_credential,
                            &source_credential);
  if (ret)
    return ret;

  sql_ps (
    "INSERT INTO credentials_data (credential, type, value)"
    " SELECT $1, type, value"
    " FROM credentials_data"
    " WHERE credential = $2;",
    SQL_RESOURCE_PARAM (*new_credential),
    SQL_RESOURCE_PARAM (source_credential),
    NULL);

  return 0;
}
