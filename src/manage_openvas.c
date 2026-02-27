/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Greenbone Vulnerability Manager OSP-style credentials handling.
 */

#include "manage_openvas.h"
#include "manage_sql.h"
#include "manage_sql_targets.h"
#include "manage_users.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

#if ENABLE_CREDENTIAL_STORES
static const target_osp_credential_getter_t target_osp_credential_getters[] = {
  target_osp_ssh_credential,
  target_osp_smb_credential,
  target_osp_esxi_credential,
  target_osp_snmp_credential,
  target_osp_krb5_credential,
};
#endif

/**
 * @brief Add OSP preferences for limiting hosts for users.
 *
 * @param[in]  scanner_options  The scanner preferences table to add to.
 */
void
add_user_scan_preferences (GHashTable *scanner_options)
{
  gchar *hosts, *name;
  int hosts_allow;

  // Limit access to hosts
  hosts = user_hosts (current_credentials.uuid);
  hosts_allow = user_hosts_allow (current_credentials.uuid);

  if (hosts_allow == 1)
    name = g_strdup ("hosts_allow");
  else if (hosts_allow == 0)
    name = g_strdup ("hosts_deny");
  else
    name = NULL;

  if (name
      && (hosts_allow || (hosts && strlen (hosts))))
    g_hash_table_replace (scanner_options,
                          name,
                          hosts ? hosts : g_strdup (""));
  else
    g_free (hosts);
}

#if ENABLE_CREDENTIAL_STORES
/**
 * @brief Set SSH credential authentication data from credential store
 *
 * @param[in]  iter            Credential iterator
 * @param[in]  osp_credential  OSP credential to set data on
 * @param[in]  elevate         Whether to set elevate (priv_) data
 *
 * @return 0 on success, 1 on error
*/
static int
set_auth_data_ssh_from_credential_store (iterator_t *iter,
                                         osp_credential_t *osp_credential,
                                         int elevate)
{
  gchar *login, *password;
  const char *cred_store_uuid
    = credential_iterator_credential_store_uuid (iter);
  const char *vault_id
    = credential_iterator_vault_id (iter);
  const char *host_identifier
    = credential_iterator_host_identifier (iter);

  if (cyberark_login_password_credential_data (cred_store_uuid,
                                               vault_id,gm
                                               host_identifier,
                                               &login,
                                               &password))
    {
      g_debug ("%s: Error retrieving credentials from "
               "CyberArk credential store '%s'.",
               __func__, cred_store_uuid);
      return 1;
    }

  if (!elevate)
    {
      osp_credential_set_auth_data (osp_credential,
                                    "username",
                                    login);
      if (strcmp (credential_iterator_type (iter), "cs_usk") == 0)
        {
          gchar *base64 = g_base64_encode ((guchar *) password,
                                           strlen (password));
          osp_credential_set_auth_data (osp_credential,
                                        "private", base64);
          g_free (base64);
        }
      else
        osp_credential_set_auth_data (osp_credential,
                                      "password",
                                      password);
    }
  else
    {
      osp_credential_set_auth_data (osp_credential,
                                    "priv_username",
                                    login);
      osp_credential_set_auth_data (osp_credential,
                                    "priv_password",
                                    password);
    }

  memset (password, 0, strlen (password));

  g_free (login);
  g_free (password);
  return 0;
}

/**
 * @brief Set SSH credential authentication data from database
 *
 * @param[in]  iter            Credential iterator
 * @param[in]  osp_credential  OSP credential to set data on
 * @param[in]  elevate         Whether to set elevate (priv_) data
 *
*/
static void
set_auth_data_ssh_from_db (iterator_t *iter,
                           osp_credential_t *osp_credential,
                           int elevate)
{
  if (!elevate)
    {
      osp_credential_set_auth_data (osp_credential,
                                    "username",
                                    credential_iterator_login (iter));
      osp_credential_set_auth_data (osp_credential,
                                    "password",
                                    credential_iterator_password (iter));
    }
  else
    {
      osp_credential_set_auth_data (osp_credential,
                                    "priv_username",
                                    credential_iterator_login (iter));
      osp_credential_set_auth_data (osp_credential,
                                    "priv_password",
                                    credential_iterator_password (iter));
    }

  if (strcmp (credential_iterator_type (iter), "usk") == 0)
    {
      const char *private_key = credential_iterator_private_key (iter);
      gchar *base64 = g_base64_encode ((guchar *) private_key,
                                        strlen (private_key));
      osp_credential_set_auth_data (osp_credential,
                                    "private", base64);
      g_free (base64);
    }
}

/**
 * @brief Set credential authentication data from credential store
 *
 * @param[in]  iter            Credential iterator
 * @param[in]  osp_credential  OSP credential to set data on
 *
 * @return 0 on success, 1 on error
*/
static int
set_auth_data_up_from_credential_store (iterator_t *iter,
                                        osp_credential_t *osp_credential)
{
  gchar *login, *password;
  const char *cred_store_uuid
    = credential_iterator_credential_store_uuid (iter);
  const char *vault_id
    = credential_iterator_vault_id (iter);
  const char *host_identifier
    = credential_iterator_host_identifier (iter);

  if (cyberark_login_password_credential_data (cred_store_uuid,
                                               vault_id,
                                               host_identifier,
                                               &login,
                                               &password))
    {
      g_debug ("%s: Error retrieving credentials from "
               "CyberArk credential store '%s'.",
               __func__, cred_store_uuid);
      return 1;
    }

  osp_credential_set_auth_data (osp_credential, "username", login);
  osp_credential_set_auth_data (osp_credential, "password", password);

  memset (password, 0, strlen (password));

  g_free (login);
  g_free (password);
  return 0;
}

/**
 * @brief Set SNMP credential authentication data from credential store
 *
 * @param[in]  iter            Credential iterator
 * @param[in]  osp_credential  OSP credential to set data on
 *
 * @return 0 on success, 1 on error
 */
static int
set_auth_data_snmp_from_credential_store (iterator_t *iter,
                                          osp_credential_t *osp_credential)
{
  gchar *login, *password, *privacy_password;
  const char *cred_store_uuid
    = credential_iterator_credential_store_uuid (iter);
  const char *vault_id
    = credential_iterator_vault_id (iter);
  const char *host_identifier
    = credential_iterator_host_identifier (iter);
  const char *privacy_host_identifier
    = credential_iterator_privacy_host_identifier (iter);

  if (cyberark_login_password_credential_data (cred_store_uuid,
                                               vault_id,
                                               host_identifier,
                                               &login,
                                               &password))
    {
      g_debug ("%s: Error retrieving SNMP username and password from"
               " CyberArk credential store '%s'.",
               __func__, cred_store_uuid);
      g_free (login);
      g_free (password);
      return 1;
    }

  if (cyberark_login_password_credential_data (cred_store_uuid,
                                               vault_id,
                                               privacy_host_identifier,
                                               NULL,
                                               &privacy_password))
    {
      g_debug ("%s: Error retrieving SNMP privacy password from"
               " CyberArk credential store '%s'.",
               __func__, cred_store_uuid);

      password (password, 0, strlen (password));

      g_free (login);
      g_free (password);
      g_free (privacy_password);
      return 1;
    }

  osp_credential_set_auth_data (osp_credential, "username", login);
  osp_credential_set_auth_data (osp_credential, "password", password);
  osp_credential_set_auth_data (osp_credential, "privacy_password",
                                privacy_password);

  memset(password, 0, strlen (password));
  memset(privacy_password, 0, strlen (privacy_password));

  g_free (login);
  g_free (password);
  g_free (privacy_password);
  return 0;
}

/**
 * @brief Get the SSH credential of a target from database or credential store
 *        as an osp_credential_t
 *
 * @param[in]  target          The target to get the credential from.
 * @param[out] ssh_credential  Pointer to store the resulting credential.
 *                             Has to be freed by the caller.
 *
 * @return A target_osp_credential_return_t return code.
 */
target_osp_credential_return_t
target_osp_ssh_credential (target_t target, osp_credential_t **ssh_credential)
{
  if (!ssh_credential)
    return TARGET_OSP_MISSING_CREDENTIAL;

  *ssh_credential = NULL;

  credential_t credential, ssh_elevate_credential;
  credential = target_ssh_credential (target);
  ssh_elevate_credential = target_ssh_elevate_credential (target);

  if (credential)
    {
      iterator_t iter, ssh_elevate_iter;
      const char *type;
      char *ssh_port;
      osp_credential_t *osp_credential;

      init_credential_iterator_one (&iter, credential);

      if (!next (&iter))
        {
          g_warning ("%s: SSH Credential not found.", __func__);
          cleanup_iterator (&iter);
          return TARGET_OSP_INTERNAL_ERROR;
        }
      type = credential_iterator_type (&iter);
      ssh_port = target_ssh_port (target);

      if (strcmp (type, "up") == 0 || strcmp (type, "usk") == 0)
        {
          osp_credential = osp_credential_new (type, "ssh", ssh_port);
          set_auth_data_ssh_from_db (&iter, osp_credential, 0);
        }
      else if (strcmp (type, "cs_up") == 0 || strcmp (type, "cs_usk") == 0)
        {
          const char *osp_type = (strcmp (type, "cs_up") == 0) ? "up" : "usk";
          osp_credential = osp_credential_new (osp_type, "ssh", ssh_port);
          if (set_auth_data_ssh_from_credential_store (&iter,
                                                       osp_credential, 0))
            {
              cleanup_iterator (&iter);
              osp_credential_free (osp_credential);
              free (ssh_port);
              g_warning ("%s: Failed to retrieve SSH credential"
                         " from credential store.", __func__);
              return TARGET_OSP_FAILED_CS_RETRIEVAL;
            }
        }
      else
        {
          g_warning ("%s: SSH Credential not a user/pass pair"
                     " or user/ssh key.", __func__);
          cleanup_iterator (&iter);
          free (ssh_port);
          return TARGET_OSP_CREDENTIAL_TYPE_MISMATCH;
        }

      free (ssh_port);
      if (ssh_elevate_credential)
        {
          const char *elevate_type;

          init_credential_iterator_one (&ssh_elevate_iter,
                                        ssh_elevate_credential);
          if (!next (&ssh_elevate_iter))
            {
              g_warning ("%s: SSH Elevate Credential not found.", __func__);
              cleanup_iterator (&ssh_elevate_iter);
              osp_credential_free (osp_credential);
              return TARGET_OSP_INTERNAL_ERROR;
            }
          elevate_type = credential_iterator_type (&ssh_elevate_iter);
          if (strcmp (elevate_type, "up") == 0)
            {
              set_auth_data_ssh_from_db (&ssh_elevate_iter, osp_credential, 1);
            }
          else if (strcmp (elevate_type, "cs_up") == 0)
            {
              if (set_auth_data_ssh_from_credential_store (&ssh_elevate_iter,
                                                           osp_credential, 1))
                {
                  cleanup_iterator (&ssh_elevate_iter);
                  osp_credential_free (osp_credential);
                  g_warning ("%s: Failed to retrieve SSH elevate"
                             " credential from credential store.", __func__);
                  return TARGET_OSP_FAILED_CS_RETRIEVAL;
                }
            }
          else
            {
              g_warning ("%s: SSH Elevate Credential not of type up or cs_up", __func__);
              cleanup_iterator (&ssh_elevate_iter);
              osp_credential_free (osp_credential);
              return TARGET_OSP_CREDENTIAL_TYPE_MISMATCH;
            }
          cleanup_iterator (&ssh_elevate_iter);
        }
      cleanup_iterator (&iter);
      *ssh_credential = osp_credential;
      return TARGET_OSP_CREDENTIAL_OK;
    }
  return TARGET_OSP_CREDENTIAL_NOT_FOUND;
}

/**
 * @brief Get the SMB credential of a target from database
 *        or credential store as an osp_credential_t
 *
 * @param[in]  target  The target to get the credential from.
 * @param[out] smb_credential  Pointer to store the resulting credential.
 *                             Has to be freed by the caller.
 *
 * @return A target_osp_credential_return_t return code.
 */
target_osp_credential_return_t
target_osp_smb_credential (target_t target, osp_credential_t **smb_credential)
{
  if (!smb_credential)
   return TARGET_OSP_MISSING_CREDENTIAL;

  *smb_credential = NULL;

  credential_t credential;
  credential = target_smb_credential (target);

  if (credential)
    {
      iterator_t iter;
      osp_credential_t *osp_credential;

      init_credential_iterator_one (&iter, credential);
      if (!next (&iter))
        {
          g_warning ("%s: SMB Credential not found.", __func__);
          cleanup_iterator (&iter);
          return TARGET_OSP_INTERNAL_ERROR;
        }
      osp_credential = osp_credential_new ("up", "smb", NULL);
      const char *type = credential_iterator_type (&iter);
      if (strcmp (type, "up") == 0)
        {
          osp_credential_set_auth_data (osp_credential,
                                        "username",
                                        credential_iterator_login (&iter));
          osp_credential_set_auth_data (osp_credential,
                                        "password",
                                        credential_iterator_password (&iter));
        }
      else if (strcmp (type, "cs_up") == 0)
        {
          if (set_auth_data_up_from_credential_store (&iter, osp_credential))
            {
              cleanup_iterator (&iter);
              osp_credential_free (osp_credential);
              g_warning ("%s: Failed to retrieve SMB credential"
                         " from credential store.", __func__);
              return TARGET_OSP_FAILED_CS_RETRIEVAL;
            }
        }
      else
        {
          g_warning ("%s: SMB Credential not a user/pass pair.", __func__);
          cleanup_iterator (&iter);
          osp_credential_free (osp_credential);
          return TARGET_OSP_CREDENTIAL_TYPE_MISMATCH;
        }

      cleanup_iterator (&iter);
      *smb_credential = osp_credential;
      return TARGET_OSP_CREDENTIAL_OK;
    }
  return TARGET_OSP_CREDENTIAL_NOT_FOUND;
}

/**
 * @brief Get the ESXi credential of a target from database
 *        or credential store as an osp_credential_t
 *
 * @param[in]  target  The target to get the credential from.
 * @param[out] esxi_credential  Pointer to store the resulting credential.
 *                              Has to be freed by the caller.
 *
 * @return A target_osp_credential_return_t return code.
 */
target_osp_credential_return_t
target_osp_esxi_credential (target_t target,
                            osp_credential_t **esxi_credential)
{
  if (!esxi_credential)
    return TARGET_OSP_MISSING_CREDENTIAL;

  *esxi_credential = NULL;

  credential_t credential;
  credential = target_esxi_credential (target);
  if (credential)
    {
      iterator_t iter;
      osp_credential_t *osp_credential;
      const char *type;

      init_credential_iterator_one (&iter, credential);
      if (!next (&iter))
        {
          g_warning ("%s: ESXi Credential not found.", __func__);
          cleanup_iterator (&iter);
          return TARGET_OSP_INTERNAL_ERROR;
        }
      type = credential_iterator_type (&iter);
      osp_credential = osp_credential_new ("up", "esxi", NULL);

      if (strcmp (type, "up") == 0)
        {
          osp_credential_set_auth_data (osp_credential,
                                        "username",
                                        credential_iterator_login (&iter));
          osp_credential_set_auth_data (osp_credential,
                                        "password",
                                        credential_iterator_password (&iter));
        }
      else if (strcmp (type, "cs_up") == 0)
        {
          if (set_auth_data_up_from_credential_store (&iter, osp_credential))
            {
              cleanup_iterator (&iter);
              osp_credential_free (osp_credential);
              g_warning ("%s: Failed to retrieve ESXi credential"
                         " from credential store.", __func__);
              return TARGET_OSP_FAILED_CS_RETRIEVAL;
            }
        }
      else
        {
          g_warning ("%s: ESXi Credential not a user/pass pair.",
                     __func__);
          cleanup_iterator (&iter);
          osp_credential_free (osp_credential);
          return TARGET_OSP_CREDENTIAL_TYPE_MISMATCH;
        }

      cleanup_iterator (&iter);
      *esxi_credential = osp_credential;
      return TARGET_OSP_CREDENTIAL_OK;
    }
  return TARGET_OSP_CREDENTIAL_NOT_FOUND;
}

/**
 * @brief Get the Kerberos 5 credential of a target from database
 *        or credential store as an osp_credential_t
 *
 * @param[in]  target  The target to get the credential from.
 * @param[out] krb5_credential  Pointer to store the resulting credential.
 *                              Has to be freed by the caller.
 *
 * @return  A target_osp_credential_return_t return code.
 */
target_osp_credential_return_t
target_osp_krb5_credential (target_t target,
                            osp_credential_t **krb5_credential)
{
  if (!krb5_credential)
    return TARGET_OSP_MISSING_CREDENTIAL;

  *krb5_credential = NULL;

  credential_t credential;
  credential = target_credential (target, "krb5");
  if (credential)
    {
      iterator_t iter;
      osp_credential_t *osp_credential;
      const char *type;

      init_credential_iterator_one (&iter, credential);
      if (!next (&iter))
        {
          g_warning ("%s: Kerberos 5 Credential not found.", __func__);
          cleanup_iterator (&iter);
          return TARGET_OSP_INTERNAL_ERROR;
        }
      type = credential_iterator_type (&iter);
      osp_credential = osp_credential_new ("up", "krb5", NULL);
      if (strcmp (type, "krb5") == 0)
        {
          osp_credential_set_auth_data (osp_credential,
                                        "username",
                                        credential_iterator_login (&iter)
                                          ?: "");
          osp_credential_set_auth_data (osp_credential,
                                        "password",
                                        credential_iterator_password (&iter)
                                          ?: "");
          osp_credential_set_auth_data (osp_credential,
                                        "kdc",
                                        credential_iterator_kdc (&iter)
                                          ?: "");
          osp_credential_set_auth_data (osp_credential,
                                        "realm",
                                        credential_iterator_realm (&iter)
                                          ?: "");
        }
      else if (strcmp (type, "cs_krb5") == 0)
        {
          if (set_auth_data_up_from_credential_store (&iter, osp_credential))
            {
              cleanup_iterator (&iter);
              osp_credential_free (osp_credential);
              g_warning ("%s: Failed to retrieve Kerberos 5 credential"
                         " from credential store.", __func__);
              return TARGET_OSP_FAILED_CS_RETRIEVAL;
            }

          osp_credential_set_auth_data (osp_credential,
                                        "kdc",
                                        credential_iterator_kdc (&iter)
                                          ?: "");
          osp_credential_set_auth_data (osp_credential,
                                        "realm",
                                        credential_iterator_realm (&iter)
                                          ?: "");
        }
      else
        {
          g_warning ("%s: Kerberos 5 Credential not of type 'krb5' or 'cs_krb5'.",
                     __func__);
          cleanup_iterator (&iter);
          osp_credential_free (osp_credential);
          return TARGET_OSP_CREDENTIAL_TYPE_MISMATCH;
        }

      cleanup_iterator (&iter);
      *krb5_credential = osp_credential;
      return TARGET_OSP_CREDENTIAL_OK;
    }
  return TARGET_OSP_CREDENTIAL_NOT_FOUND;
}

/**
 * @brief Get the SMB credential of a target from database
 *        or credential store as an osp_credential_t
 *
 * @param[in]  target  The target to get the credential from.
 * @param[out] snmp_credential  Pointer to store the resulting credential.
 *                              Has to be freed by the caller.
 *
 * @return  A target_osp_credential_return_t return code.
 */
target_osp_credential_return_t
target_osp_snmp_credential (target_t target,
                            osp_credential_t **snmp_credential)
{
  if (!snmp_credential)
    return TARGET_OSP_MISSING_CREDENTIAL;

  *snmp_credential = NULL;

  credential_t credential;
  credential = target_credential (target, "snmp");
  if (credential)
    {
      iterator_t iter;
      osp_credential_t *osp_credential;
      const char *type;

      init_credential_iterator_one (&iter, credential);
      if (!next (&iter))
        {
          g_warning ("%s: SNMP Credential not found.", __func__);
          cleanup_iterator (&iter);
          return TARGET_OSP_INTERNAL_ERROR;
        }
      type = credential_iterator_type (&iter);
      osp_credential = osp_credential_new ("snmp", "snmp", NULL);

      if (strcmp (type, "snmp") == 0)
        {
          osp_credential_set_auth_data (osp_credential,
                                        "username",
                                        credential_iterator_login (&iter)
                                          ?: "");
          osp_credential_set_auth_data (osp_credential,
                                        "password",
                                        credential_iterator_password (&iter)
                                          ?: "");
          osp_credential_set_auth_data (osp_credential,
                                        "community",
                                        credential_iterator_community (&iter)
                                          ?: "");
          osp_credential_set_auth_data (osp_credential,
                                        "auth_algorithm",
                                        credential_iterator_auth_algorithm (&iter)
                                          ?: "");
          osp_credential_set_auth_data (osp_credential,
                                        "privacy_algorithm",
                                        credential_iterator_privacy_algorithm
                                          (&iter) ?: "");
          osp_credential_set_auth_data (osp_credential,
                                        "privacy_password",
                                        credential_iterator_privacy_password
                                          (&iter) ?: "");
        }
      else if (strcmp (type, "cs_snmp") == 0)
        {
          if (set_auth_data_snmp_from_credential_store (&iter, osp_credential))
            {
              cleanup_iterator (&iter);
              osp_credential_free (osp_credential);
              g_warning ("%s: Failed to retrieve SNMP credential"
                         " from credential store.", __func__);
              return TARGET_OSP_FAILED_CS_RETRIEVAL;
            }

          osp_credential_set_auth_data (osp_credential,
                                        "auth_algorithm",
                                        credential_iterator_auth_algorithm (&iter)
                                          ?: "");
          osp_credential_set_auth_data (osp_credential,
                                        "privacy_algorithm",
                                        credential_iterator_privacy_algorithm
                                          (&iter) ?: "");
        }
      else
        {
          g_warning ("%s: SNMP Credential not of type 'snmp' or 'cs_snmp'.",
                     __func__);
          cleanup_iterator (&iter);
          osp_credential_free (osp_credential);
          return TARGET_OSP_CREDENTIAL_TYPE_MISMATCH;
        }

      cleanup_iterator (&iter);
      *snmp_credential = osp_credential;
      return TARGET_OSP_CREDENTIAL_OK;
    }
  return TARGET_OSP_CREDENTIAL_NOT_FOUND;
}

/**
 * @brief Add OSP credentials to an OSP target from database or
 *        credential store.
 *
 * @param[in]  osp_target  The OSP target to add credentials to.
 * @param[in]  target      The target to get the credentials from.
 * @param[in]  task        The task for which the OSP target is created.
 * @param[out] error       Pointer to store error message on failure.
 *                         Has to be freed by the caller.
 *
 * @return 0 on success, -1 on error.
 */
int
target_osp_add_credentials (osp_target_t *osp_target,
                            target_t target,
                            task_t task,
                            char **error)
{
  if (!osp_target)
    {
      if (error)
        *error = g_strdup ("OSP target is NULL.");
      return -1;
    }

  long long int allow_failed_retrieval_int = 0;
  gchar *allow_failed_retrieval = task_preference_value (task,
                                                  "cs_allow_failed_retrieval");
  if (allow_failed_retrieval)
    allow_failed_retrieval_int = strtol (allow_failed_retrieval, NULL, 10);
  g_free (allow_failed_retrieval);

  for (size_t i = 0;
       i < sizeof (target_osp_credential_getters)
           / sizeof (target_osp_credential_getters[0]);
       i++)
    {
      target_osp_credential_return_t cred_ret;
      osp_credential_t *credential = NULL;

      cred_ret = target_osp_credential_getters[i] (target, &credential);

      switch (cred_ret)
        {
          case TARGET_OSP_CREDENTIAL_OK:
            break;
          case TARGET_OSP_CREDENTIAL_NOT_FOUND:
            continue;
          case TARGET_OSP_CREDENTIAL_TYPE_MISMATCH:
            g_warning ("%s: Credential type mismatch.", __func__);
            continue;
          case TARGET_OSP_FAILED_CS_RETRIEVAL:
             if (allow_failed_retrieval_int == 0)
               {
                if (error)
                   *error = g_strdup ("Failed to retrieve credentials"
                                      " from credential store.");
                 return -1;
               }
              g_debug ("%s: Failed to retrieve credentials"
                       " from credential store, but allowed to continue.",
                       __func__);
              continue;
          case TARGET_OSP_INTERNAL_ERROR:
          case TARGET_OSP_MISSING_CREDENTIAL:
          default:
            if (error)
              *error = g_strdup ("Internal error retrieving credential.");
            return -1;
        }

      if (credential)
         osp_target_add_credential (osp_target, credential);

    }
  return 0;
}
#else
/**
 * @brief Get the SSH credential of a target as an osp_credential_t
 *
 * @param[in]  target  The target to get the credential from.
 *
 * @return  Pointer to a newly allocated osp_credential_t
 */
osp_credential_t *
target_osp_ssh_credential_db (target_t target)
{
  credential_t credential, ssh_elevate_credential;
  credential = target_ssh_credential (target);
  ssh_elevate_credential = target_ssh_elevate_credential (target);

  if (credential)
    {
      iterator_t iter, ssh_elevate_iter;
      const char *type;
      char *ssh_port;
      osp_credential_t *osp_credential;

      init_credential_iterator_one (&iter, credential);

      if (!next (&iter))
        {
          g_warning ("%s: SSH Credential not found.", __func__);
          cleanup_iterator (&iter);
          return NULL;
        }
      type = credential_iterator_type (&iter);
      if (strcmp (type, "up") && strcmp (type, "usk"))
        {
          g_warning ("%s: SSH Credential not a user/pass pair"
                     " or user/ssh key.", __func__);
          cleanup_iterator (&iter);
          return NULL;
        }

      ssh_port = target_ssh_port (target);
      osp_credential = osp_credential_new (type, "ssh", ssh_port);
      free (ssh_port);
      osp_credential_set_auth_data (osp_credential,
                                    "username",
                                    credential_iterator_login (&iter));
      osp_credential_set_auth_data (osp_credential,
                                    "password",
                                    credential_iterator_password (&iter));

      if (strcmp (type, "usk") == 0)
        {
          const char *private_key = credential_iterator_private_key (&iter);
          gchar *base64 = g_base64_encode ((guchar *) private_key,
                                           strlen (private_key));
          osp_credential_set_auth_data (osp_credential,
                                        "private", base64);
          g_free (base64);
        }

      if(ssh_elevate_credential)
        {
          const char *elevate_type;

          init_credential_iterator_one (&ssh_elevate_iter,
                                        ssh_elevate_credential);
          if (!next (&ssh_elevate_iter))
            {
              g_warning ("%s: SSH Elevate Credential not found.", __func__);
              cleanup_iterator (&ssh_elevate_iter);
              osp_credential_free(osp_credential);
              return NULL;
            }
          elevate_type = credential_iterator_type (&ssh_elevate_iter);
          if (strcmp (elevate_type, "up"))
            {
              g_warning ("%s: SSH Elevate Credential not of type up", __func__);
              cleanup_iterator (&ssh_elevate_iter);
              osp_credential_free(osp_credential);
              return NULL;
            }
          osp_credential_set_auth_data (osp_credential,
                                        "priv_username",
                                        credential_iterator_login
                                          (&ssh_elevate_iter));
          osp_credential_set_auth_data (osp_credential,
                                        "priv_password",
                                        credential_iterator_password
                                          (&ssh_elevate_iter));
          cleanup_iterator (&ssh_elevate_iter);
        }

      cleanup_iterator (&iter);
      return osp_credential;
    }
  return NULL;
}

/**
 * @brief Get the SMB credential of a target as an osp_credential_t
 *
 * @param[in]  target  The target to get the credential from.
 *
 * @return  Pointer to a newly allocated osp_credential_t
 */
osp_credential_t *
target_osp_smb_credential_db (target_t target)
{
  credential_t credential;
  credential = target_smb_credential (target);
  if (credential)
    {
      iterator_t iter;
      osp_credential_t *osp_credential;

      init_credential_iterator_one (&iter, credential);
      if (!next (&iter))
        {
          g_warning ("%s: SMB Credential not found.", __func__);
          cleanup_iterator (&iter);
          return NULL;
        }
      if (strcmp (credential_iterator_type (&iter), "up"))
        {
          g_warning ("%s: SMB Credential not a user/pass pair.", __func__);
          cleanup_iterator (&iter);
          return NULL;
        }

      osp_credential = osp_credential_new ("up", "smb", NULL);
      osp_credential_set_auth_data (osp_credential,
                                    "username",
                                    credential_iterator_login (&iter));
      osp_credential_set_auth_data (osp_credential,
                                    "password",
                                    credential_iterator_password (&iter));
      cleanup_iterator (&iter);
      return osp_credential;
    }
  return NULL;
}

/**
 * @brief Get the SMB credential of a target as an osp_credential_t
 *
 * @param[in]  target  The target to get the credential from.
 *
 * @return  Pointer to a newly allocated osp_credential_t
 */
osp_credential_t *
target_osp_esxi_credential_db (target_t target)
{
  credential_t credential;
  credential = target_esxi_credential (target);
  if (credential)
    {
      iterator_t iter;
      osp_credential_t *osp_credential;

      init_credential_iterator_one (&iter, credential);
      if (!next (&iter))
        {
          g_warning ("%s: ESXi Credential not found.", __func__);
          cleanup_iterator (&iter);
          return NULL;
        }
      if (strcmp (credential_iterator_type (&iter), "up"))
        {
          g_warning ("%s: ESXi Credential not a user/pass pair.",
                     __func__);
          cleanup_iterator (&iter);
          return NULL;
        }

      osp_credential = osp_credential_new ("up", "esxi", NULL);
      osp_credential_set_auth_data (osp_credential,
                                    "username",
                                    credential_iterator_login (&iter));
      osp_credential_set_auth_data (osp_credential,
                                    "password",
                                    credential_iterator_password (&iter));
      cleanup_iterator (&iter);
      return osp_credential;
    }
  return NULL;
}

/**
 * @brief Get the SMB credential of a target as an osp_credential_t
 *
 * @param[in]  target  The target to get the credential from.
 *
 * @return  Pointer to a newly allocated osp_credential_t
 */
osp_credential_t *
target_osp_snmp_credential_db (target_t target)
{
  credential_t credential;
  credential = target_credential (target, "snmp");
  if (credential)
    {
      iterator_t iter;
      osp_credential_t *osp_credential;

      init_credential_iterator_one (&iter, credential);
      if (!next (&iter))
        {
          g_warning ("%s: SNMP Credential not found.", __func__);
          cleanup_iterator (&iter);
          return NULL;
        }
      if (strcmp (credential_iterator_type (&iter), "snmp"))
        {
          g_warning ("%s: SNMP Credential not of type 'snmp'.",
                     __func__);
          cleanup_iterator (&iter);
          return NULL;
        }

      osp_credential = osp_credential_new ("snmp", "snmp", NULL);
      osp_credential_set_auth_data (osp_credential,
                                    "username",
                                    credential_iterator_login (&iter)
                                      ?: "");
      osp_credential_set_auth_data (osp_credential,
                                    "password",
                                    credential_iterator_password (&iter)
                                      ?: "");
      osp_credential_set_auth_data (osp_credential,
                                    "community",
                                    credential_iterator_community (&iter)
                                      ?: "");
      osp_credential_set_auth_data (osp_credential,
                                    "auth_algorithm",
                                    credential_iterator_auth_algorithm (&iter)
                                      ?: "");
      osp_credential_set_auth_data (osp_credential,
                                    "privacy_algorithm",
                                    credential_iterator_privacy_algorithm
                                      (&iter) ?: "");
      osp_credential_set_auth_data (osp_credential,
                                    "privacy_password",
                                    credential_iterator_privacy_password
                                      (&iter) ?: "");
      cleanup_iterator (&iter);
      return osp_credential;
    }
  return NULL;
}

/**
 * @brief Get the Kerberos 5 credential of a target as an osp_credential_t
 *
 * @param[in]  target  The target to get the credential from.
 *
 * @return  Pointer to a newly allocated osp_credential_t
 */
osp_credential_t *
target_osp_krb5_credential_db (target_t target)
{
  credential_t credential;
  credential = target_credential (target, "krb5");
  if (credential)
    {
      iterator_t iter;
      osp_credential_t *osp_credential;

      init_credential_iterator_one (&iter, credential);
      if (!next (&iter))
        {
          g_warning ("%s: Kerberos 5 Credential not found.", __func__);
          cleanup_iterator (&iter);
          return NULL;
        }
      if (strcmp (credential_iterator_type (&iter), "krb5"))
        {
          g_warning ("%s: Kerberos 5 Credential not of type 'krb5'.",
                     __func__);
          cleanup_iterator (&iter);
          return NULL;
        }

      osp_credential = osp_credential_new ("up", "krb5", NULL);
      osp_credential_set_auth_data (osp_credential,
                                    "username",
                                    credential_iterator_login (&iter)
                                      ?: "");
      osp_credential_set_auth_data (osp_credential,
                                    "password",
                                    credential_iterator_password (&iter)
                                      ?: "");
      osp_credential_set_auth_data (osp_credential,
                                    "kdc",
                                    credential_iterator_kdc (&iter)
                                      ?: "");
      osp_credential_set_auth_data (osp_credential,
                                    "realm",
                                    credential_iterator_realm (&iter)
                                      ?: "");
      cleanup_iterator (&iter);
      return osp_credential;
    }
  return NULL;
}
#endif
