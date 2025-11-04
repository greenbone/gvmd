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

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

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

/**
 * @brief Get the SSH credential of a target as an osp_credential_t
 *
 * @param[in]  target  The target to get the credential from.
 *
 * @return  Pointer to a newly allocated osp_credential_t
 */
osp_credential_t *
target_osp_ssh_credential (target_t target)
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
target_osp_smb_credential (target_t target)
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
target_osp_esxi_credential (target_t target)
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

#if ENABLE_CREDENTIAL_STORES
/**
 * @brief Get the SSH credential of a target from a credential store 
 *        as an osp_credential_t
 *
 * @param[in]  target  The target to get the credential from.
 *
 * @return  Pointer to a newly allocated osp_credential_t
 */
osp_credential_t *
target_osp_ssh_cs_credential (target_t target)
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
      const char *auth_data_login, *auth_data_password, *private_key;
      gchar *login, *password;

      auth_data_login = auth_data_password = private_key = NULL;

      init_credential_iterator_one (&iter, credential);

      if (!next (&iter))
        {
          g_warning ("%s: SSH Credential not found.", __func__);
          cleanup_iterator (&iter);
          return NULL;
        }
      type = credential_iterator_type (&iter);
      if (strcmp (type, "cs_up") && strcmp (type, "cs_usk"))
        {
          g_warning ("%s: SSH Credential not a user/pass pair"
                     " or user/ssh key.", __func__);
          cleanup_iterator (&iter);
          return NULL;
        }

      ssh_port = target_ssh_port (target);
      const char *osp_credential_type
        = strcmp (type, "cs_up") == 0 ? "up" : "usk";
      osp_credential = osp_credential_new (osp_credential_type, "ssh",
                                           ssh_port);
      free (ssh_port);

      const char *cred_store_uuid
        = credential_iterator_credential_store_uuid (&iter);
      const char *vault_id
        = credential_iterator_vault_id (&iter);
      const char *host_identifier
        = credential_iterator_host_identifier (&iter);

      if (cyberark_login_password_credential_data (cred_store_uuid,
                                                   vault_id,
                                                   host_identifier,
                                                   &login,
                                                   &password))
        {
          g_warning ("%s: Error retrieving credentials from "
                      "CyberArk credential store '%s'.",
                      __func__, cred_store_uuid);
          cleanup_iterator (&iter);
          osp_credential_free (osp_credential);
          return NULL;
        }
      auth_data_login = login;
      if (strcmp (type, "cs_usk") == 0)
        private_key = password;
      else
        auth_data_password = password;

      osp_credential_set_auth_data (osp_credential,
                                    "username",
                                    auth_data_login);
      if (auth_data_password)
        osp_credential_set_auth_data (osp_credential,
                                      "password",
                                      auth_data_password);
      if (private_key)
        {
          gchar *base64 = g_base64_encode ((guchar *) private_key,
                                           strlen (private_key));
          osp_credential_set_auth_data (osp_credential,
                                        "private",
                                        base64);
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
              osp_credential_free (osp_credential);
              return NULL;
            }
          elevate_type = credential_iterator_type (&ssh_elevate_iter);
          if (strcmp (elevate_type, "cs_up"))
            {
              g_warning ("%s: SSH Elevate Credential not of type cs_up", __func__);
              cleanup_iterator (&ssh_elevate_iter);
              osp_credential_free (osp_credential);
              return NULL;
            }

          const char *cred_store_uuid_elevate
            = credential_iterator_credential_store_uuid (&iter);
          const char *vault_id_elevate
            = credential_iterator_vault_id (&iter);
          const char *host_identifier_elevate
            = credential_iterator_host_identifier (&iter);

          if (cyberark_login_password_credential_data (cred_store_uuid_elevate,
                                                       vault_id_elevate,
                                                       host_identifier_elevate,
                                                       &login,
                                                       &password))
            {
              g_warning ("%s: Error retrieving credentials from "
                          "CyberArk credential store '%s'.",
                          __func__, cred_store_uuid);
              cleanup_iterator (&iter);
              return NULL;
            }
          auth_data_login = login;
          auth_data_password = password;

          osp_credential_set_auth_data (osp_credential,
                                        "priv_username",
                                        auth_data_login);
          osp_credential_set_auth_data (osp_credential,
                                        "priv_password",
                                        auth_data_password);
          cleanup_iterator (&ssh_elevate_iter);
        }

      cleanup_iterator (&iter);
      g_free (login);
      g_free (password);
      return osp_credential;
    }
  return NULL;
}

/**
 * @brief Get the SMB credential of a target from credential store as an osp_credential_t
 *
 * @param[in]  target  The target to get the credential from.
 *
 * @return  Pointer to a newly allocated osp_credential_t
 */
osp_credential_t *
target_osp_smb_cs_credential (target_t target)
{
  credential_t credential;
  credential = target_smb_credential (target);
  if (credential)
    {
      iterator_t iter;
      osp_credential_t *osp_credential;
      const char *auth_data_login, *auth_data_password;

      init_credential_iterator_one (&iter, credential);
      if (!next (&iter))
        {
          g_warning ("%s: SMB Credential not found.", __func__);
          cleanup_iterator (&iter);
          return NULL;
        }
      const char *type = credential_iterator_type (&iter);
      if (strcmp (type, "cs_up")
         )
        {
          g_warning ("%s: SMB Credential not a user/pass pair.", __func__);
          cleanup_iterator (&iter);
          return NULL;
        }

      const char *cred_store_uuid
        = credential_iterator_credential_store_uuid (&iter);
      const char *vault_id
        = credential_iterator_vault_id (&iter);
      const char *host_identifier
        = credential_iterator_host_identifier (&iter);

      gchar *login, *password;
      if (cyberark_login_password_credential_data (cred_store_uuid,
                                                   vault_id,
                                                   host_identifier,
                                                   &login,
                                                   &password))
        {
          g_warning ("%s: Error retrieving credentials from "
                      "CyberArk credential store '%s'.",
                      __func__, cred_store_uuid);
          cleanup_iterator (&iter);
          return NULL;
        }
      auth_data_login = login;
      auth_data_password = password;

      osp_credential = osp_credential_new ("up", "smb", NULL);
      osp_credential_set_auth_data (osp_credential, "username", auth_data_login);
      osp_credential_set_auth_data (osp_credential, "password", auth_data_password);

      cleanup_iterator (&iter);
      g_free (login);
      g_free (password);
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
target_osp_esxi_cs_credential (target_t target)
{
  credential_t credential;
  credential = target_esxi_credential (target);
  if (credential)
    {
      iterator_t iter;
      osp_credential_t *osp_credential;
      const char *auth_data_login, *auth_data_password;

      init_credential_iterator_one (&iter, credential);
      if (!next (&iter))
        {
          g_warning ("%s: ESXi Credential not found.", __func__);
          cleanup_iterator (&iter);
          return NULL;
        }
      const char *type = credential_iterator_type (&iter);
      if (strcmp (type, "cs_up"))
        {
          g_warning ("%s: ESXi Credential not a user/pass pair.",
                     __func__);
          cleanup_iterator (&iter);
          return NULL;
        }

      const char *cred_store_uuid
        = credential_iterator_credential_store_uuid (&iter);
      const char *vault_id
        = credential_iterator_vault_id (&iter);
      const char *host_identifier
        = credential_iterator_host_identifier (&iter);

      gchar *login, *password;
      if (cyberark_login_password_credential_data (cred_store_uuid,
                                                   vault_id,
                                                   host_identifier,
                                                   &login,
                                                   &password))
        {
          g_warning ("%s: Error retrieving credentials from "
                      "CyberArk credential store '%s'.",
                      __func__, cred_store_uuid);
          cleanup_iterator (&iter);
          return NULL;
        }
      auth_data_login = login;
      auth_data_password = password;

      osp_credential = osp_credential_new ("up", "esxi", NULL);
      osp_credential_set_auth_data (osp_credential,
                                    "username",
                                    auth_data_login);
      osp_credential_set_auth_data (osp_credential,
                                    "password",
                                    auth_data_password);

      cleanup_iterator (&iter);
      g_free (login);
      g_free (password);
      return osp_credential;
    }
  return NULL;
}

#endif

/**
 * @brief Get the SMB credential of a target as an osp_credential_t
 *
 * @param[in]  target  The target to get the credential from.
 *
 * @return  Pointer to a newly allocated osp_credential_t
 */
osp_credential_t *
target_osp_snmp_credential (target_t target)
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
target_osp_krb5_credential (target_t target)
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
