/* Copyright (C) 2019-2025 Greenbone AG
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

#include "manage_alerts.h"
#include "manage_acl.h"
#include "manage_report_formats.h"
#include "manage_sql.h"
#include "manage_sql_alerts.h"

#include <ctype.h>

#include <gvm/base/hosts.h>

/**
 * @file manage_sql_alerts.c
 * @brief GVM management layer: Alert SQL
 *
 * The Alert SQL for the GVM management layer.
 */

/**
 * @brief Find a alert for a specific permission, given a UUID.
 *
 * @param[in]   uuid        UUID of alert.
 * @param[out]  alert       Alert return, 0 if successfully failed to find alert.
 * @param[in]   permission  Permission.
 *
 * @return FALSE on success (including if failed to find alert), TRUE on error.
 */
gboolean
find_alert_with_permission (const char* uuid, alert_t* alert,
                            const char *permission)
{
  return find_resource_with_permission ("alert", uuid, alert, permission, 0);
}

/**
 * @brief Create an alert from an existing alert.
 *
 * @param[in]  name          Name of new alert. NULL to copy from existing.
 * @param[in]  comment       Comment on new alert. NULL to copy from
 *                           existing.
 * @param[in]  alert_id      UUID of existing alert.
 * @param[out] new_alert     New alert.
 *
 * @return 0 success, 1 alert exists already, 2 failed to find existing
 *         alert, 99 permission denied, -1 error.
 */
int
copy_alert (const char* name, const char* comment, const char* alert_id,
            alert_t* new_alert)
{
  int ret;
  alert_t new, old;

  assert (current_credentials.uuid);

  if (alert_id == NULL)
    return -1;

  sql_begin_immediate ();

  ret = copy_resource_lock ("alert", name, comment, alert_id,
                            "event, condition, method, filter, active",
                            1, &new, &old);
  if (ret)
    {
      sql_rollback ();
      return ret;
    }

  /* Copy the alert condition data */
  sql ("INSERT INTO alert_condition_data (alert, name, data)"
       " SELECT %llu, name, data FROM alert_condition_data"
       "  WHERE alert = %llu;",
       new,
       old);

  /* Copy the alert event data */
  sql ("INSERT INTO alert_event_data (alert, name, data)"
       " SELECT %llu, name, data FROM alert_event_data"
       "  WHERE alert = %llu;",
       new,
       old);

  /* Copy the alert method data */
  sql ("INSERT INTO alert_method_data (alert, name, data)"
       " SELECT %llu, name, data FROM alert_method_data"
       "  WHERE alert = %llu;",
       new,
       old);

  sql_commit ();
  if (new_alert) *new_alert = new;
  return 0;
}

/**
 * @brief Validate an email address.
 *
 * @param[in]  address  Email address.
 *
 * @return 0 success, 1 failure.
 */
static int
validate_email (const char* address)
{
  gchar **split, *point;

  assert (address);

  split = g_strsplit (address, "@", 0);

  if (split[0] == NULL || split[1] == NULL || split[2])
    {
      g_strfreev (split);
      return 1;
    }

  /* Local part. */
  point = split[0];
  while (*point)
    if (isalnum (*point)
        || strchr ("!#$%&'*+-/=?^_`{|}~", *point)
        || ((*point == '.')
            && (point > split[0])
            && point[1]
            && (point[1] != '.')
            && (point[-1] != '.')))
      point++;
    else
      {
        g_strfreev (split);
        return 1;
      }

  /* Domain. */
  point = split[1];
  while (*point)
    if (isalnum (*point)
        || strchr ("-_", *point)  /* RFC actually forbids _. */
        || ((*point == '.')
            && (point > split[1])
            && point[1]
            && (point[1] != '.')
            && (point[-1] != '.')))
      point++;
    else
      {
        g_strfreev (split);
        return 1;
      }

  g_strfreev (split);
  return 0;
}

/**
 * @brief Validate an email address list.
 *
 * @param[in]  list  Comma separated list of email addresses.
 *
 * @return 0 success, 1 failure.
 */
static int
validate_email_list (const char *list)
{
  gchar **split, **point;

  assert (list);

  split = g_strsplit (list, ",", 0);

  if (split[0] == NULL)
    {
      g_strfreev (split);
      return 1;
    }

  point = split;
  while (*point)
    {
      const char *address;
      address = *point;
      while (*address && (*address == ' ')) address++;
      if (validate_email (address))
        {
          g_strfreev (split);
          return 1;
        }
      point++;
    }

  g_strfreev (split);
  return 0;
}

/**
 * @brief Validate condition data for an alert.
 *
 * @param[in]  name      Name.
 * @param[in]  data      Data to validate.
 * @param[in]  condition The condition.
 *
 * @return 0 on success, 1 unexpected data name, 2 syntax error in data,
 *         3 failed to find filter for condition, -1 internal error.
 */
static int
validate_alert_condition_data (gchar *name, gchar* data,
                               alert_condition_t condition)
{
  if (condition == ALERT_CONDITION_ALWAYS)
    return 1;
  if (condition == ALERT_CONDITION_SEVERITY_AT_LEAST)
    {
      if (strcmp (name, "severity"))
        return 1;

      if (g_regex_match_simple ("^(-1(\\.0)?|[0-9](\\.[0-9])?|10(\\.0))$",
                                data ? data : "",
                                0,
                                0)
          == 0)
        return 2;
    }
  else if (condition == ALERT_CONDITION_SEVERITY_CHANGED)
    {
      if (strcmp (name, "direction"))
        return 1;

      if (g_regex_match_simple ("^(increased|decreased|changed)$",
                                data ? data : "",
                                0,
                                0)
          == 0)
        return 2;
    }
  else if (condition == ALERT_CONDITION_FILTER_COUNT_AT_LEAST)
    {
      if (strcmp (name, "filter_id") == 0)
        {
          filter_t filter;
          if (data == NULL)
            return 3;
          filter = 0;
          if (find_filter_with_permission (data, &filter, "get_filters"))
            return -1;
          if (filter == 0)
            return 3;
          return 0;
        }

      if (strcmp (name, "count"))
        return 1;
    }
  else if (condition == ALERT_CONDITION_FILTER_COUNT_CHANGED)
    {
      if (strcmp (name, "filter_id") == 0)
        {
          filter_t filter;
          if (data == NULL)
            return 3;
          filter = 0;
          if (find_filter_with_permission (data, &filter, "get_filters"))
            return -1;
          if (filter == 0)
            return 3;
          return 0;
        }

      if (strcmp (name, "direction")
          && strcmp (name, "count"))
        return 1;

      if (strcmp (name, "direction") == 0
          && g_regex_match_simple ("^(increased|decreased|changed)$",
                                   data ? data : "",
                                   0,
                                   0)
             == 0)
        return 2;
    }


  return 0;
}

/**
 * @brief Validate event data for an alert.
 *
 * @param[in]  name   Name.
 * @param[in]  data   Data to validate.
 * @param[in]  event  The event.
 *
 * @return 0 on success, 1 unexpected data name, 2 syntax error in data.
 */
static int
validate_alert_event_data (gchar *name, gchar* data, event_t event)
{
  if (event == EVENT_NEW_SECINFO || event == EVENT_UPDATED_SECINFO)
    {
      if (strcmp (name, "secinfo_type"))
        return 1;

      if (data == NULL)
        return 2;

      if (strcasecmp (data, "nvt")
          && strcasecmp (data, "cve")
          && strcasecmp (data, "cpe")
          && strcasecmp (data, "cert_bund_adv")
          && strcasecmp (data, "dfn_cert_adv"))
        return 2;
    }
  return 0;
}

/**
 * @brief Validate method data for the email method.
 *
 * @param[in]  method          Method that data corresponds to.
 * @param[in]  name            Name of data.
 * @param[in]  data            The data.
 * @param[in]  for_modify      Whether to return error codes for modify_alert.
 *
 * @return 0 valid, 2 or 6: validation of email address failed,
 *         7 or 9 subject too long, 8 or 10 message too long,
 *         60 recipient credential not found, 61 invalid recipient credential
 *         type, -1 error. When for_modify is 0, the first code is returned,
 *         otherwise the second one.
 */
int
validate_email_data (alert_method_t method, const gchar *name, gchar **data,
                     int for_modify)
{
  if (method == ALERT_METHOD_EMAIL
      && strcmp (name, "to_address") == 0
      && validate_email_list (*data))
    return for_modify ? 6 : 2;

  if (method == ALERT_METHOD_EMAIL
      && strcmp (name, "from_address") == 0
      && validate_email (*data))
    return for_modify ? 6 : 2;

  if (method == ALERT_METHOD_EMAIL
      && strcmp (name, "subject") == 0
      && strlen (*data) > 80)
    return for_modify ? 9 : 7;

  if (method == ALERT_METHOD_EMAIL
      && strcmp (name, "message") == 0
      && strlen (*data) > get_max_email_message_size ())
    return for_modify ? 10 : 8;

  if (method == ALERT_METHOD_EMAIL
      && strcmp (name, "recipient_credential") == 0
      && *data && strcmp (*data, ""))
    {
      credential_t credential;
      char *type;

      if (find_credential_with_permission (*data, &credential, NULL))
        return -1;
      else if (credential == 0)
        return 60;

      type = credential_type (credential);
      if (strcmp (type, "pgp")
          && strcmp (type, "smime"))
        {
          free (type);
          return 61;
        }
      free (type);
    }

  return 0;
}

/**
 * @brief Validate method data for the SCP method.
 *
 * @param[in]  method          Method that data corresponds to.
 * @param[in]  name            Name of data.
 * @param[in]  data            The data.
 *
 * @return 0 valid, 15 error in SCP host, 16 error in SCP port,
 *         17 failed to find report format for SCP method,
 *         18 error in SCP credential, 19 error in SCP path,
 *         -1 error.
 */
static int
validate_scp_data (alert_method_t method, const gchar *name, gchar **data)
{
  if (method == ALERT_METHOD_SCP
      && strcmp (name, "scp_credential") == 0)
    {
      credential_t credential;
      if (find_credential_with_permission (*data, &credential,
                                           "get_credentials"))
        return -1;
      else if (credential == 0)
        return 18;
      else
        {
          gchar *username;
          username = credential_value (credential, "username");

          if (username == NULL || strlen (username) == 0)
            {
              g_free (username);
              return 18;
            }

          if (strchr (username, ':'))
            {
              g_free (username);
              return 18;
            }

          g_free (username);
        }
    }

  if (method == ALERT_METHOD_SCP
      && strcmp (name, "scp_path") == 0)
    {
      if (strlen (*data) == 0)
        return 19;
    }

  if (method == ALERT_METHOD_SCP
      && strcmp (name, "scp_host") == 0)
    {
      int type;
      gchar *stripped;

      stripped = g_strstrip (g_strdup (*data));
      type = gvm_get_host_type (stripped);
      g_free (stripped);
      if ((type != HOST_TYPE_IPV4)
          && (type != HOST_TYPE_IPV6)
          && (type != HOST_TYPE_NAME))
        return 15;
    }

  if (method == ALERT_METHOD_SCP
      && strcmp (name, "scp_port") == 0)
    {
      int port;

      port = atoi (*data);
      if (port <= 0 || port > 65535)
        return 16;
    }

  if (method == ALERT_METHOD_SCP
      && strcmp (name, "scp_report_format") == 0)
    {
      report_format_t report_format;

      report_format = 0;
      if (find_report_format_with_permission (*data,
                                              &report_format,
                                              "get_report_formats"))
        return -1;
      if (report_format == 0)
        return 17;
    }

  return 0;
}

/**
 * @brief Validate method data for the Send method.
 *
 * @param[in]  method          Method that data corresponds to.
 * @param[in]  name            Name of data.
 * @param[in]  data            The data.
 *
 * @return 0 valid, 12 error in Send host, 13 error in Send port, 14 failed
 *         to find report format for Send method, -1 error.
 */
static int
validate_send_data (alert_method_t method, const gchar *name, gchar **data)
{
  if (method == ALERT_METHOD_SEND
      && strcmp (name, "send_host") == 0)
    {
      int type;
      gchar *stripped;

      stripped = g_strstrip (g_strdup (*data));
      type = gvm_get_host_type (stripped);
      g_free (stripped);
      if ((type != HOST_TYPE_IPV4)
          && (type != HOST_TYPE_IPV6)
          && (type != HOST_TYPE_NAME))
        return 12;
    }

  if (method == ALERT_METHOD_SEND
      && strcmp (name, "send_port") == 0)
    {
      int port;
      gchar *stripped, *end;

      stripped = g_strstrip (g_strdup (*data));
      port = strtol (stripped, &end, 10);
      if (*end != '\0')
        {
          g_free (stripped);
          return 13;
        }

      g_free (stripped);
      g_free (*data);
      *data = g_strdup_printf ("%i", port);
    }

  if (method == ALERT_METHOD_SEND
      && strcmp (name, "send_report_format") == 0)
    {
      report_format_t report_format;

      report_format = 0;
      if (find_report_format_with_permission (*data,
                                              &report_format,
                                              "get_report_formats"))
        return -1;
      if (report_format == 0)
        return 14;
    }

  return 0;
}

/**
 * @brief Validate method data for the Send method.
 *
 * @param[in]  method          Method that data corresponds to.
 * @param[in]  name            Name of data.
 * @param[in]  data            The data.
 *
 * @return 0 valid, 40 invalid credential, 41 invalid SMB share path,
 *         42 invalid SMB file path, 43 SMB file path contains dot, -1 error.
 */
static int
validate_smb_data (alert_method_t method, const gchar *name, gchar **data)
{
  if (method == ALERT_METHOD_SMB)
    {
      if (strcmp (name, "smb_credential") == 0)
        {
          credential_t credential;
          if (find_credential_with_permission (*data, &credential,
                                              "get_credentials"))
            return -1;
          else if (credential == 0)
            return 40;
          else
            {
              gchar *username;
              username = credential_value (credential, "username");

              if (username == NULL || strlen (username) == 0)
                {
                  g_free (username);
                  return 40;
                }

              if (strchr (username, '@') || strchr (username, ':'))
                {
                  g_free (username);
                  return 40;
                }

              g_free (username);
            }
        }

      if (strcmp (name, "smb_share_path") == 0)
        {
          /* Check if share path has the correct format
           *  "\\<host>\<share>" */
          if (g_regex_match_simple ("^(?>\\\\\\\\|\\/\\/)[^:?<>|]+"
                                    "(?>\\\\|\\/)[^:?<>|]+$", *data, 0, 0)
              == FALSE)
            {
              return 41;
            }
        }

      if (strcmp (name, "smb_file_path") == 0)
        {
          /* Check if file path contains invalid characters:
           *  ":", "?", "<", ">", "|" */
          if (g_regex_match_simple ("^[^:?<>|]+$", *data, 0, 0)
              == FALSE)
            {
              return 42;
            }
          /* Check if a file or directory name ends with a dot,
           *  e.g. "../a", "abc/../xyz" or "abc/..". */
          else if (g_regex_match_simple ("^(?:.*\\.)(?:[\\/\\\\].*)*$",
                                         *data, 0, 0))
            {
              return 43;
            }
        }

    }

  return 0;
}

/**
 * @brief Validate method data for the TippingPoint method.
 *
 * @param[in]  method          Method that data corresponds to.
 * @param[in]  name            Name of data.
 * @param[in]  data            The data.
 *
 * @return 0 valid, 50 invalid credential, 51 invalid hostname,
 *  52 invalid certificate, 53 invalid TLS workaround setting.
 */
static int
validate_tippingpoint_data (alert_method_t method, const gchar *name,
                             gchar **data)
{
  if (method == ALERT_METHOD_TIPPINGPOINT)
    {
      if (strcmp (name, "tp_sms_credential") == 0)
        {
          credential_t credential;
          if (find_credential_with_permission (*data, &credential,
                                               "get_credentials"))
            return -1;
          else if (credential == 0)
            return 50;
          else
            {
              if (strcmp (credential_type (credential), "up"))
                return 50;

            }
        }

      if (strcmp (name, "tp_sms_hostname") == 0)
        {
          if (g_regex_match_simple ("^[0-9A-Za-z][0-9A-Za-z.\\-]*$",
                                    *data, 0, 0)
              == FALSE)
            {
              return 51;
            }
        }

      if (strcmp (name, "tp_sms_tls_certificate") == 0)
        {
          // Check certificate, return 52 on failure
          int ret;
          gnutls_x509_crt_fmt_t crt_fmt;

          ret = get_certificate_info (*data, strlen(*data), FALSE,
                                      NULL, NULL, NULL,
                                      NULL, NULL, NULL, NULL, &crt_fmt);
          if (ret || crt_fmt != GNUTLS_X509_FMT_PEM)
            {
              return 52;
            }
        }

      if (strcmp (name, "tp_sms_tls_workaround") == 0)
        {
          if (g_regex_match_simple ("^0|1$", *data, 0, 0)
              == FALSE)
            {
              return 53;
            }
        }
    }

  return 0;
}

/**
 * @brief Validate method data for the vFire alert method.
 *
 * @param[in]  method          Method that data corresponds to.
 * @param[in]  name            Name of data.
 * @param[in]  data            The data.
 *
 * @return 0 valid, 70 credential not found, 71 invalid credential type
 */
static int
validate_vfire_data (alert_method_t method, const gchar *name,
                     gchar **data)
{
  if (method == ALERT_METHOD_VFIRE)
    {
      if (strcmp (name, "vfire_credential") == 0)
        {
          credential_t credential;
          if (find_credential_with_permission (*data, &credential,
                                               "get_credentials"))
            return -1;
          else if (credential == 0)
            return 70;
          else
            {
              char *cred_type = credential_type (credential);
              if (strcmp (cred_type, "up"))
                {
                  free (cred_type);
                  return 71;
                }
              free (cred_type);
            }
        }
    }
  return 0;
}

/**
 * @brief Validate method data for the Sourcefire method.
 *
 * @param[in]  method          Method that data corresponds to.
 * @param[in]  name            Name of data.
 * @param[in]  data            The data.
 *
 * @return 0 valid, 80 credential not found, 81 invalid credential type
 */
static int
validate_sourcefire_data (alert_method_t method, const gchar *name,
                          gchar **data)
{
  if (method == ALERT_METHOD_SOURCEFIRE)
    {
      if (strcmp (name, "pkcs12_credential") == 0)
        {
          credential_t credential;
          if (find_credential_with_permission (*data, &credential,
                                               "get_credentials"))
            return -1;
          else if (credential == 0)
            return 80;
          else
            {
              char *sourcefire_credential_type;
              sourcefire_credential_type = credential_type (credential);
              if (strcmp (sourcefire_credential_type, "up")
                  && strcmp (sourcefire_credential_type, "pw"))
                {
                  free (sourcefire_credential_type);
                  return 81;
                }
              free (sourcefire_credential_type);
            }
        }
    }

  return 0;
}

/**
 * @brief Check alert params.
 *
 * @param[in]  event           Type of event.
 * @param[in]  condition       Event condition.
 * @param[in]  method          Escalation method.
 *
 * @return 0 success, 20 method does not match event, 21 condition does not
 *         match event.
 */
static int
check_alert_params (event_t event, alert_condition_t condition,
                    alert_method_t method)
{
  if (event == EVENT_NEW_SECINFO || event == EVENT_UPDATED_SECINFO)
    {
      if (method == ALERT_METHOD_HTTP_GET
          || method == ALERT_METHOD_SOURCEFIRE
          || method == ALERT_METHOD_VERINICE)
        return 20;

      if (condition == ALERT_CONDITION_SEVERITY_AT_LEAST
          || condition == ALERT_CONDITION_SEVERITY_CHANGED
          || condition == ALERT_CONDITION_FILTER_COUNT_CHANGED)
        return 21;
    }
  return 0;
}

/**
 * @brief Create an alert.
 *
 * @param[in]  name            Name of alert.
 * @param[in]  comment         Comment on alert.
 * @param[in]  filter_id       Filter.
 * @param[in]  active          Whether the alert is active.
 * @param[in]  event           Type of event.
 * @param[in]  event_data      Type-specific event data.
 * @param[in]  condition       Event condition.
 * @param[in]  condition_data  Condition-specific data.
 * @param[in]  method          Escalation method.
 * @param[in]  method_data     Data for escalation method.
 * @param[out] alert       Created alert on success.
 *
 * @return 0 success, 1 escalation exists already, 2 validation of email failed,
 *         3 failed to find filter, 4 type must be "result" if specified,
 *         5 unexpected condition data name, 6 syntax error in condition data,
 *         7 email subject too long, 8 email message too long, 9 failed to find
 *         filter for condition, 12 error in Send host, 13 error in Send port,
 *         14 failed to find report format for Send method,
 *         15 error in SCP host, 16 error in SCP port,
 *         17 failed to find report format for SCP method, 18 error
 *         in SCP credential, 19 error in SCP path, 20 method does not match
 *         event, 21 condition does not match event, 31 unexpected event data
 *         name, 32 syntax error in event data, 40 invalid SMB credential
 *       , 41 invalid SMB share path, 42 invalid SMB file path,
 *         43 SMB file path contains dot,
 *         50 invalid TippingPoint credential, 51 invalid TippingPoint hostname,
 *         52 invalid TippingPoint certificate, 53 invalid TippingPoint TLS
 *         workaround setting, 60 recipient credential not found, 61 invalid
 *         recipient credential type, 70 vFire credential not found,
 *         71 invalid vFire credential type,
 *         99 permission denied, -1 error.
 */
int
create_alert (const char* name, const char* comment, const char* filter_id,
              const char* active, event_t event, GPtrArray* event_data,
              alert_condition_t condition, GPtrArray* condition_data,
              alert_method_t method, GPtrArray* method_data,
              alert_t *alert)
{
  int index, ret;
  gchar *item, *quoted_comment;
  gchar *quoted_name;
  filter_t filter;

  assert (current_credentials.uuid);

  sql_begin_immediate ();

  if (acl_user_may ("create_alert") == 0)
    {
      sql_rollback ();
      return 99;
    }

  ret = check_alert_params (event, condition, method);
  if (ret)
    {
      sql_rollback ();
      return ret;
    }

  filter = 0;
  if (event != EVENT_NEW_SECINFO && event != EVENT_UPDATED_SECINFO && filter_id
      && strcmp (filter_id, "0"))
    {
      char *type;

      if (find_filter_with_permission (filter_id, &filter, "get_filters"))
        {
          sql_rollback ();
          return -1;
        }

      if (filter == 0)
        {
          sql_rollback ();
          return 3;
        }

      /* Filter type must be result if specified. */

      type = sql_string ("SELECT type FROM filters WHERE id = %llu;",
                         filter);
      if (type && strcasecmp (type, "result"))
        {
          free (type);
          sql_rollback ();
          return 4;
        }
      free (type);
    }

  if (resource_with_name_exists (name, "alert", 0))
    {
      sql_rollback ();
      return 1;
    }
  quoted_name = sql_quote (name);
  quoted_comment = sql_quote (comment ?: "");

  sql ("INSERT INTO alerts (uuid, owner, name, comment, event, condition,"
       " method, filter, active, creation_time, modification_time)"
       " VALUES (make_uuid (),"
       " (SELECT id FROM users WHERE users.uuid = '%s'),"
       " '%s', '%s', %i, %i, %i, %llu, %i, m_now (), m_now ());",
       current_credentials.uuid,
       quoted_name,
       quoted_comment,
       event,
       condition,
       method,
       filter,
       active ? strcmp (active, "0") : 1);

  g_free (quoted_comment);
  g_free (quoted_name);

  *alert = sql_last_insert_id ();

  index = 0;
  while ((item = (gchar*) g_ptr_array_index (condition_data, index++)))
    {
      int validation_result;
      gchar *data_name = sql_quote (item);
      gchar *data = sql_quote (item + strlen (item) + 1);

      validation_result = validate_alert_condition_data (data_name,
                                                         data,
                                                         condition);

      if (validation_result)
        {
          g_free (data_name);
          g_free (data);
          sql_rollback ();

          switch (validation_result)
            {
              case 1:
                return 5;
              case 2:
                return 6;
              case 3:
                return 9;
              default:
                return -1;
            }
        }

      sql ("INSERT INTO alert_condition_data (alert, name, data)"
           " VALUES (%llu, '%s', '%s');",
           *alert,
           data_name,
           data);
      g_free (data_name);
      g_free (data);
    }

  index = 0;
  while ((item = (gchar*) g_ptr_array_index (event_data, index++)))
    {
      int validation_result;
      gchar *data_name = sql_quote (item);
      gchar *data = sql_quote (item + strlen (item) + 1);

      validation_result = validate_alert_event_data (data_name, data, event);

      if (validation_result)
        {
          g_free (data_name);
          g_free (data);
          sql_rollback ();

          switch (validation_result)
            {
              case 1:
                return 31;
              case 2:
                return 32;
              default:
                return -1;
            }
        }

      sql ("INSERT INTO alert_event_data (alert, name, data)"
           " VALUES (%llu, '%s', '%s');",
           *alert,
           data_name,
           data);
      g_free (data_name);
      g_free (data);
    }

  index = 0;
  while ((item = (gchar*) g_ptr_array_index (method_data, index++)))
    {
      gchar *data_name, *data;

      data_name = sql_quote (item);
      data = sql_quote (item + strlen (item) + 1);

      ret = validate_email_data (method, data_name, &data, 0);
      if (ret)
        {
          g_free (data_name);
          g_free (data);
          sql_rollback ();
          return ret;
        }

      ret = validate_scp_data (method, data_name, &data);
      if (ret)
        {
          g_free (data_name);
          g_free (data);
          sql_rollback ();
          return ret;
        }

      ret = validate_send_data (method, data_name, &data);
      if (ret)
        {
          g_free (data_name);
          g_free (data);
          sql_rollback ();
          return ret;
        }

      ret = validate_smb_data (method, data_name, &data);
      if (ret)
        {
          g_free (data_name);
          g_free (data);
          sql_rollback ();
          return ret;
        }

      ret = validate_sourcefire_data (method, data_name, &data);
      if (ret)
        {
          g_free (data_name);
          g_free (data);
          sql_rollback ();
          return ret;
        }

      ret = validate_tippingpoint_data (method, data_name, &data);
      if (ret)
        {
          g_free (data_name);
          g_free (data);
          sql_rollback ();
          return ret;
        }

      ret = validate_vfire_data (method, data_name, &data);
      if (ret)
        {
          g_free (data_name);
          g_free (data);
          sql_rollback ();
          return ret;
        }

      sql ("INSERT INTO alert_method_data (alert, name, data)"
           " VALUES (%llu, '%s', '%s');",
           *alert,
           data_name,
           data);
      g_free (data_name);
      g_free (data);
    }

  sql_commit ();

  return 0;
}

/**
 * @brief Modify an alert.
 *
 * @param[in]   alert_id        UUID of alert.
 * @param[in]   name            Name of alert.
 * @param[in]   comment         Comment on alert.
 * @param[in]   filter_id       Filter.
 * @param[in]   active          Whether the alert is active.  NULL to leave it
 *                              at the current value.
 * @param[in]   event           Type of event.
 * @param[in]   event_data      Type-specific event data.
 * @param[in]   condition       Event condition.
 * @param[in]   condition_data  Condition-specific data.
 * @param[in]   method          Escalation method.
 * @param[in]   method_data     Data for escalation method.
 *
 * @return 0 success, 1 failed to find alert, 2 alert with new name exists,
 *         3 alert_id required, 4 failed to find filter, 5 filter type must be
 *         result if specified, 6 Provided email address not valid,
 *         7 unexpected condition data name, 8 syntax error in condition data,
 *         9 email subject too long, 10 email message too long, 11 failed to
 *         find filter for condition, 12 error in Send host, 13 error in Send
 *         port, 14 failed to find report format for Send method,
 *         15 error in SCP host, 16 error in SCP port,
 *         17 failed to find report format for SCP method, 18 error
 *         in SCP credential, 19 error in SCP path, 20 method does not match
 *         event, 21 condition does not match event, 31 unexpected event data
 *         name, 32 syntax error in event data, 40 invalid SMB credential
 *       , 41 invalid SMB share path, 42 invalid SMB file path,
 *         43 SMB file path contains dot,
 *         50 invalid TippingPoint credential, 51 invalid TippingPoint hostname,
 *         52 invalid TippingPoint certificate, 53 invalid TippingPoint TLS
 *         workaround setting, 60 recipient credential not found, 61 invalid
 *         recipient credential type, 70 vFire credential not found,
 *         71 invalid vFire credential type,
 *         99 permission denied, -1 internal error.
 */
int
modify_alert (const char *alert_id, const char *name, const char *comment,
              const char *filter_id, const char *active, event_t event,
              GPtrArray *event_data, alert_condition_t condition,
              GPtrArray *condition_data, alert_method_t method,
              GPtrArray *method_data)
{
  int index, ret;
  gchar *quoted_name, *quoted_comment, *item;
  alert_t alert;
  filter_t filter;

  if (alert_id == NULL)
    return 3;

  sql_begin_immediate ();

  assert (current_credentials.uuid);

  if (acl_user_may ("modify_alert") == 0)
    {
      sql_rollback ();
      return 99;
    }

  ret = check_alert_params (event, condition, method);
  if (ret)
    {
      sql_rollback ();
      return ret;
    }

  alert = 0;
  if (find_alert_with_permission (alert_id, &alert, "modify_alert"))
    {
      sql_rollback ();
      return -1;
    }

  if (alert == 0)
    {
      sql_rollback ();
      return 1;
    }

  /* Check whether an alert with the same name exists already. */
  if (resource_with_name_exists (name, "alert", alert))
    {
      sql_rollback ();
      return 2;
    }

  /* Check filter. */
  filter = 0;
  if (event != EVENT_NEW_SECINFO && event != EVENT_UPDATED_SECINFO && filter_id
      && strcmp (filter_id, "0"))
    {
      char *type;

      if (find_filter_with_permission (filter_id, &filter, "get_filters"))
        {
          sql_rollback ();
          return -1;
        }

      if (filter == 0)
        {
          sql_rollback ();
          return 4;
        }

      /* Filter type must be report if specified. */

      type = sql_string ("SELECT type FROM filters WHERE id = %llu;",
                         filter);
      if (type && strcasecmp (type, "result"))
        {
          free (type);
          sql_rollback ();
          return 5;
        }
      free (type);
    }

  quoted_name = sql_quote (name ?: "");
  quoted_comment = sql_quote (comment ? comment : "");

  sql ("UPDATE alerts SET"
       " name = '%s',"
       " comment = '%s',"
       " filter = %llu,"
       " active = %s,"
       " modification_time = m_now ()"
       " WHERE id = %llu;",
       quoted_name,
       quoted_comment,
       filter,
       active
        ? (strcmp (active, "0") ? "1" : "0")
        : "active",
       alert);

  g_free (quoted_comment);
  g_free (quoted_name);

  /* Modify alert event */
  if (event != EVENT_ERROR)
    {
      sql ("UPDATE alerts set event = %i WHERE id = %llu", event, alert);
      sql ("DELETE FROM alert_event_data WHERE alert = %llu", alert);
      index = 0;
      while ((item = (gchar*) g_ptr_array_index (event_data, index++)))
        {
          int validation_result;
          gchar *data_name = sql_quote (item);
          gchar *data = sql_quote (item + strlen (item) + 1);

          validation_result = validate_alert_event_data (data_name,
                                                         data,
                                                         event);

          if (validation_result)
            {
              g_free (data_name);
              g_free (data);
              sql_rollback ();

              switch (validation_result)
                {
                  case 1:
                    return 31;
                  case 2:
                    return 32;
                  default:
                    return -1;
                }
            }

          sql ("INSERT INTO alert_event_data (alert, name, data)"
               " VALUES (%llu, '%s', '%s');",
               alert,
               data_name,
               data);
          g_free (data_name);
          g_free (data);
        }
    }

  /* Modify alert condition */
  if (condition != ALERT_CONDITION_ERROR)
    {
      sql ("UPDATE alerts set condition = %i WHERE id = %llu",
           condition,
           alert);
      sql ("DELETE FROM alert_condition_data WHERE alert = %llu", alert);
      index = 0;
      while ((item = (gchar*) g_ptr_array_index (condition_data, index++)))
        {
          int validation_result;
          gchar *data_name = sql_quote (item);
          gchar *data = sql_quote (item + strlen (item) + 1);

          validation_result = validate_alert_condition_data (data_name, data,
                                                             condition);

          if (validation_result)
            {
              g_free (data_name);
              g_free (data);
              sql_rollback ();

              switch (validation_result)
                {
                  case 1:
                    return 7;
                  case 2:
                    return 8;
                  case 3:
                    return 11;
                  default:
                    return -1;
                }
            }

          sql ("INSERT INTO alert_condition_data (alert, name, data)"
               " VALUES (%llu, '%s', '%s');",
               alert,
               data_name,
               data);
          g_free (data_name);
          g_free (data);
        }
    }

  /* Modify alert method */
  if (method != ALERT_METHOD_ERROR)
    {
      sql ("UPDATE alerts set method = %i WHERE id = %llu", method, alert);
      sql ("DELETE FROM alert_method_data WHERE alert = %llu", alert);
      index = 0;
      while ((item = (gchar*) g_ptr_array_index (method_data, index++)))
        {
          gchar *data_name, *data;

          data_name = sql_quote (item);
          data = sql_quote (item + strlen (item) + 1);

          ret = validate_email_data (method, data_name, &data, 1);
          if (ret)
            {
              g_free (data_name);
              g_free (data);
              sql_rollback ();
              return ret;
            }

          ret = validate_scp_data (method, data_name, &data);
          if (ret)
            {
              g_free (data_name);
              g_free (data);
              sql_rollback ();
              return ret;
            }

          ret = validate_send_data (method, data_name, &data);
          if (ret)
            {
              g_free (data_name);
              g_free (data);
              sql_rollback ();
              return ret;
            }

          ret = validate_smb_data (method, data_name, &data);
          if (ret)
            {
              g_free (data_name);
              g_free (data);
              sql_rollback ();
              return ret;
            }

          ret = validate_sourcefire_data (method, data_name, &data);
          if (ret)
            {
              g_free (data_name);
              g_free (data);
              sql_rollback ();
              return ret;
            }

          ret = validate_tippingpoint_data (method, data_name, &data);
          if (ret)
            {
              g_free (data_name);
              g_free (data);
              sql_rollback ();
              return ret;
            }

          ret = validate_vfire_data (method, data_name, &data);
          if (ret)
            {
              g_free (data_name);
              g_free (data);
              sql_rollback ();
              return ret;
            }

          sql ("INSERT INTO alert_method_data (alert, name, data)"
               " VALUES (%llu, '%s', '%s');",
               alert,
               data_name,
               data);
          g_free (data_name);
          g_free (data);
        }
    }

  sql_commit ();

  return 0;
}

/**
 * @brief Delete an alert.
 *
 * @param[in]  alert_id  UUID of alert.
 * @param[in]  ultimate      Whether to remove entirely, or to trashcan.
 *
 * @return 0 success, 1 fail because a task refers to the alert, 2 failed
 *         to find target, 99 permission denied, -1 error.
 */
int
delete_alert (const char *alert_id, int ultimate)
{
  alert_t alert = 0;

  sql_begin_immediate ();

  if (acl_user_may ("delete_alert") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (find_alert_with_permission (alert_id, &alert, "delete_alert"))
    {
      sql_rollback ();
      return -1;
    }

  if (alert == 0)
    {
      if (find_trash ("alert", alert_id, &alert))
        {
          sql_rollback ();
          return -1;
        }
      if (alert == 0)
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

      /* Check if it's in use by a task in the trashcan. */
      if (sql_int ("SELECT count(*) FROM task_alerts"
                   " WHERE alert = %llu"
                   " AND alert_location = " G_STRINGIFY (LOCATION_TRASH) ";",
                   alert))
        {
          sql_rollback ();
          return 1;
        }

      permissions_set_orphans ("alert", alert, LOCATION_TRASH);
      tags_remove_resource ("alert", alert, LOCATION_TRASH);

      sql ("DELETE FROM alert_condition_data_trash WHERE alert = %llu;",
           alert);
      sql ("DELETE FROM alert_event_data_trash WHERE alert = %llu;",
           alert);
      sql ("DELETE FROM alert_method_data_trash WHERE alert = %llu;",
           alert);
      sql ("DELETE FROM alerts_trash WHERE id = %llu;", alert);
      sql_commit ();
      return 0;
    }

  if (ultimate == 0)
    {
      alert_t trash_alert;

      if (sql_int ("SELECT count(*) FROM task_alerts"
                   " WHERE alert = %llu"
                   " AND alert_location = " G_STRINGIFY (LOCATION_TABLE)
                   " AND (SELECT hidden < 2 FROM tasks"
                   "      WHERE id = task_alerts.task);",
                   alert))
        {
          sql_rollback ();
          return 1;
        }

      sql ("INSERT INTO alerts_trash"
           " (uuid, owner, name, comment, event, condition, method, filter,"
           "  filter_location, active, creation_time, modification_time)"
           " SELECT uuid, owner, name, comment, event, condition, method,"
           "        filter, " G_STRINGIFY (LOCATION_TABLE) ", active,"
           "        creation_time, m_now ()"
           " FROM alerts WHERE id = %llu;",
           alert);

      trash_alert = sql_last_insert_id ();

      sql ("INSERT INTO alert_condition_data_trash"
           " (alert, name, data)"
           " SELECT %llu, name, data"
           " FROM alert_condition_data WHERE alert = %llu;",
           trash_alert,
           alert);

      sql ("INSERT INTO alert_event_data_trash"
           " (alert, name, data)"
           " SELECT %llu, name, data"
           " FROM alert_event_data WHERE alert = %llu;",
           trash_alert,
           alert);

      sql ("INSERT INTO alert_method_data_trash"
           " (alert, name, data)"
           " SELECT %llu, name, data"
           " FROM alert_method_data WHERE alert = %llu;",
           trash_alert,
           alert);

      /* Update the location of the alert in any trashcan tasks. */
      sql ("UPDATE task_alerts"
           " SET alert = %llu,"
           "     alert_location = " G_STRINGIFY (LOCATION_TRASH)
           " WHERE alert = %llu"
           " AND alert_location = " G_STRINGIFY (LOCATION_TABLE) ";",
           trash_alert,
           alert);

      permissions_set_locations ("alert", alert, trash_alert,
                                 LOCATION_TRASH);
      tags_set_locations ("alert", alert, trash_alert,
                          LOCATION_TRASH);
    }
  else if (sql_int ("SELECT count(*) FROM task_alerts"
                    " WHERE alert = %llu"
                    " AND alert_location = " G_STRINGIFY (LOCATION_TABLE) ";",
                    alert))
    {
      sql_rollback ();
      return 1;
    }
  else
    {
      permissions_set_orphans ("alert", alert, LOCATION_TABLE);
      tags_remove_resource ("alert", alert, LOCATION_TABLE);
    }

  sql ("DELETE FROM alert_condition_data WHERE alert = %llu;",
       alert);
  sql ("DELETE FROM alert_event_data WHERE alert = %llu;", alert);
  sql ("DELETE FROM alert_method_data WHERE alert = %llu;", alert);
  sql ("DELETE FROM alerts WHERE id = %llu;", alert);
  sql_commit ();
  return 0;
}

/**
 * @brief Return the UUID of an alert.
 *
 * @param[in]  alert  Alert.
 *
 * @return UUID of alert.
 */
char *
alert_uuid (alert_t alert)
{
  return sql_string ("SELECT uuid FROM alerts WHERE id = %llu;",
                     alert);
}

/**
 * @brief Return the owner of an alert.
 *
 * @param[in]  alert  Alert.
 *
 * @return Owner.
 */
user_t
alert_owner (alert_t alert)
{
  return sql_int64_0 ("SELECT owner FROM alerts WHERE id = %llu;",
                      alert);
}

/**
 * @brief Return the UUID of the owner of an alert.
 *
 * @param[in]  alert  Alert.
 *
 * @return UUID of owner.
 */
char *
alert_owner_uuid (alert_t alert)
{
  return sql_string ("SELECT uuid FROM users"
                     " WHERE id = (SELECT owner FROM alerts WHERE id = %llu);",
                     alert);
}

/**
 * @brief Return the name of the owner of an alert.
 *
 * @param[in]  alert  Alert.
 *
 * @return Newly allocated user name.
 */
char*
alert_owner_name (alert_t alert)
{
  return sql_string ("SELECT name FROM users WHERE id ="
                     " (SELECT owner FROM alerts WHERE id = %llu);",
                     alert);
}
/**
 * @brief Return the name of an alert.
 *
 * @param[in]  alert  Alert.
 *
 * @return Name of alert.
 */
char *
alert_name (alert_t alert)
{
  return sql_string ("SELECT name FROM alerts WHERE id = %llu;", alert);
}

/**
 * @brief Return the UUID of the filter of an alert.
 *
 * @param[in]  alert  Alert.
 *
 * @return UUID if there's a filter, else NULL.
 */
char *
alert_filter_id (alert_t alert)
{
  return sql_string ("SELECT"
                     " (CASE WHEN (SELECT filter IS NULL OR filter = 0"
                     "             FROM alerts WHERE id = %llu)"
                     "  THEN NULL"
                     "  ELSE (SELECT uuid FROM filters"
                     "        WHERE id = (SELECT filter FROM alerts"
                     "                    WHERE id = %llu))"
                     "  END);",
                     alert,
                     alert);
}

/**
 * @brief Return whether a alert is in use by a task.
 *
 * @param[in]  alert  Alert.
 *
 * @return 1 if in use, else 0.
 */
int
alert_in_use (alert_t alert)
{
  return !!sql_int ("SELECT count (*) FROM task_alerts WHERE alert = %llu;",
                    alert);
}

/**
 * @brief Return whether a trashcan alert is in use by a task.
 *
 * @param[in]  alert  Alert.
 *
 * @return 1 if in use, else 0.
 */
int
trash_alert_in_use (alert_t alert)
{
  return !!sql_int ("SELECT count(*) FROM task_alerts"
                    " WHERE alert = %llu"
                    " AND alert_location = " G_STRINGIFY (LOCATION_TRASH),
                    alert);
}

/**
 * @brief Return whether a alert is writable.
 *
 * @param[in]  alert  Alert.
 *
 * @return 1 if writable, else 0.
 */
int
alert_writable (alert_t alert)
{
    return 1;
}

/**
 * @brief Return whether a trashcan alert is writable.
 *
 * @param[in]  alert  Alert.
 *
 * @return 1 if writable, else 0.
 */
int
trash_alert_writable (alert_t alert)
{
    return 1;
}

/**
 * @brief Return the condition associated with an alert.
 *
 * @param[in]  alert  Alert.
 *
 * @return Condition.
 */
alert_condition_t
alert_condition (alert_t alert)
{
  return sql_int ("SELECT condition FROM alerts WHERE id = %llu;",
                  alert);
}

/**
 * @brief Return the event associated with an alert.
 *
 * @param[in]  alert  Alert.
 *
 * @return Event.
 */
event_t
alert_event (alert_t alert)
{
  return sql_int ("SELECT event FROM alerts WHERE id = %llu;",
                  alert);
}

/**
 * @brief Return the method associated with an alert.
 *
 * @param[in]  alert  Alert.
 *
 * @return Method.
 */
alert_method_t
alert_method (alert_t alert)
{
  return sql_int ("SELECT method FROM alerts WHERE id = %llu;",
                  alert);
}

/**
 * @brief Return data associated with an alert.
 *
 * @param[in]  alert  Alert.
 * @param[in]  type       Type of data: "condition", "event" or "method".
 * @param[in]  name       Name of the data.
 *
 * @return Freshly allocated data if it exists, else NULL.
 */
char *
alert_data (alert_t alert, const char *type, const char *name)
{
  gchar *quoted_name;
  char *data;

  assert (strcmp (type, "condition") == 0
          || strcmp (type, "event") == 0
          || strcmp (type, "method") == 0);

  quoted_name = sql_quote (name);
  data = sql_string ("SELECT data FROM alert_%s_data"
                     " WHERE alert = %llu AND name = '%s';",
                     type,
                     alert,
                     quoted_name);
  g_free (quoted_name);
  return data;
}

/**
 * @brief Check whether an alert applies to a task.
 *
 * @param[in]  alert  Alert.
 * @param[in]  task   Task.
 *
 * @return 1 if applies, else 0.
 */
int
alert_applies_to_task (alert_t alert, task_t task)
{
  return sql_int ("SELECT EXISTS (SELECT * FROM task_alerts"
                  "               WHERE task = %llu"
                  "               AND alert = %llu);",
                  task,
                  alert);
}

/**
 * @brief Count the number of alerts.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of alerts filtered set.
 */
int
alert_count (const get_data_t *get)
{
  static const char *filter_columns[] = ALERT_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = ALERT_ITERATOR_COLUMNS;
  static column_t trash_columns[] = ALERT_ITERATOR_TRASH_COLUMNS;
  return count ("alert", get, columns, trash_columns, filter_columns, 0, 0, 0,
                  TRUE);
}

/**
 * @brief Initialise an alert iterator, including observed alerts.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 *
 * @return 0 success, 1 failed to find alert, 2 failed to find filter (filt_id),
 *         -1 error.
 */
int
init_alert_iterator (iterator_t* iterator, get_data_t *get)
{
  static const char *filter_columns[] = ALERT_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = ALERT_ITERATOR_COLUMNS;
  static column_t trash_columns[] = ALERT_ITERATOR_TRASH_COLUMNS;

  return init_get_iterator (iterator,
                            "alert",
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
 * @brief Return the event from an alert iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Event of the alert or NULL if iteration is complete.
 */
int
alert_iterator_event (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT);
  return ret;
}

/**
 * @brief Return the condition from an alert iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Condition of the alert or NULL if iteration is complete.
 */
int
alert_iterator_condition (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 1);
  return ret;
}

/**
 * @brief Return the method from an alert iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Method of the alert or NULL if iteration is complete.
 */
int
alert_iterator_method (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 2);
  return ret;
}

/**
 * @brief Return the filter from an alert iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Filter of the alert or NULL if iteration is complete.
 */
static filter_t
alert_iterator_filter (iterator_t* iterator)
{
  if (iterator->done) return -1;
  return (filter_t) iterator_int64 (iterator, GET_ITERATOR_COLUMN_COUNT + 3);
}

/**
 * @brief Return the filter UUID from an alert iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return UUID of filter of the alert or NULL if iteration is complete.
 */
char *
alert_iterator_filter_uuid (iterator_t* iterator)
{
  filter_t filter;

  if (iterator->done) return NULL;

  filter = alert_iterator_filter (iterator);
  if (filter)
    {
      if (iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 4)
          == LOCATION_TABLE)
        return filter_uuid (filter);
      return trash_filter_uuid (filter);
    }
  return NULL;
}

/**
 * @brief Return the filter name from an alert iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name of filter of the alert or NULL if iteration is complete.
 */
char *
alert_iterator_filter_name (iterator_t* iterator)
{
  filter_t filter;

  if (iterator->done) return NULL;

  filter = alert_iterator_filter (iterator);
  if (filter)
    {
      if (iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 4)
          == LOCATION_TABLE)
        return filter_name (filter);
      return trash_filter_name (filter);
    }
  return NULL;
}

/**
 * @brief Return the location of an alert iterator filter.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 0 in table, 1 in trash.
 */
int
alert_iterator_filter_trash (iterator_t* iterator)
{
  if (iterator->done) return 0;
  if (alert_iterator_filter (iterator)
      && (iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 4)
          == LOCATION_TRASH))
    return 1;
  return 0;
}

/**
 * @brief Return the filter readable state from an alert iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Whether filter is readable.
 */
int
alert_iterator_filter_readable (iterator_t* iterator)
{
  filter_t filter;

  if (iterator->done) return 0;

  filter = alert_iterator_filter (iterator);
  if (filter)
    {
      char *uuid;
      uuid = alert_iterator_filter_uuid (iterator);
      if (uuid)
        {
          int readable;
          readable = acl_user_has_access_uuid
                      ("filter", uuid, "get_filters",
                       iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 4)
                       == LOCATION_TRASH);
          free (uuid);
          return readable;
        }
    }
  return 0;
}

/**
 * @brief Return the active state from an alert.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Method of the alert or NULL if iteration is complete.
 */
int
alert_iterator_active (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 5);
  return ret;
}

/**
 * @brief Initialise an alert data iterator.
 *
 * @param[in]  iterator   Iterator.
 * @param[in]  alert  Alert.
 * @param[in]  trash      Whether to iterate over trashcan alert data.
 * @param[in]  table      Type of data: "condition", "event" or "method",
 *                        corresponds to substring of the table to select
 *                        from.
 */
void
init_alert_data_iterator (iterator_t *iterator, alert_t alert,
                          int trash, const char *table)
{
  init_iterator (iterator,
                 "SELECT name, data FROM alert_%s_data%s"
                 " WHERE alert = %llu;",
                 table,
                 trash ? "_trash" : "",
                 alert);
}

/**
 * @brief Return the name from an alert data iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name of the alert data or NULL if iteration is complete.
 */
const char*
alert_data_iterator_name (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = iterator_string (iterator, 0);
  return ret;
}

/**
 * @brief Return the data from an alert data iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 *
 * @return Data of the alert data or NULL if iteration is complete.
 */
const char*
alert_data_iterator_data (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = iterator_string (iterator, 1);
  return ret;
}

/**
 * @brief Initialise a task alert iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  task      Task.
 */
void
init_task_alert_iterator (iterator_t* iterator, task_t task)
{
  gchar *owned_clause, *with_clause;
  get_data_t get;
  array_t *permissions;

  assert (task);

  get.trash = 0;
  permissions = make_array ();
  array_add (permissions, g_strdup ("get_alerts"));
  owned_clause = acl_where_owned ("alert", &get, 0, "any", 0, permissions, 0,
                                  &with_clause);
  array_free (permissions);

  init_iterator (iterator,
                 "%s"
                 " SELECT alerts.id, alerts.uuid, alerts.name"
                 " FROM alerts, task_alerts"
                 " WHERE task_alerts.task = %llu"
                 " AND task_alerts.alert = alerts.id"
                 " AND %s;",
                 with_clause ? with_clause : "",
                 task,
                 owned_clause);

  g_free (with_clause);
  g_free (owned_clause);
}

/**
 * @brief Get the UUID from a task alert iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return UUID, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (task_alert_iterator_uuid, 1);

/**
 * @brief Get the name from a task alert iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (task_alert_iterator_name, 2);

/**
 * @brief Initialise an alert task iterator.
 *
 * Iterate over all tasks that use the alert.
 *
 * @param[in]  iterator   Iterator.
 * @param[in]  alert  Alert.
 * @param[in]  ascending  Whether to sort ascending or descending.
 */
void
init_alert_task_iterator (iterator_t* iterator, alert_t alert,
                              int ascending)
{
  gchar *available, *with_clause;
  get_data_t get;
  array_t *permissions;

  assert (alert);

  get.trash = 0;
  permissions = make_array ();
  array_add (permissions, g_strdup ("get_tasks"));
  available = acl_where_owned ("task", &get, 1, "any", 0, permissions, 0,
                               &with_clause);
  array_free (permissions);

  init_iterator (iterator,
                 "%s"
                 " SELECT tasks.name, tasks.uuid, %s FROM tasks, task_alerts"
                 " WHERE tasks.id = task_alerts.task"
                 " AND task_alerts.alert = %llu"
                 " AND hidden = 0"
                 " ORDER BY tasks.name %s;",
                 with_clause ? with_clause : "",
                 available,
                 alert,
                 ascending ? "ASC" : "DESC");

  g_free (with_clause);
  g_free (available);
}

/**
 * @brief Return the name from an alert task iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name of the task or NULL if iteration is complete.
 */
const char*
alert_task_iterator_name (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = iterator_string (iterator, 0);
  return ret;
}

/**
 * @brief Return the uuid from an alert task iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return UUID of the task or NULL if iteration is complete.
 */
const char*
alert_task_iterator_uuid (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = iterator_string (iterator, 1);
  return ret;
}

/**
 * @brief Get the read permission status from a GET iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 1 if may read, else 0.
 */
int
alert_task_iterator_readable (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return iterator_int (iterator, 2);
}

/**
 * @brief Initialise a vFire alert iterator for method call data.
 *
 * @param[in]  iterator   Iterator.
 * @param[in]  alert  Alert.
 */
void
init_alert_vfire_call_iterator (iterator_t *iterator, alert_t alert)
{
  init_iterator (iterator,
                 "SELECT SUBSTR(name, %i), data"
                 " FROM alert_method_data"
                 " WHERE alert = %llu"
                 " AND name %s 'vfire_call_%%';",
                 strlen ("vfire_call_") + 1, alert, sql_ilike_op ());
}

/**
 * @brief Return the name from an alert vFire call iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name, or NULL if iteration is complete.
 */
const char*
alert_vfire_call_iterator_name (iterator_t *iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = iterator_string (iterator, 0);
  return ret;
}

/**
 * @brief Return the value from an alert vFire call iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value, or NULL if iteration is complete.
 */
const char*
alert_vfire_call_iterator_value (iterator_t *iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = iterator_string (iterator, 1);
  return ret;
}

/**
 * @brief Check for new SCAP SecInfo after an update.
 */
static void
check_for_new_scap ()
{
  if (manage_scap_loaded ())
    {
      if (sql_int ("SELECT EXISTS"
                   " (SELECT * FROM scap.cves"
                   "  WHERE creation_time"
                   "        > coalesce (CAST ((SELECT value FROM meta"
                   "                           WHERE name"
                   "                                 = 'scap_check_time')"
                   "                          AS INTEGER),"
                   "                    0));"))
        event (EVENT_NEW_SECINFO, "cve", 0, 0);

      if (sql_int ("SELECT EXISTS"
                   " (SELECT * FROM scap.cpes"
                   "  WHERE creation_time"
                   "        > coalesce (CAST ((SELECT value FROM meta"
                   "                           WHERE name"
                   "                                 = 'scap_check_time')"
                   "                          AS INTEGER),"
                   "                    0));"))
        event (EVENT_NEW_SECINFO, "cpe", 0, 0);
    }
}

/**
 * @brief Check for new CERT SecInfo after an update.
 */
static void
check_for_new_cert ()
{
  if (manage_cert_loaded ())
    {
      if (sql_int ("SELECT EXISTS"
                   " (SELECT * FROM cert.cert_bund_advs"
                   "  WHERE creation_time"
                   "        > coalesce (CAST ((SELECT value FROM meta"
                   "                           WHERE name"
                   "                                 = 'cert_check_time')"
                   "                          AS INTEGER),"
                   "                    0));"))
        event (EVENT_NEW_SECINFO, "cert_bund_adv", 0, 0);

      if (sql_int ("SELECT EXISTS"
                   " (SELECT * FROM cert.dfn_cert_advs"
                   "  WHERE creation_time"
                   "        > coalesce (CAST ((SELECT value FROM meta"
                   "                           WHERE name"
                   "                                 = 'cert_check_time')"
                   "                          AS INTEGER),"
                   "                    0));"))
        event (EVENT_NEW_SECINFO, "dfn_cert_adv", 0, 0);
    }
}

/**
 * @brief Check for updated SCAP SecInfo after an update.
 */
static void
check_for_updated_scap ()
{
  if (manage_scap_loaded ())
    {
      if (sql_int ("SELECT EXISTS"
                   " (SELECT * FROM scap.cves"
                   "  WHERE modification_time"
                   "        > coalesce (CAST ((SELECT value FROM meta"
                   "                           WHERE name"
                   "                                 = 'scap_check_time')"
                   "                          AS INTEGER),"
                   "                    0)"
                   "  AND creation_time"
                   "      <= coalesce (CAST ((SELECT value FROM meta"
                   "                          WHERE name"
                   "                                = 'scap_check_time')"
                   "                         AS INTEGER),"
                   "                   0));"))
        event (EVENT_UPDATED_SECINFO, "cve", 0, 0);

      if (sql_int ("SELECT EXISTS"
                   " (SELECT * FROM scap.cpes"
                   "  WHERE modification_time"
                   "        > coalesce (CAST ((SELECT value FROM meta"
                   "                           WHERE name"
                   "                                 = 'scap_check_time')"
                   "                          AS INTEGER),"
                   "                    0)"
                   "  AND creation_time"
                   "      <= coalesce (CAST ((SELECT value FROM meta"
                   "                          WHERE name"
                   "                                = 'scap_check_time')"
                   "                         AS INTEGER),"
                   "                   0));"))
        event (EVENT_UPDATED_SECINFO, "cpe", 0, 0);
    }
}

/**
 * @brief Check for updated CERT SecInfo after an update.
 */
static void
check_for_updated_cert ()
{
  if (manage_cert_loaded ())
    {
      if (sql_int ("SELECT EXISTS"
                   " (SELECT * FROM cert.cert_bund_advs"
                   "  WHERE modification_time"
                   "        > coalesce (CAST ((SELECT value FROM meta"
                   "                           WHERE name"
                   "                                 = 'cert_check_time')"
                   "                          AS INTEGER),"
                   "                    0)"
                   "  AND creation_time"
                   "      <= coalesce (CAST ((SELECT value FROM meta"
                   "                          WHERE name"
                   "                                = 'cert_check_time')"
                   "                         AS INTEGER),"
                   "                   0));"))
        event (EVENT_UPDATED_SECINFO, "cert_bund_adv", 0, 0);

      if (sql_int ("SELECT EXISTS"
                   " (SELECT * FROM cert.dfn_cert_advs"
                   "  WHERE modification_time"
                   "        > coalesce (CAST ((SELECT value FROM meta"
                   "                           WHERE name"
                   "                                 = 'cert_check_time')"
                   "                          AS INTEGER),"
                   "                    0)"
                   "  AND creation_time"
                   "      <= coalesce (CAST ((SELECT value FROM meta"
                   "                          WHERE name"
                   "                                = 'cert_check_time')"
                   "                         AS INTEGER),"
                   "                   0));"))
        event (EVENT_UPDATED_SECINFO, "dfn_cert_adv", 0, 0);
    }
}

/**
 * @brief Check if any SecInfo alerts are due.
 */
void
check_alerts ()
{
  if (manage_scap_loaded ())
    {
      int max_time;

      max_time
       = sql_int ("SELECT %s"
                  "        ((SELECT max (modification_time) FROM scap.cves),"
                  "         (SELECT max (modification_time) FROM scap.cpes),"
                  "         (SELECT max (creation_time) FROM scap.cves),"
                  "         (SELECT max (creation_time) FROM scap.cpes));",
                  sql_greatest ());

      if (sql_int ("SELECT NOT EXISTS (SELECT * FROM meta"
                   "                   WHERE name = 'scap_check_time')"))
        sql ("INSERT INTO meta (name, value)"
             " VALUES ('scap_check_time', %i);",
             max_time);
      else if (sql_int ("SELECT value = '0' FROM meta"
                        " WHERE name = 'scap_check_time';"))
        sql ("UPDATE meta SET value = %i"
             " WHERE name = 'scap_check_time';",
             max_time);
      else
        {
          check_for_new_scap ();
          check_for_updated_scap ();
          sql ("UPDATE meta SET value = %i"
               " WHERE name = 'scap_check_time';",
               max_time);
        }
    }

  if (manage_cert_loaded ())
    {
      int max_time;

      max_time
       = sql_int ("SELECT"
                  " %s"
                  "  ((SELECT max (modification_time) FROM cert.cert_bund_advs),"
                  "   (SELECT max (modification_time) FROM cert.dfn_cert_advs),"
                  "   (SELECT max (creation_time) FROM cert.cert_bund_advs),"
                  "   (SELECT max (creation_time) FROM cert.dfn_cert_advs));",
                  sql_greatest ());

      if (sql_int ("SELECT NOT EXISTS (SELECT * FROM meta"
                   "                   WHERE name = 'cert_check_time')"))
        sql ("INSERT INTO meta (name, value)"
             " VALUES ('cert_check_time', %i);",
             max_time);
      else if (sql_int ("SELECT value = '0' FROM meta"
                        " WHERE name = 'cert_check_time';"))
        sql ("UPDATE meta SET value = %i"
             " WHERE name = 'cert_check_time';",
             max_time);
      else
        {
          check_for_new_cert ();
          check_for_updated_cert ();
          sql ("UPDATE meta SET value = %i"
               " WHERE name = 'cert_check_time';",
               max_time);
        }
    }
}

/**
 * @brief Get the SMB file path format to use for an alert.
 *
 * @param[in]  alert  Alert.
 * @param[in]  task   Task.
 *
 * @return Freshly allocated path if there's a tag, else NULL.
 */
gchar *
alert_smb_file_path (alert_t alert, task_t task)
{
  gchar *file_path_format;

  file_path_format = sql_string ("SELECT value FROM tags"
                                 " WHERE name = 'smb-alert:file_path'"
                                 "   AND EXISTS"
                                 "         (SELECT * FROM tag_resources"
                                 "           WHERE resource_type = 'task'"
                                 "             AND resource = %llu"
                                 "             AND tag = tags.id)"
                                 " ORDER BY modification_time LIMIT 1;",
                                 task);

  if (file_path_format)
    return file_path_format;

  return alert_data (alert, "method", "smb_file_path");
}
