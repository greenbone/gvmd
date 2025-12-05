/* Copyright (C) 2020-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: License information.
 *
 * Non-SQL license information code for the GVM management layer.
 */

#include "manage_acl.h"
#include "manage_license.h"
#include "utils.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/* Actions */

/**
 * @brief Update the license file by replacing it with the given one.
 *
 * @param[in]  new_license          The content of the new license.
 * @param[out] error_msg            The error message of the license
 *                                  update if any
 *
 * @return 0 success, 1 service unavailable, 2 error sending command,
 *         3 error receiving response, 4 no new_license data,
 *         5 error updating license, 99 permission denied, -1 internal error.
 */
int
manage_update_license_file (const char *new_license, char **error_msg)
{
  *error_msg = NULL;

  if (new_license == NULL)
    return 4;
  if (! acl_user_may ("modify_license"))
    return 99;

#ifdef HAS_LIBTHEIA
  int ret;
  const char *broker_address;
  theia_client_t *client;
  theia_modify_license_cmd_t *modify_license_cmd;
  theia_modified_license_info_t *modified_license_info;
  theia_failure_modify_license_info_t *failure_modify_license_info;

  broker_address = get_broker_address ();
  if (broker_address == NULL)
    return 1;

  client = theia_client_new_mqtt (&client);
  if (client == NULL)
    {
      g_warning ("%s: Failed to create MQTT client", __func__);
      return -1;
    }

  ret = theia_client_connect (client, broker_address);
  if (ret)
    {
      g_warning ("%s: Failed to connect to MQTT broker (%s)",
                 __func__, broker_address);
      return 1;
    }
  g_debug ("%s: Connected to %s\n", __func__, broker_address);

  ret = theia_new_modify_license_cmd ((char *) new_license, &modify_license_cmd);

  if (ret)
    {
      g_warning ("%s: Error preparing modify.license command", __func__);
      theia_client_disconnect (client);
      free (client);
      return -1;
    }

  ret = theia_client_send_cmd (client, THEIA_LICENSE_CMD_TOPIC,
                               (theia_cmd_t *) modify_license_cmd);
  if (ret)
    {
      fprintf (stderr, "Error publishing modify.license message.");
      theia_client_disconnect (client);
      theia_modify_license_cmd_free (modify_license_cmd);
      free (client);
      return 2;
    }
  g_debug ("%s: Sent modify.license command"
           " (message_id: %s, group_id: %s)\n",
           __func__,
           modify_license_cmd->message->id,
           modify_license_cmd->message->group_id);

  ret = theia_client_get_info_response (client, THEIA_LICENSE_INFO_TOPIC,
                                        "modified.license",
                                        "failure.modify.license",
                                        modify_license_cmd->message->group_id,
                                        (theia_info_t **) &modified_license_info,
                                        (theia_info_t **) &failure_modify_license_info);
  if (ret)
    {
      g_debug ("%s: Failed to get modified.license response", __func__);
      theia_client_disconnect (client);
      theia_modify_license_cmd_free (modify_license_cmd);
      free (client);
      return 3;
    }
  g_debug ("%s: Received modified.license response", __func__);

  if (failure_modify_license_info)
    {
      g_message ("%s: Upload of new license file failed. Error: %s.\n",
                 __func__, failure_modify_license_info->error);
      *error_msg = g_strdup (failure_modify_license_info->error);
      theia_client_disconnect (client);
      theia_modified_license_info_free (modified_license_info);
      theia_failure_modify_license_info_free (failure_modify_license_info);
      theia_modify_license_cmd_free (modify_license_cmd);
      free (client);
      return 5;
    }
  g_message ("%s: Uploaded new license file (%lu bytes)",
             __func__, strlen (new_license));

  theia_client_disconnect (client);
  theia_modified_license_info_free (modified_license_info);
  theia_failure_modify_license_info_free (failure_modify_license_info);
  theia_modify_license_cmd_free (modify_license_cmd);
  free (client);

#else // HAS_LIBTHEIA
  return 1;
#endif // HAS_LIBTHEIA

  return 0;
}

/**
 * @brief Get the current license information.
 *
 * @param[out] status       The validation status (e.g. "valid", "expired").
 * @param[out] license_data The content of the license organized in a struct.
 *
 * @return 0 success, 1 service unavailable, 2 error sending command,
 *         3 error receiving response, 99 permission denied, -1 internal error.
 */
int
manage_get_license (gchar **status,
                    theia_license_t **license_data)
{
  if (status)
    *status = NULL;
  if (license_data)
    *license_data = NULL;

  if (! acl_user_may ("get_license"))
    return 99;

#ifdef HAS_LIBTHEIA
  int ret;
  const char *broker_address;
  theia_client_t *client;
  theia_get_license_cmd_t *get_license_cmd;
  theia_got_license_info_t *got_license_info;

  broker_address = get_broker_address ();
  if (broker_address == NULL)
    return 1;

  client = theia_client_new_mqtt (&client);
  if (client == NULL)
    {
      g_warning ("%s: Failed to create MQTT client", __func__);
      return -1;
    }

  ret = theia_client_connect (client, broker_address);
  if (ret)
    {
      g_warning ("%s: Failed to connect to MQTT broker (%s)",
                 __func__, broker_address);
      return 1;
    }
  g_debug ("%s: Connected to %s\n", __func__, broker_address);

  ret = theia_new_get_license_cmd (&get_license_cmd);
  if (ret)
    {
      g_warning ("%s: Error preparing get.license command", __func__);
      theia_client_disconnect (client);
      free (client);
      return -1;
    }

  ret = theia_client_send_cmd (client, THEIA_LICENSE_CMD_TOPIC,
                               (theia_cmd_t *) get_license_cmd);
  if (ret)
    {
      fprintf (stderr, "Error publishing get.license message.");
      theia_client_disconnect (client);
      theia_get_license_cmd_free (get_license_cmd);
      free (client);
      return 2;
    }
  g_debug ("%s: Sent get.license command"
           " (message_id: %s, group_id: %s)\n",
           __func__,
           get_license_cmd->message->id,
           get_license_cmd->message->group_id);

  ret = theia_client_get_info_response (client, THEIA_LICENSE_INFO_TOPIC,
                                        "got.license", NULL,
                                        get_license_cmd->message->group_id,
                                        (theia_info_t **) &got_license_info,
                                        NULL);
  if (ret)
    {
      g_debug ("%s: Failed to get got.license response", __func__);
      theia_client_disconnect (client);
      theia_get_license_cmd_free (get_license_cmd);
      free (client);
      return 3;
    }
  g_debug ("%s: Received got.license response", __func__);

  theia_client_disconnect (client);

  if (status)
    {
      *status = got_license_info->status;
      got_license_info->status = NULL;
    }

  if (license_data)
    {
      *license_data = got_license_info->license;
      got_license_info->license = NULL;
    }

  theia_got_license_info_free (got_license_info);

#else // HAS_LIBTHEIA
  if (status)
    *status = NULL;
  if (license_data)
    *license_data = NULL;
  return 1;
#endif // HAS_LIBTHEIA

  return 0;
}
