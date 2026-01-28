/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM manage layer: OCI Image Targets.
 *
 * General management of OCI Image Targets.
 */

#if ENABLE_CONTAINER_SCANNING

#include "manage_oci_image_targets.h"
#include "manage_sql.h"

#include <gvm/base/hosts.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Find an OCI image target for a specific permission, given a UUID.
 *
 * @param[in]   uuid               UUID of target.
 * @param[out]  oci_image_target   OCI Image Target return,
 *                                 0 if successfully failed to find target.
 * @param[in]   permission         Permission.
 *
 * @return FALSE on success (including if failed to find target), TRUE on error.
 */
gboolean
find_oci_image_target_with_permission (const char* uuid,
                                       oci_image_target_t* oci_image_target,
                                       const char *permission)
{
  return find_resource_with_permission ("oci_image_target", uuid,
                                        oci_image_target, permission, 0);
}

/**
 * @brief Return whether an OCI image target is writable.
 *
 * @param[in]  oci_image_target  OCI image target.
 *
 * @return 1 if writable, else 0.
 */
int
oci_image_target_writable (oci_image_target_t oci_image_target)
{
  return 1;
}

/**
 * @brief Return whether a trashcan oci image target is writable.
 *
 * @param[in]  oci_image_target  OCI image target.
 *
 * @return 1 if writable, else 0.
 */
int
trash_oci_image_target_writable (oci_image_target_t oci_image_target)
{
  return trash_oci_image_target_in_use (oci_image_target) == 0;
}

/**
 * @brief Validate an OCI URL.
 *
 * @param[in]  oci_url  The OCI URL to validate.
 *
 * @return 0 if valid, -1 otherwise.
 */
int
valid_oci_url (const gchar *oci_url)
{
  gchar *host, *port;

  if(!oci_url || !*oci_url)
    {
      g_warning ("%s: OCI URL is NULL or empty", __func__);
      return -1;
    }

  if (!g_str_has_prefix (oci_url, "oci://"))
    {
      g_warning ("%s: Invalid OCI URL prefix", __func__);
      return -1;
    }

  const gchar *rest = oci_url + 6;

  if (!rest || g_strcmp0 (rest, "") == 0)
    {
      g_warning ("%s: OCI URL is empty after prefix", __func__);
      return -1;
    }

  gchar **parts = g_strsplit (rest, "/", -1);
  int parts_len = g_strv_length (parts);

  if (g_str_has_prefix (parts[0], "[")) // ipv6 in brackets
    {
      gchar **ipv6_port_parts = g_strsplit (parts[0], "]", -1);
      host = g_strndup (ipv6_port_parts[0] + 1,
                        strlen (ipv6_port_parts[0]) - 1); // skip the '['
      port = NULL;
      if (g_strv_length (ipv6_port_parts) > 1 && ipv6_port_parts[1]
          && strlen (ipv6_port_parts[1]) > 1)
        port = g_strdup (ipv6_port_parts[1] + 1); // skip the ':'
      g_strfreev (ipv6_port_parts);
    }
  else
    {
      gchar **host_port_parts = g_strsplit (parts[0], ":", -1);
      int host_port_len = g_strv_length (host_port_parts);

      if (host_port_len > 2)  // ipv6 adress without a port
        {
          host = g_strjoinv (":", host_port_parts);
          port = NULL;
        }
      else if (host_port_len > 1)
        {
          host = g_strdup (host_port_parts[0]);
          port = g_strdup (host_port_parts[1]);
        }
      else
        {
          host = g_strdup (host_port_parts[0]);
          port = NULL;
        }
      g_strfreev (host_port_parts);
    }

  if (!host || !*host)
    {
      g_warning ("%s: OCI URL host is empty", __func__);
      g_strfreev (parts);
      g_free (host);
      g_free (port);
      return -1;
    }

  int type = gvm_get_host_type (host);
  if ((type != HOST_TYPE_IPV4) &&
      (type != HOST_TYPE_IPV6) &&
      (type != HOST_TYPE_NAME))
    {
      g_warning ("%s: OCI URL host is not valid", __func__);
      g_strfreev (parts);
      g_free (host);
      g_free (port);
      return -1;
    }

  g_free (host);

  if (port && *port)
    {
      int port_num = atoi (port);
      if (port_num <= 0 || port_num > 65535)
        {
          g_warning ("%s: OCI URL port is not valid", __func__);
          g_strfreev (parts);
          g_free (port);
          return -1;
        }
    }

  g_free (port);

  const gchar *url_component_regex = "^[a-zA-Z0-9_\\-.]+$";
  const gchar *url_component_with_tag_regex = "^[a-zA-Z0-9_\\-.:@]+$";

  for (int i = 1; i < parts_len; i++)
    {
      if (!parts[i] || !*parts[i])
        {
          g_warning ("%s: OCI URL contains empty path segment", __func__);
          g_strfreev (parts);
          return -1;
        }

      const gchar *pattern = ( i == parts_len - 1)
                             ? url_component_with_tag_regex
                             : url_component_regex;

      if (!g_regex_match_simple (pattern, parts[i], 0, 0))
        {
          g_warning ("%s: OCI URL path segment '%s' is not valid",
                     __func__, parts[i]);
          g_strfreev (parts);
          return -1;
        }
    }

  g_strfreev (parts);
  return 0;
}

/**
 * @brief Clean an OCI images string.
 *
 * @param[in]  given_images  String describing images.
 *
 * @return Freshly allocated new images string. NULL if error.
 *         Caller must free it.
 */
gchar*
clean_images (const char *given_images)
{
  gchar **split, **point, *images, *start;

  if (!given_images || !*given_images)
    return NULL;

  /* Treat newlines like commas. */
  images = start = g_strdup (given_images);
  while (*images)
    {
      if (*images == '\n') *images = ',';
      images++;
    }

  split = g_strsplit (start, ",", -1);
  g_free (start);
  point = split;

  GHashTable *seen = g_hash_table_new_full (g_str_hash,
                                            g_str_equal,
                                            g_free, NULL);
  GPtrArray *clean_array = make_array ();

  while (*point)
    {
      g_strstrip (*point);
      if (**point != '\0')
        {
          gchar *key = g_strdup (*point);
          if (!g_hash_table_contains (seen, key))
            {
              g_hash_table_add (seen, key);
              array_add (clean_array, g_strdup(*point));
            }
          else
            {
              g_free (key);
            }
        }
      point += 1;
    }
  array_terminate (clean_array);

  gchar *clean = (clean_array->len == 0)
    ? g_strdup ("")
    : g_strjoinv (",", (gchar **) clean_array->pdata);

  g_hash_table_destroy (seen);
  array_free (clean_array);
  g_strfreev (split);

  return clean;
}

/**
 * @brief Validate an OCI image references string.
 *
 * @param[in] image_refs_input  A comma-separated list of OCI image references.
 * @param[out] error_message    error message if any.
 *
 * @return TRUE if all references are valid URLs, FALSE otherwise.
 */
int
validate_oci_image_references (const char *image_refs_input,
                               gchar **error_message)
{
  if (!image_refs_input)
    return FALSE;

  gchar *input_copy = g_strdup (image_refs_input);

  gchar **parts = g_strsplit (input_copy, ",", 0);
  g_free (input_copy);

  for (gchar **ptr = parts; *ptr != NULL; ptr++)
    {
      const gchar *entry = *ptr;

      // reject empty strings
      if (!*entry)
        {
          g_strfreev (parts);
          if (error_message)
            *error_message = g_strdup ("OCI image URL cannot be empty");
          return FALSE;
        }


      // validate OCI URL format
      if (valid_oci_url (entry) == -1)
        {
          g_strfreev (parts);
          if (error_message)
            *error_message =
              g_strdup_printf ("Invalid OCI image URL");
          return FALSE;
        }
    }

  g_strfreev (parts);
  return TRUE;
}

#endif //ENABLE_CONTAINER_SCANNING