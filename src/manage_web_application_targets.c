/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM manage layer: Web Application Targets.
 *
 * General management of Web Application Targets.
 */

#if ENABLE_WEB_APPLICATION_SCANNING

#include "manage_web_application_targets.h"
#include "manage_sql.h"
#include "manage_sql_resources.h"

#include <glib.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Allocate and initialize a new web application target data structure.
 *
 * @return Newly allocated web application target data structure.
 *         Caller must free it.
 */
web_application_target_data_t
web_application_target_data_new ()
{
  return (web_application_target_data_t) g_malloc0 (
    sizeof (struct web_application_target_data));
}

/**
 * @brief Free a web application target data structure.
 *
 * @param[in]  data  Web application target data to free.
 */
void
web_application_target_data_free (web_application_target_data_t data)
{
  if (!data)
    return;

  g_free (data->uuid);
  g_free (data->name);
  g_free (data->comment);
  g_free (data->urls);
  g_free (data->exclude_urls);
  g_free (data->credential_uuid);
  g_free (data);
}

/**
 * @brief Find a web application target for a specific permission, given a UUID.
 *
 * @param[in]   uuid                    UUID of target.
 * @param[out]  web_application_target  Web Application Target return,
 *                                      0 if successfully failed to find target.
 * @param[in]   permission              Permission.
 *
 * @return FALSE on success, TRUE on error.
 */
gboolean
find_web_application_target_with_permission
(const char *uuid,
 web_application_target_t *web_application_target,
 const char *permission)
{
  return find_resource_with_permission ("web_application_target", uuid,
                                        web_application_target,
                                        permission, 0);
}

/**
 * @brief Return whether a web application target is writable.
 *
 * @param[in]  web_application_target  Web application target.
 *
 * @return 1 if writable, else 0.
 */
int
web_application_target_writable
(web_application_target_t web_application_target)
{
  (void) web_application_target;
  return 1;
}

/**
 * @brief Return whether a trashcan web application target is writable.
 *
 * @param[in]  web_application_target  Web application target.
 *
 * @return 1 if writable, else 0.
 */
int
trash_web_application_target_writable
(web_application_target_t web_application_target)
{
  return trash_web_application_target_in_use (web_application_target) == 0;
}

/**
 * @brief Validate a web application URL.
 *
 * @param[in]  url  The URL to validate.
 *
 * @return 0 if valid, -1 otherwise.
 */
int
valid_web_application_url (const gchar *url)
{
  if (!url || !*url)
    {
      g_warning ("%s: URL is NULL or empty", __func__);
      return -1;
    }

  if (!g_str_has_prefix (url, "http://")
      && !g_str_has_prefix (url, "https://"))
    {
      g_warning ("%s: Invalid URL scheme", __func__);
      return -1;
    }

  GUri *uri = g_uri_parse (url, G_URI_FLAGS_NONE, NULL);
  if (!uri)
    {
      g_warning ("%s: Failed to parse URL", __func__);
      return -1;
    }

  const gchar *scheme = g_uri_get_scheme (uri);
  const gchar *host = g_uri_get_host (uri);
  gint port = g_uri_get_port (uri);

  if (!scheme || !host || !*host)
    {
      g_warning ("%s: URL scheme or host is missing", __func__);
      g_uri_unref (uri);
      return -1;
    }

  if (g_strcmp0 (scheme, "http") && g_strcmp0 (scheme, "https"))
    {
      g_warning ("%s: URL scheme must be http or https", __func__);
      g_uri_unref (uri);
      return -1;
    }

  if (port > 65535)
    {
      g_warning ("%s: URL port is not valid", __func__);
      g_uri_unref (uri);
      return -1;
    }

  g_uri_unref (uri);
  return 0;
}

/**
 * @brief Clean a URLs string.
 *
 * @param[in]  given_urls  String describing URLs.
 *
 * @return Freshly allocated new URLs string. NULL if error.
 *         Caller must free it.
 */
gchar *
clean_urls (const char *given_urls)
{
  gchar **split, **point, *urls, *start;

  if (!given_urls || !*given_urls)
    return NULL;

  /* Treat newlines like commas. */
  urls = start = g_strdup (given_urls);
  while (*urls)
    {
      if (*urls == '\n')
        *urls = ',';
      urls++;
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
              array_add (clean_array, g_strdup (*point));
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
 * @brief Validate a web application URLs string.
 *
 * @param[in]   urls_input     A comma-separated list of URLs.
 * @param[out]  error_message  Error message if any.
 *
 * @return TRUE if all URLs are valid, FALSE otherwise.
 */
int
validate_web_application_urls (const char *urls_input,
                               gchar **error_message)
{
  if (!urls_input)
    return FALSE;

  gchar *input_copy = g_strdup (urls_input);
  gchar **parts = g_strsplit (input_copy, ",", 0);
  g_free (input_copy);

  for (gchar **ptr = parts; *ptr != NULL; ptr++)
    {
      const gchar *entry = *ptr;

      if (!*entry)
        {
          g_strfreev (parts);
          if (error_message)
            *error_message = g_strdup ("URL cannot be empty");
          return FALSE;
        }

      if (valid_web_application_url (entry) == -1)
        {
          g_strfreev (parts);
          if (error_message)
            *error_message = g_strdup ("Invalid web application URL");
          return FALSE;
        }
    }

  g_strfreev (parts);
  return TRUE;
}

#endif /* ENABLE_WEB_APPLICATION_SCANNING */
