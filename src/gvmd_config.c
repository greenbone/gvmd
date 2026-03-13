/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Greenbone Vulnerability Manager system configuration handling.
 */

#include "gvmd_config.h"
#include <ctype.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain used for messages from this module.
 */
#define G_LOG_DOMAIN "md   manage"

/**
 * @brief Parsed config file.
 */
static GKeyFile *parsed_config_file = NULL;

/**
 * @brief Get the default runtime configuration file path for gvmd.
 *
 * @return Path to the gvmd runtime configuration file.
 */
static const char *
get_sysconf_gvmd_config_file_path (void)
{
  static char *path;

  if (!path)
    path = g_build_filename (GVM_SYSCONF_DIR, "gvmd.conf", NULL);

  return path;
}

/**
 * @brief Load the gvmd system configuration file.
 *
 * @param[in]  path_override  Path to override the default path with or
 *                            NULL to fall back to default path.
 *
 * @return 0 success, -1 error.
 */
int
load_gvmd_config (const char *path_override)
{
  const char *config_path;
  gboolean allow_file_not_found = FALSE;
  GKeyFile *kf;
  GError *error = NULL;

  parsed_config_file = NULL;

  if (path_override && strcmp (path_override, ""))
    config_path = path_override;
  else
    {
      config_path = get_sysconf_gvmd_config_file_path ();
      allow_file_not_found = TRUE;
    }

  kf = g_key_file_new ();
  if (!g_key_file_load_from_file (kf, config_path, G_KEY_FILE_NONE, &error))
    {
      if (error && error->domain == G_FILE_ERROR
          && error->code == G_FILE_ERROR_NOENT)
        {
          g_key_file_unref (kf);

          if (allow_file_not_found)
            {
              g_clear_error (&error);
              return 0;
            }
          else
            {
              g_warning ("Failed to load gvmd config '%s': %s",
                        config_path, error->message);
              g_clear_error (&error);
              return -1;
            }
        }

      if (error)
        {
          g_warning ("Failed to load gvmd config '%s': %s",
                     config_path, error->message);
          g_clear_error (&error);
        }
      else
        {
          g_warning ("Failed to load gvmd config '%s'", config_path);
        }
      g_key_file_unref (kf);
      return -1;
    }

  g_debug ("Using gvmd config file '%s'", config_path);
  parsed_config_file = kf;
  return 0;
}

/**
 * @brief Get the parsed gvmd system config file.
 *
 * @return The parsed config file or NULL.
 */
GKeyFile *
get_gvmd_config ()
{
  return parsed_config_file;
}

/**
 * @brief Load a single boolean flag from a GKeyFile.
 *
 * @param[in]  kf          Key file handle.
 * @param[in]  group       Group name in the key file.
 * @param[in]  key         Key name inside the group.
 * @param[out] has_flag    Set to 1 if the key was found.
 * @param[out] flag_value  Set to 1 or 0 based on the key value.
 */
void
gvmd_config_get_boolean (GKeyFile *kf,
                         const char *group,
                         const char *key,
                         int *has_flag,
                         int *flag_value)
{
  gboolean b;

  if (!has_flag || !flag_value)
    return;

  if (!kf || !group || !key || !g_key_file_has_key (kf, group, key, NULL))
    {
      *has_flag = 0;
      *flag_value = 0;
      return;
    }

  b = g_key_file_get_boolean (kf, group, key, NULL);
  *has_flag = 1;
  *flag_value = b ? 1 : 0;
}

/**
 * @brief Parse a textual boolean value into an integer.
 *
 * Recognized true values: "1", "true", "yes", "on"
 * Recognized false values: "0", "false", "no", "off"
 * Comparison is case-insensitive and ignores whitespaces.
 *
 * @param[in]  str  Input string to parse.
 * @param[out] out  Parsed value (1 or 0) on success.
 *
 * @return 0 on success, -1 on invalid input or NULL arguments.
 */
static int
parse_bool_string (const char *str, int *out)
{
  char buf[32];
  char *p;

  if (!str || !out)
    return -1;

  strncpy (buf, str, sizeof (buf) - 1);
  buf[sizeof (buf) - 1] = '\0';

  g_strstrip (buf);

  for (p = buf; *p; ++p)
    *p = (char) tolower ((unsigned char) *p);

  if (!strcmp (buf, "1") ||
      !strcmp (buf, "true") ||
      !strcmp (buf, "yes") ||
      !strcmp (buf, "on"))
    {
      *out = 1;
      return 0;
    }

  if (!strcmp (buf, "0") ||
      !strcmp (buf, "false") ||
      !strcmp (buf, "no") ||
      !strcmp (buf, "off"))
    {
      *out = 0;
      return 0;
    }

  return -1;
}

/**
 * @brief Read a boolean value from an environment variable.
 *
 * @param[in]  env_name  Name of the environment variable.
 * @param[out] out       Parsed value on success. May be NULL.
 *
 * @return  1 if the variable existed and was parsed successfully,
 *          0 if the variable was not set,
 *         -1 if the variable was set but had an invalid value.
 */
static int
read_env_bool (const char *env_name, int *out)
{
  const char *val = getenv (env_name);
  int tmp;

  if (!val)
    return 0;

  if (parse_bool_string (val, &tmp) == 0)
    {
      if (out)
        *out = tmp;
      return 1;
    }

  /* Invalid env value, ignore but could be logged by caller. */
  return -1;
}

/**
 * @brief Resolve the effective state of a single boolean config flag.
 *
 * Resolution order:
 *  - If an environment variable is set and valid, use that.
 *  - Else, if a config file value exists, use that.
 *  - Else, default to FALSE.
 *
 * @param[in]     env_name       Environment variable name.
 * @param[in]     conf_has_value Non-zero if configuration provided a value.
 * @param[in]     conf_value     Value from configuration (1 or 0).
 * @param[out]    output         Pointer to boolean result.
 */
void
gvmd_config_resolve_boolean (const char *env_name,
                             gboolean conf_has_value,
                             gboolean conf_value,
                             gboolean *output)
{
  gboolean env_value;
  int env_result;

  if (output == NULL)
    return;

  env_result = read_env_bool (env_name, &env_value);
  if (env_result == 1)
    {
      *output = env_value;
      return;
    }

  if (conf_has_value)
    *output = conf_value ? TRUE : FALSE;
}
