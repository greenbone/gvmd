/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Runtime feature flag handling for gvmd.
 */

#include "manage_runtime_flags.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain used for messages from this module.
 */
#define G_LOG_DOMAIN "md   manage"

#ifndef ENABLE_AGENTS
#  define ENABLE_AGENTS 0
#endif

#ifndef ENABLE_CONTAINER_SCANNING
#  define ENABLE_CONTAINER_SCANNING 0
#endif

#ifndef OPENVASD
#  define OPENVASD 0
#endif

#ifndef ENABLE_CREDENTIAL_STORES
#  define ENABLE_CREDENTIAL_STORES 0
#endif

#ifndef FEED_VT_METADATA
#  define FEED_VT_METADATA 0
#endif

/**
 * @brief Get the default system configuration file path for gvmd.
 *
 * @return Path to the system gvmd configuration file.
 */
static const char *
get_sysconf_gvmd_config (void)
{
  static char *path;

  if (!path)
    path = g_build_filename (GVM_SYSCONF_DIR, "gvmd.conf", NULL);

  return path;
}

/**
 * @brief State of a single feature (compile-time and runtime).
 *
 * @var feature_state_t::compiled_in
 * Whether the feature is compiled into this binary (non-zero if yes).
 *
 * @var feature_state_t::enabled
 * Whether the feature is currently enabled at runtime (non-zero if yes).
 */
static feature_state_t feature_agents =
  {ENABLE_AGENTS, 0};

static feature_state_t feature_container_scanning =
  {ENABLE_CONTAINER_SCANNING, 0};

static feature_state_t feature_openvasd =
  {OPENVASD, 0};

static feature_state_t feature_credential_stores =
  {ENABLE_CREDENTIAL_STORES, 0};

static feature_state_t feature_vt_metadata =
  {FEED_VT_METADATA, 0};

/**
 * @brief Trim leading and trailing whitespace from a string in place.
 *
 * @param[in,out] s  NUL-terminated string to be trimmed.
 */
static void
trim_spaces (char *s)
{
  char *p = s;

  if (!s)
    return;

  while (*p && isspace ((unsigned char) *p))
    p++;

  char *end = p + strlen (p);
  while (end > p && isspace ((unsigned char) end[-1]))
    *--end = '\0';

  if (p != s)
    memmove (s, p, (size_t) (end - p + 1));
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

  trim_spaces (buf);

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
 * @brief Feature flags as read from the configuration file.
 */
struct conf_feature_flags
{
  int has_agents;
  int agents;

  int has_container_scanning;
  int container_scanning;

  int has_openvasd;
  int openvasd;

  int has_credential_store;
  int credential_store;

  int has_vt_metadata;
  int vt_metadata;
};

/**
 * @brief Initialize a conf_feature_flags structure with zeros.
 *
 * @param[out] t  Structure to initialize. Must not be NULL.
 */
static void
conf_file_feature_flags_init_empty (struct conf_feature_flags *t)
{
  memset (t, 0, sizeof (*t));
}

/**
 * @brief Load a single boolean feature flag from a GKeyFile.
 *
 * @param[in]  kf          Key file handle.
 * @param[in]  group       Group name in the key file.
 * @param[in]  key         Key name inside the group.
 * @param[out] has_flag    Set to 1 if the key was found.
 * @param[out] flag_value  Set to 1 or 0 based on the key value.
 */
static void
load_feature_flag (GKeyFile *kf,
                   const char *group,
                   const char *key,
                   int *has_flag,
                   int *flag_value)
{
  gboolean b;

  if (!kf || !group || !key || !has_flag || !flag_value)
    return;

  if (!g_key_file_has_key (kf, group, key, NULL))
    return;

  b = g_key_file_get_boolean (kf, group, key, NULL);
  *has_flag = 1;
  *flag_value = b ? 1 : 0;
}

/**
 * @brief Load all feature flags from a gvmd configuration file.
 *
 * @param[in]  config_path  Path to the configuration file.
 * @param[out] out          Output structure for parsed flags.
 *
 * @return  0 on success (file loaded or not present),
 *         -1 on other I/O or parse errors.
 */
static int
load_conf_file_feature_flags (const char *config_path,
                              struct conf_feature_flags *out)
{
  GKeyFile *kf;
  GError *error = NULL;

  if (!out)
    return -1;

  conf_file_feature_flags_init_empty (out);

  kf = g_key_file_new ();
  if (!g_key_file_load_from_file (kf, config_path, G_KEY_FILE_NONE, &error))
    {
      if (error && error->domain == G_FILE_ERROR
          && error->code == G_FILE_ERROR_NOENT)
        {
          g_clear_error (&error);
          g_key_file_unref (kf);
          return 0;
        }

      if (error)
        {
          g_warning ("Failed to load runtime config '%s': %s",
                     config_path, error->message);
          g_clear_error (&error);
        }
      g_key_file_unref (kf);
      return -1;
    }

  load_feature_flag (kf, "features", "enable_agents",
                     &out->has_agents, &out->agents);

  load_feature_flag (kf, "features", "enable_container_scanning",
                     &out->has_container_scanning, &out->container_scanning);

  load_feature_flag (kf, "features", "enable_credential_store",
                     &out->has_credential_store, &out->credential_store);

  load_feature_flag (kf, "features", "enable_openvasd",
                     &out->has_openvasd, &out->openvasd);

  load_feature_flag (kf, "features", "enable_vt_metadata",
                     &out->has_vt_metadata, &out->vt_metadata);

  g_key_file_unref (kf);
  return 0;
}

/**
 * @brief Resolve the effective state of a single feature.
 *
 * Resolution order:
 *  - If the feature is not compiled in, it is always disabled.
 *  - If an environment variable is set and valid, use that.
 *  - Else, if a config file value exists, use that.
 *  - Else, default to disabled (0).
 *
 * @param[in,out] feature        Feature state to update.
 * @param[in]     env_name       Environment variable name.
 * @param[in]     conf_has_value Non-zero if configuration provided a value.
 * @param[in]     conf_value     Value from configuration (1 or 0).
 */
static void
resolve_feature (feature_state_t *feature,
                 const char *env_name,
                 int conf_has_value,
                 int conf_value)
{
  int env_result;
  int env_value;

  if (!feature)
    return;

  if (!feature->compiled_in)
    {
      feature->enabled = 0;
      return;
    }

  env_result = read_env_bool (env_name, &env_value);
  if (env_result == 1)
    {
      feature->enabled = env_value;
      return;
    }

  if (conf_has_value)
    {
      feature->enabled = conf_value ? 1 : 0;
      return;
    }

  feature->enabled = 0;
}

/**
 * @brief Append a comma-separated command list to a GString.
 *
 * @param[in,out] buf   Output buffer. May be NULL (then nothing is done).
 * @param[in]     cmds  Command list to append (no leading comma).
 */
static void
append_commands (GString *buf, const char *cmds)
{
  if (!buf)
    return;

  if (buf->len)
    g_string_append_c (buf, ',');

  g_string_append (buf, cmds);
}

/**
 * @brief Initialize runtime feature flags from config file and environment.
 *
 * @param[in] config_path  Optional configuration file path, or NULL.
 *
 * @return Always 0 (errors are handled internally and fall back to defaults).
 */
int
runtime_flags_init (const char *config_path)
{
  struct conf_feature_flags conf_flags;
  const char *path;

  if (config_path)
    path = config_path;
  else
    path = get_sysconf_gvmd_config ();

  if (load_conf_file_feature_flags (path, &conf_flags) != 0)
    {
      /* Parse error */
      conf_file_feature_flags_init_empty (&conf_flags);
    }

  resolve_feature (&feature_agents,
                   "GVMD_ENABLE_AGENTS",
                   conf_flags.has_agents,
                   conf_flags.agents);

  resolve_feature (&feature_container_scanning,
                   "GVMD_ENABLE_CONTAINER_SCANNING",
                   conf_flags.has_container_scanning,
                   conf_flags.container_scanning);

  resolve_feature (&feature_openvasd,
                   "GVMD_ENABLE_OPENVASD",
                   conf_flags.has_openvasd,
                   conf_flags.openvasd);

  resolve_feature (&feature_credential_stores,
                   "GVMD_ENABLE_CREDENTIAL_STORES",
                   conf_flags.has_credential_store,
                   conf_flags.credential_store);

  resolve_feature (&feature_vt_metadata,
                   "GVMD_ENABLE_VT_METADATA",
                   conf_flags.has_vt_metadata,
                   conf_flags.vt_metadata);

  return 0;
}

/**
 * @brief Check whether a feature is currently enabled at runtime.
 *
 * @param[in] t  Feature identifier.
 *
 * @return 1 if the feature is enabled at runtime, 0 otherwise.
 */
int
feature_enabled (feature_id_t t)
{
  /* IMPORTANT: compiled-out features are never enabled */
  if (!feature_compiled_in (t))
    return 0;

  switch (t)
    {
    case AGENTS:
      return feature_agents.enabled;
    case OPENVASD_SCANNER:
      return feature_openvasd.enabled;
    case CONTAINER_SCANNING:
      return feature_container_scanning.enabled;
    case CREDENTIAL_STORES:
      return feature_credential_stores.enabled;
    case VT_METADATA:
      return feature_vt_metadata.enabled;
    default:
      return 0;
    }
}

/**
 * @brief Check whether a feature is compiled into this binary.
 *
 * @param[in] t  Feature identifier.
 *
 * @return 1 if compiled in, 0 otherwise.
 */
int
feature_compiled_in (feature_id_t t)
{
  switch (t)
    {
    case AGENTS:
      return feature_agents.compiled_in;
    case OPENVASD_SCANNER:
      return feature_openvasd.compiled_in;
    case CONTAINER_SCANNING:
      return feature_container_scanning.compiled_in;
    case CREDENTIAL_STORES:
      return feature_credential_stores.compiled_in;
    case VT_METADATA:
      return feature_vt_metadata.compiled_in;
    default:
      return 0;
    }
}

/**
 * @brief Append commands that must be disabled for inactive features.
 *
 * @param[in,out] buf  Output buffer for disabled commands. Must not be NULL.
 */
void
runtime_append_disabled_commands (GString *buf)
{
  /* AGENTS */
  if (!feature_enabled (AGENTS))
    {
      append_commands (
        buf,
        "get_agents,"
        "modify_agent,"
        "delete_agent,"
        "modify_agent_control_scan_config,"
        "get_agent_groups,"
        "create_agent_group,"
        "modify_agent_group,"
        "delete_agent_group,"
        "get_agent_installers,"
        "get_agent_installer_file");
    }
  /* CONTAINER_SCANNING */
  if (!feature_enabled (CONTAINER_SCANNING))
    {
      append_commands (
        buf,
        "get_oci_image_targets,"
        "create_oci_image_target,"
        "modify_oci_image_target,"
        "delete_oci_image_target");
    }

  /* CREDENTIAL_STORES */
  if (!feature_enabled (CREDENTIAL_STORES))
    {
      append_commands (buf, "get_credential_stores,"
                       "modify_credential_store");
    }
}