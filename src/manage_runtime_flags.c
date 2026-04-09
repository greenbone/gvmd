/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Runtime feature flag handling for gvmd.
 */

#include "gvmd_config.h"
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
/**
 * @brief Whether to enable agents.
 */
#define ENABLE_AGENTS 0
#endif

#ifndef ENABLE_CONTAINER_SCANNING
/**
 * @brief Whether to enable container scanning.
 */
#define ENABLE_CONTAINER_SCANNING 0
#endif

#ifndef ENABLE_OPENVASD
/**
 * @brief Whether to enable openvasd scanners.
 */
#define ENABLE_OPENVASD 0
#endif

#ifndef ENABLE_CREDENTIAL_STORES
/**
 * @brief Whether to enable credential stores.
 */
#define ENABLE_CREDENTIAL_STORES 0
#endif

/**
 * @brief State of a single feature.
 */
static feature_state_t feature_agents =
  {ENABLE_AGENTS, 0};

/**
 * @brief State of a single feature.
 */
static feature_state_t feature_container_scanning =
  {ENABLE_CONTAINER_SCANNING, 0};

/**
 * @brief State of a single feature.
 */
static feature_state_t feature_openvasd =
  {ENABLE_OPENVASD, 0};

/**
 * @brief State of a single feature.
 */
static feature_state_t feature_credential_stores =
  {ENABLE_CREDENTIAL_STORES, 0};

/**
 * @brief State of a single feature.
 */
static feature_state_t feature_vt_metadata =
  {1, 0};

/**
 * @brief State of a single feature.
 */
static feature_state_t feature_security_intelligence_export =
  {1, 0};

/**
 * @brief State of a single feature.
 */
static feature_state_t feature_jwt_auth =
  {ENABLE_JWT_AUTH, 0};

/**
 * @brief Feature flags as read from the configuration file.
 */
struct conf_feature_flags
{
  int has_agents;              ///< Whether flag is present.
  int agents;                  ///< Value of flag.

  int has_container_scanning;  ///< Whether flag is present.
  int container_scanning;      ///< Value of flag.

  int has_openvasd;            ///< Whether flag is present.
  int openvasd;                ///< Value of flag.

  int has_credential_store;    ///< Whether flag is present.
  int credential_store;        ///< Value of flag.

  int has_vt_metadata;         ///< Whether flag is present.
  int vt_metadata;             ///< Value of flag.

  int has_security_intelligence_export;         ///< Whether flag is present.
  int security_intelligence_export;             ///< Value of flag.

  int has_jwt_auth;           ///< Whether flag is present.
  int jwt_auth;               ///< Value of flag.
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
 * @brief Load all feature flags from a gvmd configuration file.
 *
 * @param[in]  config_path  Path to the configuration file.
 * @param[out] out          Output structure for parsed flags.
 *
 * @return  0 on success (file loaded or not present),
 *         -1 on other I/O or parse errors.
 */
static int
load_conf_file_feature_flags (struct conf_feature_flags *out)
{
  GKeyFile *kf;

  if (!out)
    return -1;

  conf_file_feature_flags_init_empty (out);

  kf = get_gvmd_config ();
  if (kf == NULL)
    return 0;

  gvmd_config_get_boolean (kf, "features", "enable_agents",
                           &out->has_agents,
                           &out->agents);

  gvmd_config_get_boolean (kf, "features", "enable_container_scanning",
                           &out->has_container_scanning,
                           &out->container_scanning);

  gvmd_config_get_boolean (kf, "features", "enable_credential_store",
                           &out->has_credential_store,
                           &out->credential_store);

  gvmd_config_get_boolean (kf, "features", "enable_openvasd",
                           &out->has_openvasd,
                           &out->openvasd);

  gvmd_config_get_boolean (kf, "features", "enable_vt_metadata",
                           &out->has_vt_metadata,
                           &out->vt_metadata);

  gvmd_config_get_boolean (kf, "features", "enable_security_intelligence_export",
                           &out->has_security_intelligence_export,
                           &out->security_intelligence_export);

  gvmd_config_get_boolean (kf, "features", "enable_jwt_auth",
                           &out->has_jwt_auth,
                           &out->jwt_auth);

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
  if (!feature)
    return;

  if (!feature->compiled_in)
    {
      feature->enabled = 0;
      return;
    }

  gvmd_config_resolve_boolean (env_name, conf_has_value, conf_value,
                               &feature->enabled);
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
 * @return Always 0 (errors are handled internally and fall back to defaults).
 */
int
runtime_flags_init ()
{
  struct conf_feature_flags conf_flags;

  if (load_conf_file_feature_flags (&conf_flags) != 0)
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

  resolve_feature (&feature_security_intelligence_export,
                   "GVMD_ENABLE_SECURITY_INTELLIGENCE_EXPORT",
                   conf_flags.has_security_intelligence_export,
                   conf_flags.security_intelligence_export);

  resolve_feature (&feature_jwt_auth,
                   "GVMD_ENABLE_JWT_AUTH",
                   conf_flags.has_jwt_auth,
                   conf_flags.jwt_auth);

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
    case FEATURE_ID_AGENTS:
      return feature_agents.enabled;
    case FEATURE_ID_OPENVASD_SCANNER:
      return feature_openvasd.enabled;
    case FEATURE_ID_CONTAINER_SCANNING:
      return feature_container_scanning.enabled;
    case FEATURE_ID_CREDENTIAL_STORES:
      return feature_credential_stores.enabled;
    case FEATURE_ID_VT_METADATA:
      return feature_vt_metadata.enabled;
    case FEATURE_ID_SECURITY_INTELLIGENCE_EXPORT:
      return feature_security_intelligence_export.enabled;
    case FEATURE_ID_JWT_AUTH:
      return feature_jwt_auth.enabled;
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
    case FEATURE_ID_AGENTS:
      return feature_agents.compiled_in;
    case FEATURE_ID_OPENVASD_SCANNER:
      return feature_openvasd.compiled_in;
    case FEATURE_ID_CONTAINER_SCANNING:
      return feature_container_scanning.compiled_in;
    case FEATURE_ID_CREDENTIAL_STORES:
      return feature_credential_stores.compiled_in;
    case FEATURE_ID_VT_METADATA:
      return feature_vt_metadata.compiled_in;
    case FEATURE_ID_SECURITY_INTELLIGENCE_EXPORT:
      return feature_security_intelligence_export.compiled_in;
    case FEATURE_ID_JWT_AUTH:
      return feature_jwt_auth.enabled;
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
  if (!feature_enabled (FEATURE_ID_AGENTS))
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
        "get_agent_installer_file,"
        "sync_agents");
    }
  /* CONTAINER_SCANNING */
  if (!feature_enabled (FEATURE_ID_CONTAINER_SCANNING))
    {
      append_commands (
        buf,
        "get_oci_image_targets,"
        "create_oci_image_target,"
        "modify_oci_image_target,"
        "delete_oci_image_target");
    }

  /* CREDENTIAL_STORES */
  if (!feature_enabled (FEATURE_ID_CREDENTIAL_STORES))
    {
      append_commands (
        buf,
        "get_credential_stores,"
        "modify_credential_store,"
        "verify_credential_store");
    }

  /* SECURITY_INTELLIGENCE_EXPORT */
  if (!feature_enabled (FEATURE_ID_SECURITY_INTELLIGENCE_EXPORT))
    {
      append_commands (
        buf,
        "get_integration_configs,"
        "modify_integration_config");
    }
}
