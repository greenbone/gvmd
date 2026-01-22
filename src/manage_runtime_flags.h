/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Headers for Runtime feature flag handler.
 */

#ifndef _GVMD_MANAGE_RUNTIME_FLAGS_H
#define _GVMD_MANAGE_RUNTIME_FLAGS_H

#include <glib.h>

/**
 * @brief Feature state.
 */
typedef struct
{
  int compiled_in; ///< Whether feature is compiled into binary.
  int enabled;     ///< Whether feature is currently enabled at runtime.
} feature_state_t;

/**
 * @brief Feature ID.
 */
typedef enum
{
  FEATURE_ID_AGENTS = 0,
  FEATURE_ID_CONTAINER_SCANNING,
  FEATURE_ID_OPENVASD_SCANNER,
  FEATURE_ID_CREDENTIAL_STORES,
  FEATURE_ID_VT_METADATA,
} feature_id_t;

int
runtime_flags_init (const gchar *config_path);

int
feature_enabled (feature_id_t);

int
feature_compiled_in (feature_id_t);

void
runtime_append_disabled_commands (GString *buf);

#endif // not _GVMD_MANAGE_RUNTIME_FLAGS_H
