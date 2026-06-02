/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM manage layer: Agent installers.
 *
 * General management of agent installers.
 */

#include "gmp_base.h"
#include "manage_agent_installers.h"

#include "manage_agent_common.h"
#include "manage_sql_resources.h"
#include <glib/gstdio.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Convert a language string to the corresponding enum value.
 *
 * Supported languages:
 * - "en" for English
 * - "de" for German
 *
 * @param[in] lang_str  The input language string.
 *
 * @return The corresponding instructions_lang_type_t enum value.
 */
instructions_lang_type_t
lang_type_from_string (const char *lang_str)
{
  if (g_strcmp0 (lang_str, "en") == 0)
    return EN;
  else if (g_strcmp0 (lang_str, "de") == 0)
    return DE;
  else
    {
      g_warning ("%s: Unsupported language '%s', default to English",
                 __func__, lang_str);
      return EN;
    }
}

/**
 * @brief Get installer instructions for an agent controller.
 *
 * @param[in] scanner_uuid  UUID of the scanner to get instructions for.
 * @param[in] lang         Language for the instructions.
 *
 * @return Allocated agent_controller_installer_instruction_t on success,
 *         NULL on failure (e.g., invalid scanner UUID, connection issues).
 */
agent_controller_installer_instruction_t
get_agent_installer_instruction (const gchar *scanner_uuid,
                                 instructions_lang_type_t lang)
{
  scanner_t scanner;
  if (!scanner_uuid)
    {
      g_warning ("%s: Scanner UUID is required but missing", __func__);
      return NULL;
    }
  if (find_resource_with_permission ("scanner", scanner_uuid, &scanner,
                                         "get_scanners", 0))
    {
      g_warning ("%s: Scanner with UUID %s not found", __func__, scanner_uuid);
      return NULL;
    }

  if (scanner == 0)
    {
      g_warning ("%s: Scanner with UUID %s not found", __func__, scanner_uuid);
      return NULL;
    }
  gvmd_agent_connector_t conn = gvmd_agent_connector_new_from_scanner (scanner);
  if (!conn)
    {
      g_warning (
        "%s: Failed to create agent controller connector for scanner %s",
        __func__, scanner_uuid);
      return NULL;
    }

  agent_controller_installer_instruction_t instr =
    agent_controller_get_installer_instruction (conn->base, lang);

  gvmd_agent_connector_free (conn);

  return instr;
}
