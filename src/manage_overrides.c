/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_overrides.h"
#include "manage_sql_resources.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Find a override for a specific permission, given a UUID.
 *
 * @param[in]   uuid        UUID of override.
 * @param[out]  override    Override return, 0 if successfully failed to find
 *                          override.
 * @param[in]   permission  Permission.
 *
 * @return FALSE on success (including if failed to find override), TRUE on
 *         error.
 */
gboolean
find_override_with_permission (const char* uuid, override_t* override,
                               const char *permission)
{
  return find_resource_with_permission ("override", uuid, override, permission,
                                        0);
}
