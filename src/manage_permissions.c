/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_permissions.h"

#include <string.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Test whether a permission is the special Admin permission.
 *
 * @param[in]  permission_id  UUID of permission.
 *
 * @return 1 permission is Admin, else 0.
 */
int
permission_is_admin (const char *permission_id)
{
  if (permission_id)
    return strcmp (permission_id, PERMISSION_UUID_ADMIN_EVERYTHING);
  return 0;
}

/**
 * @brief Return whether a permission is in use.
 *
 * @param[in]  permission  Permission.
 *
 * @return 1 if in use, else 0.
 */
int
permission_in_use (permission_t permission)
{
  return 0;
}

/**
 * @brief Return whether a trashcan permission is referenced by a task.
 *
 * @param[in]  permission  Permission.
 *
 * @return 1 if in use, else 0.
 */
int
trash_permission_in_use (permission_t permission)
{
  return 0;
}

/**
 * @brief Return whether a permission is writable.
 *
 * @param[in]  permission  Permission.
 *
 * @return 1 if writable, else 0.
 */
int
permission_writable (permission_t permission)
{
  if (permission_is_predefined (permission))
    return 0;
  return 1;
}

/**
 * @brief Return whether a trashcan permission is writable.
 *
 * @param[in]  permission  Permission.
 *
 * @return 1 if writable, else 0.
 */
int
trash_permission_writable (permission_t permission)
{
  return 1;
}
