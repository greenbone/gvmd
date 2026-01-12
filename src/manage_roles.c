/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_roles.h"
#include "manage_sql_roles.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Check whether a role is in use.
 *
 * @param[in]  role  Role.
 *
 * @return 1 yes, 0 no.
 */
int
role_in_use (role_t role)
{
  return 0;
}

/**
 * @brief Check whether a trashcan role is in use.
 *
 * @param[in]  role  Role.
 *
 * @return 1 yes, 0 no.
 */
int
trash_role_in_use (role_t role)
{
  return 0;
}

/**
 * @brief Check whether a role is writable.
 *
 * @param[in]  role  Role.
 *
 * @return 1 yes, 0 no.
 */
int
role_writable (role_t role)
{
  if (role_is_predefined (role))
    return 0;
  return 1;
}

/**
 * @brief Check whether a trashcan role is writable.
 *
 * @param[in]  role  Role.
 *
 * @return 1 yes, 0 no.
 */
int
trash_role_writable (role_t role)
{
  return 1;
}
