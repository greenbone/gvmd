/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_users.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Check whether a user is in use.
 *
 * @param[in]  user  User.
 *
 * @return 1 yes, 0 no.
 */
int
user_in_use (user_t user)
{
  return 0;
}

/**
 * @brief Check whether a trashcan user is in use.
 *
 * @param[in]  user  User.
 *
 * @return 1 yes, 0 no.
 */
int
trash_user_in_use (user_t user)
{
  return 0;
}

/**
 * @brief Check whether a user is writable.
 *
 * @param[in]  user  User.
 *
 * @return 1 yes, 0 no.
 */
int
user_writable (user_t user)
{
  return 1;
}

/**
 * @brief Check whether a trashcan user is writable.
 *
 * @param[in]  user  User.
 *
 * @return 1 yes, 0 no.
 */
int
trash_user_writable (user_t user)
{
  return 1;
}
