/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_tags.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Return whether a tag is in use by a task.
 *
 * @param[in]  tag  Tag.
 *
 * @return 1 if in use, else 0.
 */
int
tag_in_use (tag_t tag)
{
  return 0;
}

/**
 * @brief Return whether a trashcan tag is referenced by a task.
 *
 * @param[in]  tag  Tag.
 *
 * @return 1 if in use, else 0.
 */
int
trash_tag_in_use (tag_t tag)
{
  return 0;
}

/**
 * @brief Return whether a tag is writable.
 *
 * @param[in]  tag  Tag.
 *
 * @return 1 if writable, else 0.
 */
int
tag_writable (tag_t tag)
{
  return 1;
}

/**
 * @brief Return whether a trashcan tag is writable.
 *
 * @param[in]  tag  Tag.
 *
 * @return 1 if writable, else 0.
 */
int
trash_tag_writable (tag_t tag)
{
  return 0;
}
