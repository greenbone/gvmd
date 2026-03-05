/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_tags.h"
#include "sql.h"

/**
 * @file
 * @brief GVM management layer: Tags SQL
 *
 * The Tags SQL for the GVM management layer.
 */

/**
 * @brief Return the UUID of a tag.
 *
 * @param[in]  tag  Tag.
 *
 * @return Newly allocated UUID if available, else NULL.
 */
char*
tag_uuid (tag_t tag)
{
  return sql_string ("SELECT uuid FROM tags WHERE id = %llu;",
                     tag);
}
