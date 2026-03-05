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

/**
 * @brief Remove a resource from tags.
 *
 * @param[in]  type      Type.
 * @param[in]  resource  Resource.
 * @param[in]  location  Location: table or trash.
 */
void
tags_remove_resource (const char *type, resource_t resource, int location)
{
  sql ("DELETE FROM tag_resources"
       " WHERE resource_type = '%s' AND resource = %llu"
       " AND resource_location = %i;",
       type,
       resource,
       location);
}
