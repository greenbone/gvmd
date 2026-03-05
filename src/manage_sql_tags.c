/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_tags.h"
#include "manage_sql.h"
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

/**
 * @brief Adjust location of resource in tags.
 *
 * @param[in]   type  Type.
 * @param[in]   old   Resource ID in old table.
 * @param[in]   new   Resource ID in new table.
 * @param[in]   to    Destination, trash or table.
 */
void
tags_set_locations (const char *type, resource_t old, resource_t new,
                    int to)
{
  sql ("UPDATE tag_resources SET resource_location = %i, resource = %llu"
       " WHERE resource_type = '%s' AND resource = %llu"
       " AND resource_location = %i;",
       to,
       new,
       type,
       old,
       to == LOCATION_TABLE ? LOCATION_TRASH : LOCATION_TABLE);
  sql ("UPDATE tag_resources_trash SET resource_location = %i, resource = %llu"
       " WHERE resource_type = '%s' AND resource = %llu"
       " AND resource_location = %i;",
       to,
       new,
       type,
       old,
       to == LOCATION_TABLE ? LOCATION_TRASH : LOCATION_TABLE);
}
