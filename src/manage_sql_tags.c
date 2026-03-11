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

/**
 * @brief Create a tag from an existing tag.
 *
 * @param[in]  name        Name of new tag.  NULL to copy from existing.
 * @param[in]  comment     Comment on new tag.  NULL to copy from existing.
 * @param[in]  tag_id      UUID of existing tag.
 * @param[out] new_tag_return  New tag.
 *
 * @return 0 success, 2 failed to find existing tag,
 *         99 permission denied, -1 error.
 */
int
copy_tag (const char* name, const char* comment, const char *tag_id,
          tag_t* new_tag_return)
{
  int ret = 0;
  tag_t new_tag, old_tag;

  ret = copy_resource ("tag", name, comment, tag_id,
                       "value, resource_type, active",
                       1, &new_tag, &old_tag);

  if (ret)
    return ret;

  if (new_tag_return)
    *new_tag_return = new_tag;

  sql ("INSERT INTO tag_resources"
       " (tag, resource_type, resource, resource_uuid, resource_location)"
       " SELECT"
       "  %llu, resource_type, resource, resource_uuid, resource_location"
       "   FROM tag_resources"
       "  WHERE tag = %llu",
       new_tag, old_tag);

  return 0;
}
