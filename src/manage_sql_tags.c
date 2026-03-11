/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_tags.h"
#include "manage_acl.h"
#include "manage_sql.h"
#include "manage_sql_permissions.h"
#include "manage_sql_resources.h"
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
 * @brief Find a tag for a specific permission, given a UUID.
 *
 * @param[in]   uuid        UUID of tag.
 * @param[out]  tag         Tag return, 0 if successfully failed to find tag.
 * @param[in]   permission  Permission.
 *
 * @return FALSE on success (including if failed to find tag), TRUE on error.
 */
static gboolean
find_tag_with_permission (const char* uuid, tag_t* tag,
                          const char *permission)
{
  return find_resource_with_permission ("tag", uuid, tag, permission, 0);
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

/**
 * @brief Delete a tag.
 *
 * @param[in]  tag_id     UUID of tag.
 * @param[in]  ultimate   Whether to remove entirely, or to trashcan.
 *
 * @return 0 success, 2 failed to find tag, 99 permission denied, -1 error.
 */
int
delete_tag (const char *tag_id, int ultimate)
{
  tag_t tag = 0;

  sql_begin_immediate ();

  if (acl_user_may ("delete_tag") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (find_tag_with_permission (tag_id, &tag, "delete_tag"))
    {
      sql_rollback ();
      return -1;
    }

  if (tag == 0)
    {
      if (find_trash ("tag", tag_id, &tag))
        {
          sql_rollback ();
          return -1;
        }
      if (tag == 0)
        {
          sql_rollback ();
          return 2;
        }
      if (ultimate == 0)
        {
          /* It's already in the trashcan. */
          sql_commit ();
          return 0;
        }

      permissions_set_orphans ("tag", tag, LOCATION_TRASH);

      sql ("DELETE FROM tag_resources_trash WHERE tag = %llu", tag);
      sql ("DELETE FROM tags_trash WHERE id = %llu;", tag);
      sql_commit ();
      return 0;
    }

  if (ultimate == 0)
    {
      tag_t trash_tag;

      sql ("INSERT INTO tags_trash"
           " (uuid, owner, name, comment, creation_time,"
           "  modification_time, resource_type, active, value)"
           " SELECT uuid, owner, name, comment, creation_time,"
           "        modification_time, resource_type, active, value"
           " FROM tags WHERE id = %llu;",
           tag);

      trash_tag = sql_last_insert_id ();

      sql ("INSERT INTO tag_resources_trash"
           "  (tag, resource_type, resource, resource_uuid, resource_location)"
           " SELECT"
           "   %llu, resource_type, resource, resource_uuid, resource_location"
           " FROM tag_resources WHERE tag = %llu;",
           trash_tag, tag);

      permissions_set_locations ("tag", tag, trash_tag, LOCATION_TRASH);
    }
  else
    {
      permissions_set_orphans ("tag", tag, LOCATION_TABLE);
      tags_remove_resource ("tag", tag, LOCATION_TABLE);
    }

  sql ("DELETE FROM tag_resources WHERE tag = %llu", tag);
  sql ("DELETE FROM tags WHERE id = %llu;", tag);
  sql_commit ();

  return 0;
}
