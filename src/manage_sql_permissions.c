/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_permissions.h"
#include "manage_acl.h"
#include "sql.h"

/**
 * @file
 * @brief GVM management layer: Permissions SQL
 *
 * The Permissions SQL for the GVM management layer.
 */

/**
 * @brief Adjust location of resource in permissions.
 *
 * @param[in]   type  Type.
 * @param[in]   old   Resource ID in old table.
 * @param[in]   new   Resource ID in new table.
 * @param[in]   to    Destination, trash or table.
 */
void
permissions_set_locations (const char *type, resource_t old, resource_t new,
                           int to)
{
  sql ("UPDATE permissions SET resource_location = %i, resource = %llu"
       " WHERE resource_type = '%s' AND resource = %llu"
       " AND resource_location = %i;",
       to,
       new,
       type,
       old,
       to == LOCATION_TABLE ? LOCATION_TRASH : LOCATION_TABLE);
  sql ("UPDATE permissions_trash SET resource_location = %i, resource = %llu"
       " WHERE resource_type = '%s' AND resource = %llu"
       " AND resource_location = %i;",
       to,
       new,
       type,
       old,
       to == LOCATION_TABLE ? LOCATION_TRASH : LOCATION_TABLE);
}

/**
 * @brief Set permissions to orphan.
 *
 * @param[in]  type      Type.
 * @param[in]  resource  Resource ID.
 * @param[in]  location  Location: table or trash.
 */
void
permissions_set_orphans (const char *type, resource_t resource, int location)
{
  sql ("UPDATE permissions SET resource = -1"
       " WHERE resource_type = '%s' AND resource = %llu"
       " AND resource_location = %i;",
       type,
       resource,
       location);
  sql ("UPDATE permissions_trash SET resource = -1"
       " WHERE resource_type = '%s' AND resource = %llu"
       " AND resource_location = %i;",
       type,
       resource,
       location);
}

/**
 * @brief Adjust subject in permissions.
 *
 * @param[in]   type  Subject type.
 * @param[in]   old   Resource ID in old table.
 * @param[in]   new   Resource ID in new table.
 * @param[in]   to    Destination, trash or table.
 */
void
permissions_set_subjects (const char *type, resource_t old, resource_t new,
                          int to)
{
  assert (type && (strcmp (type, "group") == 0 || strcmp (type, "role") == 0));

  sql ("UPDATE permissions"
       " SET subject_location = %i, subject = %llu"
       " WHERE subject_location = %i"
       " AND subject_type = '%s'"
       " AND subject = %llu;",
       to,
       new,
       to == LOCATION_TRASH ? LOCATION_TABLE : LOCATION_TRASH,
       type,
       old);

  sql ("UPDATE permissions_trash"
       " SET subject_location = %i, subject = %llu"
       " WHERE subject_location = %i"
       " AND subject_type = '%s'"
       " AND subject = %llu;",
       to,
       new,
       to == LOCATION_TRASH ? LOCATION_TABLE : LOCATION_TRASH,
       type,
       old);
}
