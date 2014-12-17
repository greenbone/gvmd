/* OpenVAS Manager
 * $Id$
 * Description: Headers for OpenVAS Manager: the Manage library.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2013 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef OPENVAS_MANAGER_MANAGE_ACL_H
#define OPENVAS_MANAGER_MANAGE_ACL_H

#include "manage.h"
#include <glib.h>

/**
 * @brief Generate SQL for user permission check.
 *
 * @param[in]  resource  Resource.
 */
#define USER_MAY(resource)                                            \
  "SELECT count(*) FROM permissions"                                  \
  " WHERE resource = " resource                                       \
  " AND subject_location = " G_STRINGIFY (LOCATION_TABLE)             \
  " AND ((subject_type = 'user'"                                      \
  "       AND subject"                                                \
  "           = (SELECT ROWID FROM users"                             \
  "              WHERE users.uuid = '%s'))"                           \
  "      OR (subject_type = 'group'"                                  \
  "          AND subject"                                             \
  "              IN (SELECT DISTINCT `group`"                         \
  "                  FROM group_users"                                \
  "                  WHERE user = (SELECT ROWID"                      \
  "                                FROM users"                        \
  "                                WHERE users.uuid"                  \
  "                                      = '%s')))"                   \
  "      OR (subject_type = 'role'"                                   \
  "          AND subject"                                             \
  "              IN (SELECT DISTINCT role"                            \
  "                  FROM role_users"                                 \
  "                  WHERE user = (SELECT ROWID"                      \
  "                                FROM users"                        \
  "                                WHERE users.uuid"                  \
  "                                      = '%s'))))"                  \
  /* Any permission implies GET. */                                   \
  " AND ((lower (substr ('%s', 1, 3)) = 'get'"                        \
  "       AND name LIKE '%%'"                                         \
  "                     || lower (substr ('%s',"                      \
  "                                       5,"                         \
  "                                       length ('%s') - 5)))"       \
  "      OR name = lower ('%s'))"

int
user_may (const char *);

int
user_can_everything (const char *);

int
user_is_admin (const char *);

int
user_is_observer (const char *);

int
user_owns_result (const char *);

int
user_owns_uuid (const char *, const char *, int);

int
user_has_access_uuid (const char *, const char *, const char *, int);

gchar *
where_owned (const char *, const get_data_t *, int, const gchar *, resource_t,
             array_t *);

#endif /* not OPENVAS_MANAGER_MANAGE_ACL_H */
