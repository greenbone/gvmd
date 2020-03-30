/* Copyright (C) 2020 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _GVMD_MANAGE_SQL_PORT_LISTS_H
#define _GVMD_MANAGE_SQL_PORT_LISTS_H

#include "manage.h"
#include "manage_sql.h"

column_t*
port_list_select_columns ();

const char**
port_list_filter_columns ();

int
create_port_list_no_acl (const char *, const char *, const char *,
                         const char *, array_t *, port_list_t *);

int
create_port_list_unique (const char *, const char *, const char *,
                         port_list_t *);

gboolean
find_port_list_no_acl (const char *, port_list_t *);

gboolean
find_trash_port_list_no_acl (const char *, port_list_t *);

int
port_list_is_predefined (port_list_t);

port_protocol_t
port_range_iterator_type_int (iterator_t *);

int
restore_port_list (const char *);

void
empty_trashcan_port_lists ();

void
inherit_port_lists (user_t, user_t);

void
delete_port_lists_user (user_t);

void
migrate_predefined_port_lists ();

int
port_list_updated_in_feed (port_list_t, const gchar *);

void
update_port_list (port_list_t, const gchar *, const gchar *, array_t *);

void
check_db_port_lists ();

#endif /* not _GVMD_MANAGE_SQL_PORT_LISTS_H */
