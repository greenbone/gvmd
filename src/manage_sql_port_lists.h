/* Copyright (C) 2020-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_SQL_PORT_LISTS_H
#define _GVMD_MANAGE_SQL_PORT_LISTS_H

#include "manage_port_lists.h"
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

int
deprecated_port_list_id_updated_in_feed (const char *, const gchar *);

void
update_port_list (port_list_t, const gchar *, const gchar *, array_t *,
                  const gchar *);

void
check_db_port_lists (int);

#endif /* not _GVMD_MANAGE_SQL_PORT_LISTS_H */
