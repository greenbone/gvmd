/* Copyright (C) 2020-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_PORT_LISTS_H
#define _GVMD_MANAGE_PORT_LISTS_H

#include "manage_resources_types.h"
#include "gmp_get.h"

#include <glib.h>

#include <gvm/base/array.h>

gboolean
find_port_list (const char*, port_list_t*);

gboolean
find_port_list_with_permission (const char *, port_list_t *, const char *);

gboolean
find_port_range (const char*, port_list_t*);

int
trash_port_list_predefined (port_list_t);

int
port_list_predefined (port_list_t);

int
create_port_list (const char *, const char *, const char *, const char *,
                  array_t *, port_list_t *);

int
copy_port_list (const char *, const char *, const char *, port_list_t *);

int
modify_port_list (const char *, const char *, const char *);

int
create_port_range (const char *, const char *, const char *, const char *,
                   const char *, port_range_t *);

int
delete_port_list (const char *, int);

int
delete_port_range (const char *, int);

int
port_list_count (const get_data_t *);

int
init_port_list_iterator (iterator_t *, get_data_t *);

int
port_list_iterator_count_all (iterator_t *);

int
port_list_iterator_count_tcp (iterator_t *);

int
port_list_iterator_count_udp (iterator_t *);

int
port_list_iterator_predefined (iterator_t *);

char*
port_list_uuid (port_list_t);

char*
port_range_uuid (port_range_t);

int
port_list_in_use (port_list_t);

int
trash_port_list_in_use (port_list_t);

int
trash_port_list_writable (port_list_t);

int
port_list_writable (port_list_t);

int
trash_port_list_readable_uuid (const gchar *);

void
init_port_range_iterator (iterator_t *, port_range_t, int, int, const char *);

const char*
port_range_iterator_uuid (iterator_t *);

const char*
port_range_iterator_comment (iterator_t*);

const char*
port_range_iterator_start (iterator_t *);

const char*
port_range_iterator_end (iterator_t *);

const char*
port_range_iterator_type (iterator_t *);

void
init_port_list_target_iterator (iterator_t *, port_list_t, int);

const char*
port_list_target_iterator_uuid (iterator_t *);

const char*
port_list_target_iterator_name (iterator_t *);

int
port_list_target_iterator_readable (iterator_t *);

gboolean
port_lists_feed_dir_exists ();

void
manage_sync_port_lists ();

int
manage_rebuild_port_lists ();

gboolean
should_sync_port_lists ();

#endif /* not _GVMD_MANAGE_PORT_LISTS_H */
