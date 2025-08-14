/* Copyright (C) 2025 Greenbone AG
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

#ifndef _GVMD_MANAGE_ASSETS_H
#define _GVMD_MANAGE_ASSETS_H

#include "manage_get.h"

char*
host_uuid (resource_t);

report_host_t
manage_report_host_add (report_t, const char *, time_t, time_t);

void
report_host_set_end_time (report_host_t, time_t);

int
create_asset_host (const char *, const char *, resource_t* );

int
create_asset_report (const char *, const char *);

void
hosts_set_identifiers (report_t);

void
hosts_set_max_severity (report_t, int *, int *);

void
hosts_set_details (report_t);

void
init_host_identifier_iterator (iterator_t*, host_t, int, const char*);

const char*
host_identifier_iterator_value (iterator_t *);

const char*
host_identifier_iterator_source_type (iterator_t *);

const char*
host_identifier_iterator_source_id (iterator_t *);

const char*
host_identifier_iterator_source_data (iterator_t *);

int
host_identifier_iterator_source_orphan (iterator_t *);

const char*
host_identifier_iterator_os_id (iterator_t *);

const char*
host_identifier_iterator_os_title (iterator_t *);

int
init_asset_host_iterator (iterator_t *, const get_data_t *);

#endif /* not _GVMD_MANAGE_ASSETS_H */
