/* Copyright (C) 2019 Greenbone Networks GmbH
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

#ifndef _GVMD_MANAGE_TICKETS_H
#define _GVMD_MANAGE_TICKETS_H

#include "manage.h"
#include "iterator.h"

int
ticket_count (const get_data_t *);

int
init_ticket_iterator (iterator_t *, const get_data_t *);

const char*
ticket_iterator_user_id (iterator_t*);

const char*
ticket_iterator_user_name (iterator_t*);

const char*
ticket_iterator_task_id (iterator_t*);

const char*
ticket_iterator_task_name (iterator_t*);

const char*
ticket_iterator_report_id (iterator_t*);

double
ticket_iterator_severity (iterator_t*);

const char*
ticket_iterator_host (iterator_t*);

const char*
ticket_iterator_location (iterator_t*);

const char*
ticket_iterator_solution_type (iterator_t*);

const char*
ticket_iterator_status (iterator_t*);

const char*
ticket_iterator_open_time (iterator_t*);

const char*
ticket_iterator_fixed_time (iterator_t*);

const char*
ticket_iterator_closed_time (iterator_t*);

const char*
ticket_iterator_fix_verified_time (iterator_t*);

int
ticket_iterator_orphan (iterator_t*);

const char*
ticket_iterator_open_note (iterator_t*);

const char*
ticket_iterator_fixed_note (iterator_t*);

const char*
ticket_iterator_closed_note (iterator_t*);

const char*
ticket_iterator_fix_verified_report_id (iterator_t*);

const char*
ticket_iterator_nvt_oid (iterator_t*);

int
init_ticket_result_iterator (iterator_t *, const gchar *, int);

const char*
ticket_result_iterator_result_id (iterator_t*);

int
init_result_ticket_iterator (iterator_t *, result_t);

const char*
result_ticket_iterator_ticket_id (iterator_t*);

int
ticket_in_use (ticket_t);

int
trash_ticket_in_use (ticket_t);

int
ticket_writable (ticket_t);

int
trash_ticket_writable (ticket_t);

int
create_ticket (const char *, const char *, const char *, const char *, ticket_t *) __attribute__((weak));

int
copy_ticket (const char *, const char *, ticket_t *) __attribute__((weak));

char*
ticket_uuid (ticket_t) __attribute__((weak));

int
modify_ticket (const gchar *, const gchar *, const gchar *,
               const gchar *, const gchar *, const gchar *,
               const gchar *);

#endif /* not _GVMD_MANAGE_TICKETS_H */
