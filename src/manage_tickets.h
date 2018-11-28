/* GVM
 * $Id$
 * Description: GVM management layer: Ticket headers exported from layer
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2019 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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

#ifndef _GVMD_MANAGE_TICKETS_H
#define _GVMD_MANAGE_TICKETS_H

#include "manage.h"
#include "iterator.h"

int
ticket_count (const get_data_t *);

int
init_ticket_iterator (iterator_t *, const get_data_t *);

const char*
ticket_iterator_host (iterator_t*);

int
ticket_in_use (ticket_t);

int
trash_ticket_in_use (ticket_t);

int
ticket_writable (ticket_t);

int
trash_ticket_writable (ticket_t);

int
create_ticket (const char *, const char *, ticket_t *);

int
copy_ticket (const char *, const char *, const char *, ticket_t *);

char*
ticket_uuid (ticket_t);

int
modify_ticket (const char *, const char *, const char *);

#endif /* not _GVMD_MANAGE_TICKETS_H */
