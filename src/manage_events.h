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

#ifndef _GVMD_MANAGE_EVENTS_H
#define _GVMD_MANAGE_EVENTS_H

#include "iterator.h"

/**
 * @brief Types of task events.
 */
typedef enum
{
  EVENT_ERROR,
  EVENT_TASK_RUN_STATUS_CHANGED,
  EVENT_NEW_SECINFO,
  EVENT_UPDATED_SECINFO,
  EVENT_TICKET_RECEIVED,
  EVENT_ASSIGNED_TICKET_CHANGED,
  EVENT_OWNED_TICKET_CHANGED
} event_t;

const char*
event_name (event_t);

gchar*
event_description (event_t, const void *, const char *);

event_t
event_from_name (const char*);

void
event (event_t, void *, resource_t, resource_t);

int
manage_alert (const char *, const char *, event_t, const void *, gchar **);

#endif /* not _GVMD_MANAGE_EVENTS_H */
