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

#ifndef _GVMD_MANAGE_SQL_EVENTS_H
#define _GVMD_MANAGE_SQL_EVENTS_H

#include "iterator.h"
#include "manage_alerts.h"
#include "manage_events.h"

void
init_event_alert_iterator (iterator_t *, event_t);

alert_t
event_alert_iterator_alert (iterator_t *);

int
event_alert_iterator_active (iterator_t *);

#endif /* not _GVMD_MANAGE_SQL_EVENTS_H */
