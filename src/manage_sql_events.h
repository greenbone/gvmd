/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
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
