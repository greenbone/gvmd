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

/**
 * @file
 * @brief GVM management layer: Events SQL
 *
 * The Events SQL for the GVM management layer.
 */

#include "manage_sql_events.h"
#include "manage_acl.h"

#include <assert.h>

#include <gvm/base/array.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"


/**
 * @brief Initialise an event alert iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  event     Event.
 */
void
init_event_alert_iterator (iterator_t* iterator, event_t event)
{
  gchar *owned_clause, *with_clause;
  get_data_t get;
  array_t *permissions;

  assert (event);

  get.trash = 0;
  permissions = make_array ();
  array_add (permissions, g_strdup ("get_alerts"));
  owned_clause = acl_where_owned ("alert", &get, 0, "any", 0, permissions, 0,
                                  &with_clause);
  array_free (permissions);

  init_iterator (iterator,
                 "%s"
                 " SELECT alerts.id, alerts.active"
                 " FROM alerts"
                 " WHERE event = %i"
                 " AND %s;",
                 with_clause ? with_clause : "",
                 event,
                 owned_clause);

  g_free (with_clause);
  g_free (owned_clause);
}

/**
 * @brief Get the alert from a event alert iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return alert.
 */
alert_t
event_alert_iterator_alert (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (task_t) iterator_int64 (iterator, 0);
}

/**
 * @brief Get the active state from an event alert iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Active state.
 */
int
event_alert_iterator_active (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, 1);
  return ret;
}
