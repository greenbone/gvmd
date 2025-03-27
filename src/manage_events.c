/* Copyright (C) 2020-2022 Greenbone AG
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
 * @file manage_events.c
 * @brief GVM management layer: Events.
 *
 * General functions for managing events.
 */

#include "manage_events.h"
#include "manage_sql.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Get the name of an alert event.
 *
 * @param[in]  event  Event.
 *
 * @return The name of the event (for example, "Run status changed").
 */
const char*
event_name (event_t event)
{
  switch (event)
    {
      case EVENT_TASK_RUN_STATUS_CHANGED: return "Task run status changed";
      case EVENT_NEW_SECINFO:             return "New SecInfo arrived";
      case EVENT_UPDATED_SECINFO:         return "Updated SecInfo arrived";
      case EVENT_TICKET_RECEIVED:         return "Ticket received";
      case EVENT_ASSIGNED_TICKET_CHANGED: return "Assigned ticket changed";
      case EVENT_OWNED_TICKET_CHANGED:    return "Owned ticket changed";
      default:                            return "Internal Error";
    }
}

/**
 * @brief Get a description of an alert event.
 *
 * @param[in]  event       Event.
 * @param[in]  event_data  Event data.
 * @param[in]  task_name   Name of task if required in description, else NULL.
 *
 * @return Freshly allocated description of event.
 */
gchar*
event_description (event_t event, const void *event_data, const char *task_name)
{
  switch (event)
    {
      case EVENT_TASK_RUN_STATUS_CHANGED:
        if (task_name)
          return g_strdup_printf
                  ("The security scan task '%s' changed status to '%s'",
                   task_name,
                   run_status_name ((task_status_t) event_data));
        return g_strdup_printf ("Task status changed to '%s'",
                                run_status_name ((task_status_t) event_data));
        break;
      case EVENT_NEW_SECINFO:
        return g_strdup_printf ("New SecInfo arrived");
        break;
      case EVENT_UPDATED_SECINFO:
        return g_strdup_printf ("Updated SecInfo arrived");
        break;
      case EVENT_TICKET_RECEIVED:
        return g_strdup_printf ("Ticket received");
        break;
      case EVENT_ASSIGNED_TICKET_CHANGED:
        return g_strdup_printf ("Assigned ticket changed");
        break;
      case EVENT_OWNED_TICKET_CHANGED:
        return g_strdup_printf ("Owned ticket changed");
        break;
      default:
        return g_strdup ("Internal Error");
    }
}

/**
 * @brief Get an event from a name.
 *
 * @param[in]  name  Event name.
 *
 * @return The event.
 */
event_t
event_from_name (const char* name)
{
  if (strcasecmp (name, "Task run status changed") == 0)
    return EVENT_TASK_RUN_STATUS_CHANGED;
  if (strcasecmp (name, "New SecInfo arrived") == 0)
    return EVENT_NEW_SECINFO;
  if (strcasecmp (name, "Updated SecInfo arrived") == 0)
    return EVENT_UPDATED_SECINFO;
  if (strcasecmp (name, "Ticket received") == 0)
    return EVENT_TICKET_RECEIVED;
  if (strcasecmp (name, "Assigned ticket changed") == 0)
    return EVENT_ASSIGNED_TICKET_CHANGED;
  if (strcasecmp (name, "Owned ticket changed") == 0)
    return EVENT_OWNED_TICKET_CHANGED;
  return EVENT_ERROR;
}
