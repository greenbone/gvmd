/* GVM
 * $Id$
 * Description: GVM management layer SQL: Tickets.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2018 Greenbone Networks GmbH
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

/**
 * @file manage_sql_tickets.c
 * @brief GVM management layer: Ticket SQL
 *
 * The Ticket SQL for the GVM management layer.
 */

#include "manage_tickets.h"
#include "manage_acl.h"
#include "manage_sql_tickets.h"
#include "manage_sql.h"
#include "sql.h"

#include <stdlib.h>
#include <string.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Ticket statuses.
 */
typedef enum
{
  TICKET_STATUS_OPEN = 0,
  TICKET_STATUS_SOLVED = 1,
  TICKET_STATUS_CONFIRMED = 2,
  TICKET_STATUS_CLOSED = 3,
  TICKET_STATUS_ORPHANED = 4,
  TICKET_STATUS_MAX,
  TICKET_STATUS_ERROR = 100
} ticket_status_t;

/**
 * @brief Get ticket status DB identifier from string.
 *
 * @param[in]   status  Status name.
 *
 * @return Status integer.
 */
static ticket_status_t
ticket_status_integer (const char *status)
{
  if (strcasecmp (status, "open") == 0)
    return TICKET_STATUS_OPEN;
  if (strcasecmp (status, "solved") == 0)
    return TICKET_STATUS_SOLVED;
  if (strcasecmp (status, "confirmed") == 0)
    return TICKET_STATUS_CONFIRMED;
  if (strcasecmp (status, "closed") == 0)
    return TICKET_STATUS_CLOSED;
  if (strcasecmp (status, "orphaned") == 0)
    return TICKET_STATUS_ORPHANED;
  return TICKET_STATUS_ERROR;
}

/**
 * @brief Get ticket status name from DB identifier.
 *
 * @param[in]   status  Status integer.
 *
 * @return Status name.
 */
static const gchar *
ticket_status_name (ticket_status_t status)
{
  switch (status)
    {
      case TICKET_STATUS_OPEN:
        return "Open";
      case TICKET_STATUS_SOLVED:
        return "Solved";
      case TICKET_STATUS_CONFIRMED:
        return "Confirmed";
      case TICKET_STATUS_CLOSED:
        return "Closed";
      case TICKET_STATUS_ORPHANED:
        return "Orphaned";
      default:
        return "Error";
    }
}

/**
 * @brief Filter columns for ticket iterator.
 */
#define TICKET_ITERATOR_FILTER_COLUMNS                                         \
 { GET_ITERATOR_FILTER_COLUMNS, "severity", "host", "location",                \
   "solution_type", "status", "opened", "solved", "closed", "orphaned",        \
   NULL }

/**
 * @brief Ticket iterator columns.
 */
#define TICKET_ITERATOR_COLUMNS                             \
 {                                                          \
   GET_ITERATOR_COLUMNS (tickets),                          \
   {                                                        \
     "(SELECT uuid FROM users WHERE id = assigned_to)",     \
     NULL,                                                  \
     KEYWORD_TYPE_STRING                                    \
   },                                                       \
   {                                                        \
     "(SELECT uuid FROM tasks WHERE id = task)",            \
     NULL,                                                  \
     KEYWORD_TYPE_STRING                                    \
   },                                                       \
   {                                                        \
     "(SELECT uuid FROM reports WHERE id = report)",        \
     NULL,                                                  \
    KEYWORD_TYPE_STRING                                     \
   },                                                       \
   { "severity", NULL, KEYWORD_TYPE_DOUBLE },               \
   { "host", NULL, KEYWORD_TYPE_STRING },                   \
   { "location", NULL, KEYWORD_TYPE_STRING },               \
   { "solution_type", NULL, KEYWORD_TYPE_STRING },          \
   { "status", NULL, KEYWORD_TYPE_STRING },                 \
   { "iso_time (open_time)", NULL, KEYWORD_TYPE_STRING },   \
   { "open_time", "opened", KEYWORD_TYPE_INTEGER },         \
   { "iso_time (solved_time)", NULL, KEYWORD_TYPE_STRING }, \
   { "solved_time", "solved", KEYWORD_TYPE_INTEGER },       \
   { "iso_time (closed_time)", NULL, KEYWORD_TYPE_STRING }, \
   { "closed_time", "closed", KEYWORD_TYPE_INTEGER },       \
   { "iso_time (confirmed_time)", NULL, KEYWORD_TYPE_STRING },                \
   { "confirmed_time", "confirmed", KEYWORD_TYPE_INTEGER },                   \
   { "iso_time (orphaned_time)", NULL, KEYWORD_TYPE_STRING },                 \
   { "orphaned_time", "orphaned", KEYWORD_TYPE_INTEGER },                     \
   { "solved_comment", NULL, KEYWORD_TYPE_STRING },                           \
   { "closed_comment", NULL, KEYWORD_TYPE_STRING },                           \
   {                                                                          \
     "(SELECT uuid FROM reports WHERE id = confirmed_report)",                \
     NULL,                                                                    \
     KEYWORD_TYPE_STRING                                                      \
   },                                                                         \
   { "nvt", NULL, KEYWORD_TYPE_STRING },                                      \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                       \
 }

/**
 * @brief Ticket iterator columns for trash case.
 */
#define TICKET_ITERATOR_TRASH_COLUMNS                       \
 {                                                          \
   GET_ITERATOR_COLUMNS (tickets_trash),                    \
   {                                                        \
     "(SELECT uuid FROM users WHERE id = assigned_to)",     \
     NULL,                                                  \
     KEYWORD_TYPE_STRING                                    \
   },                                                       \
   {                                                        \
     "(SELECT uuid FROM tasks WHERE id = task)",            \
     NULL,                                                  \
     KEYWORD_TYPE_STRING                                    \
   },                                                       \
   {                                                        \
     "(SELECT uuid FROM reports WHERE id = report)",        \
     NULL,                                                  \
     KEYWORD_TYPE_STRING                                    \
   },                                                       \
   { "severity", NULL, KEYWORD_TYPE_DOUBLE },               \
   { "host", NULL, KEYWORD_TYPE_STRING },                   \
   { "location", NULL, KEYWORD_TYPE_STRING },               \
   { "solution_type", NULL, KEYWORD_TYPE_STRING },          \
   { "status", NULL, KEYWORD_TYPE_STRING },                 \
   { "iso_time (open_time)", NULL, KEYWORD_TYPE_STRING },   \
   { "open_time", "opened", KEYWORD_TYPE_INTEGER },         \
   { "iso_time (solved_time)", NULL, KEYWORD_TYPE_STRING }, \
   { "solved_time", "solved", KEYWORD_TYPE_INTEGER },       \
   { "iso_time (closed_time)", NULL, KEYWORD_TYPE_STRING }, \
   { "closed_time", "closed", KEYWORD_TYPE_INTEGER },       \
   { "iso_time (confirmed_time)", NULL, KEYWORD_TYPE_STRING },                \
   { "confirmed_time", "confirmed", KEYWORD_TYPE_INTEGER },                   \
   { "iso_time (orphaned_time)", NULL, KEYWORD_TYPE_STRING },                 \
   { "orphaned_time", "orphaned", KEYWORD_TYPE_INTEGER },                     \
   { "solved_comment", NULL, KEYWORD_TYPE_STRING },                           \
   { "closed_comment", NULL, KEYWORD_TYPE_STRING },                           \
   {                                                                          \
     "(SELECT uuid FROM reports WHERE id = confirmed_report)",                \
     NULL,                                                                    \
     KEYWORD_TYPE_STRING                                                      \
   },                                                                         \
   { "nvt", NULL, KEYWORD_TYPE_STRING },                                      \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                       \
 }

/**
 * @brief Count number of tickets.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of tickets in filtered set.
 */
int
ticket_count (const get_data_t *get)
{
  static const char *extra_columns[] = TICKET_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = TICKET_ITERATOR_COLUMNS;
  static column_t trash_columns[] = TICKET_ITERATOR_TRASH_COLUMNS;

  return count ("ticket", get, columns, trash_columns, extra_columns, 0, 0, 0,
                TRUE);
}

/**
 * @brief Initialise a ticket iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 *
 * @return 0 success, 1 failed to find ticket, 2 failed to find filter,
 *         -1 error.
 */
int
init_ticket_iterator (iterator_t *iterator, const get_data_t *get)
{
  static const char *filter_columns[] = TICKET_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = TICKET_ITERATOR_COLUMNS;
  static column_t trash_columns[] = TICKET_ITERATOR_TRASH_COLUMNS;

  return init_get_iterator (iterator,
                            "ticket",
                            get,
                            columns,
                            trash_columns,
                            filter_columns,
                            0,
                            NULL,
                            NULL,
                            TRUE);
}

/**
 * @brief Get a column value from a ticket iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (ticket_iterator_user_id, GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Get a column value from a ticket iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (ticket_iterator_task_id, GET_ITERATOR_COLUMN_COUNT + 1);

/**
 * @brief Get a column value from a ticket iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (ticket_iterator_report_id, GET_ITERATOR_COLUMN_COUNT + 2);

/**
 * @brief Get a column value from a ticket iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column, or SEVERITY_MISSING if iteration is complete.
 */
double
ticket_iterator_severity (iterator_t* iterator)
{
  if (iterator->done) return SEVERITY_MISSING;
  return iterator_double (iterator, GET_ITERATOR_COLUMN_COUNT + 3);
}

/**
 * @brief Get a column value from a ticket iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (ticket_iterator_host, GET_ITERATOR_COLUMN_COUNT + 4);

/**
 * @brief Get a column value from a ticket iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (ticket_iterator_location, GET_ITERATOR_COLUMN_COUNT + 5);

/**
 * @brief Get a column value from a ticket iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value of the column or NULL if iteration is complete.
 */
DEF_ACCESS (ticket_iterator_solution_type, GET_ITERATOR_COLUMN_COUNT + 6);

/**
 * @brief Get the status from a ticket iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Status of the ticket or NULL if iteration is complete.
 */
const char*
ticket_iterator_status (iterator_t* iterator)
{
  int status;
  if (iterator->done) return NULL;
  status = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 7);
  return ticket_status_name (status);
}

/**
 * @brief Get column value from a ticket iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Iterator column value or NULL if iteration is complete.
 */
DEF_ACCESS (ticket_iterator_open_time, GET_ITERATOR_COLUMN_COUNT + 8);

/**
 * @brief Get column value from a ticket iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Iterator column value or NULL if iteration is complete.
 */
DEF_ACCESS (ticket_iterator_solved_time, GET_ITERATOR_COLUMN_COUNT + 10);

/**
 * @brief Get column value from a ticket iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Iterator column value or NULL if iteration is complete.
 */
DEF_ACCESS (ticket_iterator_closed_time, GET_ITERATOR_COLUMN_COUNT + 12);

/**
 * @brief Get column value from a ticket iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Iterator column value or NULL if iteration is complete.
 */
DEF_ACCESS (ticket_iterator_confirmed_time, GET_ITERATOR_COLUMN_COUNT + 14);

/**
 * @brief Get column value from a ticket iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Iterator column value or NULL if iteration is complete.
 */
DEF_ACCESS (ticket_iterator_orphaned_time, GET_ITERATOR_COLUMN_COUNT + 16);

/**
 * @brief Get column value from a ticket iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Iterator column value or NULL if iteration is complete.
 */
DEF_ACCESS (ticket_iterator_solved_comment, GET_ITERATOR_COLUMN_COUNT + 18);

/**
 * @brief Get column value from a ticket iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Iterator column value or NULL if iteration is complete.
 */
DEF_ACCESS (ticket_iterator_closed_comment, GET_ITERATOR_COLUMN_COUNT + 19);

/**
 * @brief Get column value from a ticket iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Iterator column value or NULL if iteration is complete.
 */
DEF_ACCESS (ticket_iterator_confirmed_report_id,
            GET_ITERATOR_COLUMN_COUNT + 20);

/**
 * @brief Get column value from a ticket iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Iterator column value or NULL if iteration is complete.
 */
DEF_ACCESS (ticket_iterator_nvt_oid, GET_ITERATOR_COLUMN_COUNT + 21);

/**
 * @brief Initialise a ticket result iterator.
 *
 * Will iterate over all the results assigned to the ticket.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  ticket_id   UUID of ticket.
 * @param[in]  trash       Whether ticket is in trash.
 *
 * @return 0 success, 1 failed to find ticket, -1 error.
 */
int
init_ticket_result_iterator (iterator_t *iterator, const gchar *ticket_id,
                             int trash)
{
  ticket_t ticket;

  if (find_resource_with_permission ("ticket", ticket_id, &ticket, NULL, trash))
    return -1;

  if (ticket == 0)
    return 1;

  init_iterator (iterator,
                 "SELECT result,"
                 "       ticket,"
                 "       (CASE"
                 "        WHEN result_location = %i"
                 "        THEN (SELECT uuid FROM results"
                 "              WHERE id = result)"
                 "        ELSE (SELECT uuid FROM results_trash"
                 "              WHERE id = result)"
                 "        END)"
                 " FROM ticket_results%s"
                 " WHERE ticket = %llu"
                 " ORDER BY id;",
                 LOCATION_TABLE,
                 trash ? "_trash" : "",
                 ticket);
  return 0;
}

/**
 * @brief Get column value from a ticket result iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Iterator column value or NULL if iteration is complete.
 */
DEF_ACCESS (ticket_result_iterator_result_id, 2);

/**
 * @brief Initialise a result ticket iterator.
 *
 * Will iterate over all the tickets that apply to the result's NVT.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  result_id   UUID of result.
 *
 * @return 0 success, 1 failed to find result, -1 error.
 */
int
init_result_ticket_iterator (iterator_t *iterator, const gchar *result_id)
{
  result_t result;

  if (find_resource_with_permission ("result", result_id, &result, NULL, 0))
    return -1;

  if (result == 0)
    return 1;

  init_iterator (iterator,
                 "SELECT id, uuid"
                 " FROM tickets"
                 " WHERE (SELECT nvt FROM results WHERE id = %llu)"
                 "       IN (SELECT nvt FROM results"
                 "           WHERE id = (SELECT result FROM ticket_results"
                 "                       WHERE ticket = tickets.id"
                 "                       AND result_location = %i"
                 "                       LIMIT 1))"
                 " ORDER BY id;",
                 result,
                 LOCATION_TABLE);
  return 0;
}

/**
 * @brief Get column value from a ticket result iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Iterator column value or NULL if iteration is complete.
 */
DEF_ACCESS (result_ticket_iterator_ticket_id, 1);

/**
 * @brief Return whether a ticket is in use.
 *
 * @param[in]  ticket  Ticket.
 *
 * @return 1 if in use, else 0.
 */
int
ticket_in_use (ticket_t ticket)
{
  return 0;
}

/**
 * @brief Return whether a trashcan ticket is in use.
 *
 * @param[in]  ticket  Ticket.
 *
 * @return 1 if in use, else 0.
 */
int
trash_ticket_in_use (ticket_t ticket)
{
  return 0;
}

/**
 * @brief Return whether a ticket is writable.
 *
 * @param[in]  ticket  Ticket.
 *
 * @return 1 if writable, else 0.
 */
int
ticket_writable (ticket_t ticket)
{
  return 1;
}

/**
 * @brief Return whether a trashcan ticket is writable.
 *
 * @param[in]  ticket  Ticket.
 *
 * @return 1 if writable, else 0.
 */
int
trash_ticket_writable (ticket_t ticket)
{
  return trash_ticket_in_use (ticket) == 0;
}

/**
 * @brief Delete a ticket.
 *
 * @param[in]  ticket_id  UUID of ticket.
 * @param[in]  ultimate   Whether to remove entirely, or to trashcan.
 *
 * @return 0 success, 1 fail because ticket is in use, 2 failed to find ticket,
 *         3 predefined ticket, 99 permission denied, -1 error.
 */
int
delete_ticket (const char *ticket_id, int ultimate)
{
  ticket_t ticket = 0;

  sql_begin_immediate ();

  if (acl_user_may ("delete_ticket") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (find_resource_with_permission ("ticket", ticket_id, &ticket,
                                     "delete_ticket", 0))
    {
      sql_rollback ();
      return -1;
    }

  if (ticket == 0)
    {
      if (find_trash ("ticket", ticket_id, &ticket))
        {
          sql_rollback ();
          return -1;
        }
      if (ticket == 0)
        {
          sql_rollback ();
          return 2;
        }
      if (ultimate == 0)
        {
          /* It's already in the trashcan. */
          sql_commit ();
          return 0;
        }

      sql ("DELETE FROM permissions"
           " WHERE resource_type = 'ticket'"
           " AND resource_location = %i"
           " AND resource = %llu;",
           LOCATION_TRASH,
           ticket);

      sql ("DELETE FROM permissions"
           " WHERE resource_type = 'task'"
           " AND comment = 'Automatically created for ticket'"
           " AND resource = (SELECT task FROM tickets_trash"
           "                 WHERE id = %llu);",
           ticket);

      tags_remove_resource ("ticket", ticket, LOCATION_TRASH);

      sql ("DELETE FROM ticket_results_trash WHERE ticket = %llu;", ticket);
      sql ("DELETE FROM tickets_trash WHERE id = %llu;", ticket);

      sql_commit ();
      return 0;
    }

  if (ultimate == 0)
    {
      ticket_t trash_ticket;

      sql ("INSERT INTO tickets_trash"
           " (uuid, owner, name, comment, nvt, task, report, severity, host,"
           "  location, solution_type, assigned_to, status, open_time,"
           "  solved_time, solved_comment, confirmed_time, confirmed_report,"
           "  closed_time, closed_comment, orphaned_time, creation_time,"
           "  modification_time)"
           " SELECT uuid, owner, name, comment, nvt, task, report, severity,"
           "        host, location, solution_type, assigned_to, status,"
           "        open_time, solved_time, solved_comment, confirmed_time,"
           "        confirmed_report, closed_time, closed_comment,"
           "        orphaned_time, creation_time, modification_time"
           " FROM tickets WHERE id = %llu;",
           ticket);

      trash_ticket = sql_last_insert_id ();

      sql ("INSERT INTO ticket_results_trash"
           " (ticket, result, result_location, result_uuid, report)"
           " SELECT %llu, result, result_location, result_uuid, report"
           " FROM ticket_results"
           " WHERE ticket = %llu;",
           trash_ticket,
           ticket);

      permissions_set_locations ("ticket", ticket, trash_ticket,
                                 LOCATION_TRASH);
      tags_set_locations ("ticket", ticket, trash_ticket,
                          LOCATION_TRASH);
    }
  else
    {
      sql ("DELETE FROM permissions"
           " WHERE resource_type = 'ticket'"
           " AND resource_location = %i"
           " AND resource = %llu;",
           LOCATION_TABLE,
           ticket);

      sql ("DELETE FROM permissions"
           " WHERE resource_type = 'task'"
           " AND comment = 'Automatically created for ticket'"
           " AND resource = (SELECT task FROM tickets"
           "                 WHERE id = %llu);",
           ticket);

      tags_remove_resource ("ticket", ticket, LOCATION_TABLE);
    }

  sql ("DELETE FROM ticket_results WHERE ticket = %llu;", ticket);
  sql ("DELETE FROM tickets WHERE id = %llu;", ticket);

  sql_commit ();
  return 0;
}

/**
 * @brief Try restore a ticket.
 *
 * Ends transaction for caller before exiting.
 *
 * @param[in]  ticket_id  UUID of resource.
 *
 * @return 0 success, 1 fail because ticket is in use, 2 failed to find ticket,
 *         3 predefined ticket, -1 error.
 */
int
restore_ticket (const char *ticket_id)
{
  ticket_t ticket;

  if (find_trash ("ticket", ticket_id, &ticket))
    {
      sql_rollback ();
      return -1;
    }

  if (ticket)
    {
      if (sql_int ("SELECT count(*) FROM tickets"
                   " WHERE name ="
                   " (SELECT name FROM tickets_trash WHERE id = %llu)"
                   " AND " ACL_USER_OWNS () ";",
                   ticket,
                   current_credentials.uuid))
        {
          sql_rollback ();
          return 3;
        }

      sql ("INSERT INTO tickets"
           " (uuid, owner, name, comment, nvt, task, report, severity, host,"
           "  location, solution_type, assigned_to, status, open_time,"
           "  solved_time, solved_comment, confirmed_time, confirmed_report,"
           "  closed_time, closed_comment, orphaned_time, creation_time,"
           "  modification_time)"
           " SELECT uuid, owner, name, comment, nvt, task, report, severity,"
           "        host, location, solution_type, assigned_to, status,"
           "        open_time, solved_time, solved_comment, confirmed_time,"
           "        confirmed_report, closed_time, closed_comment,"
           "        orphaned_time, creation_time, modification_time"
           " FROM tickets_trash WHERE id = %llu;",
           ticket);

      permissions_set_locations ("ticket", ticket,
                                 sql_last_insert_id (),
                                 LOCATION_TABLE);
      tags_set_locations ("ticket", ticket,
                          sql_last_insert_id (),
                          LOCATION_TABLE);

      sql ("DELETE FROM tickets_trash WHERE id = %llu;", ticket);
      sql_commit ();
      return 0;
    }

  return 2;
}

/**
 * @brief Create a ticket.
 *
 * @param[in]   comment         Comment on ticket.
 * @param[in]   result_id       Result that the ticket is on.
 * @param[in]   user_id         User the ticket is assigned to.
 * @param[out]  ticket          Created ticket.
 *
 * @return 0 success, 1 failed to find user, 2 failed to find result,
 *         99 permission denied, -1 error.
 */
int
create_ticket (const char *comment, const char *result_id,
               const char *user_id, ticket_t *ticket)
{
  ticket_t new_ticket;
  permission_t permission;
  user_t user;
  iterator_t results;
  get_data_t get;
  gchar *quoted_name, *quoted_comment, *quoted_oid, *quoted_host;
  gchar *quoted_location, *quoted_solution, *quoted_uuid;
  char *new_ticket_id, *task_id;
  task_t task;

  assert (current_credentials.uuid);
  assert (result_id);
  assert (user_id);

  sql_begin_immediate ();

  if (acl_user_may ("create_ticket") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (find_resource_with_permission ("user", user_id, &user, NULL, 0))
    {
      sql_rollback ();
      return -1;
    }

  if (user == 0)
    {
      sql_rollback ();
      return 1;
    }

  memset (&get, 0, sizeof (get));
  get.id = g_strdup (result_id);
  switch (init_result_get_iterator (&results, &get, 0, NULL, NULL))
    {
      case 0:
        break;
      case 1:
        g_free (get.id);
        sql_rollback ();
        return 2;
      default:
        g_free (get.id);
        sql_rollback ();
        return -1;
    }
  g_free (get.id);

  if (next (&results) == 0)
    {
      sql_rollback ();
      return -1;
    }

  if (comment)
    quoted_comment = sql_quote (comment);
  else
    quoted_comment = sql_quote ("");

  quoted_name = sql_quote (result_iterator_nvt_name (&results) ?: "");
  quoted_oid = sql_quote (result_iterator_nvt_oid (&results) ?: "");
  quoted_host = sql_quote (result_iterator_host (&results) ?: "");
  quoted_location = sql_quote (result_iterator_port (&results) ?: "");
  quoted_solution = sql_quote (result_iterator_solution_type (&results) ?: "");

  task = result_iterator_task (&results);

  sql ("INSERT INTO tickets"
       " (uuid, name, owner, comment, nvt, task, report, severity, host,"
       "  location, solution_type, assigned_to, status, open_time,"
       "  creation_time, modification_time)"
       " VALUES"
       " (make_uuid (), '%s',"
       "  (SELECT id FROM users WHERE users.uuid = '%s'),"
       "  '%s', '%s', %llu, %llu, %0.1f, '%s', '%s', '%s',"
       "  %llu, %i, m_now (), m_now (), m_now ());",
       quoted_name,
       current_credentials.uuid,
       quoted_comment,
       quoted_oid,
       task,
       result_iterator_report (&results),
       result_iterator_severity_double (&results),
       quoted_host,
       quoted_location,
       quoted_solution,
       user,
       TICKET_STATUS_OPEN);

  g_free (quoted_location);
  g_free (quoted_host);
  g_free (quoted_oid);
  g_free (quoted_comment);
  g_free (quoted_name);

  new_ticket = sql_last_insert_id ();
  if (ticket)
    *ticket = new_ticket;

  quoted_uuid = sql_quote (get_iterator_uuid (&results));

  sql ("INSERT INTO ticket_results"
       " (ticket, result, result_location, result_uuid, report)"
       " VALUES (%llu, %llu, %i, '%s', %llu)",
       new_ticket,
       result_iterator_result (&results),
       LOCATION_TABLE,
       quoted_uuid,
       result_iterator_report (&results));

  g_free (quoted_uuid);
  cleanup_iterator (&results);

  new_ticket_id = ticket_uuid (new_ticket);

  if (create_permission_internal ("modify_ticket",
                                  "Automatically created for ticket",
                                  NULL,
                                  new_ticket_id,
                                  "user",
                                  user_id,
                                  &permission))
    {
      sql_rollback ();
      return -1;
    }

  task_uuid (task, &task_id);
  if (create_permission_internal ("get_tasks",
                                  "Automatically created for ticket",
                                  NULL,
                                  task_id,
                                  "user",
                                  user_id,
                                  &permission))
    {
      free (task_id);
      sql_rollback ();
      return -1;
    }
  free (task_id);

  free (new_ticket_id);

  sql_commit ();

  return 0;
}

/**
 * @brief Create a ticket from an existing ticket.
 *
 * @param[in]  comment     Comment on new ticket.  NULL to copy from existing.
 * @param[in]  ticket_id   UUID of existing ticket.
 * @param[out] new_ticket  New ticket.
 *
 * @return 0 success, 1 ticket exists already, 2 failed to find existing
 *         ticket, 99 permission denied, -1 error.
 */
int
copy_ticket (const char *comment, const char *ticket_id, ticket_t *new_ticket)
{
  int ret;
  ticket_t old_ticket;

  assert (new_ticket);

  ret = copy_resource ("ticket", NULL, comment, ticket_id,
                       "task, report, severity, host, location, solution_type,"
                       " assigned_to, status, open_time, solved_time,"
                       " solved_comment, confirmed_time, confirmed_report,"
                       " closed_time, closed_comment, orphaned_time",
                       1, new_ticket, &old_ticket);
  if (ret)
    return ret;

  return 0;
}

/**
 * @brief Return the UUID of a ticket.
 *
 * @param[in]  ticket  Ticket.
 *
 * @return Newly allocated UUID if available, else NULL.
 */
char*
ticket_uuid (ticket_t ticket)
{
  return sql_string ("SELECT uuid FROM tickets WHERE id = %llu;",
                     ticket);
}

/**
 * @brief Modify a ticket.
 *
 * @param[in]   ticket_id       UUID of ticket.
 * @param[in]   comment         Comment on ticket.
 * @param[in]   status_name     Status of ticket.
 * @param[in]   solved_comment  Comment if status is 'Solved'.
 * @param[in]   closed_comment  Comment if status is 'Closed'.
 * @param[in]   user_id         UUID of user that ticket is assigned to.
 *
 * @return 0 success, 1 ticket exists already, 2 failed to find ticket,
 *         3 failed to find user, 4 error in status,
 *         5 Solved status requires a solved_comment,
 *         6 Closed status requires a closed_comment,
 *         99 permission denied, -1 error.
 */
int
modify_ticket (const gchar *ticket_id, const gchar *comment,
               const gchar *status_name, const gchar *solved_comment,
               const gchar *closed_comment, const gchar *user_id)
{
  ticket_t ticket;

  assert (ticket_id);

  sql_begin_immediate ();

  assert (current_credentials.uuid);

  if (acl_user_may ("modify_ticket") == 0)
    {
      sql_rollback ();
      return 99;
    }

  ticket = 0;
  if (find_resource_with_permission ("ticket", ticket_id, &ticket,
                                     "modify_ticket", 0))
    {
      sql_rollback ();
      return -1;
    }

  if (ticket == 0)
    {
      sql_rollback ();
      return 2;
    }

  if (comment)
    {
      gchar *quoted_comment;

      quoted_comment = sql_quote (comment);
      sql ("UPDATE tickets SET"
           " comment = '%s',"
           " modification_time = m_now ()"
           " WHERE id = %llu;",
           quoted_comment,
           ticket);
      g_free (quoted_comment);
    }

  if (status_name)
    {
      ticket_status_t status;
      const gchar *time_column;

      status = ticket_status_integer (status_name);
      switch (status)
        {
          case TICKET_STATUS_OPEN:
            time_column = "open_time";
            break;
          case TICKET_STATUS_SOLVED:
            {
              gchar *quoted_comment;

              time_column = "solved_time";
              if ((solved_comment == NULL) || (strlen (solved_comment) == 0))
                {
                  sql_rollback ();
                  return 5;
                }
              quoted_comment = sql_quote (solved_comment);
              sql ("UPDATE tickets SET solved_comment = '%s'"
                   " WHERE id = %llu;",
                   quoted_comment,
                   ticket);
              g_free (quoted_comment);
            }
            break;
          case TICKET_STATUS_CLOSED:
            {
              gchar *quoted_comment;

              time_column = "closed_time";
              if ((closed_comment == NULL) || (strlen (closed_comment) == 0))
                {
                  sql_rollback ();
                  return 6;
                }
              quoted_comment = sql_quote (closed_comment);
              sql ("UPDATE tickets SET closed_comment = '%s'"
                   " WHERE id = %llu;",
                   quoted_comment,
                   ticket);
              g_free (quoted_comment);
            }
            break;
          default:
            sql_rollback ();
            return 4;
        }

      sql ("UPDATE tickets SET"
           " status = %i,"
           " modification_time = m_now (),"
           " %s = m_now ()"
           " WHERE id = %llu;",
           status,
           time_column,
           ticket);
    }

  if (user_id)
    {
      user_t user;
      permission_t permission;

      if (find_resource_with_permission ("user", user_id, &user, NULL, 0))
        {
          sql_rollback ();
          return -1;
        }

      if (user == 0)
        {
          sql_rollback ();
          return 3;
        }

      sql ("UPDATE tickets SET"
           " assigned_to = %llu,"
           " modification_time = m_now ()"
           " WHERE id = %llu;",
           user,
           ticket);

      if (create_permission_internal ("modify_ticket",
                                      "Automatically created for ticket",
                                      NULL,
                                      ticket_id,
                                      "user",
                                      user_id,
                                      &permission))
        {
          sql_rollback ();
          return -1;
        }
    }


  sql_commit ();

  return 0;
}

/**
 * @brief Empty ticket trashcans.
 */
void
empty_trashcan_tickets ()
{
  sql ("DELETE FROM permissions"
       " WHERE resource_type = 'ticket'"
       " AND resource_location = %i"
       " AND resource IN (SELECT id FROM tickets_trash"
       "                  WHERE owner = (SELECT id FROM users"
       "                                 WHERE uuid = '%s'));",
       LOCATION_TRASH,
       current_credentials.uuid);

  sql ("DELETE FROM permissions"
       " WHERE resource_type = 'task'"
       " AND comment = 'Automatically created for ticket'"
       " AND resource IN (SELECT task FROM tickets_trash"
       "                  WHERE owner = (SELECT id FROM users"
       "                                 WHERE uuid = '%s'));",
       current_credentials.uuid);

  sql ("DELETE FROM ticket_results_trash"
       " WHERE ticket in (SELECT id FROM tickets_trash"
       "                  WHERE owner = (SELECT id FROM users"
       "                                 WHERE uuid = '%s'));",
       current_credentials.uuid);
  sql ("DELETE FROM tickets_trash"
       " WHERE owner = (SELECT id FROM users WHERE uuid = '%s');",
       current_credentials.uuid);
}

/**
 * @brief Check if tickets have been resolved.
 *
 * @param[in]  task  Task.
 */
void
check_tickets (task_t task)
{
  report_t report;

  if (task_last_report (task, &report))
    {
      g_warning ("%s: failed to get last report of task %llu,"
                 " skipping ticket check",
                 __FUNCTION__,
                 task);
      return;
    }

  sql ("UPDATE tickets"
       " SET status = %i,"
       "     confirmed_time = m_now (),"
       "     confirmed_report = %llu"
       " WHERE task = %llu"
       " AND (status = %i"
       "      OR status = %i)"
       /* Only if the same host was scanned. */
       " AND EXISTS (SELECT * FROM report_hosts"
       "             WHERE report = %llu"
       "             AND report_hosts.host = tickets.host)"
       /* Only if the problem result is gone. */
       " AND NOT EXISTS (SELECT * FROM results"
       "                 WHERE report = %llu"
       "                 AND nvt = (SELECT nvt FROM results"
       "                            WHERE id = (SELECT result"
       "                                        FROM ticket_results"
       "                                        WHERE ticket = tickets.id"
       "                                        AND result_location = %i"
       "                                        LIMIT 1)))"
       /* Only if there were no login failures. */
       " AND NOT EXISTS (SELECT * FROM results"
       "                 WHERE report = %llu"
       /*                SSH Login Failed For Authenticated Checks. */
       "                 AND nvt = '1.3.6.1.4.1.25623.1.0.105936')"
       " AND NOT EXISTS (SELECT * FROM results"
       "                 WHERE report = %llu"
       /*                SMG Login Failed For Authenticated Checks. */
       "                 AND nvt = '1.3.6.1.4.1.25623.1.0.106091');",
       TICKET_STATUS_CONFIRMED,
       report,
       task,
       TICKET_STATUS_OPEN,
       TICKET_STATUS_SOLVED,
       report,
       LOCATION_TABLE,
       report,
       report);
}

/**
 * @brief Set tickets to orphaned, because a report has been deleted.
 *
 * @param[in]  report  Report that is being deleted.
 */
void
tickets_set_orphans (report_t report)
{
  sql ("UPDATE tickets"
       " SET report = -1,"
       "     status = %i,"
       "     orphaned_time = m_now ()"
       " WHERE report = %llu",
       TICKET_STATUS_ORPHANED,
       report);
  sql ("DELETE FROM ticket_results WHERE report = %llu;",
       report);
  sql ("UPDATE tickets"
       " SET confirmed_report = -1"
       " WHERE confirmed_report = %llu",
       report);

  sql ("UPDATE tickets_trash"
       " SET report = -1,"
       "     status = %i,"
       "     orphaned_time = m_now ()"
       " WHERE report = %llu",
       TICKET_STATUS_ORPHANED,
       report);
  sql ("DELETE FROM ticket_results_trash WHERE report = %llu;",
       report);
  sql ("UPDATE tickets_trash"
       " SET confirmed_report = -1"
       " WHERE confirmed_report = %llu",
       report);
}

/**
 * @brief Delete all tickets owner by a user.
 *
 * Also delete trash tickets and assign any tickets that were assigned to
 * the user back to the owner.
 *
 * @param[in]  user  The user.
 */
void
delete_tickets_user (user_t user)
{
  sql ("DELETE FROM ticket_results"
       " WHERE ticket IN (SELECT id FROM tickets WHERE owner = %llu);",
       user);
  sql ("DELETE FROM tickets WHERE owner = %llu;", user);

  sql ("UPDATE tickets SET assigned_to = owner WHERE assigned_to = %llu;",
       user);

  sql ("DELETE FROM ticket_results_trash"
       " WHERE ticket IN (SELECT id FROM tickets_trash WHERE owner = %llu);",
       user);
  sql ("DELETE FROM tickets_trash WHERE owner = %llu;", user);

  sql ("UPDATE tickets_trash SET assigned_to = owner WHERE assigned_to = %llu;",
       user);
}

/**
 * @brief Change ownership of tickets, for user deletion.
 *
 * Also assign tickets that are assigned to the user to the inheritor.
 *
 * @param[in]  user       Current owner.
 * @param[in]  inheritor  New owner.
 */
void
inherit_tickets (user_t user, user_t inheritor)
{
  sql ("UPDATE tickets SET owner = %llu WHERE owner = %llu;",
       inheritor, user);
  sql ("UPDATE tickets SET assigned_to = %llu WHERE assigned_to = %llu;",
       inheritor, user);

  sql ("UPDATE tickets_trash SET owner = %llu WHERE owner = %llu;",
       inheritor, user);
  sql ("UPDATE tickets_trash SET assigned_to = %llu WHERE assigned_to = %llu;",
       inheritor, user);
}

/**
 * @brief Remove a task from all tickets.
 *
 * @param[in]  task  Task.
 */
void
tickets_remove_task (task_t task)
{
  sql ("UPDATE tickets SET task = -1 WHERE task = %llu;", task);
  sql ("UPDATE tickets_trash SET task = -1 WHERE task = %llu;", task);
}

/**
 * @brief Remove all of a user's tasks from all tickets.
 *
 * @param[in]  user  User.
 */
void
tickets_remove_tasks_user (user_t user)
{
  sql ("UPDATE tickets SET task = -1"
       " WHERE task IN (SELECT id FROM tasks WHERE owner = %llu);",
       user);
  sql ("UPDATE tickets_trash SET task = -1"
       " WHERE task IN (SELECT id FROM tasks WHERE owner = %llu);",
       user);
}

/**
 * @brief Adjust tickets for task being moved to trash.
 *
 * This must be called while the old and new results still exist.
 *
 * @param[in]  task  Task.
 */
void
tickets_trash_task (task_t task)
{
  sql ("UPDATE ticket_results"
       " SET result_location = %i,"
       "     result = (SELECT id FROM results_trash"
       "               WHERE task = %llu"
       "               AND uuid = ticket_results.result_uuid)"
       " WHERE result IN (SELECT id FROM results WHERE task = %llu);",
       LOCATION_TRASH,
       task,
       task);
  sql ("UPDATE ticket_results_trash"
       " SET result_location = %i,"
       "     result = (SELECT id FROM results_trash"
       "               WHERE task = %llu"
       "               AND uuid = ticket_results_trash.result_uuid)"
       " WHERE result IN (SELECT id FROM results WHERE task = %llu);",
       LOCATION_TRASH,
       task,
       task);
}

/**
 * @brief Adjust tickets for task being restored.
 *
 * This must be called while the old and new results still exist.
 *
 * @param[in]  task  Task.
 */
void
tickets_restore_task (task_t task)
{
  sql ("UPDATE ticket_results"
       " SET result_location = %i,"
       "     result = (SELECT id FROM results"
       "               WHERE task = %llu"
       "               AND uuid = ticket_results.result_uuid)"
       " WHERE result IN (SELECT id FROM results_trash WHERE task = %llu);",
       LOCATION_TABLE,
       task,
       task);
  sql ("UPDATE ticket_results_trash"
       " SET result_location = %i,"
       "     result = (SELECT id FROM results"
       "               WHERE task = %llu"
       "               AND uuid = ticket_results_trash.result_uuid)"
       " WHERE result IN (SELECT id FROM results_trash WHERE task = %llu);",
       LOCATION_TABLE,
       task,
       task);
}
