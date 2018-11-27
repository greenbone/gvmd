/* GVM
 * $Id$
 * Description: GVM GMP layer: Tickets.
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
 * @file gmp_tickets.c
 * @brief GVM GMP layer: Tickets
 *
 * GMP tickets.
 */

#include "gmp_tickets.h"
#include "gmp_base.h"
#include "gmp_get.h"
#include "manage_tickets.h"

#include <glib.h>
#include <stdlib.h>
#include <string.h>

#include <gvm/util/xmlutils.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"


/* GET_TICKETS. */

/**
 * @brief The get_tickets command.
 */
typedef struct
{
  get_data_t get;    ///< Get args.
} get_tickets_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static get_tickets_t get_tickets_data;

/**
 * @brief Reset command data.
 */
static void
get_tickets_reset ()
{
  get_data_reset (&get_tickets_data.get);
  memset (&get_tickets_data, 0, sizeof (get_tickets_t));
}

/**
 * @brief Handle command start element.
 *
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
get_tickets_start (const gchar **attribute_names,
                   const gchar **attribute_values)
{
  get_data_parse_attributes (&get_tickets_data.get, "ticket",
                             attribute_names,
                             attribute_values);
}

/**
 * @brief Handle end element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
void
get_tickets_run (gmp_parser_t *gmp_parser, GError **error)
{
  iterator_t tickets;
  int count, filtered, ret, first;

  count = 0;

  ret = init_get ("get_tickets",
                  &get_tickets_data.get,
                  "Tickets",
                  &first);
  if (ret)
    {
      switch (ret)
        {
          case 99:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("get_tickets",
                                "Permission denied"));
            break;
          default:
            internal_error_send_to_client (error);
            get_tickets_reset ();
            return;
        }
      get_tickets_reset ();
      return;
    }

  ret = init_ticket_iterator (&tickets, &get_tickets_data.get);
  if (ret)
    {
      switch (ret)
        {
          case 1:
            if (send_find_error_to_client ("get_tickets",
                                           "ticket",
                                           get_tickets_data.get.id,
                                           gmp_parser))
              {
                error_send_to_client (error);
                get_tickets_reset ();
                return;
              }
            break;
          case 2:
            if (send_find_error_to_client
                  ("get_tickets", "filter",
                   get_tickets_data.get.filt_id, gmp_parser))
              {
                error_send_to_client (error);
                get_tickets_reset ();
                return;
              }
            break;
          case -1:
            SEND_TO_CLIENT_OR_FAIL
              (XML_INTERNAL_ERROR ("get_tickets"));
            break;
        }
      get_tickets_reset ();
      return;
    }

  SEND_GET_START ("ticket");
  while (1)
    {
      const char *host;

      ret = get_next (&tickets, &get_tickets_data.get, &first,
                      &count, init_ticket_iterator);
      if (ret == 1)
        break;
      if (ret == -1)
        {
          internal_error_send_to_client (error);
          get_tickets_reset ();
          return;
        }

      SEND_GET_COMMON (ticket, &get_tickets_data.get, &tickets);

      host = ticket_iterator_host (&tickets);

      SENDF_TO_CLIENT_OR_FAIL ("<host>%s</host>",
                               host);

      SEND_TO_CLIENT_OR_FAIL ("</ticket>");
      count++;
    }
  cleanup_iterator (&tickets);
  filtered = get_tickets_data.get.id
              ? 1
              : ticket_count (&get_tickets_data.get);
  SEND_GET_END ("ticket", &get_tickets_data.get, count, filtered);

  get_tickets_reset ();
}


/* CREATE_TICKET. */

#if 0
/**
 * @brief Command layout.
 */
typedef struct
{
  gchar *name,
  spec_t elements[]
} spec_t;

spec_t spec = {
                "create_ticket",
                [
                  { "name", [] },
                  { "comment", [] },
                  { "copy", [] },
                  { "result", [] },
                  { NULL, [] }
                ]
              };
#endif

/**
 * @brief The create_ticket command.
 */
typedef struct
{
  context_data_t *context;     ///< XML parser context.
} create_ticket_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static create_ticket_t create_ticket_data;

/**
 * @brief Reset command data.
 */
static void
create_ticket_reset ()
{
  if (create_ticket_data.context->first)
    {
      free_entity (create_ticket_data.context->first->data);
      g_slist_free_1 (create_ticket_data.context->first);
    }
  g_free (create_ticket_data.context);
  memset (&create_ticket_data, 0, sizeof (get_tickets_t));
}

/**
 * @brief Start a command.
 *
 * @param[in]  gmp_parser        GMP parser.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
create_ticket_start (gmp_parser_t *gmp_parser,
                     const gchar **attribute_names,
                     const gchar **attribute_values)
{
  memset (&create_ticket_data, 0, sizeof (get_tickets_t));
  create_ticket_data.context = g_malloc0 (sizeof (context_data_t));
  create_ticket_element_start (gmp_parser, "create_ticket", attribute_names,
                               attribute_values);
}

/**
 * @brief Start element.
 *
 * @param[in]  gmp_parser        GMP parser.
 * @param[in]  name              Element name.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
create_ticket_element_start (gmp_parser_t *gmp_parser, const gchar *name,
                             const gchar **attribute_names,
                             const gchar **attribute_values)
{
  //element_start (&spec, create_ticket_data.context...);
  xml_handle_start_element (create_ticket_data.context, name, attribute_names,
                            attribute_values);
}

/**
 * @brief Execute command.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
void
create_ticket_run (gmp_parser_t *gmp_parser, GError **error)
{
  entity_t entity, copy, name, comment;
  ticket_t new_ticket;

  entity = (entity_t) create_ticket_data.context->first->data;

  copy = entity_child (entity, "copy");
  name = entity_child (entity, "name");

  if (copy)
    {
      comment = entity_child (entity, "comment");
      switch (copy_ticket (entity_text (name),
                           comment ? entity_text (comment) : "",
                           entity_text (copy),
                           &new_ticket))
        {
          case 0:
            {
              char *uuid;
              uuid = ticket_uuid (new_ticket);
              SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_ticket"),
                                       uuid);
              log_event ("ticket", "Ticket", uuid, "created");
              free (uuid);
              break;
            }
          case 1:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_ticket",
                                "Ticket exists already"));
            log_event_fail ("ticket", "Ticket", NULL, "created");
            break;
          case 2:
            if (send_find_error_to_client ("create_ticket", "ticket",
                                           entity_text (copy),
                                           gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            log_event_fail ("ticket", "Ticket", NULL, "created");
            break;
          case 99:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_ticket",
                                "Permission denied"));
            log_event_fail ("ticket", "Ticket", NULL, "created");
            break;
          case -1:
          default:
            SEND_TO_CLIENT_OR_FAIL
             (XML_INTERNAL_ERROR ("create_ticket"));
            log_event_fail ("ticket", "Ticket", NULL, "created");
            break;
        }
      create_ticket_reset (create_ticket_data);
      return;
    }

  comment = entity_child (entity, "comment");

  if (name == NULL)
    SEND_TO_CLIENT_OR_FAIL
     (XML_ERROR_SYNTAX ("create_ticket",
                        "CREATE_TICKET requires a NAME"));
  else if (strlen (entity_text (name)) == 0)
    SEND_TO_CLIENT_OR_FAIL
     (XML_ERROR_SYNTAX ("create_ticket",
                        "CREATE_TICKET name must be at"
                        " least one character long"));
  else switch (create_ticket
                (entity_text (name),
                 comment ? entity_text (comment) : "",
                 &new_ticket))
    {
      case 1:
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("create_ticket",
                            "Ticket exists already"));
        log_event_fail ("ticket", "Ticket", NULL, "created");
        break;
      case 99:
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("create_ticket",
                            "Permission denied"));
        log_event_fail ("ticket", "Ticket", NULL, "created");
        break;
      case -1:
        SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_ticket"));
        log_event_fail ("ticket", "Ticket", NULL, "created");
        break;
      default:
        {
          char *uuid = ticket_uuid (new_ticket);
          SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_ticket"),
                                   uuid);
          log_event ("ticket", "Ticket", uuid, "created");
          free (uuid);
          break;
        }
    }

  create_ticket_reset (create_ticket_data);
}

/**
 * @brief End element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 * @param[in]  name         Element name.
 *
 * @return 0 success, 1 command finished.
 */
int
create_ticket_element_end (gmp_parser_t *gmp_parser, GError **error,
                           const gchar *name)
{
  //element_end (&spec, create_ticket_data.context...);
  xml_handle_end_element (create_ticket_data.context, name);
  if (create_ticket_data.context->done)
    {
      create_ticket_run (gmp_parser, error);
      return 1;
    }
  return 0;
}

/**
 * @brief Add text to element.
 *
 * @param[in]  text         Text.
 * @param[in]  text_len     Text length.
 */
void
create_ticket_element_text (const gchar *text, gsize text_len)
{
  //element_text (&spec, create_ticket_data.context...);
  xml_handle_text (create_ticket_data.context, text, text_len);
}
