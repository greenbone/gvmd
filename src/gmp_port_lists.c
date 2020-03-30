/* Copyright (C) 2020 Greenbone Networks GmbH
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
 * @file gmp_port_lists.c
 * @brief GVM GMP layer: Port Lists
 *
 * GMP port lists.
 */

#include "gmp_port_lists.h"
#include "gmp_base.h"
#include "gmp_get.h"
#include "manage_port_lists.h"
#include "utils.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>


/* CREATE_PORT_LIST. */

/**
 * @brief The create_port_list command.
 */
typedef struct
{
  context_data_t *context;     ///< XML parser context.
} create_port_list_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static create_port_list_t create_port_list_data;

/**
 * @brief Reset command data.
 */
static void
create_port_list_reset ()
{
  if (create_port_list_data.context->first)
    {
      free_entity (create_port_list_data.context->first->data);
      g_slist_free_1 (create_port_list_data.context->first);
    }
  g_free (create_port_list_data.context);
  memset (&create_port_list_data, 0, sizeof (create_port_list_t));
}

/**
 * @brief Start a command.
 *
 * @param[in]  gmp_parser        GMP parser.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
create_port_list_start (gmp_parser_t *gmp_parser,
                        const gchar **attribute_names,
                        const gchar **attribute_values)
{
  memset (&create_port_list_data, 0, sizeof (create_port_list_t));
  create_port_list_data.context = g_malloc0 (sizeof (context_data_t));
  create_port_list_element_start (gmp_parser, "create_port_list", attribute_names,
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
create_port_list_element_start (gmp_parser_t *gmp_parser, const gchar *name,
                                const gchar **attribute_names,
                                const gchar **attribute_values)
{
  xml_handle_start_element (create_port_list_data.context, name, attribute_names,
                            attribute_values);
}

/**
 * @brief Get creation data from a port_list entity.
 *
 * @param[in]  port_list     Port list entity.
 * @param[out] port_list_id  Address for port list ID if required, else NULL.
 * @param[out] name          Address for name.
 * @param[out] comment       Address for comment.
 * @param[out] ranges        Address for port ranges.
 */
void
parse_port_list_entity (entity_t port_list, const char **port_list_id,
                        char **name, char **comment, array_t **ranges)
{
  entity_t entity, port_ranges;

  *name = *comment = NULL;

  if (port_list_id)
    *port_list_id = entity_attribute (port_list, "id");

  entity = entity_child (port_list, "name");
  if (entity)
    *name = entity_text (entity);

  entity = entity_child (port_list, "comment");
  if (entity)
    *comment = entity_text (entity);

  /* Collect port ranges. */

  *ranges = NULL;
  port_ranges = entity_child (port_list, "port_ranges");
  if (port_ranges)
    {
      entity_t port_range;
      entities_t children;

      *ranges = make_array ();

      children = port_ranges->entities;
      while ((port_range = first_entity (children)))
        {
          range_t *range;
          entity_t range_comment, end, start, type;

          range = g_malloc0 (sizeof (range_t));

          range_comment = entity_child (port_range, "comment");
          range->comment = range_comment ? entity_text (range_comment) : NULL;

          end = entity_child (port_range, "end");
          range->end = end ? atoi (entity_text (end)) : 0;

          /* Nothing is going to modify ID.  Casting is simpler than dealing
           * with an allocation because create_port_list may remove ranges from
           * the array. */
          range->id = (gchar *) entity_attribute (port_range, "id");

          start = entity_child (port_range, "start");
          range->start = start ? atoi (entity_text (start)) : 0;

          type = entity_child (port_range, "type");
          if (type && strcasecmp (entity_text (type), "TCP") == 0)
            range->type = PORT_PROTOCOL_TCP;
          else if (type && strcasecmp (entity_text (type), "UDP") == 0)
            range->type = PORT_PROTOCOL_UDP;
          else
            range->type = PORT_PROTOCOL_OTHER;

          range->exclude = 0;

          array_add (*ranges, range);

          children = next_entities (children);
        }
    }
}

/**
 * @brief Execute command.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
void
create_port_list_run (gmp_parser_t *gmp_parser, GError **error)
{
  port_list_t new_port_list;
  entity_t entity, get_port_lists_response, port_list, name, copy;

  entity = (entity_t) create_port_list_data.context->first->data;

  /* The import element, GET_PORT_LISTS_RESPONSE, overrides
   * any other elements. */

  get_port_lists_response = entity_child (entity, "get_port_lists_response");
  if (get_port_lists_response
      && (port_list = entity_child (get_port_lists_response, "port_list")))
    {
      char *comment, *import_name;
      const char *port_list_id;
      array_t *ranges;

      /* Get the port_list data from the XML. */

      parse_port_list_entity (port_list, &port_list_id, &import_name,
                              &comment, &ranges);

      /* Check data, then create port list. */

      if (import_name == NULL)
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("create_port_list",
                            "GET_PORT_LISTS_RESPONSE requires a"
                            " NAME element"));
      else if (strlen (import_name) == 0)
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("create_port_list",
                            "GET_PORT_LISTS_RESPONSE NAME must be"
                            " at least one character long"));
      else if (port_list_id == NULL)
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("create_port_list",
                            "GET_PORT_LISTS_RESPONSE must have an"
                            " ID attribute"));
      else if (strlen (port_list_id) == 0)
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("create_port_list",
                            "GET_PORT_LISTS_RESPONSE ID must be"
                            " at least one character long"));
      else if (!is_uuid (port_list_id))
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("create_port_list",
                            "GET_PORT_LISTS_RESPONSE ID must be"
                            " a UUID"));
      else switch (create_port_list (port_list_id,
                                     import_name,
                                     comment,
                                     NULL,  /* Optional port range string. */
                                     ranges,
                                     &new_port_list))
        {
          case 0:
            {
              char *uuid = port_list_uuid (new_port_list);
              SENDF_TO_CLIENT_OR_FAIL
               (XML_OK_CREATED_ID ("create_port_list"),
                uuid);
              log_event ("port_list", "Port List", uuid, "created");
              free (uuid);
              break;
            }
          case 1:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_port_list",
                                "Port list exists already"));
            log_event_fail ("port_list", "Port List", NULL, "created");
            break;
          case 2:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_port_list",
                                "Port list exists already, in"
                                " trashcan"));
            log_event_fail ("port_list", "Port List", NULL, "created");
            break;
          case 99:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_port_list",
                                "Permission denied"));
            log_event_fail ("port_list", "Port List", NULL, "created");
            break;
          default:
          case -1:
            SEND_TO_CLIENT_OR_FAIL
             (XML_INTERNAL_ERROR ("create_port_list"));
            log_event_fail ("port_list", "Port List", NULL, "created");
            break;
        }

      /* Cleanup. */

      array_free (ranges);

      create_port_list_reset ();
      return;
    }

  copy = entity_child (entity, "copy");
  if (copy)
    {
      entity_t comment;

      /* Copy from an existing port list. */

      name = entity_child (entity, "name");
      comment = entity_child (entity, "comment");

      switch (copy_port_list (name ? entity_text (name) : NULL,
                              comment ? entity_text (comment) : NULL,
                              entity_text (copy),
                              &new_port_list))
        {
          case 0:
            {
              char *uuid;
              uuid = port_list_uuid (new_port_list);
              SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID
                                       ("create_port_list"),
                                       uuid);
              log_event ("port_list", "Port List", uuid, "created");
              free (uuid);
              break;
            }
          case 1:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_port_list",
                                "Port List exists already"));
            log_event_fail ("port_list", "Port List", NULL, "created");
            break;
          case 2:
            if (send_find_error_to_client ("create_port_list",
                                           "port_list",
                                           entity_text (copy),
                                           gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            log_event_fail ("port_list", "Port List", NULL, "created");
            break;
          case 99:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_port_list",
                                "Permission denied"));
            log_event_fail ("port_list", "Port List", NULL, "created");
            break;
          case -1:
          default:
            SEND_TO_CLIENT_OR_FAIL
             (XML_INTERNAL_ERROR ("create_port_list"));
            log_event_fail ("port_list", "Port List", NULL, "created");
            break;
        }

      create_port_list_reset ();
      return;
    }

  /* Manually create a port list. */

  name = entity_child (entity, "name");
  if (name == NULL)
    SEND_TO_CLIENT_OR_FAIL
     (XML_ERROR_SYNTAX ("create_port_list",
                        "A NAME is required"));
  else if (strlen (entity_text (name)) == 0)
    SEND_TO_CLIENT_OR_FAIL
     (XML_ERROR_SYNTAX ("create_port_list",
                        "Name must be at"
                        " least one character long"));
  else switch (create_port_list (NULL,
                                 entity_text (name),
                                 entity_child (entity, "comment")
                                  ? entity_text (entity_child (entity,
                                                               "comment"))
                                  : NULL,
                                 entity_child (entity, "port_range")
                                  ? entity_text (entity_child (entity,
                                                               "port_range"))
                                  : NULL,
                                 NULL, /* Optional port ranges array. */
                                 &new_port_list))
    {
      case 1:
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("create_port_list",
                            "Port list exists already"));
        log_event_fail ("port_list", "Port List", NULL, "created");
        break;
      case 4:
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("create_port_list",
                            "Error in port range"));
        log_event_fail ("port_list", "Port List", NULL, "created");
        break;
      case 99:
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("create_port_list",
                            "Permission denied"));
        log_event_fail ("port_list", "Port List", NULL, "created");
        break;
      case -1:
        SEND_TO_CLIENT_OR_FAIL
         (XML_INTERNAL_ERROR ("create_port_list"));
        log_event_fail ("port_list", "Port List", NULL, "created");
        break;
      default:
        {
          char *uuid = port_list_uuid (new_port_list);
          SENDF_TO_CLIENT_OR_FAIL
           (XML_OK_CREATED_ID ("create_port_list"), uuid);
          log_event ("port_list", "Port List", uuid, "created");
          free (uuid);
          break;
        }
    }

  create_port_list_reset ();
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
create_port_list_element_end (gmp_parser_t *gmp_parser, GError **error,
                              const gchar *name)
{
  xml_handle_end_element (create_port_list_data.context, name);
  if (create_port_list_data.context->done)
    {
      create_port_list_run (gmp_parser, error);
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
create_port_list_element_text (const gchar *text, gsize text_len)
{
  xml_handle_text (create_port_list_data.context, text, text_len);
}
