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
 * @file gmp_report_formats.c
 * @brief GVM GMP layer: Report Formats
 *
 * GMP report formats.
 */

#include "gmp_report_formats.h"
#include "gmp_base.h"
#include "gmp_get.h"
#include "manage_report_formats.h"
#include "utils.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>


/* CREATE_REPORT_FORMAT. */

/**
 * @brief The create_report_format command.
 */
typedef struct
{
  context_data_t *context;     ///< XML parser context.
} create_report_format_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static create_report_format_t create_report_format_data;

/**
 * @brief Reset command data.
 */
static void
create_report_format_reset ()
{
  if (create_report_format_data.context->first)
    {
      free_entity (create_report_format_data.context->first->data);
      g_slist_free_1 (create_report_format_data.context->first);
    }
  g_free (create_report_format_data.context);
  memset (&create_report_format_data, 0, sizeof (create_report_format_t));
}

/**
 * @brief Start a command.
 *
 * @param[in]  gmp_parser        GMP parser.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
create_report_format_start (gmp_parser_t *gmp_parser,
                        const gchar **attribute_names,
                        const gchar **attribute_values)
{
  memset (&create_report_format_data, 0, sizeof (create_report_format_t));
  create_report_format_data.context = g_malloc0 (sizeof (context_data_t));
  create_report_format_element_start (gmp_parser, "create_report_format", attribute_names,
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
create_report_format_element_start (gmp_parser_t *gmp_parser, const gchar *name,
                                const gchar **attribute_names,
                                const gchar **attribute_values)
{
  xml_handle_start_element (create_report_format_data.context, name, attribute_names,
                            attribute_values);
}

/**
 * @brief Return text of child if child exists, else NULL.
 *
 * @param[in]  entity  Entity.
 * @param[in]  name    Name of child.
 *
 * @return Text of child if there is such a child, else NULL.
 */
static char *
child_or_null (entity_t entity, const gchar *name)
{
  entity_t child;

  child = entity_child (entity, name);
  if (child)
    return entity_text (child);
  return NULL;
}

/**
 * @brief Free a "params_options".
 *
 * @param[in] params_options  Param options.
 */
void
params_options_free (array_t *params_options)
{
  if (params_options)
    {
      guint index = params_options->len;
      while (index--)
        {
          array_t *options;
          options = (array_t*) g_ptr_array_index (params_options, index);
          if (options)
            array_free (options);
        }
      g_ptr_array_free (params_options, TRUE);
    }
}

/**
 * @brief Get creation data from a report_format entity.
 *
 * @param[in]  report_format     Report format entity.
 * @param[out] report_format_id  Address for report format ID if required, else NULL.
 * @param[out] name              Address for name.
 * @param[out] content_type      Address for content type.
 * @param[out] extension         Address for extension.
 * @param[out] summary           Address for summary.
 * @param[out] description       Address for description.
 * @param[out] signature         Address for signature.
 * @param[out] files             Address for files.
 * @param[out] params            Address for params.
 * @param[out] params_options    Address for param options.
 */
void
parse_report_format_entity (entity_t report_format,
                            const char **report_format_id, char **name,
                            char **content_type, char **extension,
                            char **summary, char **description,
                            char **signature, array_t **files,
                            array_t **params, array_t **params_options)
{
  entity_t file, param_entity;
  entities_t children;

  if (report_format_id)
    *report_format_id = entity_attribute (report_format, "id");

  *name = child_or_null (report_format, "name");
  *content_type = child_or_null (report_format, "content_type");
  *extension = child_or_null (report_format, "extension");
  *summary = child_or_null (report_format, "summary");
  *description = child_or_null (report_format, "description");
  *signature = child_or_null (report_format, "signature");

  *files = make_array ();
  *params = make_array ();
  *params_options = make_array ();

  /* Collect files. */

  children = report_format->entities;
  while ((file = first_entity (children)))
    {
      if (strcmp (entity_name (file), "file") == 0)
        {
          const char *file_name;

          file_name = entity_attribute (file, "name");
          if (file_name)
            {
              const char *content;
              gchar *combined;

              content = entity_text (file);
              combined = g_strconcat (file_name, "0", content, NULL);
              combined[strlen (file_name)] = '\0';
              array_add (*files, combined);
            }
        }
      children = next_entities (children);
    }
  array_terminate (*files);

  /* Collect params. */

  children = report_format->entities;
  while ((param_entity = first_entity (children)))
    {
      if (strcmp (entity_name (param_entity), "param") == 0)
        {
          create_report_format_param_t *param;
          entity_t type, options_entity;
          array_t *options;

          options = make_array ();

          param = g_malloc0 (sizeof (*param));

          if (entity_child (param_entity, "default"))
            param->fallback = g_strdup (entity_text (entity_child (param_entity,
                                                                   "default")));

          if (entity_child (param_entity, "name"))
            param->name = g_strdup (entity_text (entity_child (param_entity,
                                                               "name")));
          else
            param->name = g_strdup ("");

          type = entity_child (param_entity, "type");
          if (type)
            {
              param->type = g_strstrip (g_strdup (entity_text (type)));
              if (entity_child (type, "max"))
                param->type_max = g_strdup (entity_text (entity_child (type,
                                                                       "max")));
              if (entity_child (type, "min"))
                param->type_min = g_strdup (entity_text (entity_child (type,
                                                                       "min")));
            }

          if (entity_child (param_entity, "value"))
            param->value = g_strdup (entity_text (entity_child (param_entity,
                                                                "value")));
          else
            param->value = g_strdup ("");

          array_add (*params, param);

          /* Collect options for the param. */

          options_entity = entity_child (param_entity, "options");
          if (options_entity)
            {
              entities_t options_children;
              entity_t option;

              options_children = options_entity->entities;
              while ((option = first_entity (options_children)))
                {
                  if (strcmp (entity_name (option), "option") == 0)
                    array_add (options, g_strdup (entity_text (option)));

                  options_children = next_entities (options_children);
                }
            }

          array_terminate (options);
          array_add (*params_options, options);
        }
      children = next_entities (children);
    }

  array_terminate (*params_options);
  array_terminate (*params);
}

/**
 * @brief Execute command.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
void
create_report_format_run (gmp_parser_t *gmp_parser, GError **error)
{
  report_format_t new_report_format;
  entity_t entity, get_report_formats_response, report_format, name, copy;

  entity = (entity_t) create_report_format_data.context->first->data;

  copy = entity_child (entity, "copy");
  if (copy)
    {
      /* Copy from an existing report format. */

      name = entity_child (entity, "name");

      switch (copy_report_format (name ? entity_text (name) : NULL,
                                  entity_text (copy),
                                  &new_report_format))
        {
          case 0:
            {
              char *uuid;
              uuid = report_format_uuid (new_report_format);
              SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID
                                       ("create_report_format"),
                                       uuid);
              log_event ("report_format", "Report Format", uuid, "created");
              free (uuid);
              break;
            }
          case 1:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_report_format",
                                "Report Format exists already"));
            log_event_fail ("report_format", "Report Format", NULL, "created");
            break;
          case 2:
            if (send_find_error_to_client ("create_report_format",
                                           "report_format",
                                           entity_text (copy),
                                           gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            log_event_fail ("report_format", "Report Format", NULL, "created");
            break;
          case 99:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_report_format",
                                "Permission denied"));
            log_event_fail ("report_format", "Report Format", NULL, "created");
            break;
          case -1:
          default:
            SEND_TO_CLIENT_OR_FAIL
             (XML_INTERNAL_ERROR ("create_report_format"));
            log_event_fail ("report_format", "Report Format", NULL, "created");
            break;
        }

      create_report_format_reset ();
      return;
    }

  /* No COPY, must by importing. */

  get_report_formats_response = entity_child (entity, "get_report_formats_response");
  if (get_report_formats_response
      && (report_format = entity_child (get_report_formats_response, "report_format")))
    {
      char *import_name, *content_type, *extension, *summary, *description;
      char *signature;
      const char *report_format_id;
      array_t *files, *params, *params_options;

      /* Get the report_format data from the XML. */

      parse_report_format_entity (report_format, &report_format_id,
                                  &import_name, &content_type, &extension,
                                  &summary, &description, &signature, &files,
                                  &params, &params_options);

      /* Check data, then create report format. */

      if (import_name == NULL)
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("create_report_format",
                            "GET_REPORT_FORMATS_RESPONSE requires a"
                            " NAME element"));
      else if (strlen (import_name) == 0)
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("create_report_format",
                            "GET_REPORT_FORMATS_RESPONSE NAME must be"
                            " at least one character long"));
      else if (report_format_id == NULL)
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("create_report_format",
                            "GET_REPORT_FORMATS_RESPONSE must have an"
                            " ID attribute"));
      else if (strlen (report_format_id) == 0)
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("create_report_format",
                            "GET_REPORT_FORMATS_RESPONSE ID must be"
                            " at least one character long"));
      else if (!is_uuid (report_format_id))
        SEND_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("create_report_format",
                            "GET_REPORT_FORMATS_RESPONSE ID must be"
                            " a UUID"));
      else switch (create_report_format (report_format_id,
                                         import_name,
                                         content_type,
                                         extension,
                                         summary,
                                         description,
                                         files,
                                         params,
                                         params_options,
                                         signature,
                                         &new_report_format))
        {
          case -1:
            SEND_TO_CLIENT_OR_FAIL
             (XML_INTERNAL_ERROR ("create_report_format"));
            log_event_fail ("report_format", "Report Format", NULL,
                            "created");
            break;
          case 1:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_report_format",
                                "Report format exists already"));
            log_event_fail ("report_format", "Report Format", NULL,
                            "created");
            break;
          case 2:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_report_format",
                                "Every FILE must have a name"
                                " attribute"));
            log_event_fail ("report_format", "Report Format", NULL,
                            "created");
            break;
          case 3:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_report_format",
                                "Parameter value validation failed"));
            log_event_fail ("report_format", "Report Format", NULL,
                            "created");
            break;
          case 4:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_report_format",
                                "Parameter default validation failed"));
            log_event_fail ("report_format", "Report Format", NULL,
                            "created");
            break;
          case 5:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_report_format",
                                "PARAM requires a DEFAULT element"));
            log_event_fail ("report_format", "Report Format", NULL,
                            "created");
            break;
          case 6:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_report_format",
                                "PARAM MIN or MAX out of range"));
            log_event_fail ("report_format", "Report Format", NULL,
                            "created");
            break;
          case 7:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_report_format",
                                "PARAM requires a TYPE element"));
            log_event_fail ("report_format", "Report Format", NULL,
                            "created");
            break;
          case 8:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_report_format",
                                "Duplicate PARAM name"));
            log_event_fail ("report_format", "Report Format", NULL,
                            "created");
            break;
          case 9:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_report_format",
                                "Bogus PARAM type"));
            log_event_fail ("report_format", "Report Format", NULL,
                            "created");
            break;
          case 99:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_report_format",
                                "Permission denied"));
            log_event_fail ("report_format", "Report Format", NULL,
                            "created");
            break;
          default:
            {
              char *uuid = report_format_uuid (new_report_format);
              SENDF_TO_CLIENT_OR_FAIL
               (XML_OK_CREATED_ID ("create_report_format"),
                uuid);
              log_event ("report_format", "Report Format", uuid, "created");
              free (uuid);
              break;
            }
        }

      /* Cleanup. */

      array_free (files);
      params_options_free (params_options);
      array_free (params);

      create_report_format_reset ();
      return;
    }

  /* Must have COPY or GET_REPORT_FORMATS_RESPONSE. */

  SEND_TO_CLIENT_OR_FAIL
   (XML_ERROR_SYNTAX ("create_report_format",
                      "Either a GET_REPORT_FORMATS_RESPONSE or a COPY is"
                      " required"));
  log_event_fail ("report_format", "Report Format", NULL, "created");
  create_report_format_reset ();
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
create_report_format_element_end (gmp_parser_t *gmp_parser, GError **error,
                              const gchar *name)
{
  xml_handle_end_element (create_report_format_data.context, name);
  if (create_report_format_data.context->done)
    {
      create_report_format_run (gmp_parser, error);
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
create_report_format_element_text (const gchar *text, gsize text_len)
{
  xml_handle_text (create_report_format_data.context, text, text_len);
}
