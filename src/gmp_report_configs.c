/* Copyright (C) 2024 Greenbone AG
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
 * @brief GVM GMP layer: Report Configs
 *
 * GMP report configurations.
 */

#include "gmp_report_configs.h"
#include "gmp_base.h"
#include "gmp_get.h"
#include "manage_report_configs.h"
#include "utils.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>


/* General helper functions */

/**
 * @brief Collect params from entity.
 *
 * @param[in] entity  Entity to check for param elements.
 *
 * @return Array of params
 */
array_t *
params_from_entity (entity_t entity)
{
  array_t *params;
  entities_t children;
  entity_t param_entity;

  params = make_array ();
  children = entity->entities;
  while ((param_entity = first_entity (children)))
    {
      children = children->next;

      if (strcmp (entity_name (param_entity), "param") == 0)
        {
          report_config_param_data_t *param;
          entity_t param_name, param_value;

          param = g_malloc0 (sizeof (*param));

          param_name = entity_child (param_entity, "name");
          if (param_name)
            {
              param->name = g_strstrip (g_strdup (entity_text (param_name)));
              if (strcmp (param->name, "") == 0)
                {
                  g_warning ("%s: got param with empty name", __func__);
                  report_config_param_data_free (param);
                  continue;
                }
            }
          else
            {
              g_warning ("%s: got param without name", __func__);
              report_config_param_data_free (param);
              continue;
            }

          param_value = entity_child (param_entity, "value");
          if (param_value)
            {
              const char *use_default_str;

              param->value = g_strdup (entity_text (param_value));
              use_default_str = entity_attribute (param_value, "use_default");
              if (use_default_str)
                {
                  param->use_default_value = (atoi(use_default_str) != 0);
                }
            }
          else
            {
              g_warning ("%s: got param \"%s\" without value",
                         __func__, param_name->text);
              report_config_param_data_free (param);
              continue;
            }


          array_add (params, param);
        }
    }

  array_terminate (params);
  return params;
}

/**
 * @brief Free an array of report config param structs and its elements
 *
 * @param[in]  array  Pointer to array.
 */
static void
param_array_free (GPtrArray *array)
{
  if (array)
    {
      guint index = array->len;
      while (index--)
        report_config_param_data_free (g_ptr_array_index (array, index));

      g_ptr_array_free (array, TRUE);
    }
}


/* CREATE_REPORT_CONFIG. */

/**
 * @brief The create_report_config command.
 */
typedef struct
{
  context_data_t *context;     ///< XML parser context.
} create_report_config_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static create_report_config_t create_report_config_data;

/**
 * @brief Reset command data.
 */
static void
create_report_config_reset ()
{
  if (create_report_config_data.context->first)
    {
      free_entity (create_report_config_data.context->first->data);
      g_slist_free_1 (create_report_config_data.context->first);
    }
  g_free (create_report_config_data.context);
  memset (&create_report_config_data, 0, sizeof (create_report_config_t));
}

/**
 * @brief Start a command.
 *
 * @param[in]  gmp_parser        GMP parser.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
create_report_config_start (gmp_parser_t *gmp_parser,
                            const gchar **attribute_names,
                            const gchar **attribute_values)
{
  memset (&create_report_config_data, 0, sizeof (create_report_config_t));
  create_report_config_data.context = g_malloc0 (sizeof (context_data_t));
  create_report_config_element_start (gmp_parser, "create_report_config",
                                      attribute_names, attribute_values);
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
create_report_config_element_start (gmp_parser_t *gmp_parser,
                                    const gchar *name,
                                    const gchar **attribute_names,
                                    const gchar **attribute_values)
{
  xml_handle_start_element (create_report_config_data.context, name,
                            attribute_names, attribute_values);
}

/**
 * @brief Execute command.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
void
create_report_config_run (gmp_parser_t *gmp_parser, GError **error)
{
  report_config_t new_report_config;
  entity_t entity, name, copy, comment, report_format;
  const char *report_format_id;
  array_t *params;
  int ret;
  gchar *error_message = NULL;

  entity = (entity_t) create_report_config_data.context->first->data;

  copy = entity_child (entity, "copy");
  if (copy)
    {
      /* Copy from an existing report config. */

      name = entity_child (entity, "name");

      switch (copy_report_config (name ? entity_text (name) : NULL,
                                  entity_text (copy),
                                  &new_report_config))
        {
          case 0:
            {
              char *uuid;
              uuid = report_config_uuid (new_report_config);
              SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID
                                       ("create_report_config"),
                                       uuid);
              log_event ("report_config", "Report Config", uuid, "created");
              free (uuid);
              break;
            }
          case 1:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_report_config",
                                "Report Config exists already"));
            log_event_fail ("report_config", "Report Config", NULL, "created");
            break;
          case 2:
            if (send_find_error_to_client ("create_report_config",
                                           "Report Config",
                                           entity_text (copy),
                                           gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            log_event_fail ("report_config", "Report Config", NULL, "created");
            break;
          case 3:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_report_config",
                                "Report Format for Config must have params"));
            log_event_fail ("report_config", "Report Config", NULL, "created");
            break;
          case 99:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_report_config",
                                "Permission denied"));
            log_event_fail ("report_config", "Report Config", NULL, "created");
            break;
          case -1:
          default:
            SEND_TO_CLIENT_OR_FAIL
             (XML_INTERNAL_ERROR ("create_report_config"));
            log_event_fail ("report_config", "Report Config", NULL, "created");
            break;
        }

      create_report_config_reset ();
      return;
    }

  /* Create new report config */

  name = entity_child (entity, "name");
  comment = entity_child (entity, "comment");
  report_format = entity_child (entity, "report_format");
  report_format_id = NULL;
  if (report_format)
    report_format_id = entity_attribute (report_format, "id");

  if (name == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("create_report_config",
                           "A NAME element is required"));
      create_report_config_reset ();
      return;
    }
  else if (strlen (name->text) == 0)
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("create_report_config",
                           "The NAME element must not be empty"));
      create_report_config_reset ();
      return;
    }
  else if (report_format_id == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("create_report_config",
                           "A REPORT_FORMAT element with an ID attribute"
                           " is required"));
      create_report_config_reset ();
      return;
    }

  params = params_from_entity (entity);

  ret = create_report_config (name->text,
                              comment ? comment->text : NULL,
                              report_format_id,
                              params,
                              &new_report_config,
                              &error_message);

  switch (ret)
    {
      case 0:
        {
          char *uuid = report_config_uuid (new_report_config);
          SENDF_TO_CLIENT_OR_FAIL
            (XML_OK_CREATED_ID ("create_report_config"), uuid);
          log_event ("report_config", "Report Config", uuid, "created");
          free (uuid);
          break;
        }
      case 1:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("create_report_config",
                             "Report config with given name exists already"));
        log_event_fail ("report_config", "Report Config", NULL, "created");
        break;
      case 2:
        if (send_find_error_to_client ("create_report_config",
                                       "Report Format",
                                       report_format_id,
                                       gmp_parser))
          {
            error_send_to_client (error);
            return;
          }
        log_event_fail ("report_config", "Report Config", NULL, "created");
        break;
      case 3:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("create_report_config",
                             "Given report format does not have any"
                             " configurable parameters."));
        log_event_fail ("report_config", "Report Config", NULL, "created");
        break;
      case 4:
        SENDF_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("create_report_config",
                             "Parameter validation failed: %s"),
           error_message);
        log_event_fail ("report_config", "Report Config", NULL, "created");
        break;
      case 99:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("create_report_config",
                             "Permission config"));
        log_event_fail ("report_config", "Report Config", NULL, "created");
        break;
      default:
        SEND_TO_CLIENT_OR_FAIL
          (XML_INTERNAL_ERROR ("create_report_config"));
        log_event_fail ("report_config", "Report Config", NULL, "created");
        break;
    }

  g_free (error_message);
  param_array_free (params);
  create_report_config_reset ();
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
create_report_config_element_end (gmp_parser_t *gmp_parser, GError **error,
                                  const gchar *name)
{
  xml_handle_end_element (create_report_config_data.context, name);
  if (create_report_config_data.context->done)
    {
      create_report_config_run (gmp_parser, error);
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
create_report_config_element_text (const gchar *text, gsize text_len)
{
  xml_handle_text (create_report_config_data.context, text, text_len);
}


/* MODIFY_REPORT_CONFIG */

/**
 * @brief The modify_report_config command.
 */
typedef struct
{
  context_data_t *context;     ///< XML parser context.
} modify_report_config_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static modify_report_config_t modify_report_config_data;

/**
 * @brief Reset command data.
 */
static void
modify_report_config_reset ()
{
  if (modify_report_config_data.context->first)
    {
      free_entity (modify_report_config_data.context->first->data);
      g_slist_free_1 (modify_report_config_data.context->first);
    }
  g_free (modify_report_config_data.context);
  memset (&modify_report_config_data, 0, sizeof (modify_report_config_t));
}

/**
 * @brief Start a command.
 *
 * @param[in]  gmp_parser        GMP parser.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
modify_report_config_start (gmp_parser_t *gmp_parser,
                            const gchar **attribute_names,
                            const gchar **attribute_values)
{
  memset (&modify_report_config_data, 0, sizeof (modify_report_config_t));
  modify_report_config_data.context = g_malloc0 (sizeof (context_data_t));
  modify_report_config_element_start (gmp_parser, "modify_report_config",
                                      attribute_names, attribute_values);
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
modify_report_config_element_start (gmp_parser_t *gmp_parser, const gchar *name,
                                    const gchar **attribute_names,
                                    const gchar **attribute_values)
{
  xml_handle_start_element (modify_report_config_data.context, name,
                            attribute_names, attribute_values);
}

/**
 * @brief Execute command.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
void
modify_report_config_run (gmp_parser_t *gmp_parser, GError **error)
{
  entity_t entity, name, comment;
  const char *report_config_id;
  array_t *params;
  int ret;
  gchar *error_message = NULL;

  entity = (entity_t) modify_report_config_data.context->first->data;

  report_config_id = entity_attribute(entity, "report_config_id");
  name = entity_child (entity, "name");
  comment = entity_child (entity, "comment");

  if (report_config_id == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("modify_report_config",
                           "A report_config_id attribute is required"));
      modify_report_config_reset ();
      return;
    }
  else if (name && strlen (name->text) == 0)
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("modify_report_config",
                           "The NAME element must not be empty"));
      modify_report_config_reset ();
      return;
    }

  params = params_from_entity (entity);

  ret = modify_report_config (report_config_id,
                              name ? name->text : NULL,
                              comment ? comment->text : NULL,
                              params,
                              &error_message);

  switch (ret)
    {
      case 0:
        {
          SENDF_TO_CLIENT_OR_FAIL
            (XML_OK ("modify_report_config"));
          log_event ("report_config", "Report Config", report_config_id,
                     "modified");
          break;
        }
      case 1:
        if (send_find_error_to_client ("modify_report_config",
                                       "Report Config",
                                       report_config_id,
                                       gmp_parser))
          {
            error_send_to_client (error);
            return;
          }
        log_event_fail ("report_config", "Report Config", report_config_id,
                        "modified");
        break;
      case 2:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_report_config",
                             "Report config with given name exists already"));
        log_event_fail ("report_config", "Report Config", NULL, "modified");
        break;
      case 3:
        SENDF_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_report_config",
                             "Cannot modify params of"
                             " an orphaned report config"));
        log_event_fail ("report_config", "Report Config", report_config_id,
                        "modified");
        break;
      case 4:
        SENDF_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_report_config",
                             "Parameter validation failed: %s"),
           error_message);
        log_event_fail ("report_config", "Report Config", report_config_id,
                        "modified");
        break;
      case 99:
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_report_config",
                             "Permission config"));
        log_event_fail ("report_config", "Report Config", report_config_id,
                        "modified");
        break;
      default:
        SEND_TO_CLIENT_OR_FAIL
          (XML_INTERNAL_ERROR ("modify_report_config"));
        log_event_fail ("report_config", "Report Config", report_config_id,
                        "modified");
        break;
    }

  g_free (error_message);
  param_array_free (params);
  modify_report_config_reset ();
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
modify_report_config_element_end (gmp_parser_t *gmp_parser, GError **error,
                              const gchar *name)
{
  xml_handle_end_element (modify_report_config_data.context, name);
  if (modify_report_config_data.context->done)
    {
      modify_report_config_run (gmp_parser, error);
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
modify_report_config_element_text (const gchar *text, gsize text_len)
{
  xml_handle_text (modify_report_config_data.context, text, text_len);
}
