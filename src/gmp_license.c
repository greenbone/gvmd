/* Copyright (C) 2021-2022 Greenbone AG
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
 * @brief GVM GMP layer: License information
 *
 * This includes function and variable definitions for GMP handling
 *  of license information.
 */

#include "gmp_license.h"
#include "manage_license.h"
#include "utils.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"

/* GET_LICENSE. */

/**
 * @brief The get_license command.
 */
typedef struct
{
  context_data_t *context;     ///< XML parser context.
} get_license_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static get_license_t get_license_data;

/**
 * @brief Reset command data.
 */
static void
get_license_reset ()
{
  if (get_license_data.context->first)
    {
      free_entity (get_license_data.context->first->data);
      g_slist_free_1 (get_license_data.context->first);
    }
  g_free (get_license_data.context);
  memset (&get_license_data, 0, sizeof (get_license_t));
}

/**
 * @brief Start a command.
 *
 * @param[in]  gmp_parser        GMP parser.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
get_license_start (gmp_parser_t *gmp_parser,
                   const gchar **attribute_names,
                   const gchar **attribute_values)
{
  memset (&get_license_data, 0, sizeof (get_license_t));
  get_license_data.context = g_malloc0 (sizeof (context_data_t));
  get_license_element_start (gmp_parser, "get_license",
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
get_license_element_start (gmp_parser_t *gmp_parser,
                           const gchar *name,
                           const gchar **attribute_names,
                           const gchar **attribute_values)
{
  xml_handle_start_element (get_license_data.context, name,
                            attribute_names, attribute_values);
}

/**
 * @brief Writes license data to a GString as XML
 *
 * @param[in]  response     The GString buffer to write the license content to.
 * @param[in]  license_data The license data struct to get the data from.
 */
static void
buffer_license_content_xml (GString *response, theia_license_t *license_data)
{
#ifdef HAS_LIBTHEIA
  if (license_data == NULL)
    {
      xml_string_append (response, "<content></content>");
      return;
    }

  xml_string_append (response,
                     "<content>"
                     "<meta>"
                     "<id>%s</id>"
                     "<version>%s</version>"
                     "<comment>%s</comment>"
                     "<type>%s</type>"
                     "<customer_name>%s</customer_name>",
                     license_data->meta->id,
                     license_data->meta->version,
                     license_data->meta->comment,
                     license_data->meta->type,
                     license_data->meta->customer_name);

  xml_string_append (response,
                     "<created>%s</created>",
                     iso_time (&license_data->meta->created));
  xml_string_append (response,
                     "<begins>%s</begins>",
                     iso_time (&license_data->meta->begins));
  xml_string_append (response,
                     "<expires>%s</expires>",
                     iso_time (&license_data->meta->expires));

  xml_string_append (response,
                     "</meta>"
                     "<appliance>"
                     "<model>%s</model>"
                     "<model_type>%s</model_type>"
                     "<sensor>%d</sensor>"
                     "</appliance>"
                     "<keys>"
                     "<key name=\"feed\">%s</key>"
                     "</keys>"
                     "<signatures>"
                     "<signature name=\"license\">%s</signature>"
                     "</signatures>"
                     "</content>",
                     license_data->appliance->model,
                     license_data->appliance->model_type,
                     license_data->appliance->sensor,
                     license_data->keys->feed,
                     license_data->signatures->license);

#else // HAS_LIBTHEIA
  xml_string_append (response, "<content></content>");
#endif // HAS_LIBTHEIA
}


/**
 * @brief Execute command.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
get_license_run (gmp_parser_t *gmp_parser,
                 GError **error)
{
  int ret;

  gchar *license_status;
  theia_license_t *license_data;

  license_status = NULL;
  license_data = NULL;

  ret = manage_get_license (&license_status,
                            &license_data);

  switch (ret)
    {
      case 0:
        {
          GString *response;

          response = g_string_new ("");
          xml_string_append (response,
                             "<get_license_response status=\"%s\""
                             " status_text=\"%s\">"
                             "<license>"
                             "<status>%s</status>",
                             STATUS_OK,
                             STATUS_OK_TEXT,
                             license_status);

          if (license_data)
            {
              buffer_license_content_xml (response, license_data);
            }

          xml_string_append (response,
                             "</license>"
                             "</get_license_response>");

          SEND_TO_CLIENT_OR_FAIL (response->str);
          g_string_free (response, TRUE);
        }
        break;
      case 1:
        SENDF_TO_CLIENT_OR_FAIL
         ("<get_license_response status=\"%s\""
          " status_text=\"Licensing service unavailable.\"/>",
          STATUS_SERVICE_DOWN);
        break;
      case 2:
        SENDF_TO_CLIENT_OR_FAIL
         ("<get_license_response status=\"%s\""
          " status_text=\"Could not send get.license command.\"/>",
          STATUS_SERVICE_DOWN);
        break;
      case 3:
        SENDF_TO_CLIENT_OR_FAIL
         ("<get_license_response status=\"%s\""
          " status_text=\"Could not retrieve got.license response.\"/>",
          STATUS_SERVICE_DOWN);
        break;
      case 99:
        SEND_TO_CLIENT_OR_FAIL (XML_ERROR_ACCESS ("get_license"));
        break;
      default:
        SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_license"));
        break;
    }

  g_free (license_status);

#ifdef HAS_LIBTHEIA
  theia_license_free (license_data);
#endif

  get_license_reset ();
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
get_license_element_end (gmp_parser_t *gmp_parser,
                         GError **error,
                         const gchar *name)
{
  xml_handle_end_element (get_license_data.context, name);
  if (get_license_data.context->done)
    {
      get_license_run (gmp_parser, error);
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
get_license_element_text (const gchar *text,
                          gsize text_len)
{
  xml_handle_text (get_license_data.context, text, text_len);
}


/* MODIFY_LICENSE. */

/**
 * @brief The modify_license command.
 */
typedef struct
{
  context_data_t *context;     ///< XML parser context.
} modify_license_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static modify_license_t modify_license_data;

/**
 * @brief Reset command data.
 */
static void
modify_license_reset ()
{
  if (modify_license_data.context->first)
    {
      free_entity (modify_license_data.context->first->data);
      g_slist_free_1 (modify_license_data.context->first);
    }
  g_free (modify_license_data.context);
  memset (&modify_license_data, 0, sizeof (modify_license_t));
}

/**
 * @brief Start a command.
 *
 * @param[in]  gmp_parser        GMP parser.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
modify_license_start (gmp_parser_t *gmp_parser,
                      const gchar **attribute_names,
                      const gchar **attribute_values)
{
  memset (&modify_license_data, 0, sizeof (modify_license_t));
  modify_license_data.context = g_malloc0 (sizeof (context_data_t));
  modify_license_element_start (gmp_parser, "modify_license",
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
modify_license_element_start (gmp_parser_t *gmp_parser,
                              const gchar *name,
                              const gchar **attribute_names,
                              const gchar **attribute_values)
{
  xml_handle_start_element (modify_license_data.context, name,
                            attribute_names, attribute_values);
}

/**
 * @brief Handles modifying the license
 *
 * @param[in]  file_content         The content of the new license file.
 * @param[in]  allow_empty          Whether to allow an empty file.
 * @param[out] error_msg            The error message of the license update
 *                                  if any
 *
 * @return 0 success, 1 service unavailable, 2 empty file not allowed,
 *         99 permission denied.
 */
static int
modify_license (gchar *file_content, gboolean allow_empty, char **error_msg)
{
  if (allow_empty == FALSE
      && (file_content == NULL || strcmp (file_content, "") == 0))
    return 4;

  return manage_update_license_file(file_content, error_msg);
}

/**
 * @brief Execute command.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
modify_license_run (gmp_parser_t *gmp_parser,
                    GError **error)
{
  entity_t entity, file_entity;
  const char *allow_empty_str;
  char *error_msg;
  int allow_empty, ret;

  entity = (entity_t) modify_license_data.context->first->data;

  allow_empty_str = entity_attribute (entity, "allow_empty");
  allow_empty = allow_empty_str ? atoi(allow_empty_str) != 0 : 0;

  file_entity = entity_child (entity, "file");

  ret = modify_license (file_entity ? file_entity->text : NULL, allow_empty,
                        &error_msg);
  switch (ret)
    {
      case 0:
        SENDF_TO_CLIENT_OR_FAIL
         ("<modify_license_response status=\"%s\""
          " status_text=\"%s\">"
          " </modify_license_response>",
          STATUS_OK,
          STATUS_OK_TEXT);
        break;
      case 1:
        SENDF_TO_CLIENT_OR_FAIL
         ("<modify_license_response status=\"%s\""
          " status_text=\"Licensing service unavailable.\"/>",
          STATUS_SERVICE_DOWN);
        break;
      case 2:
        SENDF_TO_CLIENT_OR_FAIL
         ("<modify_license_response status=\"%s\""
          " status_text=\"Could not send modify.license command.\"/>",
          STATUS_SERVICE_DOWN);
        break;
      case 3:
        SENDF_TO_CLIENT_OR_FAIL
         ("<modify_license_response status=\"%s\""
          " status_text=\"Could not retrieve modify.license response.\"/>",
          STATUS_SERVICE_DOWN);
        break;
      case 4:
        SENDF_TO_CLIENT_OR_FAIL
         (XML_ERROR_SYNTAX ("modify_license",
                            "A non-empty FILE is required."));
        break;
      case 5:
        if (error_msg)
          {
            SENDF_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("modify_license",
                                "%s"), error_msg);
            g_free (error_msg);
          }
        else
          {
            SENDF_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("modify_license",
                                "License could not be updated."));
          }
        break;
      case 99:
        SEND_TO_CLIENT_OR_FAIL (XML_ERROR_ACCESS ("modify_license"));
        break;
      default:
        SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_license"));
        break;
    }

  modify_license_reset ();
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
modify_license_element_end (gmp_parser_t *gmp_parser,
                            GError **error,
                            const gchar *name)
{
  xml_handle_end_element (modify_license_data.context, name);
  if (modify_license_data.context->done)
    {
      modify_license_run (gmp_parser, error);
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
modify_license_element_text (const gchar *text,
                             gsize text_len)
{
  xml_handle_text (modify_license_data.context, text, text_len);
}
