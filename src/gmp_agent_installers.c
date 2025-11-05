/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Agent installers.
 *
 * GMP handlers for agent installers.
 */

#include "gmp_agent_installers.h"
#include "gmp_get.h"
#include "manage.h"
#include "manage_acl.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"

/* GET_AGENT_INSTALLERS. */

/**
 * @brief The get_agent_installers command.
 */
typedef struct
{
  get_data_t get;    ///< Get args.
} get_agent_installers_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static get_agent_installers_t get_agent_installers_data;

/**
 * @brief Reset command data.
 */
static void
get_agent_installers_reset ()
{
  get_data_reset (&get_agent_installers_data.get);
  memset (&get_agent_installers_data, 0, sizeof (get_agent_installers_t));
}

/**
 * @brief Handle command start element.
 *
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
get_agent_installers_start (const gchar **attribute_names,
                            const gchar **attribute_values)
{
  get_data_parse_attributes (&get_agent_installers_data.get,
                             "agent_installer",
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
get_agent_installers_run (gmp_parser_t *gmp_parser, GError **error)
{
  iterator_t agent_installers;
  int count, filtered, ret, first;

  count = 0;

  ret = init_get ("get_agent_installers",
                  &get_agent_installers_data.get,
                  "Agent Installers",
                  &first);
  if (ret)
    {
      switch (ret)
        {
          case 99:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("get_agent_installers",
                                "Permission denied"));
            break;
          default:
            internal_error_send_to_client (error);
            get_agent_installers_reset ();
            return;
        }
      get_agent_installers_reset ();
      return;
    }

  /* Setup the iterator. */

  ret = init_agent_installer_iterator (&agent_installers,
                                       &get_agent_installers_data.get);
  if (ret)
    {
      switch (ret)
        {
          case 1:
            if (send_find_error_to_client ("get_agent_installers",
                                           "agent_installer",
                                           get_agent_installers_data.get.id,
                                           gmp_parser))
              {
                error_send_to_client (error);
                get_agent_installers_reset ();
                return;
              }
            break;
          case 2:
            if (send_find_error_to_client
                  ("get_agent_installers", "filter",
                   get_agent_installers_data.get.filt_id, gmp_parser))
              {
                error_send_to_client (error);
                get_agent_installers_reset ();
                return;
              }
            break;
          case -1:
            SEND_TO_CLIENT_OR_FAIL
              (XML_INTERNAL_ERROR ("get_agent_installers"));
            break;
        }
      get_agent_installers_reset ();
      return;
    }

  /* Loop through agent_installers, sending XML. */

  SEND_GET_START ("agent_installer");
  while (1)
    {
      time_t last_update;
      ret = get_next (&agent_installers, &get_agent_installers_data.get, &first,
                      &count, init_agent_installer_iterator);
      if (ret == 1)
        break;
      if (ret == -1)
        {
          internal_error_send_to_client (error);
          get_agent_installers_reset ();
          return;
        }

      /* Send generic GET command elements. */

      SEND_GET_COMMON (agent_installer, &get_agent_installers_data.get,
                       &agent_installers);

      SENDF_TO_CLIENT_OR_FAIL (
        "<description>%s</description>"
        "<content_type>%s</content_type>"
        "<file_extension>%s</file_extension>"
        "<version>%s</version>"
        "<checksum>%s</checksum>",
        agent_installer_iterator_description (&agent_installers),
        agent_installer_iterator_content_type (&agent_installers),
        agent_installer_iterator_file_extension (&agent_installers),
        agent_installer_iterator_version (&agent_installers),
        agent_installer_iterator_checksum (&agent_installers)
      );

      last_update 
        = agent_installer_iterator_last_update (&agent_installers);
      SENDF_TO_CLIENT_OR_FAIL ("<last_update>%s</last_update>",
                               iso_if_time (last_update));

      SENDF_TO_CLIENT_OR_FAIL ("</agent_installer>");

      /* Send agent_installer info. */

      count++;
    }
  cleanup_iterator (&agent_installers);
  filtered = get_agent_installers_data.get.id
              ? 1
              : agent_installer_count (&get_agent_installers_data.get);
  SEND_GET_END ("agent_installer", &get_agent_installers_data.get, count, filtered);

  get_agent_installers_reset ();
}

/* GET_AGENT_INSTALLER_FILE. */

/**
 * @brief The get_agent_installers command.
 */
typedef struct
{
  char *agent_installer_id;    ///< UUID of the agent installer to get file of.
} get_agent_installer_file_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static get_agent_installer_file_t get_agent_installer_file_data;

/**
 * @brief Reset command data.
 */
static void
get_agent_installer_file_reset ()
{
  g_free (get_agent_installer_file_data.agent_installer_id);
  memset (&get_agent_installer_file_data, 0,
          sizeof (get_agent_installer_file_t));
}

/**
 * @brief Handle command start element.
 *
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
get_agent_installer_file_start (const gchar **attribute_names,
                                const gchar **attribute_values)
{
  const gchar* attribute;
  if (find_attribute (attribute_names, attribute_values,
                      "agent_installer_id", &attribute))
    get_agent_installer_file_data.agent_installer_id = g_strdup (attribute);
  else
    get_agent_installer_file_data.agent_installer_id = NULL;
}

/**
 * @brief Read an agent installer file and send it to the GMP client as Base64.
 * 
 * @param[in]  gmp_parser  The GMP parser.
 * @param[in]  stream      The file stream to read from.
 * @param[in]  validator   The validator to check validity of the file.
 * @param[out] message     Message to return in case of an error.
 * @param[out] error       GError output.
 */
int
read_agent_installer_file_and_send_base64 (gmp_parser_t *gmp_parser,
                                           FILE *stream,
                                           gvm_stream_validator_t validator,
                                           gchar **message,
                                           GError **error)
{
  gvm_stream_validator_return_t validator_return;
  char file_buffer[AGENT_INSTALLER_READ_BUFFER_SIZE];
  char base64_buffer[AGENT_INSTALLER_BASE64_WITH_BREAKS_BUFFER_SIZE + 1];
  size_t read_bytes, base64_bytes;
  gint base64_state = 0;
  gint base64_save = 0;

  do {
    read_bytes = fread (file_buffer,
                        1,
                        AGENT_INSTALLER_READ_BUFFER_SIZE,
                        stream);
    if (read_bytes)
      {
        validator_return = gvm_stream_validator_write (validator,
                                                       file_buffer,
                                                       read_bytes);
        if (validator_return)
          {
            if (message)
              *message = g_strdup_printf ("file validation failed: %s",
                                          gvm_stream_validator_return_str (
                                            validator_return));
            gvm_stream_validator_free (validator);
            return -1;
          }

        base64_bytes = g_base64_encode_step ((guchar*) file_buffer,
                                             read_bytes,
                                             TRUE,
                                             base64_buffer,
                                             &base64_state,
                                             &base64_save);
        base64_buffer[base64_bytes] = 0;
        if (send_to_client (base64_buffer, gmp_parser->client_writer,
                            gmp_parser->client_writer_data))
          {
            error_send_to_client (error);
            return -1;
          }
      }
  } while (read_bytes);
  
  if (ferror (stream))
    {
      if (message)
        *message = g_strdup_printf ("error reading installer file: %s",
                                    strerror (errno));
      return -1;
    }

  validator_return = gvm_stream_validator_end (validator);
  if (validator_return)
    {
      if (message)
        *message = g_strdup_printf ("%s",
                                    gvm_stream_validator_return_str (
                                      validator_return));
      return -1;
    }

  base64_bytes = g_base64_encode_close (TRUE,
                                        base64_buffer,
                                        &base64_state,
                                        &base64_save);
  base64_buffer[base64_bytes] = 0;
  if (send_to_client (base64_buffer, gmp_parser->client_writer,
                      gmp_parser->client_writer_data))
    {
      error_send_to_client (error);
      return -1;
    }

  return 0;
}

/**
 * @brief Handle end element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
void
get_agent_installer_file_run (gmp_parser_t *gmp_parser, GError **error)
{
  int ret;
  get_data_t get;
  iterator_t iterator;
  FILE *file;
  gvm_stream_validator_t validator = NULL;
  gvm_stream_validator_return_t validator_return;
  gchar *file_validity = NULL;

  memset (&get, 0, sizeof (get_data_t));
  get.type = "agent_installer";
  get.id = get_agent_installer_file_data.agent_installer_id;

  if (!acl_user_may ("get_agent_installer"))
    {
      SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("get_agent_installer_file",
                              "Permission denied"));
      get_agent_installer_file_reset ();
      return;
    }

  if (get.id == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("get_agent_installer_file",
                              "Required agent_installer_id is missing"));
      get_agent_installer_file_reset ();
      return;
    }

  init_agent_installer_iterator (&iterator, &get);
  if (next (&iterator) == 0)
    {
      if (send_find_error_to_client ("get_agent_installer_file",
                                     "agent_installer",
                                     get.id,
                                     gmp_parser))
        {
          error_send_to_client (error);
        }
      cleanup_iterator (&iterator);
      get_agent_installer_file_reset ();
      return;
    }

  validator_return
    = gvm_stream_validator_new (agent_installer_iterator_checksum (&iterator),
                                &validator);
  if (validator_return)
    {
      SENDF_TO_CLIENT_OR_FAIL 
        (XML_ERROR_UNAVAILABLE ("get_agent_installer_file",
                                "error in expected checksum: %s"),
         gvm_stream_validator_return_str (validator_return));
      cleanup_iterator (&iterator);
      get_agent_installer_file_reset ();
      return;
    }

  file = open_agent_installer_file (
    agent_installer_iterator_installer_path (&iterator),
    &file_validity);
  if (file == NULL 
      || (! agent_installer_stream_is_valid (file, validator, &file_validity)))
    {
      SENDF_TO_CLIENT_OR_FAIL 
        (XML_ERROR_UNAVAILABLE ("get_agent_installer_file",
                                "%s"),
         file_validity);
      cleanup_iterator (&iterator);
      gvm_stream_validator_free (validator);
      g_free (file_validity);
      if (file)
        fclose (file);
      get_agent_installer_file_reset ();
      return;
    }

  g_free (file_validity);
  file_validity = NULL;
  gvm_stream_validator_rewind (validator);
  rewind (file);
  if (ftell (file))
    {
      g_warning ("%s: error rewinding file stream", __func__);
      SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_agent_installer_file"));
      cleanup_iterator (&iterator);
      gvm_stream_validator_free (validator);
      fclose (file);
      get_agent_installer_file_reset ();
      return;
    }

  SENDF_TO_CLIENT_OR_FAIL ("<get_agent_installer_file_response"
                           " status=\"200\" status_text=\"OK\">"
                           "<file agent_installer_id=\"%s\">"
                           "<name>%s</name>"
                           "<content_type>%s</content_type>"
                           "<file_extension>%s</file_extension>"
                           "<checksum>%s</checksum>"
                           "<content>",
                           get.id,
                           get_iterator_name (&iterator),
                           agent_installer_iterator_content_type (&iterator),
                           agent_installer_iterator_file_extension (&iterator),
                           agent_installer_iterator_checksum (&iterator));

  ret = read_agent_installer_file_and_send_base64 (gmp_parser,
                                                   file,
                                                   validator,
                                                   &file_validity,
                                                   error);

  cleanup_iterator (&iterator);
  gvm_stream_validator_free (validator);
  fclose (file);
  get_agent_installer_file_reset ();

  if (ret)
    {
      g_warning ("%s: re-reading file for base64 output failed: %s",
                 __func__, file_validity);
      g_free (file_validity);
      return;
    }
  g_free (file_validity);

  SEND_TO_CLIENT_OR_FAIL ("</content>"
                          "</file>"
                          "</get_agent_installer_file_response>");

}

