/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Agent support bundle.
 *
 * GMP handlers for downloading agent support bundles.
 */

#include "gmp_agent_support_bundle.h"

#include "manage.h"
#include "manage_acl.h"

#undef G_LOG_DOMAIN

/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"

/* GET_AGENT_SUPPORT_BUNDLE. */

/**
 * @brief The get_agent_support_bundle command.
 */
typedef struct
{
  gchar *agent_uuid; ///< UUID of the agent.
  gchar *days;       ///< Optional number of days to include.
} get_agent_support_bundle_t;

/**
 * @brief Parser callback data.
 *
 * This is initially zero because it is a global variable.
 */
static get_agent_support_bundle_t get_agent_support_bundle_data;

/**
 * @brief Reset command data.
 */
static void
get_agent_support_bundle_reset (void)
{
  g_free (get_agent_support_bundle_data.agent_uuid);
  g_free (get_agent_support_bundle_data.days);

  memset (&get_agent_support_bundle_data,
          0,
          sizeof (get_agent_support_bundle_t));
}

/**
 * @brief Handle command start element.
 *
 * @param[in] attribute_names  All attribute names.
 * @param[in] attribute_values All attribute values.
 */
void
get_agent_support_bundle_start (const gchar **attribute_names,
                                const gchar **attribute_values)
{
  const gchar *attribute;

  if (find_attribute (attribute_names, attribute_values,
                      "agent_uuid", &attribute))
    get_agent_support_bundle_data.agent_uuid = g_strdup (attribute);

  if (find_attribute (attribute_names, attribute_values,
                      "days", &attribute))
    get_agent_support_bundle_data.days = g_strdup (attribute);
}

/**
 * @brief Parse the optional days attribute.
 *
 * @param[out] days Parsed number of days.
 *
 * @return TRUE if valid, FALSE otherwise.
 */
static gboolean
get_agent_support_bundle_parse_days (int *days)
{
  gchar *end = NULL;
  gint64 parsed;

  if (!days)
    return FALSE;

  *days = 0;

  if (!get_agent_support_bundle_data.days)
    return TRUE;

  parsed = g_ascii_strtoll (get_agent_support_bundle_data.days, &end, 10);

  if (end == get_agent_support_bundle_data.days
      || *end != '\0'
      || parsed < 0
      || parsed > G_MAXINT)
    return FALSE;

  *days = (int) parsed;
  return TRUE;
}

#define AGENT_SUPPORT_BUNDLE_READ_BUFFER_SIZE 4096
#define AGENT_SUPPORT_BUNDLE_BASE64_BUFFER_SIZE \
  (((AGENT_SUPPORT_BUNDLE_READ_BUFFER_SIZE + 2) / 3) * 4 + 16)

/**
 * @brief Send binary data to the GMP client as Base64.
 *
 * @param[in] gmp_parser GMP parser.
 * @param[in] data Binary data to encode.
 * @param[in] size Size of the binary data.
 * @param[out] error GError output.
 *
 * @return 0 on success, -1 on error.
 */
static int
send_agent_support_bundle_base64 (gmp_parser_t *gmp_parser,
                                  const guint8 *data,
                                  gsize size,
                                  GError **error)
{
  gchar base64_buffer[AGENT_SUPPORT_BUNDLE_BASE64_BUFFER_SIZE];
  gsize offset = 0;
  gint base64_state = 0;
  gint base64_save = 0;
  gsize chunk_size;
  gsize encoded_size;

  if (!gmp_parser || (!data && size > 0))
    return -1;

  while (offset < size)
    {
      chunk_size =
        MIN ((gsize) AGENT_SUPPORT_BUNDLE_READ_BUFFER_SIZE,
             size - offset);

      encoded_size =
        g_base64_encode_step (data + offset,
                              chunk_size,
                              FALSE,
                              base64_buffer,
                              &base64_state,
                              &base64_save);

      base64_buffer[encoded_size] = '\0';

      if (encoded_size
          && send_to_client (base64_buffer,
                             gmp_parser->client_writer,
                             gmp_parser->client_writer_data))
        {
          error_send_to_client (error);
          return -1;
        }

      offset += chunk_size;
    }

  encoded_size =
    g_base64_encode_close (FALSE,
                           base64_buffer,
                           &base64_state,
                           &base64_save);

  base64_buffer[encoded_size] = '\0';

  if (encoded_size
      && send_to_client (base64_buffer,
                         gmp_parser->client_writer,
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
 * @param[in] gmp_parser GMP parser.
 * @param[in] error      Error parameter.
 */
void
get_agent_support_bundle_run (gmp_parser_t *gmp_parser, GError **error)
{
  agent_controller_support_bundle_t bundle = NULL;
  agent_response_t result;
  gchar *escaped_filename = NULL;
  int days;
  int ret;

  if (!acl_user_may ("get_agents"))
    {
      SEND_TO_CLIENT_OR_FAIL
      (XML_ERROR_SYNTAX ("get_agent_support_bundle",
        "Permission denied"));
      get_agent_support_bundle_reset ();
      return;
    }

  if (!get_agent_support_bundle_data.agent_uuid
      || *get_agent_support_bundle_data.agent_uuid == '\0')
    {
      SEND_TO_CLIENT_OR_FAIL
      (XML_ERROR_SYNTAX ("get_agent_support_bundle",
        "Required agent_uuid is missing"));
      get_agent_support_bundle_reset ();
      return;
    }

  if (!get_agent_support_bundle_parse_days (&days))
    {
      SEND_TO_CLIENT_OR_FAIL
      (XML_ERROR_SYNTAX ("get_agent_support_bundle",
        "Invalid days value"));
      get_agent_support_bundle_reset ();
      return;
    }

  result =
    get_agent_support_bundle (get_agent_support_bundle_data.agent_uuid,
                              days,
                              &bundle);

  switch (result)
    {
    case AGENT_RESPONSE_SUCCESS:
      break;

    case AGENT_RESPONSE_AGENT_NOT_FOUND:
      SEND_TO_CLIENT_OR_FAIL
      (XML_ERROR_SYNTAX ("get_agent_support_bundle",
        "Agent not found"));
      get_agent_support_bundle_reset ();
      return;

    case AGENT_RESPONSE_INVALID_ARGUMENT:
      SEND_TO_CLIENT_OR_FAIL
      (XML_ERROR_SYNTAX ("get_agent_support_bundle",
        "Invalid arguments"));
      get_agent_support_bundle_reset ();
      return;

    case AGENT_RESPONSE_SCANNER_LOOKUP_FAILED:
      SEND_TO_CLIENT_OR_FAIL
      (XML_ERROR_UNAVAILABLE ("get_agent_support_bundle",
        "Failed to find scanner for agent"));
      get_agent_support_bundle_reset ();
      return;

    case AGENT_RESPONSE_CONNECTOR_CREATION_FAILED:
      SEND_TO_CLIENT_OR_FAIL
      (XML_ERROR_UNAVAILABLE ("get_agent_support_bundle",
        "Failed to connect to Agent Controller"));
      get_agent_support_bundle_reset ();
      return;

    default:
      SEND_TO_CLIENT_OR_FAIL
      (XML_ERROR_UNAVAILABLE ("get_agent_support_bundle",
        "Failed to download support bundle"));
      get_agent_support_bundle_reset ();
      return;
    }

  if (!bundle || !bundle->data || bundle->size == 0)
    {
      SEND_TO_CLIENT_OR_FAIL
      (XML_ERROR_UNAVAILABLE ("get_agent_support_bundle",
        "Received an empty support bundle"));
      agent_controller_support_bundle_free (bundle);
      get_agent_support_bundle_reset ();
      return;
    }

  escaped_filename =
    g_markup_escape_text (bundle->filename ? bundle->filename : "", -1);

  SENDF_TO_CLIENT_OR_FAIL
  ("<get_agent_support_bundle_response"
   " status=\"200\" status_text=\"OK\">"
   "<file>"
   "<name>%s</name>"
   "<content_type>application/octet-stream</content_type>"
   "<size>%" G_GSIZE_FORMAT "</size>"
   "<content encoding=\"base64\">",
   escaped_filename,
   bundle->size);

  g_free (escaped_filename);

  ret =
    send_agent_support_bundle_base64 (gmp_parser,
                                      bundle->data,
                                      bundle->size,
                                      error);

  if (ret)
    {
      g_warning ("%s: Failed to send support bundle to GMP client",
                 __func__);

      agent_controller_support_bundle_free (bundle);
      get_agent_support_bundle_reset ();
      return;
    }

  SEND_TO_CLIENT_OR_FAIL
  ("</content>"
    "</file>"
    "</get_agent_support_bundle_response>");

  agent_controller_support_bundle_free (bundle);
  get_agent_support_bundle_reset ();
}
