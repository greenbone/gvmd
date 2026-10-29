/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GMP handlers for agent inventory authentication.
 */

#include "gmp_agent_inventory_authentication.h"

#include "manage.h"
#include "manage_acl.h"
#include "manage_agent_inventory_authentication.h"
#include "manage_runtime_flags.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"

/* GET_AGENT_INVENTORY_TOKEN. */

/**
 * @brief Handle the get_agent_inventory_token start element.
 *
 * @param[in] attribute_names   Unused attribute names.
 * @param[in] attribute_values  Unused attribute values.
 */
void
get_agent_inventory_token_start (const gchar **attribute_names,
                                 const gchar **attribute_values)
{
  /* This command has no attributes or parser data to initialize. */
  (void) attribute_names;
  (void) attribute_values;
}


/**
 * @brief Execute the get_agent_inventory_token command.
 *
 * @param[in]  gmp_parser  Parser for the authenticated GMP connection.
 * @param[out] error       Error on failure to send the response.
 */
void
get_agent_inventory_token_run (gmp_parser_t *gmp_parser, GError **error)
{
#if ENABLE_AGENTS
  gchar *token = NULL;
  gchar *response;
  int ret;

  if (!acl_user_may ("get_agents"))
    {
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("get_agent_inventory_token", "Permission denied"));
      return;
    }

  ret = generate_agent_inventory_token (&token);

  switch (ret)
    {
    case AGENT_INVENTORY_TOKEN_OK:
      response = g_markup_printf_escaped (
        "<get_agent_inventory_token_response"
        " status=\"" STATUS_OK
        "\" status_text=\"" STATUS_OK_TEXT "\">"
        "<token>%s</token>"
        "</get_agent_inventory_token_response>",
        token);
      break;

    case AGENT_INVENTORY_TOKEN_UNAVAILABLE:
      response = g_strdup (XML_ERROR_UNAVAILABLE (
        "get_agent_inventory_token",
        "Agent inventory token issuance is unavailable"));
      break;

    case AGENT_INVENTORY_TOKEN_ERROR:
    default:
      response = g_strdup (
        XML_INTERNAL_ERROR ("get_agent_inventory_token"));
      break;
    }

  g_free (token);

  ret = send_to_client (response, gmp_parser->client_writer,
                        gmp_parser->client_writer_data);

  g_free (response);

  if (ret)
    {
      error_send_to_client (error);
      return;
    }

#else
  SEND_TO_CLIENT_OR_FAIL (
    XML_ERROR_UNAVAILABLE ("get_agent_inventory_token", "Command unavailable"));
#endif
}
