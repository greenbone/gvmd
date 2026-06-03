/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Agent installer instruction.
 *
 * GMP handlers for agent installer instructions.
 */

#include "gmp_agent_installer_instructions.h"
#include "manage.h"
#include "manage_acl.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"

/* GET_AGENT_INSTALLER_INSTRUCTION. */

/**
 * @brief The get_agent_installer_instruction command.
 */
typedef struct
{
  gchar *scanner_id;  ///< UUID of the scanner.
  gchar *language;    ///< Requested instruction language, e.g. "en" or "de".
} get_agent_installer_instruction_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static get_agent_installer_instruction_t get_agent_installer_instruction_data;

/**
 * @brief Reset command data.
 */
static void
get_agent_installer_instruction_reset ()
{
  g_free (get_agent_installer_instruction_data.scanner_id);
  g_free (get_agent_installer_instruction_data.language);

  memset (&get_agent_installer_instruction_data,
          0,
          sizeof (get_agent_installer_instruction_t));
}

/**
 * @brief Check whether an instruction language is supported.
 *
 * @param[in] language  Language string.
 *
 * @return TRUE if supported, FALSE otherwise.
 */
static gboolean
instruction_language_is_supported (const gchar *language)
{
  return (g_strcmp0 (language, "en") == 0
          || g_strcmp0 (language, "de") == 0);
}

/**
 * @brief Handle command start element.
 *
 * @param[in] attribute_names   All attribute names.
 * @param[in] attribute_values  All attribute values.
 */
void
get_agent_installer_instruction_start (const gchar **attribute_names,
                                       const gchar **attribute_values)
{
  const gchar *attribute;

  if (find_attribute (attribute_names, attribute_values,
                      "scanner_id", &attribute))
    get_agent_installer_instruction_data.scanner_id = g_strdup (attribute);
  else
    get_agent_installer_instruction_data.scanner_id = NULL;

  if (find_attribute (attribute_names, attribute_values,
                      "language", &attribute))
    get_agent_installer_instruction_data.language = g_strdup (attribute);
  else
    get_agent_installer_instruction_data.language = NULL;
}

/**
 * @brief Handle end element.
 *
 * @param[in] gmp_parser  GMP parser.
 * @param[in] error       Error parameter.
 */
void
get_agent_installer_instruction_run (gmp_parser_t *gmp_parser, GError **error)
{
  instructions_lang_type_t lang_type;
  agent_controller_installer_instruction_t instruction;

  if (!acl_user_may ("get_scanners"))
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("get_agent_installer_instruction",
                           "Permission denied"));
      get_agent_installer_instruction_reset ();
      return;
    }

  if (get_agent_installer_instruction_data.scanner_id == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("get_agent_installer_instruction",
                           "Required scanner_id is missing"));
      get_agent_installer_instruction_reset ();
      return;
    }

  if (get_agent_installer_instruction_data.language == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("get_agent_installer_instruction",
                           "Required language is missing"));
      get_agent_installer_instruction_reset ();
      return;
    }

  if (!instruction_language_is_supported
        (get_agent_installer_instruction_data.language))
    {
      SENDF_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("get_agent_installer_instruction",
                           "Unsupported language '%s'"),
         get_agent_installer_instruction_data.language);
      get_agent_installer_instruction_reset ();
      return;
    }

  lang_type = lang_type_from_string
                (get_agent_installer_instruction_data.language);

  instruction = get_agent_installer_instruction
                  (get_agent_installer_instruction_data.scanner_id,
                   lang_type);

  if (instruction == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_UNAVAILABLE ("get_agent_installer_instruction",
                                "Failed to get installer instruction"));
      get_agent_installer_instruction_reset ();
      return;
    }

  SENDF_TO_CLIENT_OR_FAIL
    ("<get_agent_installer_instruction_response"
     " status=\"200\" status_text=\"OK\">"
     "<language>%s</language>"
     "<instruction>%s</instruction>"
     "</get_agent_installer_instruction_response>",
     get_agent_installer_instruction_data.language,
     instruction->instruction ? instruction->instruction : "");

  g_free (instruction->instruction);
  g_free (instruction);

  get_agent_installer_instruction_reset ();
}
