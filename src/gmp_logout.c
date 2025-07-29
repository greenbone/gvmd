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
 * @brief GVM GMP layer: Logout handling
 *
 * This includes functions for GMP handling of the user logout.
 */

#include "gmp_logout.h"
#include "manage.h"

/**
 * @brief The logout command.
 */
typedef struct
{
  context_data_t *context;     ///< XML parser context.
} logout_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static logout_t logout_data;

/**
 * @brief Reset command data.
 */
static void
logout_reset ()
{
  if (logout_data.context->first)
    {
      free_entity (logout_data.context->first->data);
      g_slist_free_1 (logout_data.context->first);
    }
  g_free (logout_data.context);
  memset (&logout_data, 0, sizeof (logout_t));
}

/**
 * @brief Start a command.
 *
 * @param[in]  gmp_parser        GMP parser.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
logout_start (gmp_parser_t *gmp_parser,
              const gchar **attribute_names,
              const gchar **attribute_values)
{
  memset (&logout_data, 0, sizeof (logout_t));
  logout_data.context = g_malloc0 (sizeof (context_data_t));
  logout_element_start (gmp_parser, "logout",
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
logout_element_start (gmp_parser_t *gmp_parser,
                           const gchar *name,
                           const gchar **attribute_names,
                           const gchar **attribute_values)
{
  xml_handle_start_element (logout_data.context, name,
                            attribute_names, attribute_values);
}

/**
 * @brief Execute command.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
static void
logout_run (gmp_parser_t *gmp_parser,
            GError **error)
{
  logout_user ();
  SEND_TO_CLIENT_OR_FAIL ("<logout_response status=\"200\" status_text=\"User logged out\"/>");
  logout_reset ();
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
logout_element_end (gmp_parser_t *gmp_parser,
                    GError **error,
                    const gchar *name)
{
  xml_handle_end_element (logout_data.context, name);
  if (logout_data.context->done)
    {
      logout_run (gmp_parser, error);
      return 1;
    }
  return 0;
}
