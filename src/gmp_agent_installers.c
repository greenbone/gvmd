/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gmp_agent_installers.c
 * @brief GVM GMP layer: Agent installers.
 *
 * GMP handlers for agent installers.
 */

#include "gmp_agent_installers.h"
#include "gmp_get.h"
#include "manage.h"

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
        "<checksum>%s</checksum>"
        "<file_size>%d</file_size>",
        agent_installer_iterator_description (&agent_installers),
        agent_installer_iterator_content_type (&agent_installers),
        agent_installer_iterator_file_extension (&agent_installers),
        agent_installer_iterator_version (&agent_installers),
        agent_installer_iterator_checksum (&agent_installers),
        agent_installer_iterator_file_size (&agent_installers)
      );

      last_update 
        = agent_installer_iterator_last_update (&agent_installers);
      SENDF_TO_CLIENT_OR_FAIL ("<last_update>%s</last_update>",
                               iso_if_time (last_update));
      
      if (get_agent_installers_data.get.details)
        {
          gchar *file_validity;
          iterator_t cpes_iterator;
          
          agent_installer_file_is_valid (
              agent_installer_iterator_installer_path (&agent_installers),
              agent_installer_iterator_checksum (&agent_installers),
              agent_installer_iterator_file_size (&agent_installers),
              &file_validity
            );

          SENDF_TO_CLIENT_OR_FAIL (
            "<file_validity>%s</file_validity>",
            file_validity
          );
          g_free (file_validity);

          init_agent_installer_cpe_iterator (
            &cpes_iterator,
            get_iterator_resource (&agent_installers),
            get_agent_installers_data.get.trash);

          SENDF_TO_CLIENT_OR_FAIL ("<cpes>");
          while (next (&cpes_iterator))
            {
              const char *version_start_incl, *version_start_excl;
              const char *version_end_incl, *version_end_excl;

              version_start_incl
                = agent_installer_cpe_iterator_version_start_incl (
                    &cpes_iterator);
              version_start_excl
                = agent_installer_cpe_iterator_version_start_excl (
                    &cpes_iterator);
              version_end_incl
                = agent_installer_cpe_iterator_version_end_incl (
                    &cpes_iterator);
              version_end_excl
                = agent_installer_cpe_iterator_version_end_excl (
                                    &cpes_iterator);

              SENDF_TO_CLIENT_OR_FAIL (
                "<cpe>"
                "<criteria>%s</criteria>",
                agent_installer_cpe_iterator_criteria (&cpes_iterator)
              );
              
              if (version_start_incl)
                SENDF_TO_CLIENT_OR_FAIL (
                  "<version_start_incl>%s</version_start_incl>",
                  version_start_incl);

              if (version_start_excl)
                SENDF_TO_CLIENT_OR_FAIL (
                  "<version_start_excl>%s</version_start_excl>",
                  version_start_excl);

              if (version_end_incl)
                SENDF_TO_CLIENT_OR_FAIL (
                  "<version_end_incl>%s</version_end_incl>",
                  version_end_incl);

              if (version_end_excl)
                SENDF_TO_CLIENT_OR_FAIL (
                  "<version_end_excl>%s</version_end_excl>",
                  version_end_excl);

              SENDF_TO_CLIENT_OR_FAIL ("</cpe>");
            }
          SENDF_TO_CLIENT_OR_FAIL ("</cpes>");
          cleanup_iterator (&cpes_iterator);
        }

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
