/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Integration Configuration
 *
 * This includes function and variable definitions for GMP handling
 *  of integration configuration.
 */

#include "gmp_integration_configs.h"
#include "gmp_get.h"
#include "manage_get.h"
#include "manage.h"
#include "manage_acl.h"


/**
 * @brief Structure for storing data related to the `<get_integration_configs>` GMP command.
 *
 * This structure holds generic data needed for handling integration config retrieval
 * operations.
 */
typedef struct
{
  get_data_t get; ///< Get args.
} get_integration_configs_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static get_integration_configs_t get_integration_configs_data;

/**
 * @brief Structure for storing context related to the `<modify_integration_config>` GMP
 * command.
 *
 * The context is used to accumulate and parse XML input data for modifying
 * integration configs.
 */
typedef struct
{
  context_data_t *context;
  ///< XML parsing context for `<modify_integration_config>` input.
} modify_integration_config_data_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static modify_integration_config_data_t modify_integration_config_data;

/* GET_INTEGRATION_CONFIGS. */

/**
 * @brief Reset the internal state of the `<get_integration_configs>` command.
 *
 */
static void
get_integration_configs_reset ()
{
  get_data_reset (&get_integration_configs_data.get);
  memset (&get_integration_configs_data, 0,
          sizeof (get_integration_configs_data));
}

/**
 * @brief Initialize the `<get_integration_configs>` GMP command by parsing
 *        attributes.
 *
 * @param[in] attribute_names  Null-terminated array of attribute names.
 * @param[in] attribute_values Null-terminated array of corresponding attribute
 * values.
 */
void
get_integration_configs_start (const gchar **attribute_names,
                               const gchar **attribute_values)
{
  get_data_parse_attributes (&get_integration_configs_data.get,
                             "integration_config",
                             attribute_names,
                             attribute_values);
}

/**
 * @brief Execute the `<get_integration_configs>` GMP command.
 *
 * @param[in] gmp_parser Pointer to the GMP parser handling the current session.
 * @param[in] error      Location to store error information, if any occurs.
 */
void
get_integration_configs_run (gmp_parser_t *gmp_parser, GError **error)
{
  iterator_t integration_configs;
  int count = 0, filtered, ret, first;

  ret = init_get ("get_integration_configs", &get_integration_configs_data.get,
                  "Integration Configs", &first);
  if (ret)
    {
      switch (ret)
        {
        case 99:
          SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("get_integration_configs",
            "Permission denied"));
          break;
        default:
          internal_error_send_to_client (error);
          get_integration_configs_reset ();
          return;
        }
      get_integration_configs_reset ();
      return;
    }

  ret = init_integration_config_iterator (&integration_configs,
                                          &get_integration_configs_data.get);
  if (ret)
    {
      switch (ret)
        {
        case 1:
          if (send_find_error_to_client ("get_integration_configs",
                                         "integration_config",
                                         get_integration_configs_data.get.id,
                                         gmp_parser))
            {
              error_send_to_client (error);
              get_integration_configs_reset ();
              return;
            }
          break;
        case 2:
          if (send_find_error_to_client
            ("get_integration_configs", "filter",
             get_integration_configs_data.get.filt_id, gmp_parser))
            {
              error_send_to_client (error);
              get_integration_configs_reset ();
              return;
            }
          break;
        case -1:
          SEND_TO_CLIENT_OR_FAIL
          (XML_INTERNAL_ERROR ("get_integration_configs"));
          break;
        }
      get_integration_configs_reset ();
      return;
    }

  SEND_GET_START ("integration_config");

  while (1)
    {
      const char *service_url;
      const char *oidc_url;
      const char *oidc_client_id;

      ret = get_next (&integration_configs,
                      &get_integration_configs_data.get,
                      &first,
                      &count,
                      init_integration_config_iterator);
      if (ret == 1)
        break;
      if (ret == -1)
        {
          internal_error_send_to_client (error);
          break;
        }

      SEND_GET_COMMON_NO_TRASH (integration_config,
                                &get_integration_configs_data.get,
                                &integration_configs);

      if (get_integration_configs_data.get.details)
        {
          service_url = integration_config_iterator_service_url (
            &integration_configs);
          oidc_url =
            integration_config_iterator_oidc_url (&integration_configs);
          oidc_client_id = integration_config_iterator_oidc_client_id (
            &integration_configs);

          SENDF_TO_CLIENT_OR_FAIL (
            "<service>"
            "<url>%s</url>"
            "</service>",
            service_url ? service_url : "");

          SEND_TO_CLIENT_OR_FAIL ("<oidc>");
          SENDF_TO_CLIENT_OR_FAIL ("<url>%s</url>",
                                   oidc_url ? oidc_url : "");
          SENDF_TO_CLIENT_OR_FAIL (
            "<client>"
            "<id>%s</id>"
            "</client>",
            oidc_client_id ? oidc_client_id : "");
          SEND_TO_CLIENT_OR_FAIL ("</oidc>");
        }

      SEND_TO_CLIENT_OR_FAIL ("</integration_config>");
      count++;
    }

  cleanup_iterator (&integration_configs);

  filtered = get_integration_configs_data.get.id
               ? 1
               : integration_config_count (&get_integration_configs_data.get);

  SEND_GET_END ("integration_config",
                &get_integration_configs_data.get,
                count,
                filtered);

  get_integration_configs_reset ();
}

/* MODIFY_INTEGRATION_CONFIG */

/**
 * @brief Reset command data.
 */
static void
modify_integration_config_reset (void)
{
  if (modify_integration_config_data.context && modify_integration_config_data.
                                                context->first)
    {
      free_entity (modify_integration_config_data.context->first->data);
      g_slist_free_1 (modify_integration_config_data.context->first);
    }
  g_free (modify_integration_config_data.context);
  memset (&modify_integration_config_data, 0,
          sizeof (modify_integration_config_data));
}

/**
 * @brief Handle command start.
 *
 * @param[in] gmp_parser        Active GMP parser (unused).
 * @param[in] attribute_names   Null-terminated array of attribute names.
 * @param[in] attribute_values  Null-terminated array of attribute values.
 */
void
modify_integration_config_start (gmp_parser_t *gmp_parser,
                                 const gchar **attribute_names,
                                 const gchar **attribute_values)
{
  (void) gmp_parser;
  (void) attribute_names;
  (void) attribute_values;
  memset (&modify_integration_config_data, 0,
          sizeof (modify_integration_config_data));
  modify_integration_config_data.context = g_malloc0 (sizeof (context_data_t));
  xml_handle_start_element (modify_integration_config_data.context,
                            "modify_integration_config",
                            attribute_names,
                            attribute_values);
}

/**
 * @brief Handle command start element.
 *
 * @param[in] gmp_parser        Active GMP parser (unused).
 * @param[in] name              Element name.
 * @param[in] attribute_names   Null-terminated array of attribute names.
 * @param[in] attribute_values  Null-terminated array of attribute values.
 */
void
modify_integration_config_element_start (gmp_parser_t *gmp_parser,
                                         const gchar *name,
                                         const gchar **attribute_names,
                                         const gchar **attribute_values)
{
  xml_handle_start_element (modify_integration_config_data.context, name,
                            attribute_names, attribute_values);
}

/**
 * @brief Add text to element in the command
 *
 * @param[in] text      the text to add.
 * @param[in] len  the length of the text being added.
 */
void
modify_integration_config_element_text (const gchar *text, gsize len)
{
  xml_handle_text (modify_integration_config_data.context, text, len);
}

/**
 * @brief Run modify_integration_config command
 *
 * @param[in] gmp_parser  current instance of GMP parser.
 * @param[in] error       the errors, if any.
 */
void
modify_integration_config_run (gmp_parser_t *gmp_parser, GError **error)
{
  const char *config_uuid;
  entity_t root = (entity_t) modify_integration_config_data.context->first->
    data;

  config_uuid = entity_attribute (root, "uuid");

  if (!acl_user_may ("modify_integration_config"))
    {
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("modify_integration_config",
          "Permission denied"));
      modify_integration_config_reset ();
      return;
    }

  if (!config_uuid || !is_uuid (config_uuid))
    {
      SENDF_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("modify_integration_config",
          "Missing or invalid integration config UUID"));
      modify_integration_config_reset ();
      return;
    }

  /* <service> */
  entity_t svc_e = entity_child (root, "service");
  if (!svc_e)
    {
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("modify_integration_config",
          "Missing <service>"));
      modify_integration_config_reset ();
      return;
    }

  /* <oidc> */
  entity_t oidc_e = entity_child (root, "oidc");
  if (!oidc_e)
    {
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("modify_integration_config",
          "Missing <oidc>"));
      modify_integration_config_reset ();
      return;
    }

  integration_config_data_t config_data = integration_config_data_new ();
  config_data->uuid = g_strdup (config_uuid);

  entity_t e = NULL;
  if ((e = entity_child (svc_e, "url")))
    config_data->service_url = g_strdup (entity_text (e));
  if ((e = entity_child (svc_e, "cacert")))
    config_data->service_cacert = g_strdup (entity_text (e));
  if ((e = entity_child (oidc_e, "url")))
    config_data->oidc_url = g_strdup (entity_text (e));
  if ((e = entity_child (oidc_e, "client")))
    {
      entity_t o = NULL;
      if ((o = entity_child (e, "id")))
        config_data->oidc_client_id = g_strdup (entity_text (o));
      if ((o = entity_child (e, "secret")))
        config_data->oidc_client_secret = g_strdup (entity_text (o));
    }

  integration_config_response_t response;
  response = modify_integration_config (config_data);
  integration_config_data_free (config_data);
  switch (response)
    {
    case INTEGRATION_CONFIG_SUCCESS:
      /* Success */
      SENDF_TO_CLIENT_OR_FAIL (XML_OK ("modify_integration_config"));
      log_event ("modify_integration_config", "Integration Config",
                 config_uuid, "modified");
      modify_integration_config_reset ();
      return;

    case INTEGRATION_CONFIG_INVALID_DATA:
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("modify_integration_config",
          "Invalid arguments: data <modify_integration_config>"));
      log_event_fail ("modify_integration_config", "Integration Config",
                      config_uuid, "modified");
      modify_integration_config_reset ();
      return;

    case INTEGRATION_CONFIG_MISSING_SERVICE_URL:
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("modify_integration_config",
          "Invalid arguments: missing service <url>"));
      log_event_fail ("modify_integration_config", "Integration Config",
                      config_uuid, "modified");
      modify_integration_config_reset ();
      return;

    case INTEGRATION_CONFIG_MISSING_OIDC_URL:
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("modify_integration_config",
          "Invalid arguments: missing oidc url <url>"));
      log_event_fail ("modify_integration_config", "Integration Config",
                      config_uuid, "modified");
      modify_integration_config_reset ();
      return;

    case INTEGRATION_CONFIG_MISSING_OIDC_CLIENT_ID:
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("modify_integration_config",
          "Invalid arguments: missing oidc client id <id>"));
      log_event_fail ("modify_integration_config", "Integration Config",
                      config_uuid, "modified");
      modify_integration_config_reset ();
      return;

    case INTEGRATION_CONFIG_MISSING_OIDC_CLIENT_SECRET:
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("modify_integration_config",
          "Invalid arguments: missing oidc client secret <secret>"));
      log_event_fail ("modify_integration_config", "Integration Config",
                      config_uuid, "modified");
      modify_integration_config_reset ();
      return;

    case INTEGRATION_CONFIG_INVALID_OWNER:
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("modify_integration_config", "Permission denied"));
      log_event_fail ("modify_integration_config", "Integration Config",
                      config_uuid, "modified");
      modify_integration_config_reset ();
      return;

    case INTEGRATION_CONFIG_NOT_FOUND:
      log_event_fail ("modify_integration_config", "Integration Config",
                      config_uuid, "modified");
      if (send_find_error_to_client ("modify_integration_config",
                                     "integration_config",
                                     config_uuid,
                                     gmp_parser))
        {
          error_send_to_client (error);
          modify_integration_config_reset ();
          return;
        }
      modify_integration_config_reset ();
      return;
    case INTEGRATION_CONFIG_INTERNAL_ERROR:
      SEND_TO_CLIENT_OR_FAIL (
        XML_INTERNAL_ERROR ("modify_integration_config"));
      log_event_fail ("modify_integration_config", "Integration Config",
                      config_uuid, "modified");
      modify_integration_config_reset ();
      return;

    default:
      SEND_TO_CLIENT_OR_FAIL (
        XML_INTERNAL_ERROR ("modify_integration_config"));
      log_event_fail ("modify_integration_config", "Integration Config",
                      config_uuid, "modified");
      modify_integration_config_reset ();
    }
}

/**
 * @brief End element in the command
 *
 *
 * @param[in] gmp_parser  current instance of GMP parser.
 * @param[in] error       the errors, if any.
 * @param[in] name        name of element.
 *
 * @return 1 if the command ran successfully, 0 otherwise.
 */
int
modify_integration_config_element_end (gmp_parser_t *gmp_parser,
                                       GError **error,
                                       const gchar *name)
{
  xml_handle_end_element (modify_integration_config_data.context, name);
  if (modify_integration_config_data.context->done)
    {
      modify_integration_config_run (gmp_parser, error);
      return 1;
    }
  return 0;
}
