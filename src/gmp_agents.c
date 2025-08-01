/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Agent management
 *
 * This file contains GMP command implementations for managing agents,
 * including retrieval, modification, authorization, and deletion of agents.
 * These functions interact with the underlying management and database layers
 * to support agent-related operations via the GMP protocol.
 */

#include "gmp_agents.h"
#include "gmp_get.h"
#include "manage.h"

#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "md gmp"

/* GET_AGENTS. */

/**
 * @struct get_agents_t
 * @brief Structure for storing data related to the <get_agents> GMP command.
 *
 * This structure holds generic data needed for handling agent retrieval operations.
 */
typedef struct
{
  get_data_t get; ///< Parameters and context for the get operation (e.g., filters, format).
} get_agents_t;
static get_agents_t get_agents_data;

/**
 * @struct modify_agent_data_t
 * @brief Structure for storing context related to the <modify_agents> GMP command.
 *
 * The context is used to accumulate and parse XML input data for modifying agents.
 */
typedef struct
{
  context_data_t *context; ///< XML parsing context for <modify_agents> input.
} modify_agent_data_t;

static modify_agent_data_t modify_agent_data;

/**
 * @struct delete_agent_data_t
 * @brief Structure for storing context related to the <delete_agents> GMP command.
 */
typedef struct
{
  context_data_t *context; ///< XML parsing context for <delete_agents> input.
} delete_agent_data_t;

static delete_agent_data_t delete_agent_data;

/**
 * @brief Reset the internal state of the <get_agents> command.
 *
 */
static void
get_agents_reset ()
{
  get_data_reset (&get_agents_data.get);
  memset (&get_agents_data, 0, sizeof (get_agents_t));
}

/**
 * @brief Initialize the <get_agents> GMP command by parsing attributes.
 *
 * @param[in] attribute_names  Null-terminated array of attribute names.
 * @param[in] attribute_values Null-terminated array of corresponding attribute values.
 */
void
get_agents_start (const gchar **attribute_names, const gchar **attribute_values)
{
  get_data_parse_attributes (&get_agents_data.get, "agent", attribute_names,
                             attribute_values);
}

/**
 * @brief Execute the <get_agents> GMP command.
 *
 * @param[in] gmp_parser Pointer to the GMP parser handling the current session.
 * @param[in] error      Location to store error information, if any occurs.
 */
void
get_agents_run (gmp_parser_t *gmp_parser, GError **error)
{
#if ENABLE_AGENTS
  iterator_t agents;
  int count = 0, filtered, ret, first;

  ret = init_get ("get_agents",
                  &get_agents_data.get,
                  "Agents",
                  &first);
  if (ret)
    {
      SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("get_agents", "Permission denied"));
      get_agents_reset ();
      return;
    }

  ret = init_agent_iterator (&agents, &get_agents_data.get);
  if (ret)
    {
      SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("get_agents", "Permission denied"));
      get_agents_reset ();
      return;
    }

  SEND_GET_START ("agent");

  while (1)
    {
      ret = get_next (&agents, &get_agents_data.get, &first, &count,
                      init_agent_iterator);
      scanner_t scanner;
      char *agent_scanner_name, *agent_scanner_uuid;

      if (ret == 1)
        break;
      if (ret == -1)
        {
          internal_error_send_to_client (error);
          get_agents_reset ();
          return;
        }

      scanner = agent_iterator_scanner (&agents);
      agent_scanner_uuid = scanner_uuid (scanner);
      agent_scanner_name = scanner_name (scanner);
      SEND_GET_COMMON_NO_TRASH (agent,
                                &get_agents_data.get,
                                &agents);

      // Remaining fields
      SENDF_TO_CLIENT_OR_FAIL ("<hostname>%s</hostname>"
                               "<agent_id>%s</agent_id>"
                               "<authorized>%i</authorized>"
                               "<min_interval>%i</min_interval>"
                               "<heartbeat_interval>%i</heartbeat_interval>"
                               "<connection_status>%s</connection_status>"
                               "<last_update>%s</last_update>"
                               "<schedule>%s</schedule>"
                               "<scanner id=\"%s\">"
                               "<name>%s</name>"
                               "</scanner>",
                               agent_iterator_hostname (&agents),
                               agent_iterator_agent_id (&agents),
                               agent_iterator_authorized (&agents),
                               agent_iterator_min_interval (&agents),
                               agent_iterator_heartbeat_interval (&agents),
                               agent_iterator_connection_status (&agents),
                               iso_if_time (agent_iterator_last_update (&agents)),
                               agent_iterator_schedule (&agents),
                               agent_scanner_uuid ? agent_scanner_uuid : "",
                               agent_scanner_name ? agent_scanner_name : "");

      // IPs
      agent_ip_data_list_t ip_list = load_agent_ip_addresses (agent_iterator_agent_id (&agents));
      if (ip_list)
        {
          for (int i = 0; i < ip_list->count; ++i)
            {
              SENDF_TO_CLIENT_OR_FAIL ("<ip>%s</ip>", ip_list->items[i]->ip_address);
            }
          agent_ip_data_list_free (ip_list);
        }

      // Close agent
      SEND_TO_CLIENT_OR_FAIL ("</agent>");
      count++;

      g_free(agent_scanner_name);
      g_free(agent_scanner_uuid);
    }

  cleanup_iterator (&agents);

  filtered = get_agents_data.get.id ? 1 : agent_count (&get_agents_data.get);
  SEND_GET_END ("agent", &get_agents_data.get, count, filtered);

#else
  SEND_TO_CLIENT_OR_FAIL (XML_ERROR_UNAVAILABLE ("get_agents",
                                                 "Command unavailable"));
#endif

  get_agents_reset ();
}

/* MODIFY_AGENTS. */

/**
 * @brief Reset the internal state for the <modify_agents> GMP command.
 *
 */
static void
modify_agents_reset ()
{
  if (modify_agent_data.context && modify_agent_data.context->first)
    {
      free_entity (modify_agent_data.context->first->data);
      g_slist_free_1 (modify_agent_data.context->first);
    }

  g_free (modify_agent_data.context);
  memset (&modify_agent_data, 0, sizeof (modify_agent_data_t));
}

/**
 * @brief Handle the start of an XML element within the <modify_agents> command.
 *
 * @param[in] gmp_parser        Pointer to the active GMP parser instance.
 * @param[in] name              Name of the XML element being parsed.
 * @param[in] attribute_names   Null-terminated array of attribute names.
 * @param[in] attribute_values  Null-terminated array of attribute values.
 */
void
modify_agents_element_start (gmp_parser_t *gmp_parser,
                             const gchar *name,
                             const gchar **attribute_names,
                             const gchar **attribute_values)
{
  xml_handle_start_element (modify_agent_data.context,
                            name,
                            attribute_names,
                            attribute_values);
}

/**
 * @brief Initialize the <modify_agents> GMP command.
 *
 * @param[in] gmp_parser        Pointer to the GMP parser instance.
 * @param[in] attribute_names   Null-terminated array of attribute names.
 * @param[in] attribute_values  Null-terminated array of corresponding attribute values.
 */
void
modify_agents_start (gmp_parser_t *gmp_parser,
                     const gchar **attribute_names,
                     const gchar **attribute_values)
{
  memset (&modify_agent_data, 0, sizeof (modify_agent_data_t));
  modify_agent_data.context = g_malloc0 (sizeof (context_data_t));

  modify_agents_element_start (gmp_parser, "modify_agents",
                              attribute_names, attribute_values);
}

/**
 * @brief Handle the text content of an XML element within <modify_agents>.
 *
 * @param[in] text      Pointer to the text content.
 * @param[in] text_len  Length of the text content.
 */
void
modify_agents_element_text (const gchar *text, gsize text_len)
{
  xml_handle_text (modify_agent_data.context, text, text_len);
}

/**
 * @brief Handle the end of an XML element within the <modify_agents> command.
 *
 * @param gmp_parser  Pointer to the GMP parser handling the current session.
 * @param error       Location to store error information, if any.
 * @param name        Name of the XML element that ended.
 *
 * @return 1 if the command has been fully parsed and executed, 0 otherwise.
 */
int
modify_agents_element_end (gmp_parser_t *gmp_parser,
                           GError **error,
                           const gchar *name)
{
  xml_handle_end_element (modify_agent_data.context, name);

  if (modify_agent_data.context->done)
    {
      modify_agents_run (gmp_parser, error);
      return 1;
    }
  return 0;
}

/**
 * @brief Execute the <modify_agents> GMP command.
 *
 * @param[in] gmp_parser Pointer to the active GMP parser instance.
 * @param[in] error      Location to store error information, if any occurs.
 */
void
modify_agents_run (gmp_parser_t *gmp_parser, GError **error)
{
#if ENABLE_AGENTS
  entity_t root = (entity_t) modify_agent_data.context->first->data;

  // Extract <agents>
  entity_t agents_elem = entity_child (root, "agents");
  if (!agents_elem)
    {
      SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("modify_agents", "Missing <agents>"));
      log_event_fail ("agents", "Agents", NULL, "modified");
      modify_agents_reset ();
      return;
    }

  GSList *agent_entities = agents_elem->entities;
  int uuid_count = g_slist_length (agent_entities);
  agent_uuid_list_t agent_uuids = agent_uuid_list_new (uuid_count);

  int index = 0;
  for (; agent_entities; agent_entities = g_slist_next (agent_entities))
    {
      entity_t agent_elem = agent_entities->data;

      if (strcmp (entity_name (agent_elem), "agent") != 0)
        continue;

      const gchar *uuid = entity_attribute (agent_elem, "id");

      if (uuid && is_uuid (uuid))
        agent_uuids->agent_uuids[index++] = g_strdup (uuid);
      else
        {
          agent_uuid_list_free (agent_uuids);
          SENDF_TO_CLIENT_OR_FAIL (
            XML_ERROR_SYNTAX ("modify_agents", "Agent UUID '%s' is invalid"),
            uuid);
          modify_agents_reset ();
          return;
        }
    }

  if (index == 0)
    {
      agent_uuid_list_free (agent_uuids);
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("modify_agents", "No agent UUIDs provided"));
      modify_agents_reset ();
      return;
    }

  // Parse update fields
  agent_controller_agent_update_t update = agent_controller_agent_update_new ();
  gchar *comment = NULL;
  entity_t e = NULL;
  if ((e = entity_child (root, "authorized")))
    update->authorized = atoi (entity_text (e));
  if ((e = entity_child (root, "min_interval")))
    update->min_interval = atoi (entity_text (e));
  if ((e = entity_child (root, "heartbeat_interval")))
    update->heartbeat_interval = atoi (entity_text (e));
  if ((e = entity_child (root, "schedule")))
    {
      update->schedule_config = agent_controller_config_schedule_new ();
      update->schedule_config->schedule = g_strdup (entity_text (e));
    }
  if ((e = entity_child (root, "comment")))
    comment = g_strdup (entity_text (e));

  agent_response_t response = modify_and_resync_agents (agent_uuids, update, comment);

  switch (response)
    {
      case AGENT_RESPONSE_SUCCESS:
        SENDF_TO_CLIENT_OR_FAIL (XML_OK ("modify_agents"));
        log_event_plural ("agents", "Agents", NULL, "modified");
        break;

      case AGENT_RESPONSE_NO_AGENTS_PROVIDED:
        SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("modify_agents", "No agents provided"));
        log_event_fail ("agents", "Agents", NULL, "modified");
        break;

      case AGENT_RESPONSE_SCANNER_LOOKUP_FAILED:
        if (send_find_error_to_client ("modify_agents",
                                       "scanner",
                                       NULL,
                                       gmp_parser))
          {
            error_send_to_client (error);
            modify_agents_reset ();
            return;
          }

        log_event_fail ("agents", "Agents", NULL, "modified");
        break;

      case AGENT_RESPONSE_AGENT_NOT_FOUND:
        if (send_find_error_to_client ("modify_agents",
                                       "agents",
                                       NULL,
                                       gmp_parser))
          {
            error_send_to_client (error);
            modify_agents_reset ();
            return;
          }

        log_event_fail ("agents", "Agents", NULL, "modified");
        break;

      case AGENT_RESPONSE_INVALID_ARGUMENT:
        SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_agents"));
        break;

      case AGENT_RESPONSE_INVALID_AGENT_OWNER:
        SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_agents"));
        log_event_fail ("agents", "Agents", NULL, "modified");
        break;

      case AGENT_RESPONSE_AGENT_SCANNER_MISMATCH:
        SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("modify_agents", "Agents belong to different scanners"));
        log_event_fail ("agents", "Agents", NULL, "modified");
        break;

      case AGENT_RESPONSE_CONNECTOR_CREATION_FAILED:
        SEND_TO_CLIENT_OR_FAIL (XML_ERROR_UNAVAILABLE (
                                     "modify_agents",
                                     "Could not connect to Agent-Controller"));
        log_event_fail ("agents", "Agents", NULL, "modified");
        break;

      case AGENT_RESPONSE_CONTROLLER_UPDATE_FAILED:
      SEND_TO_CLIENT_OR_FAIL (XML_ERROR_UNAVAILABLE (
                                   "modify_agents",
                                   "Updates of Agents in Agent-Controller failed"));
        log_event_fail ("agents", "Agents", NULL, "modified");
        break;

      case AGENT_RESPONSE_SYNC_FAILED:
        SEND_TO_CLIENT_OR_FAIL (XML_ERROR_UNAVAILABLE (
                                   "modify_agents",
                                   "Synchronization of Agents in Agent-Controller failed"));
        log_event_fail ("agents", "Agents", NULL, "modified");
        break;

      case AGENT_RESPONSE_INTERNAL_ERROR:
        SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_agents"));
        log_event_fail ("agents", "Agents", NULL, "modified");
        break;
      case AGENT_RESPONSE_IN_USE_ERROR:
      default:
        SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_agents"));
        log_event_fail ("agents", "Agents", NULL, "modified");
        break;
    }

  agent_uuid_list_free (agent_uuids);
  agent_controller_agent_update_free (update);
  g_free (comment);

#else
  SEND_TO_CLIENT_OR_FAIL (XML_ERROR_UNAVAILABLE ("modify_agents",
                                                 "Command unavailable"));
#endif // ENABLE_AGENTS

  modify_agents_reset ();
}

/* DELETE_AGENTS. */

/**
 * @brief Reset the internal state for the <delete_agents> GMP command.
 *
 */
static void
delete_agent_reset ()
{
  if (delete_agent_data.context && delete_agent_data.context->first)
    {
      free_entity (delete_agent_data.context->first->data);
      g_slist_free_1 (delete_agent_data.context->first);
    }

  g_free (delete_agent_data.context);
  memset (&delete_agent_data, 0, sizeof (delete_agent_data_t));
}

/**
 * @brief Handle the start of an XML element within the <delete_agents> command.
 *
 * @param[in] gmp_parser        Pointer to the active GMP parser instance.
 * @param[in] name              Name of the XML element being parsed.
 * @param[in] attribute_names   Null-terminated array of attribute names.
 * @param[in] attribute_values  Null-terminated array of attribute values.
 */
void
delete_agents_element_start (gmp_parser_t *gmp_parser,
                             const gchar *name,
                             const gchar **attribute_names,
                             const gchar **attribute_values)
{
  xml_handle_start_element (delete_agent_data.context,
                            name,
                            attribute_names,
                            attribute_values);
}

/**
 * @brief Initialize the <delete_agents> GMP command.
 *
 * @param[in] gmp_parser        Pointer to the GMP parser handling the current session.
 * @param[in] attribute_names   Null-terminated array of attribute names.
 * @param[in] attribute_values  Null-terminated array of corresponding attribute values.
 */
void
delete_agents_start (gmp_parser_t *gmp_parser,
                     const gchar **attribute_names,
                     const gchar **attribute_values)
{
  memset (&delete_agent_data, 0, sizeof (delete_agent_data_t));
  delete_agent_data.context = g_malloc0 (sizeof (context_data_t));

  delete_agents_element_start (gmp_parser, "delete_agents",
                               attribute_names, attribute_values);
}

/**
 * @brief Handle the text content of an XML element within <delete_agents>.
 *
 * @param[in] text      Pointer to the text content.
 * @param[in] text_len  Length of the text content.
 */
void
delete_agents_element_text (const gchar *text, gsize text_len)
{
  xml_handle_text (delete_agent_data.context, text, text_len);
}

/**
 * @brief Handle the end of an XML element within the <delete_agents> command.
 *
 * @param[in] gmp_parser  Pointer to the GMP parser handling the current session.
 * @param[in] error       Pointer to a GError to store error details, if any.
 * @param[in] name        Name of the XML element that just ended.
 *
 * @return 1 if the full <delete_agents> command has been parsed and executed,
 *         0 otherwise.
 */
int
delete_agents_element_end (gmp_parser_t *gmp_parser,
                           GError **error,
                           const gchar *name)
{
  xml_handle_end_element (delete_agent_data.context, name);

  if (delete_agent_data.context->done)
    {
      delete_agents_run (gmp_parser, error);
      return 1;
    }

  return 0;
}

/**
 * @brief Execute the <delete_agents> GMP command.
 *
 * @param[in] gmp_parser Pointer to the GMP parser handling the current session.
 * @param[in] error      Pointer to a GError to store error information, if any occurs.
 */
void
delete_agents_run (gmp_parser_t *gmp_parser, GError **error)
{
#if ENABLE_AGENTS
  entity_t root = (entity_t) delete_agent_data.context->first->data;

  // Extract <agents>
  entity_t agents_elem = entity_child (root, "agents");
  if (!agents_elem)
    {
      SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("delete_agents", "Missing <agents>"));
      delete_agent_reset ();
      return;
    }

  GSList *agent_entities = agents_elem->entities;
  int uuid_count = g_slist_length (agent_entities);
  agent_uuid_list_t agent_uuids = agent_uuid_list_new (uuid_count);

  int index = 0;
  for (; agent_entities; agent_entities = g_slist_next (agent_entities))
    {
      entity_t agent_elem = agent_entities->data;

      if (strcmp (entity_name (agent_elem), "agent") != 0)
        continue;

      const gchar *uuid = entity_attribute (agent_elem, "id");

      if (uuid && is_uuid (uuid))
        agent_uuids->agent_uuids[index++] = g_strdup (uuid);
      else
        {
          agent_uuid_list_free (agent_uuids);
          SENDF_TO_CLIENT_OR_FAIL (
            XML_ERROR_SYNTAX ("delete_agents", "Agent UUID '%s' is invalid"),
            uuid);
          modify_agents_reset ();
          return;
        }
    }

  if (index == 0)
    {
      agent_uuid_list_free (agent_uuids);
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("delete_agents", "No agent UUIDs provided"));
      modify_agents_reset ();
      return;
    }

  agent_response_t response = delete_and_resync_agents (agent_uuids);

  switch (response)
    {
      case AGENT_RESPONSE_SUCCESS:
        SENDF_TO_CLIENT_OR_FAIL (XML_OK ("delete_agents"));
        log_event_plural ("agents", "Agents", NULL, "deleted");
        break;

      case AGENT_RESPONSE_NO_AGENTS_PROVIDED:
        if (send_find_error_to_client ("delete_agents",
                                       "agents",
                                       NULL,
                                       gmp_parser))
          {
            error_send_to_client (error);
            modify_agents_reset ();
            return;
          }

        log_event_fail ("agents", "Agents", NULL, "deleted");
        break;
      case AGENT_RESPONSE_AGENT_NOT_FOUND:
        if (send_find_error_to_client ("modify_agents",
                                       "agents",
                                       NULL,
                                       gmp_parser))
          {
            error_send_to_client (error);
            modify_agents_reset ();
            return;
          }

        log_event_fail ("agents", "Agents", NULL, "deleted");
        break;
      case AGENT_RESPONSE_SCANNER_LOOKUP_FAILED:
        if (send_find_error_to_client ("delete_agents",
                                       "scanner",
                                       NULL,
                                       gmp_parser))
          {
            error_send_to_client (error);
            modify_agents_reset ();
            return;
          }

        log_event_fail ("agents", "Agents", NULL, "deleted");
        break;

      case AGENT_RESPONSE_INVALID_ARGUMENT:
        SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("delete_agents"));
        log_event_fail ("agents", "Agents", NULL, "deleted");
        break;

      case AGENT_RESPONSE_INVALID_AGENT_OWNER:
        SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("delete_agents"));
        log_event_fail ("agents", "Agents", NULL, "deleted");
        break;

      case AGENT_RESPONSE_AGENT_SCANNER_MISMATCH:
        SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("delete_agents", "Agents belong to different scanners"));
        log_event_fail ("agents", "Agents", NULL, "deleted");
        break;

      case AGENT_RESPONSE_CONNECTOR_CREATION_FAILED:
        SEND_TO_CLIENT_OR_FAIL (XML_ERROR_UNAVAILABLE (
                                   "delete_agents",
                                   "Could not connect to Agent-Controller"));
        log_event_fail ("agents", "Agents", NULL, "deleted");
        break;

      case AGENT_RESPONSE_CONTROLLER_DELETE_FAILED:
        SEND_TO_CLIENT_OR_FAIL (XML_ERROR_UNAVAILABLE (
                                 "delete_agents",
                                 "Deletion of Agents in Agent-Controller failed"));
        log_event_fail ("agents", "Agents", NULL, "deleted");
        break;

      case AGENT_RESPONSE_SYNC_FAILED:
        SEND_TO_CLIENT_OR_FAIL (XML_ERROR_UNAVAILABLE (
                                   "delete_agents",
                                   "Synchronization of Agents in Agent-Controller failed"));
        log_event_fail ("agents", "Agents", NULL, "deleted");
        break;

      case AGENT_RESPONSE_INTERNAL_ERROR:
        SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("delete_agents"));
        log_event_fail ("agents", "Agents", NULL, "deleted");
        break;

      case AGENT_RESPONSE_IN_USE_ERROR:
        SENDF_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("delete_agents", "Resource is in use"));
        log_event_fail ("agent", "Agents", NULL, "deleted");
        break;

      default:
        SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("delete_agents"));
        log_event_fail ("agents", "Agents", NULL, "deleted");
        break;
    }

  agent_uuid_list_free (agent_uuids);
#else
  SEND_TO_CLIENT_OR_FAIL (XML_ERROR_UNAVAILABLE ("delete_agents",
                                                 "Command unavailable"));
#endif
  delete_agent_reset ();
}