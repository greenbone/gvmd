/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gmp_agents.c
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
 * @param attribute_names  Null-terminated array of attribute names.
 * @param attribute_values Null-terminated array of corresponding attribute values.
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
 * @param gmp_parser Pointer to the GMP parser handling the current session.
 * @param error      Location to store error information, if any occurs.
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
      if (ret == 1)
        break;
      if (ret == -1)
        {
          internal_error_send_to_client (error);
          get_agents_reset ();
          return;
        }

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
                               scanner_uuid (agent_iterator_scanner (&agents)),
                               scanner_name (agent_iterator_scanner (&agents))
                               );

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
    }

  cleanup_iterator (&agents);

  filtered = get_agents_data.get.id ? 1 : agent_count (&get_agents_data.get);
  SEND_GET_END ("agent", &get_agents_data.get, count, filtered);

#else
  SEND_TO_CLIENT_OR_FAIL ("</agent>");
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
 * @param gmp_parser        Pointer to the active GMP parser instance.
 * @param name              Name of the XML element being parsed.
 * @param attribute_names   Null-terminated array of attribute names.
 * @param attribute_values  Null-terminated array of attribute values.
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
 * @param gmp_parser        Pointer to the GMP parser instance.
 * @param attribute_names   Null-terminated array of attribute names.
 * @param attribute_values  Null-terminated array of corresponding attribute values.
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
 * @param text      Pointer to the text content.
 * @param text_len  Length of the text content.
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
 * @param gmp_parser Pointer to the active GMP parser instance.
 * @param error      Location to store error information, if any occurs.
 */
void
modify_agents_run (gmp_parser_t *gmp_parser, GError **error)
{
#if ENABLE_AGENTS
  entity_t root = (entity_t) modify_agent_data.context->first->data;

  // Extract scanner_id from attribute
  entity_t scanner_elem = entity_child (root, "scanner");
  const gchar *scanner_uuid = scanner_elem ? entity_attribute (scanner_elem, "id") : NULL;

  if (!scanner_uuid || !is_uuid (scanner_uuid))
    {
      SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("modify_agents", "Invalid or missing scanner_id"));
      modify_agents_reset ();
      return;
    }

  // Extract agent UUIDs from attribute
  entity_t agents_elem = entity_child (root, "agents");
  if (!agents_elem)
    {
      SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("modify_agents", "Missing <agents>"));
      modify_agents_reset ();
      return;
    }

  GPtrArray *uuid_array = g_ptr_array_new_with_free_func (g_free);
  GSList *agent_entities = agents_elem->entities;

  for (; agent_entities; agent_entities = g_slist_next (agent_entities))
    {
      entity_t agent_elem = agent_entities->data;

      if (strcmp (entity_name (agent_elem), "agent") != 0)
        continue;

      const gchar *uuid = entity_attribute (agent_elem, "id");

      if (uuid && is_uuid (uuid))
        g_ptr_array_add (uuid_array, g_strdup (uuid));
      else
        g_warning ("Skipping invalid UUID in <agent id=\"...\">: %s", uuid ? uuid : "NULL");
    }

  if (uuid_array->len == 0)
    {
      g_ptr_array_free (uuid_array, TRUE);
      SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("modify_agents", "No valid agent UUIDs"));
      modify_agents_reset ();
      return;
    }

  agent_uuid_list_t agent_uuids = g_malloc0 (sizeof (struct agent_uuid_list));
  agent_uuids->count = uuid_array->len;
  agent_uuids->agent_uuids = (gchar **) g_ptr_array_free (uuid_array, FALSE);

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

  int success = modify_and_resync_agents (scanner_uuid, agent_uuids, update, comment);

  if (success == 0)
    SENDF_TO_CLIENT_OR_FAIL (XML_OK ("modify_agents"));
  else
    SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_agents"));

  agent_uuid_list_free (agent_uuids);
  agent_controller_agent_update_free (update);
  g_free (comment);

#else
  SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_agents"));
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
 * @param gmp_parser        Pointer to the active GMP parser instance.
 * @param name              Name of the XML element being parsed.
 * @param attribute_names   Null-terminated array of attribute names.
 * @param attribute_values  Null-terminated array of attribute values.
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
 * @param gmp_parser        Pointer to the GMP parser handling the current session.
 * @param attribute_names   Null-terminated array of attribute names.
 * @param attribute_values  Null-terminated array of corresponding attribute values.
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
 * @param text      Pointer to the text content.
 * @param text_len  Length of the text content.
 */
void
delete_agents_element_text (const gchar *text, gsize text_len)
{
  xml_handle_text (delete_agent_data.context, text, text_len);
}

/**
 * @brief Handle the end of an XML element within the <delete_agents> command.
 *
 * @param gmp_parser  Pointer to the GMP parser handling the current session.
 * @param error       Pointer to a GError to store error details, if any.
 * @param name        Name of the XML element that just ended.
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
 * @param gmp_parser Pointer to the GMP parser handling the current session.
 * @param error      Pointer to a GError to store error information, if any occurs.
 */
void
delete_agents_run (gmp_parser_t *gmp_parser, GError **error)
{
#if ENABLE_AGENTS
  entity_t root = (entity_t) delete_agent_data.context->first->data;

  // Updated scanner extraction from attribute
  entity_t scanner_elem = entity_child (root, "scanner");
  const gchar *scanner_uuid = scanner_elem ? entity_attribute (scanner_elem, "id") : NULL;

  if (!scanner_uuid || !is_uuid (scanner_uuid))
    {
      SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("delete_agents", "Invalid or missing scanner_id"));
      delete_agent_reset ();
      return;
    }

  // Updated agents list extraction from attribute
  entity_t agents_elem = entity_child (root, "agents");
  if (!agents_elem)
    {
      SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("delete_agents", "Missing <agents>"));
      delete_agent_reset ();
      return;
    }

  GPtrArray *uuid_array = g_ptr_array_new_with_free_func (g_free);
  GSList *agent_entities = agents_elem->entities;

  for (; agent_entities; agent_entities = g_slist_next (agent_entities))
    {
      entity_t agent_elem = agent_entities->data;
      if (strcmp (entity_name (agent_elem), "agent") != 0)
        continue;

      const gchar *uuid = entity_attribute (agent_elem, "id");

      if (uuid && is_uuid (uuid))
        g_ptr_array_add (uuid_array, g_strdup (uuid));
      else
        g_warning ("Skipping invalid UUID in <agent id=\"...\">: %s", uuid ? uuid : "NULL");
    }

  if (uuid_array->len == 0)
    {
      g_ptr_array_free (uuid_array, TRUE);
      SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("delete_agents", "No valid agent UUIDs"));
      delete_agent_reset ();
      return;
    }

  agent_uuid_list_t agent_uuids = g_malloc0 (sizeof (struct agent_uuid_list));
  agent_uuids->count = uuid_array->len;
  agent_uuids->agent_uuids = (gchar **) g_ptr_array_free (uuid_array, FALSE);

  int success = delete_and_resync_agents (scanner_uuid, agent_uuids);
  if (success == 0)
    SENDF_TO_CLIENT_OR_FAIL (XML_OK ("delete_agents"));
  else
    SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("delete_agents"));

  agent_uuid_list_free (agent_uuids);
#else
  SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("delete_agents"));
#endif
  delete_agent_reset ();
}