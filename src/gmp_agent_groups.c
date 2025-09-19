/* Copyright (C) 2009-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Agent groups.
 *
 * GMP Handlers for reading, creating, modifying and deleting agent groups.
 */

#include "gmp_agent_groups.h"
#include "manage.h"
#include "manage_acl.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"

/* GET_AGENT_GROUPS */

/**
 * @struct get_agent_groups_t
 * @brief data for <get_agent_groups> command
 *
 */
typedef struct
{
    get_data_t get;
} get_agent_groups_t;

/**
 * @brief Parser <get_agent_groups> callback data.
 */
static get_agent_groups_t get_agent_groups_data;

static void
get_agent_groups_reset ()
{
    get_data_reset (&get_agent_groups_data.get);
    memset (&get_agent_groups_data, 0, sizeof (get_agent_groups_data));
}

/**
 * @brief start getting agent groups
 *
 * @param[in] attribute_names  the names of the attributes
 * @param[in] attribute_values the values of the attributes
 */
void
get_agent_groups_start (const gchar **attribute_names,
                        const gchar **attribute_values)
{
    get_data_parse_attributes (&get_agent_groups_data.get,
                               "agent_groups",
                               attribute_names,
                               attribute_values);
}

/**
 * @brief complete get agent groups command
 *
 * @param[in] gmp_parser GMP Parser handling the current session
 * @param[in] error      The errors, if any.
 */
void
get_agent_groups_run (gmp_parser_t *gmp_parser, GError **error)
{
#if ENABLE_AGENTS
  iterator_t agent_groups;
  int count = 0, filtered, ret, first;

  ret = init_get ("get_agent_groups",
                  &get_agent_groups_data.get,
                  "Agent Groups",
                  &first);

  if (ret)
    {
      switch (ret)
        {
        case 99:
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("get_agent_groups",
                              "Permission denied"));
          break;
        default:
          internal_error_send_to_client (error);
          get_agent_groups_reset ();
          return;
        }
      get_agent_groups_reset ();
      return;
    }

  ret = init_agent_group_iterator (&agent_groups, &get_agent_groups_data.get);
  if (ret)
    {
      SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("get_agent_groups", "Permission denied"));
      get_agent_groups_reset ();
      return;
    }

  SEND_GET_START ("agent_group");

  while (1)
    {
      const char *agent_scanner_name, *agent_scanner_uuid;

      ret = get_next (&agent_groups, &get_agent_groups_data.get, &first, &count,
                      init_agent_group_iterator);
      if (ret == 1)
        break;
      if (ret == -1)
        {
          internal_error_send_to_client (error);
          get_agent_groups_reset ();
          return;
        }

      agent_scanner_uuid = agent_group_iterator_scanner_id (&agent_groups);
      agent_scanner_name = agent_group_iterator_scanner_name (&agent_groups);

      // Start <agent_group>
      SEND_GET_COMMON (agent_group,
                       &get_agent_groups_data.get,
                       &agent_groups);

      SENDF_TO_CLIENT_OR_FAIL ("<scanner id=\"%s\">"
                               "<name>%s</name>"
                               "</scanner>",
                               agent_scanner_uuid ? agent_scanner_uuid : "",
                               agent_scanner_name ? agent_scanner_name : "");

      iterator_t agent_iter;
      init_agent_group_agents_iterator (&agent_iter, get_iterator_resource (&agent_groups));
      SEND_TO_CLIENT_OR_FAIL ("<agents>");
      while (next (&agent_iter))
        {
          const char *uuid = agent_group_agent_iterator_uuid (&agent_iter);
          const char *name = agent_group_agent_iterator_name (&agent_iter);

          SENDF_TO_CLIENT_OR_FAIL (
            "<agent id=\"%s\"><name>%s</name></agent>",
            uuid ? uuid : "",
            name ? name : "");
        }

      SEND_TO_CLIENT_OR_FAIL ("</agents>");
      cleanup_iterator (&agent_iter);

      SEND_TO_CLIENT_OR_FAIL ("</agent_group>");
      count++;
    }

  cleanup_iterator (&agent_groups);

  filtered = get_agent_groups_data.get.id
               ? 1
               : agent_group_count (&get_agent_groups_data.get);

  SEND_GET_END ("agent_group", &get_agent_groups_data.get, count, filtered);

#else
  SEND_TO_CLIENT_OR_FAIL (XML_ERROR_UNAVAILABLE ("get_agent_groups",
                                                 "Command unavailable"));
#endif

  get_agent_groups_reset ();
}


/* CREATE_AGENT_GROUP */

/**
 * @brief The create_agent_group command
 */
typedef struct
{
  context_data_t *context;
} create_agent_group_t;

/**
 * @brief Data used by parser to handle create_agent_group command
 */
static create_agent_group_t create_agent_group_data;

/**
 * @brief Resets create_agent_group command data.
 */
static void
create_agent_group_reset ()
{
  if (create_agent_group_data.context->first)
    {
      free_entity (create_agent_group_data.context->first->data);
      g_slist_free_1 (create_agent_group_data.context->first);
    }
    g_free (create_agent_group_data.context);
    memset (&create_agent_group_data, 0, sizeof (create_agent_group_t));
}

/**
 * @brief Start the create_agent_group command
 *
 * @param[in] gmp_parser       current instance of GMP parser.
 * @param[in] attribute_names  All attribute names.
 * @param[in] attribute_values All attribute values.
 */
void
create_agent_group_start (gmp_parser_t *gmp_parser,
                          const gchar **attribute_names,
                          const gchar **attribute_values)
{
  memset (&create_agent_group_data, 0, sizeof (create_agent_group_t));
  create_agent_group_data.context = g_malloc0 (sizeof (context_data_t));
  create_agent_group_element_start (gmp_parser, "create_agent_group",
                                    attribute_names, attribute_values);
}

/**
 * @brief Start an element of the create_agent_group command
 *
 * @param[in]  gmp_parser        current instance of GMP parser.
 * @param[in]  name              name of element being started.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
create_agent_group_element_start (gmp_parser_t *gmp_parser, const gchar *name,
                                  const gchar **attribute_names,
                                  const gchar **attribute_values)
{
  xml_handle_start_element (create_agent_group_data.context, name,
                            attribute_names, attribute_values);
}

/**
 * @brief End element in create_agent_group command
 *
 * @param[in] gmp_parser  The current GMP parser instance
 * @param[in] error       the errors, if any
 * @param[in] name        name of element
 *
 * @return 1 if the command ran successfully, 0 otherwise
 */
int
create_agent_group_element_end (gmp_parser_t *gmp_parser, GError **error,
                                const gchar *name)
{
  xml_handle_end_element (create_agent_group_data.context, name);
  if (create_agent_group_data.context->done)
  {
    create_agent_group_run (gmp_parser, error);
    return 1;
  }
  return 0;
}

/**
 * @brief Add text to element in create_agent_group command
 *
 * @param[in] text      the text to add.
 * @param[in] text_len  the length of the text being added
 */
void
create_agent_group_element_text (const gchar *text, gsize text_len)
{
  xml_handle_text (create_agent_group_data.context, text, text_len);
}

/**
 * @brief Execute the create_agent_group command
 *
 * @param[in] gmp_parser  current instance of GMP parser.
 * @param[in] error       the errors, if any.
 */
void
create_agent_group_run (gmp_parser_t *gmp_parser, GError **error)
{
#if ENABLE_AGENTS
  entity_t root, copy, name, comment, agents_elem;
  const char *name_text;
  agent_group_data_t group_data;
  agent_uuid_list_t agent_uuids = NULL;
  agent_group_t new_agent_group;

  if (!acl_user_may ("create_agent_group"))
    {
      SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("create_agent_group",
                              "Permission denied"));
      create_agent_group_reset ();
      return;
    }

  root = (entity_t) create_agent_group_data.context->first->data;

  // Handle copy logic if provided
  copy = entity_child (root, "copy");
  if (copy)
  {
    // Parse <name> and <comment> elements
    name = entity_child (root, "name");
    comment = entity_child (root, "comment");

    name_text = (name && entity_text (name)) ? entity_text (name) : NULL;
    const char *comment_text = (comment && entity_text (comment)) ? entity_text (comment) : "";

    // Call the updated copy_agent_group with name
    switch (copy_agent_group (name_text,
                              comment_text,
                              entity_text (copy),
                              &new_agent_group))
    {
      case 0:
      {
        char *uuid = agent_group_uuid (new_agent_group);
        SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_agent_group"), uuid);
        log_event ("agent_group", "Agent Group", uuid, "copied");
        free (uuid);
        break;
      }
      case 2:
        if (send_find_error_to_client ("create_agent_group", "agent_group",
                                       entity_text (copy), gmp_parser))
        {
          error_send_to_client (error);
          return;
        }
      log_event_fail ("agent_group", "Agent Group", NULL, "copied");
      break;
      case 99:
        SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("create_agent_group", "Permission denied"));
      break;
      case -1:
        default:
          SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_agent_group"));
      log_event_fail ("agent_group", "Agent Group", NULL, "copied");
      break;
    }

    create_agent_group_reset ();
    return;
  }

  // Parse required fields
  name = entity_child (root, "name");
  if (!name || !(name_text = entity_text (name)) || strlen (name_text) == 0)
    {
      SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("create_agent_group", "Missing or empty <name>"));
      create_agent_group_reset ();
      return;
    }

  comment = entity_child (root, "comment");

  // Allocate and populate group data
  group_data = agent_group_data_new();
  group_data->name = g_strdup (name_text);
  group_data->comment = comment ? g_strdup (entity_text (comment)) : g_strdup ("");
  group_data->creation_time = group_data->modification_time = time (NULL);

  // Parse <agents> if provided
  agents_elem = entity_child (root, "agents");
  if (agents_elem)
    {
      GSList *agent_entities = agents_elem->entities;
      int uuid_count = g_slist_length (agent_entities);
      agent_uuids = agent_uuid_list_new (uuid_count);

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
              agent_group_data_free(group_data);
              SENDF_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("create_agent_group",
                                                         "Invalid agent UUID: %s"),
                                       uuid);
              create_agent_group_reset ();
              return;
            }
        }
      agent_uuids->count = index;
    }

  // Execute creation
  agent_group_resp_t response = create_agent_group (group_data, agent_uuids);

  switch (response)
  {
    case AGENT_GROUP_RESP_SUCCESS:
    {
      char *uuid = agent_group_uuid (sql_last_insert_id ());
      SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_agent_group"), uuid);
      log_event ("agent_group", "Agent Group", uuid, "created");
      g_free (uuid);
      break;
    }

    case AGENT_GROUP_RESP_NO_AGENTS_PROVIDED:
      SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("create_agent_group", "No agents provided"));
      log_event_fail ("agent_group", "Agent Group", NULL, "created");
      break;

    case AGENT_GROUP_RESP_SCANNER_NOT_FOUND:
      if (send_find_error_to_client ("create_agent_group",
                                     "scanner",
                                     NULL,
                                     gmp_parser))
      {
        error_send_to_client (error);
        create_agent_group_reset ();
        return;
      }

      log_event_fail ("create_agent_group", "Agent Group", NULL, "created");
      break;

    case AGENT_GROUP_RESP_SCANNER_PERMISSION:
      SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("create_agent_group",
                                                "Permission denied"));

      log_event_fail ("create_agent_group", "Agent Group", NULL, "created");
      break;
    case AGENT_GROUP_RESP_AGENT_SCANNER_MISMATCH:
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("create_agent_group", "Agents belong to different scanners"));
      log_event_fail ("agent_group", "Agent Group", NULL, "created");
      break;

    case AGENT_GROUP_RESP_INVALID_ARGUMENT:
      SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("create_agent_group", "Invalid input"));
      log_event_fail ("agent_group", "Agent Group", NULL, "created");
    break;

    case AGENT_GROUP_RESP_AGENT_NOT_FOUND:
      if (send_find_error_to_client ("create_agent_group",
                                     "agent",
                                     NULL,
                                     gmp_parser))
      {
        error_send_to_client (error);
        create_agent_group_reset ();
        return;
      }

      log_event_fail ("create_agent_group", "Agent Group", NULL, "created");
      break;

    case AGENT_GROUP_RESP_AGENT_UNAUTHORIZED:
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("create_agent_group", "Unauthorized Agent"));
      log_event_fail ("agent_group", "Agent Group", NULL, "created");
      break;

    case AGENT_GROUP_RESP_INTERNAL_ERROR:
    default:
        SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_agent_group"));
        log_event_fail ("agent_group", "Agent Group", NULL, "created");
        break;
  }

  // Cleanup
  agent_uuid_list_free (agent_uuids);
  agent_group_data_free(group_data);

#else
  SEND_TO_CLIENT_OR_FAIL (XML_ERROR_UNAVAILABLE ("create_agent_group",
                                                 "Command unavailable"));
#endif

  create_agent_group_reset ();
}

/* MODIFY_AGENT_GROUP */

/**
 * @struct modify_agent_group_data_t
 * @brief data for <modify_agent_group> command
 */
typedef struct
{
    context_data_t *context;
} modify_agent_group_data_t;

/**
 * @brief Parser <modify_agent_group> callback data.
 */
static modify_agent_group_data_t modify_agent_group_data;

static void
modify_agent_group_reset ()
{
  if (modify_agent_group_data.context && modify_agent_group_data.context->first)
    {
      free_entity (modify_agent_group_data.context->first->data);
      g_slist_free_1 (modify_agent_group_data.context->first);
    }

  g_free (modify_agent_group_data.context);
  memset (&modify_agent_group_data, 0, sizeof (modify_agent_group_data_t));
}

/**
 * @brief Start the element in the <modify_agent_group> command.
 *
 * @param[in] gmp_parser       Active GMP parser instance.
 * @param[in] name             Name of the XML element being parsed.
 * @param[in] attribute_names  Null-terminated array of attribute names.
 * @param[in] attribute_values Null-terminated array of attribute values.
 */
void
modify_agent_group_element_start (gmp_parser_t *gmp_parser,
                                  const gchar *name,
                                  const gchar **attribute_names,
                                  const gchar **attribute_values)
{
  xml_handle_start_element (modify_agent_group_data.context,
                            name,
                            attribute_names,
                            attribute_values);
}

/**
 * @brief Initialize the <modify_agent_group> GMP command.
 *
 * @param[in] gmp_parser        Active GMP parser instance.
 * @param[in] attribute_names   Null-terminated array of attribute names.
 * @param[in] attribute_values  Null-terminated array of attribute names.
 */
void
modify_agent_group_start (gmp_parser_t *gmp_parser,
                          const gchar **attribute_names,
                          const gchar **attribute_values)
{
  memset (&modify_agent_group_data, 0, sizeof (modify_agent_group_data_t));
  modify_agent_group_data.context = g_malloc0 (sizeof (context_data_t));

  modify_agent_group_element_start (gmp_parser, "modify_agent_group",
                                    attribute_names, attribute_values);
}

/**
 * @brief Add text to element for modify_agent_group.
 *
 * @param[in]  text         Text.
 * @param[in]  text_len     Text length.
 */
void
modify_agent_group_element_text (const gchar *text, gsize text_len)
{
  xml_handle_text (modify_agent_group_data.context, text, text_len);
}

/**
 * @brief End the XML element within the <modify_agent_group> command.
 *
 * @param[in] gmp_parser  Active GMP parser instance
 * @param[in] error       The errors, if any
 * @param[in] name        Name of the XML element that ended.
 *
 * @return 1 if the command ran successfully, 0 otherwise
 */
int
modify_agent_group_element_end (gmp_parser_t *gmp_parser, GError **error,
                                const gchar *name)
{
  xml_handle_end_element (modify_agent_group_data.context, name);
  if (modify_agent_group_data.context->done)
  {
    modify_agent_group_run (gmp_parser, error);
    return 1;
  }
  return 0;
}

/**
 * @brief Execute the <modify_agent_group> GMP command.
 *
 * @param[in] gmp_parser  Active GMP parser instance.
 * @param[in] error       the errors, if any.
 */
void
modify_agent_group_run (gmp_parser_t *gmp_parser, GError **error)
{
#if ENABLE_AGENTS
  entity_t root, name, comment, agents_elem;
  const char *agent_group_uuid, *name_text;

  if (!acl_user_may ("modify_agent_group"))
    {
      SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("modify_agent_group",
                              "Permission denied"));
      create_agent_group_reset ();
      return;
    }

  root = (entity_t) modify_agent_group_data.context->first->data;

  agent_group_uuid = entity_attribute (root, "agent_group_id");

  if (!agent_group_uuid || !is_uuid (agent_group_uuid))
    {
      SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("modify_agent_group",
                                                "Missing or invalid agent_group_id"));
      modify_agent_group_reset ();
      return;
    }

  agent_group_t agent_group = agent_group_id_by_uuid (agent_group_uuid);
  if (!agent_group)
    {
      if (send_find_error_to_client ("modify_agent_group",
                                     "agent_group",
                                     agent_group_uuid,
                                     gmp_parser))
      {
        error_send_to_client (error);
        modify_agent_group_reset ();
        return;
      }
    }

  name = entity_child (root, "name");
  if (!name || !(name_text = entity_text (name)) || strlen (name_text) == 0)
    {
      SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("modify_agent_group",
                                                "modify_agent_group requires a name"));
      modify_agent_group_reset ();
      return;
    }

  comment = entity_child (root, "comment");

  // Parse agent UUIDs
  agents_elem = entity_child (root, "agents");
  agent_uuid_list_t agent_uuids = NULL;

  if (agents_elem)
    {
      GSList *agent_entities = agents_elem->entities;
      int count = g_slist_length (agent_entities);
      agent_uuids = agent_uuid_list_new (count);

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
                XML_ERROR_SYNTAX ("modify_agent_group", "Agent UUID '%s' is invalid"), uuid);
              modify_agent_group_reset ();
              return;
            }
        }
    }

  // Prepare agent group data
  agent_group_data_t group_data = agent_group_data_new();
  group_data->name = g_strdup (name_text);
  group_data->comment = g_strdup (comment ? entity_text (comment) : "");
  group_data->modification_time = time(NULL);

  agent_group_resp_t response = modify_agent_group (agent_group, group_data, agent_uuids);

  switch (response)
    {
      case AGENT_GROUP_RESP_SUCCESS:
        {
          char *uuid = g_strdup (agent_group_uuid);
          SENDF_TO_CLIENT_OR_FAIL (XML_OK ("modify_agent_group"));
          log_event ("agent_group", "Agent Group", uuid, "modified");
          g_free (uuid);
          break;
        }

      case AGENT_GROUP_RESP_NO_AGENTS_PROVIDED:
        SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("modify_agent_group", "No agents provided"));
        log_event_fail ("agent_group", "Agent Group", NULL, "modified");
        break;

      case AGENT_GROUP_RESP_SCANNER_NOT_FOUND:
        if (send_find_error_to_client ("modify_agent_group",
                                       "scanner",
                                       NULL,
                                       gmp_parser))
          {
            error_send_to_client (error);
            modify_agent_group_reset ();
            return;
          }

        log_event_fail ("agent_group", "Agent Group", NULL, "modified");
        break;

      case AGENT_GROUP_RESP_SCANNER_PERMISSION:
        SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("modify_agent_group", "Permission denied"));
        log_event_fail ("agent_group", "Agent Group", NULL, "modified");
        break;

      case AGENT_GROUP_RESP_AGENT_SCANNER_MISMATCH:
        SEND_TO_CLIENT_OR_FAIL (
          XML_ERROR_SYNTAX ("modify_agent_group", "Agents belong to different scanners"));
        log_event_fail ("agent_group", "Agent Group", NULL, "modified");
        break;

      case AGENT_GROUP_RESP_INVALID_ARGUMENT:
        SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("modify_agent_group", "Invalid input"));
        log_event_fail ("agent_group", "Agent Group", NULL, "modified");
        break;

      case AGENT_GROUP_RESP_AGENT_NOT_FOUND:
        if (send_find_error_to_client ("modify_agent_group",
                                       "agent",
                                       NULL,
                                       gmp_parser))
          {
            error_send_to_client (error);
            modify_agent_group_reset ();
            return;
          }

        log_event_fail ("agent_group", "Agent Group", NULL, "modified");
        break;

      case AGENT_GROUP_RESP_AGENT_UNAUTHORIZED:
        SEND_TO_CLIENT_OR_FAIL (
          XML_ERROR_SYNTAX ("modify_agent_group", "Unauthorized Agent"));
        log_event_fail ("agent_group", "Agent Group", NULL, "modified");
        break;

      case AGENT_GROUP_RESP_INTERNAL_ERROR:
      default:
        SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_agent_group"));
        log_event_fail ("agent_group", "Agent Group", NULL, "modified");
        break;
    }

  // Cleanup
  agent_group_data_free (group_data);
  agent_uuid_list_free (agent_uuids);

#else
  SEND_TO_CLIENT_OR_FAIL (XML_ERROR_UNAVAILABLE ("modify_agent_group",
                                                 "Command unavailable"));
#endif

  modify_agent_group_reset ();
}