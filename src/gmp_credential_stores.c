/* Copyright (C) 2009-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Credential stores.
 *
 * GMP Handlers for reading and managing credential stores.
 */

#include "gmp_credential_stores.h"
#include "manage_credential_stores.h"
#include "manage.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"

/* GET_CREDENTIAL_STORES */

/**
 * @struct get_credential_stores_t
 * @brief Parser callback data struct type for get_credential_stores command
 */
typedef struct
{
  get_data_t get;
} get_credential_stores_t;

/**
 * @brief Parser callback data for get_credential_stores command
 */
static get_credential_stores_t get_credential_stores_data;


/**
 * @brief Reset the parser callback data of the get_credential_stores command
 */
static void
get_credential_stores_reset ()
{
  get_data_reset (&get_credential_stores_data.get);
  memset (&get_credential_stores_data, 0, sizeof (get_credential_stores_data));
}

/**
 * @brief Parse the root element start of the get_agent_groups command.
 *
 * @param[in] attribute_names  the names of the attributes
 * @param[in] attribute_values the values of the attributes
 */
void
get_credential_stores_start (const gchar **attribute_names,
                             const gchar **attribute_values)
{
  get_data_parse_attributes (&get_credential_stores_data.get,
                             "credential_stores",
                             attribute_names,
                             attribute_values);
}

#if ENABLE_CREDENTIAL_STORES
/**
 * @brief Send a credential store preference to the GMP client.
 *
 * @param[in]  gmp_parser       The GMP parser
 * @param[out] error            Output pointer for errors
 * @param[in]  prefs_iterator   Preferences iterator to get data from
 */
static void
send_credential_store_preference (gmp_parser_t *gmp_parser, GError **error,
                                  iterator_t *prefs_iterator)
{
  SENDF_TO_CLIENT_OR_FAIL (
    "<preference secret=\"%d\">"
    "<name>%s</name>"
    "<type>%s</type>"
    "<pattern>%s</pattern>"
    "<passphrase_name>%s</passphrase_name>",
    credential_store_preference_iterator_secret (prefs_iterator),
    credential_store_preference_iterator_name (prefs_iterator),
    credential_store_preference_iterator_type_name (prefs_iterator),
    credential_store_preference_iterator_pattern (prefs_iterator),
    credential_store_preference_iterator_passphrase_name (prefs_iterator));

  if (credential_store_preference_iterator_secret (prefs_iterator) == 0)
    {
      SENDF_TO_CLIENT_OR_FAIL (
        "<value>%s</value>"
        "<default_value>%s</default_value>",
        credential_store_preference_iterator_value (prefs_iterator),
        credential_store_preference_iterator_default_value (prefs_iterator));
    }

  SEND_TO_CLIENT_OR_FAIL ("</preference>");
}

/**
 * @brief Send a credential store selector to the GMP client.
 *
 * @param[in]  gmp_parser       The GMP parser
 * @param[out] error            Output pointer for errors
 * @param[in]  prefs_iterator   Selectors iterator to get data from
 */
static void
send_credential_store_selector (gmp_parser_t *gmp_parser, GError **error,
                                iterator_t *selectors_iterator)
{
  iterator_t type_iterator;
  resource_t selector_rowid
    = credential_store_selector_iterator_resource_id (selectors_iterator);

  SENDF_TO_CLIENT_OR_FAIL (
    "<selector>"
    "<name>%s</name>"
    "<pattern>%s</pattern>"
    "<default_value>%s</default_value>"
    "<credential_types>",
    credential_store_selector_iterator_name (selectors_iterator),
    credential_store_selector_iterator_pattern (selectors_iterator),
    credential_store_selector_iterator_default_value (selectors_iterator));

  init_credential_store_selector_type_iterator (&type_iterator,
                                                selector_rowid);
  while (next (&type_iterator))
    {
      SENDF_TO_CLIENT_OR_FAIL ("<credential_type>%s</credential_type>",
                               credential_store_selector_type_iterator_type
                               (&type_iterator));
    }
  cleanup_iterator (&type_iterator);

  SEND_TO_CLIENT_OR_FAIL ("</credential_types>"
    "</selector>");
}
#endif /* ENABLE_CREDENTIAL_STORES */

/**
 * @brief Run the get_credential_stores command.
 *
 * @param[in]   gmp_parser GMP Parser handling the current session
 * @param[out]  error      Error output.
 */
void
get_credential_stores_run (gmp_parser_t *gmp_parser, GError **error)
{
#if ENABLE_CREDENTIAL_STORES
  iterator_t credential_stores;
  int count = 0, filtered, ret, first;

  ret = init_get ("get_credential_stores",
                  &get_credential_stores_data.get,
                  "Credential Stores",
                  &first);

  if (ret)
    {
      switch (ret)
        {
        case 99:
          SEND_TO_CLIENT_OR_FAIL
            (XML_ERROR_SYNTAX ("get_credential_stores",
                               "Permission denied"));
          break;
        default:
          SEND_TO_CLIENT_OR_FAIL
            (XML_INTERNAL_ERROR ("get_credential_stores"));
          get_credential_stores_reset ();
          return;
        }
      get_credential_stores_reset ();
      return;
    }

  ret = init_credential_store_iterator (&credential_stores,
                                        &get_credential_stores_data.get);
  if (ret)
    {
      switch (ret)
        {
        case 1:
          if (send_find_error_to_client ("get_credential_stores",
                                         "Credential Store",
                                         get_credential_stores_data.get.id,
                                         gmp_parser))
            {
              error_send_to_client (error);
              return;
            }
          break;
        case 2:
          if (send_find_error_to_client
            ("get_credential_stores", "Filter",
             get_credential_stores_data.get.filt_id, gmp_parser))
            {
              error_send_to_client (error);
              return;
            }
          break;
        case -1:
          SEND_TO_CLIENT_OR_FAIL
            (XML_INTERNAL_ERROR ("get_credential_stores"));
          break;
        }
      get_credential_stores_reset ();
      return;
    }

  SEND_GET_START ("credential_store");

  while (1)
    {
      iterator_t prefs, selectors;

      ret = get_next (&credential_stores, &get_credential_stores_data.get,
                      &first, &count, init_credential_store_iterator);
      if (ret == 1)
        break;
      if (ret == -1)
        {
          internal_error_send_to_client (error);
          get_credential_stores_reset ();
          return;
        }

      // Start <credential_store>
      SEND_GET_COMMON_NO_TRASH (credential_store,
                                &get_credential_stores_data.get,
                                &credential_stores);

      int port = credential_store_iterator_port (&credential_stores);

      gchar *port_str = port > 0 ? g_strdup_printf ("%d", port) : g_strdup ("");

      SENDF_TO_CLIENT_OR_FAIL (
        "<version>%s</version>"
        "<active>%d</active>"
        "<host>%s</host>"
        "<path>%s</path>"
        "<port>%s</port>"
        "<preferences>",
        credential_store_iterator_version (&credential_stores),
        credential_store_iterator_active (&credential_stores),
        credential_store_iterator_host (&credential_stores),
        credential_store_iterator_path (&credential_stores),
        port_str);

      g_free (port_str);

      init_credential_store_preference_iterator (
        &prefs, get_iterator_resource (&credential_stores)
        );
      while (next (&prefs))
        {
          send_credential_store_preference (gmp_parser, error, &prefs);
        }
      cleanup_iterator (&prefs);
      SEND_TO_CLIENT_OR_FAIL ("</preferences>"
        "<selectors>");

      init_credential_store_selector_iterator (
        &selectors, get_iterator_resource (&credential_stores)
        );
      while (next (&selectors))
        {
          send_credential_store_selector (gmp_parser, error, &selectors);
        }
      cleanup_iterator (&selectors);

      SEND_TO_CLIENT_OR_FAIL ("</selectors>"
        "</credential_store>");
      count++;
    }

  cleanup_iterator (&credential_stores);

  filtered = get_credential_stores_data.get.id
               ? 1
               : credential_store_count (&get_credential_stores_data.get);

  SEND_GET_END ("credential_store", &get_credential_stores_data.get,
                count, filtered);

#else
  SEND_TO_CLIENT_OR_FAIL (XML_ERROR_UNAVAILABLE ("get_credential_stores",
    "Command unavailable"));
#endif

  get_credential_stores_reset ();
}

/* MODIFY_credential_store */

/**
 * @struct modify_credential_store_data_t
 * @brief Parser callback struct type for modify_credential_store command
 */
typedef struct
{
  context_data_t *context;
} modify_credential_store_data_t;

/**
 * @brief Parser callback data for modify_credential_store.
 */
static modify_credential_store_data_t modify_credential_store_data;

/**
 * @brief Reset the parser callback data for modify_credential_store.
 */
static void
modify_credential_store_reset ()
{
  if (modify_credential_store_data.context
      && modify_credential_store_data.context->first)
    {
      free_entity (modify_credential_store_data.context->first->data);
      g_slist_free_1 (modify_credential_store_data.context->first);
    }

  g_free (modify_credential_store_data.context);
  memset (&modify_credential_store_data, 0,
          sizeof (modify_credential_store_data_t));
}

/**
 * @brief Start an element in the modify_credential_store command.
 *
 * @param[in] gmp_parser       Active GMP parser instance.
 * @param[in] name             Name of the XML element being parsed.
 * @param[in] attribute_names  Null-terminated array of attribute names.
 * @param[in] attribute_values Null-terminated array of attribute values.
 */
void
modify_credential_store_element_start (gmp_parser_t *gmp_parser,
                                       const gchar *name,
                                       const gchar **attribute_names,
                                       const gchar **attribute_values)
{
  xml_handle_start_element (modify_credential_store_data.context,
                            name,
                            attribute_names,
                            attribute_values);
}

/**
 * @brief Handle the root element start of the modify_credential_store command.
 *
 * @param[in] gmp_parser        Active GMP parser instance.
 * @param[in] attribute_names   Null-terminated array of attribute names.
 * @param[in] attribute_values  Null-terminated array of attribute names.
 */
void
modify_credential_store_start (gmp_parser_t *gmp_parser,
                               const gchar **attribute_names,
                               const gchar **attribute_values)
{
  memset (&modify_credential_store_data,
          0, sizeof (modify_credential_store_data_t));
  modify_credential_store_data.context = g_malloc0 (sizeof (context_data_t));

  modify_credential_store_element_start (gmp_parser,
                                         "modify_credential_store",
                                         attribute_names,
                                         attribute_values);
}

/**
 * @brief Add text to element for modify_credential_store.
 *
 * @param[in]  text         Text.
 * @param[in]  text_len     Text length.
 */
void
modify_credential_store_element_text (const gchar *text, gsize text_len)
{
  xml_handle_text (modify_credential_store_data.context, text, text_len);
}

/**
 * @brief Handle the end of an element in the modify_credential_store command.
 *
 * @param[in] gmp_parser  Active GMP parser instance
 * @param[in] error       The errors, if any
 * @param[in] name        Name of the XML element that ended.
 *
 * @return 1 if the command ran successfully, 0 otherwise
 */
int
modify_credential_store_element_end (gmp_parser_t *gmp_parser, GError **error,
                                     const gchar *name)
{
  xml_handle_end_element (modify_credential_store_data.context, name);
  if (modify_credential_store_data.context->done)
    {
      modify_credential_store_run (gmp_parser, error);
      return 1;
    }
  return 0;
}

/**
 * @brief Convert credential store preferences XML to a hashtable of structs.
 *
 * @param[in]  prefs_list_entity  The preferences list XML element.
 *
 * @return A hashtable of preference structs using the names as keys.
 */
static GHashTable *
credential_store_preferences_from_entity (entity_t prefs_list_entity)
{
  entities_t children;
  entity_t child;
  GHashTable *prefs;
  if (prefs_list_entity == NULL)
    return NULL;

  prefs = g_hash_table_new (g_str_hash, g_str_equal);
  children = prefs_list_entity->entities;
  while ((child = first_entity (children)))
    {
      if (strcmp (entity_name (child), "preference") == 0)
        {
          const char *pref_name;
          entity_t pref_name_entity;
          pref_name_entity = entity_child (child, "name");
          pref_name = pref_name_entity ? entity_text (pref_name_entity) : NULL;

          if (pref_name && strcmp (pref_name, ""))
            {
              entity_t pref_value_entity;
              const char *pref_value;

              pref_value_entity = entity_child (child, "value");
              if (pref_value_entity)
                pref_value = entity_text (pref_value_entity);
              else
                pref_value = NULL;

              g_hash_table_insert (prefs, (void *) pref_name,
                                   (void *) pref_value);
            }
        }
      children = next_entities (children);
    }
  return prefs;
}

/**
 * @brief Run the modify_credential_store command.
 *
 * @param[in] gmp_parser  Active GMP parser instance.
 * @param[in] error       the errors, if any.
 */
void
modify_credential_store_run (gmp_parser_t *gmp_parser, GError **error)
{
#if ENABLE_CREDENTIAL_STORES
  entity_t entity, child_entity;
  const char *credential_store_id, *active, *host, *path, *port, *comment;
  modify_credential_store_return_t ret;
  gchar *message;

  entity = (entity_t) modify_credential_store_data.context->first->data;
  credential_store_id = entity_attribute (entity, "credential_store_id");

  child_entity = entity_child (entity, "active");
  active = child_entity ? entity_text (child_entity) : NULL;

  child_entity = entity_child (entity, "host");
  host = child_entity ? entity_text (child_entity) : NULL;

  child_entity = entity_child (entity, "path");
  path = child_entity ? entity_text (child_entity) : NULL;

  child_entity = entity_child (entity, "port");
  port = child_entity ? entity_text (child_entity) : NULL;

  child_entity = entity_child (entity, "comment");
  comment = child_entity ? entity_text (child_entity) : NULL;

  child_entity = entity_child (entity, "preferences");
  GHashTable *preferences = credential_store_preferences_from_entity (
    child_entity);

  ret = modify_credential_store (credential_store_id,
                                 active,
                                 host,
                                 path,
                                 port,
                                 comment,
                                 preferences,
                                 &message);
  if (preferences)
    g_hash_table_destroy (preferences);
  switch (ret)
    {
    case MODIFY_CREDENTIAL_STORE_OK:
      SEND_TO_CLIENT_OR_FAIL (XML_OK ("modify_credential_store"));
      log_event ("credential_store", "Credential Store",
                 credential_store_id, "modified");
      break;
    case MODIFY_CREDENTIAL_STORE_MISSING_ID:
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("modify_credential_store",
                           "The credential_store_id attribute is required"));
      break;
    case MODIFY_CREDENTIAL_STORE_NOT_FOUND:
      if (send_find_error_to_client ("modify_credential_store",
                                     "Credential Store",
                                     credential_store_id,
                                     gmp_parser))
        {
          error_send_to_client (error);
          return;
        }
      break;
    case MODIFY_CREDENTIAL_STORE_INVALID_HOST:
      if (message)
        SENDF_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_credential_store",
                             "Invalid host: %s"), message);
      else
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_credential_store",
                             "Invalid host"));
      log_event_fail ("credential_store", "Credential Store",
                      credential_store_id, "modified");
      break;
    case MODIFY_CREDENTIAL_STORE_INVALID_PATH:
      if (message)
        SENDF_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_credential_store",
                             "Invalid path: %s"), message);
      else
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_credential_store",
                             "Invalid path"));
      log_event_fail ("credential_store", "Credential Store",
                      credential_store_id, "modified");
      break;
    case MODIFY_CREDENTIAL_STORE_INVALID_PORT:
      if (message)
        SENDF_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_credential_store",
                             "Invalid port: %s"), message);
      else
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_credential_store",
                             "Invalid port"));
      log_event_fail ("credential_store", "Credential Store",
                      credential_store_id, "modified");
      break;
    case MODIFY_CREDENTIAL_STORE_INVALID_PREFERENCE:
      if (message)
        SENDF_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_credential_store",
                             "Invalid preference: %s"), message);
      else
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("modify_credential_store",
                             "Invalid preference"));
      log_event_fail ("credential_store", "Credential Store",
                      credential_store_id, "modified");
      break;
    case MODIFY_CREDENTIAL_STORE_PERMISSION_DENIED:
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("modify_credential_store",
                           "Permission denied"));
      log_event_fail ("credential_store", "Credential Store",
                      credential_store_id, "modified");
      break;
    default:
      SEND_TO_CLIENT_OR_FAIL
        (XML_INTERNAL_ERROR ("modify_credential_store"));
      log_event_fail ("credential_store", "Credential Store",
                      credential_store_id, "modified");
    }
  g_free (message);

#else
  SEND_TO_CLIENT_OR_FAIL (XML_ERROR_UNAVAILABLE ("modify_credential_store",
    "Command unavailable"));
#endif

  modify_credential_store_reset ();
}

/* VERIFY_credential_store */

/**
 * @struct verify_credential_store_data_t
 * @brief Parser callback struct type for verify_credential_store command
 */
typedef struct
{
  context_data_t *context;
  gchar *credential_store_id;
} verify_credential_store_data_t;

/**
 * @brief Parser callback data for verify_credential_store.
 */
static verify_credential_store_data_t verify_credential_store_data;

/**
 * @brief Reset the parser callback data for verify_credential_store.
 */
static void
verify_credential_store_reset ()
{
  if (verify_credential_store_data.context
      && verify_credential_store_data.context->first)
    {
      free_entity (verify_credential_store_data.context->first->data);
      g_slist_free_1 (verify_credential_store_data.context->first);
    }

  g_free (verify_credential_store_data.context);
  g_free (verify_credential_store_data.credential_store_id);
  memset (&verify_credential_store_data, 0,
          sizeof (verify_credential_store_data_t));
}

/**
 * @brief Handle the root element start of the verify_credential_store command.
 *
 * @param[in] gmp_parser        Active GMP parser instance.
 * @param[in] attribute_names   Null-terminated array of attribute names.
 * @param[in] attribute_values  Null-terminated array of attribute names.
 */
void
verify_credential_store_start (gmp_parser_t *gmp_parser,
                               const gchar **attribute_names,
                               const gchar **attribute_values)
{
  const char *attribute = NULL;
  memset (&verify_credential_store_data,
          0, sizeof (verify_credential_store_data_t));
  verify_credential_store_data.context = g_malloc0 (sizeof (context_data_t));

  find_attribute (attribute_names, attribute_values,
                  "credential_store_id",
                  &attribute);
  verify_credential_store_data.credential_store_id
    = attribute ? g_strdup (attribute) : NULL;
}

/**
 * @brief Run the modify_credential_store command.
 *
 * @param[in] gmp_parser  Active GMP parser instance.
 * @param[in] error       the errors, if any.
 */
void
verify_credential_store_run (gmp_parser_t *gmp_parser, GError **error)
{
#if ENABLE_CREDENTIAL_STORES
  const char *credential_store_id
    = verify_credential_store_data.credential_store_id;
  gchar *message = NULL;
  switch (verify_credential_store (credential_store_id, &message))
    {
    case VERIFY_CREDENTIAL_STORE_OK:
      SEND_TO_CLIENT_OR_FAIL (XML_OK ("verify_credential_store"));
      break;

    case VERIFY_CREDENTIAL_STORE_MISSING_ID:
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("verify_credential_store",
                           "The credential_store_id attribute is required"));
      break;

    case VERIFY_CREDENTIAL_STORE_NOT_FOUND:
      if (send_find_error_to_client ("verify_credential_store",
                                     "Credential Store",
                                     credential_store_id,
                                     gmp_parser))
        {
          error_send_to_client (error);
          return;
        }
      break;

    case VERIFY_CREDENTIAL_STORE_CONNECTOR_ERROR:
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("verify_credential_store",
                           "Invalid connector configuration for credential store"));
      break;

    case VERIFY_CREDENTIAL_STORE_HOST_ERROR:
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("verify_credential_store",
                           "Invalid or missing host for credential store"));
      break;

    case VERIFY_CREDENTIAL_STORE_PATH_ERROR:
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("verify_credential_store",
                           "Invalid path for credential store"));
      break;

    case VERIFY_CREDENTIAL_STORE_PORT_ERROR:
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("verify_credential_store",
                           "Invalid port for credential store"));
      break;

    case VERIFY_CREDENTIAL_STORE_PREFERENCE_ERROR:
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("verify_credential_store",
                           "Invalid preferences for credential store"));
      break;

    case VERIFY_CREDENTIAL_STORE_CONNECTION_FAILED:
      if (message)
        SENDF_TO_CLIENT_OR_FAIL
          (XML_ERROR_UNAVAILABLE ("verify_credential_store",
                                  "Connection failed: %s"), message);
      else
        SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_UNAVAILABLE ("verify_credential_store",
                                  "Connection failed"));
      break;

    case VERIFY_CREDENTIAL_STORE_PERMISSION_DENIED:
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("verify_credential_store",
                           "Permission denied"));
      break;

    case VERIFY_CREDENTIAL_STORE_FEATURE_DISABLED:
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("verify_credential_store",
                             "Credential store feature is disabled"));
      break;

    case VERIFY_CREDENTIAL_STORE_INTERNAL_ERROR:
      SEND_TO_CLIENT_OR_FAIL
        (XML_INTERNAL_ERROR ("verify_credential_store"));
      break;

    default:
      SEND_TO_CLIENT_OR_FAIL
        (XML_INTERNAL_ERROR ("verify_credential_store"));
      break;
    }

  g_free (message);
  verify_credential_store_reset ();
#endif /* ENABLE_CREDENTIAL_STORES */
}