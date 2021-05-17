/* Copyright (C) 2018-2021 Greenbone Networks GmbH
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
 * @file gmp_configs.c
 * @brief GVM GMP layer: Configs
 *
 * GMP configs.
 */

#include "gmp_configs.h"
#include "gmp_base.h"
#include "gmp_get.h"
#include "manage_acl.h"
#include "manage_configs.h"

#include <assert.h>
#include <glib.h>
#include <stdlib.h>
#include <string.h>

#include <gvm/util/xmlutils.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"


/* Helpers. */

/**
 * @brief Create a new NVT selector.
 *
 * @param[in]  name           Name of NVT selector.
 * @param[in]  type           Type of NVT selector.
 * @param[in]  include        Include/exclude flag.
 * @param[in]  family_or_nvt  Family or NVT.
 *
 * @return Newly allocated NVT selector.
 */
static gpointer
nvt_selector_new (char *name, char *type, int include, char *family_or_nvt)
{
  nvt_selector_t *selector;

  selector = (nvt_selector_t*) g_malloc0 (sizeof (nvt_selector_t));
  selector->name = name;
  selector->type = type;
  selector->include = include;
  selector->family_or_nvt = family_or_nvt;

  return selector;
}


/* CREATE_CONFIG. */

/**
 * @brief The create_config command.
 */
typedef struct
{
  context_data_t *context;     ///< XML parser context.
} create_config_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static create_config_t create_config_data;

/**
 * @brief Reset command data.
 */
static void
create_config_reset ()
{
  if (create_config_data.context->first)
    {
      free_entity (create_config_data.context->first->data);
      g_slist_free_1 (create_config_data.context->first);
    }
  g_free (create_config_data.context);
  memset (&create_config_data, 0, sizeof (create_config_t));
}

/**
 * @brief Start a command.
 *
 * @param[in]  gmp_parser        GMP parser.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
create_config_start (gmp_parser_t *gmp_parser,
                     const gchar **attribute_names,
                     const gchar **attribute_values)
{
  memset (&create_config_data, 0, sizeof (create_config_t));
  create_config_data.context = g_malloc0 (sizeof (context_data_t));
  create_config_element_start (gmp_parser, "create_config", attribute_names,
                               attribute_values);
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
create_config_element_start (gmp_parser_t *gmp_parser, const gchar *name,
                             const gchar **attribute_names,
                             const gchar **attribute_values)
{
  xml_handle_start_element (create_config_data.context, name, attribute_names,
                            attribute_values);
}

/**
 * @brief Get the text of entity.
 *
 * @param[in]  entity  Entity.  Can be NULL.
 *
 * @return Entity text if there's an entity, else NULL.
 */
static gchar*
text_or_null (entity_t entity)
{
  if (entity
      && strlen (entity_text (entity)))
    return entity_text (entity);
  return NULL;
}

/**
 * @brief Get the attribute of entity.
 *
 * @param[in]  entity  Entity.  Can be NULL.
 * @param[in]  name    Name of attribute.
 *
 * @return Entity attribute if there's an entity, else NULL.
 */
static gchar *
attr_or_null (entity_t entity, const gchar *name)
{
  assert (name);

  if (entity)
    return (gchar*) entity_attribute (entity, name);
  return NULL;
}

/**
 * @brief Get creation data from a config entity.
 *
 * @param[in]  config                Config entity.
 * @param[out] config_id             Address for config ID, or NULL.
 * @param[out] name                  Address for name.
 * @param[out] comment               Address for comment.
 * @param[out] type                  Address for type.
 * @param[out] usage_type            Address for usage type.
 * @param[out] all_selector          True if ALL_SELECTOR was present.
 * @param[out] import_nvt_selectors  Address for selectors.
 * @param[out] import_preferences    Address for preferences.
 *
 * @return 0 success, 1 preference did no exist, -1 preference without ID.
 */
int
parse_config_entity (entity_t config, const char **config_id, char **name,
                     char **comment, char **type, char **usage_type,
                     int *all_selector,
                     array_t **import_nvt_selectors,
                     array_t **import_preferences)
{
  entity_t entity, preferences, nvt_selectors;

  *name = *comment = *type = NULL;
  *all_selector = 0;

  if (config_id)
    *config_id = entity_attribute (config, "id");

  entity = entity_child (config, "name");
  if (entity)
    *name = entity_text (entity);

  entity = entity_child (config, "comment");
  if (entity)
    *comment = entity_text (entity);

  entity = entity_child (config, "type");
  if (entity)
    *type = entity_text (entity);

  if (usage_type)
    {
      entity = entity_child (config, "usage_type");
      if (entity)
        *usage_type = entity_text (entity);
      else
        *usage_type = NULL;
    }

  /* Collect NVT selectors. */

  *import_nvt_selectors = NULL;
  nvt_selectors = entity_child (config, "nvt_selectors");
  if (nvt_selectors)
    {
      entity_t nvt_selector;
      entities_t children;

      *import_nvt_selectors = make_array ();
      children = nvt_selectors->entities;
      while ((nvt_selector = first_entity (children)))
        {
          entity_t include, selector_name, selector_type, selector_fam;
          int import_include;

          if (strcmp (entity_name (nvt_selector), "all_selector") == 0)
            {
              array_free (*import_nvt_selectors);
              *import_nvt_selectors = NULL;
              *all_selector = 1;
              break;
            }

          include = entity_child (nvt_selector, "include");
          if (include && strcmp (entity_text (include), "0") == 0)
            import_include = 0;
          else
            import_include = 1;

          selector_name = entity_child (nvt_selector, "name");
          selector_type = entity_child (nvt_selector, "type");
          selector_fam = entity_child (nvt_selector, "family_or_nvt");

          array_add (*import_nvt_selectors,
                     nvt_selector_new (text_or_null (selector_name),
                                       text_or_null (selector_type),
                                       import_include,
                                       text_or_null (selector_fam)));

          children = next_entities (children);
        }

      if (*import_nvt_selectors)
        array_terminate (*import_nvt_selectors);
    }

  /* Collect NVT preferences. */

  *import_preferences = NULL;
  preferences = entity_child (config, "preferences");
  if (preferences)
    {
      entity_t preference;
      entities_t children;

      *import_preferences = make_array ();
      children = preferences->entities;
      while ((preference = first_entity (children)))
        {
          entity_t pref_name, pref_nvt_name, hr_name, nvt, alt;
          char *preference_hr_name, *preference_nvt_oid;
          array_t *import_alts;
          entities_t alts;
          preference_t *new_preference;

          pref_name = entity_child (preference, "name");

          pref_nvt_name = NULL;
          nvt = entity_child (preference, "nvt");
          if (nvt)
            pref_nvt_name = entity_child (nvt, "name");

          hr_name = entity_child (preference, "hr_name");
          if (*type == NULL || strcmp (*type, "0") == 0)
            /* Classic OpenVAS config preference. */
            preference_hr_name = NULL;
          else if (hr_name && strlen (entity_text (hr_name)))
            /* OSP config preference with hr_name given. */
            preference_hr_name = entity_text (hr_name);
          else
            /* Old OSP config without hr_name. */
            preference_hr_name = text_or_null (pref_name);

          import_alts = make_array ();
          alts = preference->entities;
          while ((alt = first_entity (alts)))
            {
              if (strcasecmp (entity_name (alt), "ALT") == 0)
                array_add (import_alts, text_or_null (alt));
              alts = next_entities (alts);
            }
          array_terminate (import_alts);

          preference_nvt_oid = attr_or_null (nvt, "oid");

          if ((*type == NULL || strcmp (*type, "0") == 0)
              && preference_nvt_oid
              && strcmp (preference_nvt_oid, ""))
            {
              /* Preference in an OpenVAS config:
               * Get the preference from nvt_preferences */
              char *preference_id, *preference_name, *preference_type;
              char *preference_value;

              preference_id
                = text_or_null (entity_child (preference, "id"));
              preference_name
                = text_or_null (entity_child (preference, "name"));
              preference_type
                = text_or_null (entity_child (preference, "type"));
              preference_value
                = text_or_null (entity_child (preference, "value"));

              if (preference_id && strcmp (preference_id, ""))
                {
                  new_preference
                    = get_nvt_preference_by_id (preference_nvt_oid,
                                                preference_id,
                                                preference_name,
                                                preference_type,
                                                preference_value ?: "");
                }
              else
                {
                  g_warning ("%s: Config contains a preference for NVT %s"
                             " without a preference id: %s",
                             __func__,
                             preference_nvt_oid,
                             preference_name);

                  cleanup_import_preferences (*import_preferences);
                  array_free (*import_nvt_selectors);

                  return -1;
                }
            }
          else
            {
              /* Scanner preference (for OpenVAS or OSP configs):
               * Use directly from imported config.
               */
              new_preference
                = preference_new
                      (text_or_null (entity_child (preference, "id")),
                       text_or_null (pref_name),
                       text_or_null (entity_child (preference, "type")),
                       text_or_null (entity_child (preference, "value")),
                       text_or_null (pref_nvt_name),
                       preference_nvt_oid,
                       import_alts,
                       text_or_null (entity_child (preference, "default")),
                       preference_hr_name,
                       0 /* do not free strings */);
            }

          array_add (*import_preferences, new_preference);

          children = next_entities (children);
        }

      array_terminate (*import_preferences);
    }

  return 0;
}

/**
 * @brief Execute command.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
void
create_config_run (gmp_parser_t *gmp_parser, GError **error)
{
  entity_t entity, get_configs_response, config, name, copy, scanner;

  entity = (entity_t) create_config_data.context->first->data;

  /* For now the import element, GET_CONFIGS_RESPONSE, overrides
   * any other elements. */

  get_configs_response = entity_child (entity, "get_configs_response");
  if (get_configs_response
      && (config = entity_child (get_configs_response, "config")))
    {
      config_t new_config;
      const char *usage_type_text;
      char *created_name, *comment, *type, *import_name;
      entity_t usage_type;
      array_t *import_nvt_selectors, *import_preferences;
      int all_selector;

      /* Allow user to overwrite usage type. */
      usage_type = entity_child (entity, "usage_type");
      if (usage_type && strcmp (entity_text (usage_type), ""))
        usage_type_text = entity_text (usage_type);
      else
        {
          usage_type = entity_child (config, "usage_type");
          if (usage_type)
            usage_type_text = entity_text (usage_type);
          else
            usage_type_text = NULL;
        }

      /* Get the config data from the XML. */

      if (parse_config_entity (config, NULL, &import_name, &comment, &type,
                               NULL, &all_selector, &import_nvt_selectors,
                               &import_preferences))
        {
          SEND_TO_CLIENT_OR_FAIL
           (XML_ERROR_SYNTAX ("create_config",
                              "Error in PREFERENCES element."));
          log_event_fail ("config", "Scan config", NULL, "created");

          /* Cleanup. */

          create_config_reset ();
          return;
        }

      /* Create config. */

      switch (create_config (NULL,                  /* Generate a UUID. */
                             import_name,
                             1,                     /* Make name unique. */
                             comment,
                             all_selector,
                             import_nvt_selectors,
                             import_preferences,
                             type,
                             usage_type_text,
                             &new_config,
                             &created_name))
        {
          case 0:
            {
              gchar *uuid = config_uuid (new_config);
              SENDF_TO_CLIENT_OR_FAIL
               ("<create_config_response"
                " status=\"" STATUS_OK_CREATED "\""
                " status_text=\"" STATUS_OK_CREATED_TEXT "\""
                " id=\"%s\">"
                /* This is a hack for the GSA, which should really
                 * do a GET_CONFIG with the ID to get the name. */
                "<config id=\"%s\"><name>%s</name></config>"
                "</create_config_response>",
                uuid,
                uuid,
                created_name);
              log_event ("config", "Scan config", uuid, "created");
              g_free (uuid);
              free (created_name);
              break;
            }
          case 1:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_config",
                                "Config exists already"));
            log_event_fail ("config", "Scan config", NULL, "created");
            break;
          case 99:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_config",
                                "Permission denied"));
            log_event_fail ("config", "Scan config", NULL, "created");
            break;
          case -1:
            SEND_TO_CLIENT_OR_FAIL
             (XML_INTERNAL_ERROR ("create_config"));
            log_event_fail ("config", "Scan config", NULL, "created");
            break;
          case -2:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_config",
                                "Import name must be at"
                                " least one character long"));
            log_event_fail ("config", "Scan config", NULL, "created");
            break;
          case -3:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_config",
                                "Error in NVT_SELECTORS element."));
            log_event_fail ("config", "Scan config", NULL, "created");
            break;
          case -4:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_config",
                                "Error in PREFERENCES element."));
            log_event_fail ("config", "Scan config", NULL, "created");
            break;
        }

      /* Cleanup. */

      cleanup_import_preferences (import_preferences);
      array_free (import_nvt_selectors);

      create_config_reset ();
      return;
    }

  /* Check for creation from scanner. */

  scanner = entity_child (entity, "scanner");
  if (scanner && strlen (entity_text (scanner)))
    {
      char *uuid;

      uuid = NULL;

      switch (create_config_from_scanner
               (entity_text (scanner),
                text_or_null (entity_child (entity, "name")),
                text_or_null (entity_child (entity, "comment")),
                text_or_null (entity_child (entity, "usage_type")),
                &uuid))
        {
          case 0:
            SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID
                                      ("create_config"), uuid);
            log_event ("config", "Scan config", uuid, "created");
            break;
          case 1:
            SENDF_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_config",
                                "Failed to find scanner"));
            break;
          case 2:
            SENDF_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_config",
                                "Scanner not of type OSP"));
            break;
          case 3:
            SENDF_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_config",
                                "Config name exists already"));
            break;
          case 4:
            SENDF_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_config",
                                "Failed to get params from scanner"
                                " - the scanner may be offline or not"
                                " configured correctly"));
            break;
          case 99:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_config",
                                "Permission denied"));
            log_event_fail ("config", "Scan config", NULL, "created");
            break;
          case -1:
          default:
            SEND_TO_CLIENT_OR_FAIL
             (XML_INTERNAL_ERROR ("create_config"));
            log_event_fail ("config", "Scan config", NULL, "created");
            break;
        }
      g_free (uuid);

      create_config_reset ();
      return;
    }

  /* Try copy from an existing config. */

  copy = entity_child (entity, "copy");
  name = entity_child (entity, "name");

  if (((name == NULL) || (strlen (entity_text (name)) == 0))
      && ((copy == NULL) || (strlen (entity_text (copy)) == 0)))
    {
      log_event_fail ("config", "Scan config", NULL, "created");
      SEND_TO_CLIENT_OR_FAIL
       (XML_ERROR_SYNTAX ("create_config",
                          "Name and base config to copy"
                          " must be at least one character long"));
    }
  else if (copy == NULL)
    {
      log_event_fail ("config", "Scan config", NULL, "created");
      SEND_TO_CLIENT_OR_FAIL
       (XML_ERROR_SYNTAX ("create_config",
                          "A COPY element is required"));
    }
  else
    {
      config_t new_config;
      entity_t comment, usage_type;

      comment = entity_child (entity, "comment");
      usage_type = entity_child (entity, "usage_type");

      switch (copy_config (entity_text (name),
                           comment ? entity_text (comment) : "",
                           entity_text (copy),
                           usage_type ? entity_text (usage_type) : NULL,
                           &new_config))
        {
          case 0:
            {
              char *uuid = config_uuid (new_config);
              SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_config"),
                                       uuid);
              log_event ("config", "Scan config", uuid, "created");
              free (uuid);
              break;
            }
          case 1:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_config",
                                "Config exists already"));
            log_event_fail ("config", "Scan config", NULL, "created");
            break;
          case 2:
            if (send_find_error_to_client ("create_config", "config",
                                           entity_text (copy),
                                           gmp_parser))
              {
                error_send_to_client (error);
                return;
              }
            log_event_fail ("config", "Config", NULL, "created");
            break;
          case 99:
            SEND_TO_CLIENT_OR_FAIL
             (XML_ERROR_SYNTAX ("create_config",
                                "Permission denied"));
            log_event_fail ("config", "Scan config", NULL, "created");
            break;
          case -1:
          default:
            SEND_TO_CLIENT_OR_FAIL
             (XML_INTERNAL_ERROR ("create_config"));
            log_event_fail ("config", "Scan config", NULL, "created");
            break;
        }
    }

  create_config_reset ();
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
create_config_element_end (gmp_parser_t *gmp_parser, GError **error,
                           const gchar *name)
{
  xml_handle_end_element (create_config_data.context, name);
  if (create_config_data.context->done)
    {
      create_config_run (gmp_parser, error);
      return 1;
    }
  return 0;
}

/**
 * @brief Add text to element.
 *
 * @param[in]  text         Text.
 * @param[in]  text_len     Text length.
 */
void
create_config_element_text (const gchar *text, gsize text_len)
{
  xml_handle_text (create_config_data.context, text, text_len);
}


/* MODIFY_CONFIG. */

/**
 * @brief The modify_config command.
 */
typedef struct
{
  context_data_t *context;     ///< XML parser context.
} modify_config_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static modify_config_t modify_config_data;

/**
 * @brief Reset command data.
 */
static void
modify_config_reset ()
{
  if (modify_config_data.context->first)
    {
      free_entity (modify_config_data.context->first->data);
      g_slist_free_1 (modify_config_data.context->first);
    }
  g_free (modify_config_data.context);
  memset (&modify_config_data, 0, sizeof (modify_config_t));
}

/**
 * @brief Start a command.
 *
 * @param[in]  gmp_parser        GMP parser.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
modify_config_start (gmp_parser_t *gmp_parser,
                     const gchar **attribute_names,
                     const gchar **attribute_values)
{
  memset (&modify_config_data, 0, sizeof (modify_config_t));
  modify_config_data.context = g_malloc0 (sizeof (context_data_t));
  modify_config_element_start (gmp_parser, "modify_config", attribute_names,
                               attribute_values);
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
modify_config_element_start (gmp_parser_t *gmp_parser, const gchar *name,
                             const gchar **attribute_names,
                             const gchar **attribute_values)
{
  xml_handle_start_element (modify_config_data.context, name, attribute_names,
                            attribute_values);
}

/**
 * @brief Handle basic, single-value fields of modify_config.
 * 
 * @param[in]  config       The config to modify.
 * @param[in]  name         The name to set or NULL to keep old value.
 * @param[in]  comment      The comment to set or NULL to keep old value.
 * @param[in]  scanner_id   The scanner ID to set or NULL to keep old value.
 * @param[in]  gmp_parser   GMP parser.
 * @param[out] error        GError output.
 * 
 * @return 0 on success, -1 on error.
 */
static int
modify_config_handle_basic_fields (config_t config,
                                   const char *name,
                                   const char *comment,
                                   const char *scanner_id,
                                   gmp_parser_t *gmp_parser,
                                   GError **error)
{
  switch (manage_set_config (config, name, comment, scanner_id))
    {
      case 0:
        return 0;
      case 1:
        SENDF_TO_CLIENT_OR_FAIL_WITH_RETURN
          (-1, XML_ERROR_SYNTAX ("modify_config", "Name must be unique"));
        return -1;
      case 2:
        if (send_find_error_to_client ("modify_config",
                                       "scanner",
                                       scanner_id,
                                       gmp_parser))
          {
            error_send_to_client (error);
            return -1;
          }
        return -1;
      case 3:
        SENDF_TO_CLIENT_OR_FAIL_WITH_RETURN
          (-1, XML_ERROR_SYNTAX ("modify_config", "Config is in use"));
        return -1;
      case -1:
        SENDF_TO_CLIENT_OR_FAIL_WITH_RETURN
          (-1, XML_INTERNAL_ERROR ("modify_config"));
        return -1;
      default:
        SENDF_TO_CLIENT_OR_FAIL_WITH_RETURN
          (-1, XML_INTERNAL_ERROR ("modify_config"));
        return -1;
    }
}

/**
 * @brief Collect VT families from parsed modify_config XML into arrays.
 *
 * Family name strings are to be freed with entity.
 * VT families not collected are assumed to be static and empty.
 *
 * @param[in]  entities   The entities struct with family elems as children.
 * @param[out] families_growing_all    Array of growing families with all VTs.
 * @param[out] families_growing_empty  Array of growing, empty families.
 * @param[out] families_static_all     Array of static families with all VTs.
 * 
 * @return 0 on success, -1 on error.
 */
static int
modify_config_collect_selection_families (entities_t entities,
                                          array_t **families_growing_all,
                                          array_t **families_growing_empty,
                                          array_t **families_static_all)
{
  entities_t iter_entities;
  entity_t entity;

  assert (families_growing_all);
  assert (families_growing_empty);
  assert (families_static_all);

  *families_growing_all = make_array ();
  *families_growing_empty = make_array ();
  *families_static_all = make_array ();

  iter_entities = entities;
  while ((entity = first_entity (iter_entities)))
    {
      if (strcmp (entity_name (entity), "family") == 0)
        {
          char *name, *growing_str, *all_str;
          name = text_or_null (entity_child (entity, "name"));
          all_str = text_or_null (entity_child (entity, "all"));
          growing_str = text_or_null (entity_child (entity, "growing"));

          if (growing_str && strcmp (growing_str, "0"))
            {
              if (all_str && strcmp (all_str, "0"))
                array_add (*families_growing_all, name);
              else
                array_add (*families_growing_empty, name);
            }
          else if (all_str && strcmp (all_str, "0"))
            array_add (*families_static_all, name);
        }
      iter_entities = next_entities (iter_entities);
    }

  array_terminate (*families_growing_all);
  array_terminate (*families_growing_empty);
  array_terminate (*families_static_all);

  return 0;
}

/**
 * @brief Handles a family selection inside a modify_config command.
 * 
 * @param[in]  config                   The config to modify.
 * @param[in]  families_growing_all     Array of growing families with all VTs.
 * @param[in]  families_growing_empty   Array of growing, empty families.
 * @param[in]  families_static_all      Array of static families with all VTs.
 * @param[in]  family_selection_growing 1 if families should grow, else 0.
 * @param[in]  gmp_parser               The GMP parser.
 * @param[out] error                    GError output.
 * 
 * @return 0 on success, -1 on error.
 */
static int
modify_config_handle_family_selection (config_t config,
                                       array_t *families_growing_all,
                                       array_t *families_growing_empty,
                                       array_t *families_static_all,
                                       int family_selection_growing,
                                       gmp_parser_t *gmp_parser,
                                       GError **error)
{
  gchar *rejected_family;

  switch (manage_set_config_families
             (config,
              families_growing_all,
              families_static_all,
              families_growing_empty,
              family_selection_growing,
              &rejected_family))
    {
      case 0:
        return 0;
      case 1:
        SENDF_TO_CLIENT_OR_FAIL_WITH_RETURN
          (-1, XML_ERROR_SYNTAX ("modify_config", "Config is in use"));
        return -1;
      case 2:
        SENDF_TO_CLIENT_OR_FAIL_WITH_RETURN
          (-1,
           XML_ERROR_SYNTAX ("modify_config",
                             "Family &quot;%s&quot; must be growing and"
                             " include all VTs or it must be static and"
                             " empty."),
           rejected_family);
        g_free (rejected_family);
        return -1;
      case -1:
        SENDF_TO_CLIENT_OR_FAIL_WITH_RETURN
          (-1, XML_INTERNAL_ERROR ("modify_config"));
        return -1;
      default:
        SENDF_TO_CLIENT_OR_FAIL_WITH_RETURN
          (-1, XML_INTERNAL_ERROR ("modify_config"));
        return -1;
    }
}

/**
 * @brief Collect a list of VT OIDs for a particular family in modify_config.
 *
 * @param[in]  entities  The entities containing nvt elements as children.
 * @param[out] nvt_oids  The list of VT OIDs to select.
 *
 * @return 0 on success, -1 on error.
 */
static int
modify_config_collect_selection_nvts (entities_t entities,
                                      array_t **nvt_oids)
{
  entities_t iter_entities;
  entity_t entity;

  assert (entities);
  assert (nvt_oids);

  *nvt_oids = make_array ();

  iter_entities = entities;
  while ((entity = first_entity (iter_entities)))
    {
      if (strcmp (entity_name (entity), "nvt") == 0)
        {
          char *oid;
          oid = attr_or_null (entity, "oid");
          if (oid)
            array_add (*nvt_oids, oid);
        }
      iter_entities = next_entities (iter_entities);
    }

  array_terminate (*nvt_oids);

  return 0;
}

/**
 * @brief Changes the VT selection of a given family in modify_config.
 *
 * @param[in]  config               The config to modify.
 * @param[in]  nvt_selection_family The family to set the VT selection of.
 * @param[in]  nvt_selection        Array of VT OIDs to select of the family.
 * @param[in]  gmp_parser           The GMP parser.
 * @param[out] error                GError output.
 *
 * @return 0 on success, -1 on error.
 */
static int
modify_config_handle_nvt_selection (config_t config,
                                    const char *nvt_selection_family,
                                    GPtrArray *nvt_selection,
                                    gmp_parser_t *gmp_parser,
                                    GError **error)
{
  switch (manage_set_config_nvts
            (config,
             nvt_selection_family,
             nvt_selection))
    {
      case 0:
        return 0;
      case 1:
        SENDF_TO_CLIENT_OR_FAIL_WITH_RETURN
          (-1, XML_ERROR_SYNTAX ("modify_config", "Config is in use"));
        return -1;
      case 2:
        SENDF_TO_CLIENT_OR_FAIL_WITH_RETURN
          (-1,
           XML_ERROR_SYNTAX ("modify_config",
                             "Attempt to modify NVT in whole-only family %s"),
           nvt_selection_family);
        return -1;
      case -1:
        SENDF_TO_CLIENT_OR_FAIL_WITH_RETURN
          (-1, XML_INTERNAL_ERROR ("modify_config"));
        return -1;
      default:
        SENDF_TO_CLIENT_OR_FAIL_WITH_RETURN
          (-1, XML_INTERNAL_ERROR ("modify_config"));
        return -1;
    }
}

/**
 * @brief Modifies a single preference inside a modify_config command.
 *
 * @param[in]  config     The config to modify
 * @param[in]  nvt_oid    VT OID of the preference or NULL for scanner pref.
 * @param[in]  name       Name of the preference to Changes
 * @param[in]  value      Value to set for the preference.
 * @param[in]  gmp_parser The GMP parser.
 * @param[out] error      GError output.
 * 
 * @return 0 on success, -1 on error.
 */
static int
modify_config_handle_preference (config_t config,
                                 const char *nvt_oid,
                                 const char *name,
                                 const char *value,
                                 gmp_parser_t *gmp_parser,
                                 GError **error)
{
  switch (manage_set_config_preference (config, nvt_oid, name, value))
    {
      case 0:
        return 0;
      case 1:
        SENDF_TO_CLIENT_OR_FAIL_WITH_RETURN
          (-1, XML_ERROR_SYNTAX ("modify_config", "Config is in use"));
        return -1;
      case 2:
        if (nvt_oid)
          {
            SENDF_TO_CLIENT_OR_FAIL_WITH_RETURN
              (-1, 
               XML_ERROR_SYNTAX ("modify_config",
                                 "Empty radio value for preference %s"
                                 " of NVT %s"),
               name,
               nvt_oid);
          }
        else
          {
            SENDF_TO_CLIENT_OR_FAIL_WITH_RETURN
              (-1, 
               XML_ERROR_SYNTAX ("modify_config",
                                 "Empty radio value for preference %s"),
               nvt_oid);
          }
        return -1;
      case -1:
        SENDF_TO_CLIENT_OR_FAIL_WITH_RETURN 
          (-1, XML_INTERNAL_ERROR ("modify_config"));
        return -1;
      default:
        SENDF_TO_CLIENT_OR_FAIL_WITH_RETURN 
          (-1, XML_INTERNAL_ERROR ("modify_config"));
        return -1;
    }
}

/**
 * @brief Execute command.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[out] error        Error parameter.
 */
static void
modify_config_run (gmp_parser_t *gmp_parser, GError **error)
{
  entity_t entity, child;
  entities_t children;
  const char *config_id;
  config_t config;

  entity = (entity_t) modify_config_data.context->first->data;

  // Check command permission
  if (acl_user_may ("modify_config") == 0)
    {
      SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("modify_config",
                                                "Permission denied"));
      return;
    }

  config_id = attr_or_null (entity, "config_id");

  if (config_id == NULL)
    SEND_TO_CLIENT_OR_FAIL
     (XML_ERROR_SYNTAX ("modify_config",
                        "A config_id attribute is required"));
  else if (config_predefined_uuid (config_id))
    SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("modify_config",
                                              "Permission denied"));

  // Find the config
  switch (manage_modify_config_start (config_id, &config)) 
    {
      case 0:
        break;
      case 1:
        if (send_find_error_to_client ("modify_config",
                                       "config",
                                       config_id,
                                       gmp_parser))
          {
            error_send_to_client (error);
            return;
          }
        log_event_fail ("config", "Scan Config", config_id, "modified");
        return;
      default:
        SEND_TO_CLIENT_OR_FAIL
          (XML_INTERNAL_ERROR ("modify_config"));
        log_event_fail ("config", "Scan Config", config_id, "modified");
    }

  // Handle basic attributes and elements
  if (modify_config_handle_basic_fields
         (config,
          text_or_null (entity_child (entity, "name")),
          text_or_null (entity_child (entity, "comment")),
          text_or_null (entity_child (entity, "scanner")),
          gmp_parser,
          error))
    {
      manage_modify_config_cancel ();
      log_event_fail ("config", "Scan config", config_id, "modified");
      return;
    }

  // Preferences and NVT selections
  children = entity->entities;
  while ((child = first_entity (children)))
    {
      if (strcmp (child->name, "family_selection") == 0)
        {
          array_t *families_growing_all;
          array_t *families_growing_empty;
          array_t *families_static_all;
          const char *growing_str;
          int growing;

          growing_str = text_or_null (entity_child (child, "growing"));
          growing = (growing_str && strcmp (growing_str, "0")) ? 1 : 0;

          if (modify_config_collect_selection_families
                 (child->entities,
                  &families_growing_all,
                  &families_growing_empty,
                  &families_static_all)
              || modify_config_handle_family_selection
                   (config,
                    families_growing_all,
                    families_growing_empty,
                    families_static_all,
                    growing,
                    gmp_parser,
                    error))
            {
              manage_modify_config_cancel ();
              log_event_fail ("config", "Scan config", config_id, "modified");
              g_ptr_array_free (families_growing_all, TRUE);
              g_ptr_array_free (families_growing_empty, TRUE);
              g_ptr_array_free (families_static_all, TRUE);
              return;
            }
          g_ptr_array_free (families_growing_all, TRUE);
          g_ptr_array_free (families_growing_empty, TRUE);
          g_ptr_array_free (families_static_all, TRUE);
        }
      else if (strcmp (child->name, "nvt_selection") == 0)
        {
          array_t *nvt_selection;

          if (modify_config_collect_selection_nvts
                 (child->entities,
                  &nvt_selection)
              || modify_config_handle_nvt_selection
                   (config,
                    text_or_null (entity_child (child, "family")),
                    nvt_selection,
                    gmp_parser,
                    error))
            {
              manage_modify_config_cancel ();
              log_event_fail ("config", "Scan config", config_id, "modified");
              g_ptr_array_free (nvt_selection, TRUE);
              return;
            }
          g_ptr_array_free (nvt_selection, TRUE);
        }
      else if (strcmp (child->name, "preference") == 0)
        {
          if (modify_config_handle_preference
                 (config,
                  attr_or_null (entity_child (child, "nvt"), "oid"),
                  text_or_null (entity_child (child, "name")),
                  text_or_null (entity_child (child, "value")),
                  gmp_parser,
                  error))
            {
              manage_modify_config_cancel ();
              log_event_fail ("config", "Scan config", config_id, "modified");
              return;
            }
        }
      children = next_entities (children);
    }

  manage_modify_config_commit ();
  SEND_TO_CLIENT_OR_FAIL (XML_OK ("modify_config"));
  log_event ("config", "Scan Config", config_id, "modified");

  // Cleanup
  modify_config_reset ();
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
modify_config_element_end (gmp_parser_t *gmp_parser, GError **error,
                           const gchar *name)
{
  xml_handle_end_element (modify_config_data.context, name);
  if (modify_config_data.context->done)
    {
      modify_config_run (gmp_parser, error);
      return 1;
    }
  return 0;
}

/**
 * @brief Add text to element.
 *
 * @param[in]  text         Text.
 * @param[in]  text_len     Text length.
 */
void
modify_config_element_text (const gchar *text, gsize text_len)
{
  xml_handle_text (modify_config_data.context, text, text_len);
}
