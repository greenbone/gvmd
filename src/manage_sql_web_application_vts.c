/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Web application vulnerability test SQL.
 *
 * SQL Web application vulnerability test code for the GVM management layer.
 */

#include "manage_utils.h"
#include "manage_resources_types.h"
#include "manage_sql_web_application_vts.h"
#include "sql.h"

#include <gvm/util/json.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Insert child ZAP VTs / alerts from a JSON array into the db.
 *
 * @param[in] json      The "child_alerts" fields of the current ZAP VT / alert.
 * @param[in] parent_id The ZAP id of the parent VT / alert.
 */
static void
insert_zap_child_vts_from_json (cJSON *json, const char *parent_id)
{
  cJSON *child_alert;

  if (json == NULL)
    return;

  if (! cJSON_IsArray (json))
    {
      g_warning ("%s: child_alerts is not an array in ZAP alert '%s'",
                 __func__, parent_id);
      return;
    }

  cJSON_ArrayForEach (child_alert, json)
    {
      if (cJSON_IsObject (child_alert))
        {
          char *child_id = NULL;
          gvm_json_obj_check_str (child_alert, "id", &child_id);
          if (child_id)
            {
              sql_ps ("INSERT INTO vts.web_application_vt_refs"
                      " (vt_id, ref_id, type)"
                      " VALUES ('ZAP-' || $1, 'ZAP-' || $2, 'child_vt')",
                      SQL_STR_PARAM (parent_id),
                      SQL_STR_PARAM (child_id),
                      NULL);
              sql_ps ("INSERT INTO vts.web_application_vt_refs"
                      " (vt_id, ref_id, type)"
                      " VALUES ('ZAP-' || $1, 'ZAP-' || $2, 'parent_vt')",
                      SQL_STR_PARAM (child_id),
                      SQL_STR_PARAM (parent_id),
                      NULL);
            }
          else
            g_warning ("%s: child_alerts item has no valid 'id' string"
                       " in ZAP alert '%s'",
                       __func__, parent_id);
        }
      else
        g_warning ("%s: child_alerts item is not an object"
                   " in ZAP alert '%s'",
                   __func__, parent_id);
    }
}

/**
 * @brief Insert ZAP VT references from a "references" field into the db.
 *
 * @param[in] json      The "references" fields of the current ZAP VT / alert.
 * @param[in] parent_id The ZAP id of the parent VT / alert.
 */
static void
insert_zap_vt_refs_from_references_json (cJSON *parent_json,
                                         const char *parent_id)
{
  cJSON *references_json, *current_reference_json;
  gchar *type = NULL, *value = NULL;

  if (parent_json == NULL)
    return;

  references_json = cJSON_GetObjectItem (parent_json, "references");
  if (references_json == NULL || !(cJSON_IsArray (references_json)))
    {
      g_warning ("%s: Field 'references' missing or not an array"
                 " in ZAP alert '%s'",
                 __func__, parent_id);
      return;
    }

  cJSON_ArrayForEach (current_reference_json, references_json)
    {
      if (! cJSON_IsObject (current_reference_json))
        {
          g_warning ("%s: reference in '%s' is not an object",
                    __func__, parent_id);
          continue;
        }
      if (gvm_json_obj_check_str (current_reference_json, "type", &type))
        {
          g_warning ("%s: reference type in '%s' is missing or not a string",
                    __func__, parent_id);
          continue;
        }

      if (gvm_json_obj_check_str (current_reference_json, "value", &value))
        {
          g_warning ("%s: reference value in '%s' is missing or not a string",
                    __func__, parent_id);
          continue;
        }

      sql_ps ("INSERT INTO vts.web_application_vt_refs"
              " (vt_id, type, ref_id, ref_text)"
              " VALUES ('ZAP-' || $1, $2, $3, '');",
              SQL_STR_PARAM (parent_id),
              SQL_STR_PARAM (type),
              SQL_STR_PARAM (value),
              NULL);
    }
}

/**
 * @brief Insert ZAP VT references from a JSON string array into the db.
 *
 * @param[in]  parent_id   The ZAP id of the parent VT / alert.
 * @param[in]  field_name  Name of the field (for error messages).
 * @param[in]  array_json  The array field from the current ZAP VT / alert.
 * @param[in]  ref_type    The reference type to insert into the db.
 */
static void
insert_zap_vt_refs_from_str_array_json (const char *parent_id,
                                        const char *field_name,
                                        cJSON *array_json,
                                        const char *ref_type)
{
  cJSON *current_item_json;

  if (array_json == NULL || !(cJSON_IsArray (array_json)))
    {
      g_warning ("%s: Field '%s' missing or not an array"
                 " in ZAP alert '%s'",
                 __func__, field_name, parent_id);
      return;
    }

  cJSON_ArrayForEach (current_item_json, array_json)
    {
      if (! cJSON_IsString (current_item_json))
        {
          g_warning ("%s: item in '%s' of '%s' is not a string",
                    __func__, field_name, parent_id);
          continue;
        }

      sql_ps ("INSERT INTO vts.web_application_vt_refs"
              " (vt_id, type, ref_id, ref_text)"
              " VALUES ('ZAP-' || $1, $2, $3, '');",
              SQL_STR_PARAM (parent_id),
              SQL_STR_PARAM (ref_type),
              SQL_STR_PARAM (cJSON_GetStringValue (current_item_json)),
              NULL);
    }
}

/**
 * @brief Insert all known reference types from a ZAP VT into the db.
 *
 * @param[in]  parent_json  Parent VT / "alert" JSON object to get ref from.
 * @param[in]  parent_id   The ZAP id of the parent VT / alert.
 */
static void
insert_zap_vt_refs_from_json (cJSON *parent_json,
                              const char *parent_id)
{
  cJSON *array_json, *tags_json;
  if (parent_json == NULL)
    return;

  insert_zap_vt_refs_from_references_json (parent_json, parent_id);

  array_json = cJSON_GetObjectItem (parent_json, "cwe");
  insert_zap_vt_refs_from_str_array_json (parent_id, "cwe", array_json,
                                          "cwe");

  array_json = cJSON_GetObjectItem (parent_json, "cve");
  insert_zap_vt_refs_from_str_array_json (parent_id, "cve", array_json,
                                          "cve");

  array_json = cJSON_GetObjectItem (parent_json, "wasc");
  insert_zap_vt_refs_from_str_array_json (parent_id, "wasc", array_json,
                                          "WASC");

  tags_json = cJSON_GetObjectItem (parent_json, "alert_tags");
  if (tags_json)
    {
      array_json = cJSON_GetObjectItem (tags_json, "owasp");
      if (array_json)
        insert_zap_vt_refs_from_str_array_json (parent_id, "owasp", array_json,
                                                "OWASP");
    }
}

/**
 * @brief Handle adding a single ZAP VT from the parsed JSON object.
 *
 * @param[in]  entry  The current JSON entry to insert.
 *
 * @return 0 on success, -1 on error
 */
int
insert_zap_vt_from_json (cJSON *entry)
{
  char *id = NULL, *name = NULL, *document_type = NULL, *risk = NULL;
  char *description = NULL, *solution = NULL;
  char *alert_type = NULL, *status = NULL;
  double severity = SEVERITY_MISSING;
  cJSON *type_metadata_json, *child_alerts_json;
  char *type_metadata_str = NULL;

  gvm_json_obj_check_str (entry, "id", &id);
  gvm_json_obj_check_str (entry, "name", &name);
  gvm_json_obj_check_str (entry, "document_type", &document_type);
  gvm_json_obj_check_str (entry, "risk", &risk);

  if (id == NULL)
    {
      g_warning ("%s: entry rejected because"
                 " 'id' field is missing or not a string", __func__);
      return -1;
    }

  if (name == NULL)
    {
      g_warning ("%s: Field 'name' missing or not a string"
                 " in ZAP alert '%s'",
                 __func__, id);
      return -1;
    }

  if (document_type == NULL)
    {
      g_warning ("%s: Field 'document_type' missing or not a string"
                 " in ZAP alert '%s'",
                 __func__, id);
      return -1;
    }

  severity = zap_risk_to_cvss (risk);
  if (severity == SEVERITY_UNDEFINED)
    {
      g_warning ("%s: ZAP alert '%s' has unexpected risk '%s'",
                 __func__, id, risk);
     severity = 10.0;
    }
  else if (severity == SEVERITY_MISSING)
    {
      if (strcasecmp (document_type, "alertset"))
        {
          g_debug ("%s: Missing risk in non-alertset ZAP alert '%s'",
                   __func__, id);
        }
    }

  gvm_json_obj_check_str (entry, "description", &description);
  gvm_json_obj_check_str (entry, "solution", &solution);
  gvm_json_obj_check_str (entry, "status", &status);
  gvm_json_obj_check_str (entry, "alert_type", &alert_type);

  type_metadata_json = cJSON_CreateObject ();
  cJSON_AddStringToObject (type_metadata_json, "document_type", document_type);
  if (risk)
    cJSON_AddStringToObject (type_metadata_json, "risk", risk);
  if (status)
    cJSON_AddStringToObject (type_metadata_json, "status", status);
  if (alert_type)
    cJSON_AddStringToObject (type_metadata_json, "alert_type", alert_type);
  type_metadata_str = cJSON_PrintBuffered (type_metadata_json, 256, 0);

  sql_ps ("INSERT INTO vts.web_application_vts"
          "  (uuid, name, creation_time, modification_time,"
          "   type, description, solution, severity, type_metadata)"
          " VALUES ('ZAP-' || $1, $2, m_now(), m_now(),"
          "         'ZAP-' || $3, $4, $5, $6, $7)"
          " ON CONFLICT (uuid) DO UPDATE"
          "  SET name = EXCLUDED.name,"
          "      modification_time = EXCLUDED.modification_time,"
          "      type = EXCLUDED.type,"
          "      description = EXCLUDED.description,"
          "      solution = EXCLUDED.solution,"
          "      severity = EXCLUDED.severity,"
          "      type_metadata = EXCLUDED.type_metadata"
          " RETURNING id;",
          SQL_STR_PARAM (id),
          SQL_STR_PARAM (name ?: id),
          SQL_STR_PARAM (document_type),
          SQL_STR_PARAM (description ?: ""),
          SQL_STR_PARAM (solution ?: ""),
          SQL_DOUBLE_PARAM (severity),
          SQL_STR_PARAM (type_metadata_str),
          NULL);

  sql_ps ("DELETE FROM vts.web_application_vt_refs"
          " WHERE vt_id = 'ZAP-' || $1",
          SQL_STR_PARAM (id),
          NULL);

  child_alerts_json = cJSON_GetObjectItem (entry, "child_alerts");
  insert_zap_child_vts_from_json (child_alerts_json, id);

  insert_zap_vt_refs_from_json (entry, id);

  cJSON_free (type_metadata_str);
  cJSON_Delete (type_metadata_json);

  return 0;
}

/**
 * @brief Replace estimate severity scores of ZAP VTs with ones from CVE refs.
 *
 * If a ZAP VT contains references to CVEs, its severity score will be
 *  overwritten with the maximum severity from the refrenced CVEs.
 */
void
update_zap_vt_severities_from_cves ()
{
  g_info ("%s: updating ZAP VT severities from CVEs", __func__);
  sql ("UPDATE vts.web_application_vts"
       " SET severity = ("
       "   SELECT coalesce(max(cves.severity), web_application_vts.severity)"
       "    FROM scap.cves"
       "    WHERE cves.uuid IN ("
       "      SELECT ref_id"
       "      FROM vts.web_application_vt_refs"
       "      WHERE type = 'cve' AND vt_id = web_application_vts.uuid"
       "    )"
       "  )"
       " WHERE EXISTS (SELECT * FROM vts.web_application_vt_refs"
       "               WHERE type = 'cve' AND vt_id = uuid);");

}

/**
 * @brief Try to assign severity scores to "alert group" type ZAP VTs.
 *
 * If a ZAP VT has no risk rating, it's likely a group, so try to get the
 *  maximum severity from the child VTs.
 */
void
update_zap_vt_group_severity_scores ()
{
  g_info ("%s: updating ZAP VT severities for groups", __func__);
  sql ("UPDATE vts.web_application_vts AS outer_vts"
       " SET severity ="
       "   (SELECT coalesce(max(severity), outer_vts.severity)"
       "    FROM vts.web_application_vts AS inner_vts"
       "    WHERE inner_vts.uuid IN"
       "      (SELECT ref_id"
       "       FROM vts.web_application_vt_refs"
       "       WHERE vt_id = outer_vts.uuid"
       "         AND type = 'child_vt')"
       "   )"
       " WHERE type = 'ZAP';");
}

/**
 * @brief Get the severity score of a web application VT by id.
 *
 * @param[in]  vt_id  Identifier of the VT to get the severity of.
 *
 * @return  Newly allocated severity score string.
 */
gchar *
web_application_vt_severity_by_id (const char *vt_id)
{
  return sql_string_ps ("SELECT severity FROM web_application_vts"
                        " WHERE uuid = $1",
                        SQL_STR_PARAM (vt_id),
                        NULL);
}
