/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: ZAP vulnerability test SQL.
 *
 * SQL ZAP vulnerability test code for the GVM management layer.
 */

#include "manage_utils.h"
#include "manage_resources_types.h"
#include "manage_sql_zap_vts.h"
#include "sql.h"

#include <gvm/util/json.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

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
    }

  cJSON_ArrayForEach (child_alert, json)
    {
      if (cJSON_IsObject (child_alert))
        {
          char *child_id = NULL;
          gvm_json_obj_check_str (child_alert, "id", &child_id);
          if (child_id)
            {
              sql_ps ("INSERT INTO extra_vts2.zap_vt_child_vts"
                      " (parent_zap_id, child_zap_id) VALUES ($1, $2)",
                      SQL_STR_PARAM (parent_id),
                      SQL_STR_PARAM (child_id),
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

      sql_ps ("INSERT INTO extra_vts2.zap_vt_refs"
              " (vt_id, type, ref_id, ref_text)"
              " VALUES ('ZAP-' || $1, $2, $3, '');",
              SQL_STR_PARAM (parent_id),
              SQL_STR_PARAM (type),
              SQL_STR_PARAM (value),
              NULL);
    }
}

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

      sql_ps ("INSERT INTO extra_vts2.zap_vt_refs"
              " (vt_id, type, ref_id, ref_text)"
              " VALUES ('ZAP-' || $1, $2, $3, '');",
              SQL_STR_PARAM (parent_id),
              SQL_STR_PARAM (ref_type),
              SQL_STR_PARAM (cJSON_GetStringValue (current_item_json)),
              NULL);
    }
}

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

int
insert_zap_vt_from_json (cJSON *entry)
{
  char *id = NULL, *name = NULL, *document_type = NULL, *risk = NULL;
  char *description = NULL, *solution = NULL;
  char *alert_type = NULL, *status = NULL;
  double severity = SEVERITY_MISSING;
  cJSON *child_alerts_json;
  gchar *child_alerts_str = NULL;

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

  sql_ps ("INSERT INTO extra_vts2.zap_vts"
          "  (uuid, zap_id, name, creation_time, modification_time,"
          "   description, severity, risk,"
          "   document_type, alert_type, status, solution)"
          " VALUES ('ZAP-' || $1, $1, $2, m_now(), m_now(),"
          "         $3, $4, $5,"
          "         $6, $7, $8, $9)"
          " RETURNING id;",
          SQL_STR_PARAM (id),
          SQL_STR_PARAM (name ?: id),
          SQL_STR_PARAM (description ?: ""),
          SQL_DOUBLE_PARAM (severity),
          SQL_STR_PARAM (risk ?: ""),
          SQL_STR_PARAM (document_type),
          SQL_STR_PARAM (alert_type ?: ""),
          SQL_STR_PARAM (status ?: ""),
          SQL_STR_PARAM (solution ?: ""),
          NULL);

  child_alerts_json = cJSON_GetObjectItem (entry, "child_alerts");
  insert_zap_child_vts_from_json (child_alerts_json, id);

  insert_zap_vt_refs_from_json (entry, id);

  g_free (child_alerts_str);

  return 0;
}

void
update_zap_vt_severities_from_cves ()
{
  g_info ("%s: updating ZAP VT severities from CVEs", __func__);
  sql ("UPDATE extra_vts.zap_vts"
       " SET severity = ("
       "   SELECT coalesce(max(cves.severity), zap_vts.severity)"
       "    FROM scap.cves"
       "    WHERE cves.uuid IN ("
       "      SELECT ref_id"
       "      FROM extra_vts.zap_vt_refs"
       "      WHERE type = 'cve' AND vt_id = zap_vts.uuid"
       "    )"
       "  )"
       " WHERE EXISTS (SELECT * FROM extra_vts.zap_vt_refs"
       "               WHERE type = 'cve' AND vt_id = uuid);");

}

void
update_zap_vt_group_severity_scores ()
{
  g_info ("%s: updating ZAP VT severities for groups", __func__);
  sql ("UPDATE extra_vts.zap_vts AS outer_vts"
       " SET severity ="
       "   (SELECT coalesce(max(severity), outer_vts.severity)"
       "    FROM extra_vts.zap_vts AS inner_vts"
       "    WHERE inner_vts.zap_id IN"
       "      (SELECT child_zap_id"
       "       FROM extra_vts.zap_vt_child_vts"
       "       WHERE parent_zap_id = outer_vts.zap_id)"
       "   )"
       " WHERE risk = '';");
}
