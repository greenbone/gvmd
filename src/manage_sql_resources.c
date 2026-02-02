/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_resources.h"
#include "manage_utils.h"
#include "sql.h"

#include <assert.h>

/**
 * @file
 * @brief GVM management layer: Resources SQL
 *
 * The resources SQL for the GVM management layer.
 */

/**
 * @brief Get the UUID of a resource.
 *
 * @param[in]  type      Type.
 * @param[in]  resource  Resource.
 *
 * @return Freshly allocated UUID on success, else NULL.
 */
gchar *
resource_uuid (const gchar *type, resource_t resource)
{
  assert (valid_db_resource_type (type));

  return sql_string ("SELECT uuid FROM %ss WHERE id = %llu;",
                     type,
                     resource);
}
