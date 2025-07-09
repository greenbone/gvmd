/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file manage_agent_groups.c
 * @brief GVM management layer: Agent Groups.
 *
 * General management of Agent Groups
 */

 #include "manage_agent_groups.h"
 #include "manage_sql_agent_groups.h"
 #include <gvm/util/jsonpull.h>
 #include <gvm/util/fileutils.h>
 #include <glib/gstdio.h>

 #undef G_LOG_DOMAIN

 /**
  * @brief Free an agent_group_data_t structure
  * 
  * @param[in] data The structure to free.
  */
 void
 agent_group_data_free (agent_group_data_t *data)
 {
    g_free (data->uuid);
    g_free (data->name);
    g_free (data->description);
    g_free (data->controller_id);
    g_free (data); 
 }
