/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_TASKS_H
#define _GVMD_MANAGE_TASKS_H


typedef enum tasks_target_type
{
  TASKS_TARGET_TYPE_UNDEFINED = -1,
  TASKS_TARGET_TYPE_IMPORT_TASK = 0,
  TASKS_TARGET_TYPE_REGULAR = 1,
  TASKS_TARGET_TYPE_AGENT_GROUP = 2,
  TASKS_TARGET_TYPE_OCI_IMAGE = 3,
  TASKS_TARGET_TYPE_WEB_APPLICATION = 4,
} tasks_target_type_t;


#endif /* not _GVMD_MANAGE_TASKS_H */
