/* Copyright (C) 2025 Greenbone AG
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

#ifndef _GVMD_MANAGE_ALERTS_H
#define _GVMD_MANAGE_ALERTS_H

#include "iterator.h"

#include <glib.h>

typedef resource_t alert_t;

/**
 * @brief Types of alert conditions.
 */
typedef enum
{
  ALERT_CONDITION_ERROR,
  ALERT_CONDITION_ALWAYS,
  ALERT_CONDITION_SEVERITY_AT_LEAST,
  ALERT_CONDITION_SEVERITY_CHANGED,
  ALERT_CONDITION_FILTER_COUNT_AT_LEAST,
  ALERT_CONDITION_FILTER_COUNT_CHANGED
} alert_condition_t;

const char*
alert_condition_name (alert_condition_t);

gchar*
alert_condition_description (alert_condition_t, alert_t);

alert_condition_t
alert_condition_from_name (const char*);

/**
 * @brief Data about a report sent by an alert.
 */
typedef struct {
  gchar *local_filename;          ///< Path to the local report file.
  gchar *remote_filename;         ///< Path or filename to send to / as.
  gchar *content_type;            ///< The MIME content type of the report.
  gchar *report_format_name;      ///< Name of the report format used.
} alert_report_data_t;

void
alert_report_data_free (alert_report_data_t *);

void
alert_report_data_reset (alert_report_data_t *);

/**
 * @brief Types of alerts.
 */
typedef enum
{
  ALERT_METHOD_ERROR,
  ALERT_METHOD_EMAIL,
  ALERT_METHOD_HTTP_GET,
  ALERT_METHOD_SOURCEFIRE,
  ALERT_METHOD_START_TASK,
  ALERT_METHOD_SYSLOG,
  ALERT_METHOD_VERINICE,
  ALERT_METHOD_SEND,
  ALERT_METHOD_SCP,
  ALERT_METHOD_SNMP,
  ALERT_METHOD_SMB,
  ALERT_METHOD_TIPPINGPOINT,
  ALERT_METHOD_VFIRE,
} alert_method_t;

const char*
alert_method_name (alert_method_t);

alert_method_t
alert_method_from_name (const char*);

gboolean
find_alert_with_permission (const char *, alert_t *, const char *);

int
copy_alert (const char*, const char*, const char*, alert_t*);

#endif /* not _GVMD_MANAGE_ALERTS_H */
