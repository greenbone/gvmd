/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_ALERTS_H
#define _GVMD_MANAGE_ALERTS_H

#include "manage_resources.h"
#include "manage_events.h"
#include "manage_get.h"
#include "manage_tasks.h"
#include "sql.h"

#include <glib.h>

int
get_max_email_attachment_size ();

void
set_max_email_attachment_size (int);

int
get_max_email_include_size ();

void
set_max_email_include_size (int);

int
get_max_email_message_size ();

void
set_max_email_message_size (int);

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

int
create_alert (const char*, const char*, const char*, const char*, event_t,
              GPtrArray*, alert_condition_t, GPtrArray*, alert_method_t,
              GPtrArray*, alert_t*);

int
modify_alert (const char*, const char*, const char*, const char*,
              const char*, event_t, GPtrArray*, alert_condition_t, GPtrArray*,
              alert_method_t, GPtrArray*);

int
delete_alert (const char *, int);

char *
alert_uuid (alert_t);

int
alert_in_use (alert_t);

int
trash_alert_in_use (alert_t);

int
alert_writable (alert_t);

int
trash_alert_writable (alert_t);

alert_condition_t
alert_condition (alert_t);

alert_method_t
alert_method (alert_t alert);

int
manage_test_alert (const char *, gchar **);

int
init_alert_iterator (iterator_t*, get_data_t*);

int
alert_iterator_event (iterator_t*);

int
alert_iterator_condition (iterator_t*);

int
alert_iterator_method (iterator_t*);

char *
alert_iterator_filter_uuid (iterator_t*);

char *
alert_iterator_filter_name (iterator_t*);

int
alert_iterator_filter_trash (iterator_t*);

int
alert_iterator_filter_readable (iterator_t*);

int
alert_iterator_active (iterator_t*);

int
alert_count (const get_data_t *);

void
init_alert_data_iterator (iterator_t *, alert_t, int, const char *);

const char*
alert_data_iterator_name (iterator_t*);

const char*
alert_data_iterator_data (iterator_t*);

void
init_task_alert_iterator (iterator_t*, task_t);

const char*
task_alert_iterator_uuid (iterator_t*);

const char*
task_alert_iterator_name (iterator_t*);

void
init_alert_task_iterator (iterator_t*, alert_t, int);

const char*
alert_task_iterator_name (iterator_t*);

const char*
alert_task_iterator_uuid (iterator_t*);

int
alert_task_iterator_readable (iterator_t*);

int
manage_check_alerts (GSList *, const db_conn_info_t *);

int
trigger (alert_t, task_t, report_t, event_t, const void *, alert_method_t,
         alert_condition_t, const get_data_t *, int, int, gchar **);

#endif /* not _GVMD_MANAGE_ALERTS_H */
