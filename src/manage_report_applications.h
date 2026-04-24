/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report applications.
 *
 * Non-SQL report applications code for the GVM management layer.
 */
#ifndef _GVM_MANAGE_REPORT_APPLICATIONS_H
#define _GVM_MANAGE_REPORT_APPLICATIONS_H


#include "manage_resources.h"

#include <glib.h>

struct report_application {
  gchar *application_name;
  int hosts_count;
  int occurrences;
  double severity_double;
};
typedef struct report_application *report_application_t;

report_application_t
report_application_new(void);

void
report_application_free(report_application_t);

GPtrArray *
report_application_list_new (void);

void
report_application_list_free (GPtrArray *);

int
get_report_applications(report_t,
                        const get_data_t *,
                        GPtrArray **);
int
report_applications_count (report_t);

#endif //_GVM_MANAGE_REPORT_APPLICATIONS_H
