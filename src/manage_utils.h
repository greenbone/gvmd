/* Copyright (C) 2014-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/*
 * @file
 * @brief Module for Greenbone Vulnerability Manager: Manage library utilities.
 */

#ifndef _GVMD_MANAGE_UTILS_H
#define _GVMD_MANAGE_UTILS_H

/* For strptime in time.h. */
#undef _XOPEN_SOURCE
#define _XOPEN_SOURCE
#include <glib.h>
#include <libical/ical.h>
#include <time.h>

// Log message severity constant
#define SEVERITY_LOG 0.0
// False positive severity constant
#define SEVERITY_FP -1.0
// Error message severity constant
#define SEVERITY_ERROR -3.0
// Constant for missing or invalid severity
#define SEVERITY_MISSING -99.0
// Constant for undefined severity (for ranges)
#define SEVERITY_UNDEFINED -98.0
// Maximum possible severity
#define SEVERITY_MAX 10.0
// Number of subdivisions for 1 severity point (10 => step size 0.1)
#define SEVERITY_SUBDIVISIONS 10

time_t
add_months (time_t, int);

time_t
next_time (time_t, int, int, int, const char *, int);

int
manage_count_hosts_max (const char *, const char *, int);

double
level_min_severity (const char *);

double
level_max_severity (const char *);

int
valid_db_resource_type (const char *);

void
blank_control_chars (char *);

icaltimezone *
icalendar_timezone_from_string (const char *);

icalcomponent *
icalendar_from_string (const char *, icaltimezone *, gchar **);

int
icalendar_approximate_rrule_from_vcalendar (icalcomponent *, time_t *, time_t *,
                                            int *);

time_t
icalendar_next_time_from_vcalendar (icalcomponent *, time_t, const char *, int);

time_t
icalendar_next_time_from_string (const char *, time_t, const char *, int);

int
icalendar_duration_from_vcalendar (icalcomponent *);

time_t
icalendar_first_time_from_vcalendar (icalcomponent *, icaltimezone *);

gchar *
clean_hosts_string (const char *);

gchar *
clean_hosts (const char *, int *);

gchar *
concat_error_messages (const GPtrArray *errors, const gchar *sep,
                       const gchar *prefix);

gchar *
extract_sha256_digest_if_found (const gchar *);

#endif /* not _GVMD_MANAGE_UTILS_H */
