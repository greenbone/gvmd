/* Copyright (C) 2009-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/*
 * @file
 * @brief Headers for Greenbone Vulnerability Manager: the Manage library.
 */

#ifndef _GVMD_MANAGE_H
#define _GVMD_MANAGE_H

#include "iterator.h"
#include "manage_agent_installers.h"
#include "manage_filter_utils.h"
#include "manage_resources.h"
#include "manage_settings.h"

#include "manage_alerts.h"
#include "manage_configs.h"
#include "manage_events.h"
#include "manage_get.h"
#include "manage_tasks.h"
#include "sql.h"
#include "utils.h"

#include <stdio.h>
#include <glib.h>
#include <gnutls/gnutls.h>

#include <gvm/base/array.h>
#include <gvm/base/credentials.h>
#include <gvm/base/nvti.h>
#include <gvm/base/networking.h>
#include <gvm/util/serverutils.h>
#include <gvm/util/authutils.h>
#include <gvm/osp/osp.h>

#if ENABLE_HTTP_SCANNER
#include "manage_http_scanner.h"
#endif

#if ENABLE_OPENVASD
#include <gvm/openvasd/openvasd.h>
#endif

#if ENABLE_AGENTS
#include <gvm/agent_controller/agent_controller.h>
#include "manage_agent_control_scan_config.h"
#include "manage_agent_groups.h"
#include "manage_agents.h"
#endif

#if ENABLE_CONTAINER_SCANNING
#include "manage_oci_image_targets.h"
#include "manage_container_image_scanner.h"
#endif

/**
 * @brief OID of ping_host.nasl
 */
#define OID_PING_HOST "1.3.6.1.4.1.25623.1.0.100315"

/**
 * @brief OID of ssh_authorization_init.nasl
 */
#define OID_SSH_AUTH "1.3.6.1.4.1.25623.1.0.103591"

/**
 * @brief OID of smb_authorization.nasl
 */
#define OID_SMB_AUTH "1.3.6.1.4.1.25623.1.0.90023"

/**
 * @brief OID of gb_esxi_authorization.nasl
 */
#define OID_ESXI_AUTH "1.3.6.1.4.1.25623.1.0.105058"

/**
 * @brief OID of gb_snmp_authorization.nasl
 */
#define OID_SNMP_AUTH "1.3.6.1.4.1.25623.1.0.105076"

/**
 * @brief OID of find_services.nasl
 */
#define OID_SERVICES "1.3.6.1.4.1.25623.1.0.10330"

/**
 * @brief OID of logins.nasl
 */
#define OID_LOGINS "1.3.6.1.4.1.25623.1.0.10870"

/**
 * @brief OID of global_settings.nasl
 */
#define OID_GLOBAL_SETTINGS "1.3.6.1.4.1.25623.1.0.12288"

/**
 * @brief Flag with all Glib log levels.
 */
#define ALL_LOG_LEVELS  (G_LOG_LEVEL_MASK       \
                         | G_LOG_FLAG_FATAL     \
                         | G_LOG_FLAG_RECURSION)

/**
 * @brief Defines g_info for glib versions older than 2.40.
 */
#ifndef g_info
#define g_info(...)  g_log (G_LOG_DOMAIN,         \
                            G_LOG_LEVEL_INFO,     \
                            __VA_ARGS__)
#endif /* g_info not defined */

/**
 * @brief Name value pair.
 */
typedef struct
{
  gchar *name;    ///< Name.
  gchar *value;   ///< Param value.
} name_value_t;

/**
 * @brief Fork helper function type.
 */
typedef int (*manage_connection_forker_t) (gvm_connection_t * conn,
                                           const gchar* uuid);

int
init_manage (GSList*, const db_conn_info_t *, int, int, int, int,
             manage_connection_forker_t, int);

int
init_manage_helper (GSList *, const db_conn_info_t *, int, int);

void
init_manage_process (const db_conn_info_t*);

void
cleanup_manage_process (gboolean);

void
manage_cleanup_process_error (int);

void
manage_reset_currents ();

/* Commands. */

#define MAX_LOCK_RETRIES 16

#define MAX_DATABASE_CONNECTIONS_DEFAULT 50

#define MAX_REPORT_PROCESSING_DEFAULT 30

/* Certificate and key management. */

gchar*
truncate_certificate (const gchar*);

gchar*
truncate_private_key (const gchar*);

int
get_certificate_info (const gchar *,
                      gssize,
                      gboolean,
                      time_t *,
                      time_t *,
                      gchar **,
                      gchar **,
                      gchar **,
                      gchar **,
                      gchar **,
                      gnutls_x509_crt_fmt_t *);

gchar *
certificate_iso_time (time_t);

const gchar *
certificate_time_status (time_t, time_t);

void
parse_ssldetails (const char *, time_t *, time_t *, gchar **, gchar **);

const char*
tls_certificate_format_str (gnutls_x509_crt_fmt_t certificate_format);


/* Credentials. */

extern credentials_t current_credentials;

int
authenticate (credentials_t*);

void
logout_user ();


/* Database. */

int
manage_db_supported_version ();

int
manage_db_version ();

int
manage_scap_db_supported_version ();

int
manage_scap_db_version ();

int
manage_cert_db_supported_version ();

int
manage_cert_db_version ();

void
set_db_version (int version);

int
manage_migrate (GSList*, const db_conn_info_t*);

int
manage_encrypt_all_credentials (GSList *, const db_conn_info_t *);

int
manage_decrypt_all_credentials (GSList *, const db_conn_info_t *);

int
manage_create_encryption_key (GSList *log_config,
                              const db_conn_info_t *database);

int
manage_set_encryption_key (GSList *log_config,
                           const db_conn_info_t *database,
                           const char*);

char *
current_encryption_key_uid (gboolean);

void
set_current_encryption_key_uid (const char *new_uid);

int
validate_sort_field (const gchar*, const gchar*);

void
manage_session_set_timezone (const char *);

void
manage_transaction_start ();

void
manage_transaction_stop (gboolean);


/* Task macros and structures. */

/**
 * @brief Default for Scanner max_checks preference.
 */
#define MAX_CHECKS_DEFAULT "4"

/**
 * @brief Default for Scanner max_hosts preference.
 */
#define MAX_HOSTS_DEFAULT "20"

/**
 * @brief Task statuses, also used as scan/report statuses.
 *
 * These numbers are used in the database, so if the number associated with
 * any symbol changes then a migrator must be added to update existing data.
 */
typedef enum
{
  TASK_STATUS_DELETE_REQUESTED = 0,
  TASK_STATUS_DONE = 1,
  TASK_STATUS_NEW  = 2,
  TASK_STATUS_REQUESTED = 3,
  TASK_STATUS_RUNNING   = 4,
  TASK_STATUS_STOP_REQUESTED   = 10,
  TASK_STATUS_STOP_WAITING     = 11,
  TASK_STATUS_STOPPED = 12,
  TASK_STATUS_INTERRUPTED = 13,
  TASK_STATUS_DELETE_ULTIMATE_REQUESTED = 14,
  /* 15 was removed (TASK_STATUS_STOP_REQUESTED_GIVEUP). */
  TASK_STATUS_DELETE_WAITING = 16,
  TASK_STATUS_DELETE_ULTIMATE_WAITING = 17,
  TASK_STATUS_QUEUED = 18,
  TASK_STATUS_PROCESSING = 19,
} task_status_t;

/**
 * Minimum value for number of reports to keep on auto_delete
 */
#define AUTO_DELETE_KEEP_MIN 2

/**
 * Maximum value for number of reports to keep on auto_delete
 */
#define AUTO_DELETE_KEEP_MAX 1200


/**
 * @brief Alive tests.
 *
 * These numbers are used in the database, so if the number associated with
 * any symbol changes then a migrator must be added to update existing data.
 */
typedef enum
{
  ALIVE_TEST_TCP_ACK_SERVICE = 1,
  ALIVE_TEST_ICMP = 2,
  ALIVE_TEST_ARP = 4,
  ALIVE_TEST_CONSIDER_ALIVE = 8,
  ALIVE_TEST_TCP_SYN_SERVICE = 16
} alive_test_t;

/**
 * @brief Scanner types.
 *
 * These numbers are used in the database, so if the number associated with
 * any symbol changes then a migrator must be added to update existing data.
 */
typedef enum scanner_type
{
  SCANNER_TYPE_NONE = 0,
  /* 1 was removed (SCANNER_TYPE_OSP). */
  SCANNER_TYPE_OPENVAS = 2,
  SCANNER_TYPE_CVE = 3,
  /* 4 was removed (SCANNER_TYPE_GMP). */
  SCANNER_TYPE_OSP_SENSOR = 5,
  SCANNER_TYPE_OPENVASD = 6,
  SCANNER_TYPE_AGENT_CONTROLLER = 7,
  SCANNER_TYPE_OPENVASD_SENSOR = 8,
  SCANNER_TYPE_AGENT_CONTROLLER_SENSOR = 9,
  SCANNER_TYPE_CONTAINER_IMAGE = 10,
  SCANNER_TYPE_MAX = 11,
} scanner_type_t;

/**
 * @brief Scanner feature status.
 *
 * These numbers are indicating whether the required feature
 * for a given scanner type is available.
 */
typedef enum
{
 SCANNER_FEATURE_OK = 0,
 SCANNER_FEATURE_OPENVASD_DISABLED = 1,
 SCANNER_FEATURE_AGENTS_DISABLED = 2,
 SCANNER_FEATURE_CONTAINER_DISABLED = 3
} scanner_feature_status_t;

int
scanner_type_valid (scanner_type_t);

int
scanner_type_supports_unix_sockets (scanner_type_t);

scanner_type_t
get_scanner_type (scanner_t);

scanner_feature_status_t
check_scanner_feature (scanner_type_t);

scanner_type_t
get_scanner_type_by_uuid (const char *);


/* Resources. */

int
manage_resource_name (const char *, const char *, char **);

int
manage_trash_resource_name (const char *, const char *, char **);

int
resource_count (const char *, const get_data_t *);

int
resource_id_exists (const char *, const char *);

int
trash_id_exists (const char *, const char *);

gboolean
find_resource (const char*, const char*, resource_t*);

gboolean
find_resource_no_acl (const char*, const char*, resource_t*);

int
delete_resource (const char *, const char *, int);

int
resource_id_deprecated (const char *, const char *);

void
set_resource_id_deprecated (const char *, const char *, gboolean);


/* Events and Alerts. */

/**
 * @brief Default format string for alert email, when including report.
 */
#define ALERT_MESSAGE_INCLUDE                                                 \
 "Task '$n': $e\n"                                                            \
 "\n"                                                                         \
 "After the event $e,\n"                                                      \
 "the following condition was met: $c\n"                                      \
 "\n"                                                                         \
 "This email escalation is configured to apply report format '$r'.\n"         \
 "Full details and other report formats are available on the scan engine.\n"  \
 "\n"                                                                         \
 "$t"                                                                         \
 "\n"                                                                         \
 "$i"                                                                         \
 "\n"                                                                         \
 "\n"                                                                         \
 "Note:\n"                                                                    \
 "This email was sent to you as a configured security scan escalation.\n"     \
 "Please contact your local system administrator if you think you\n"          \
 "should not have received it.\n"

/**
 * @brief Default format string for SecInfo alert email, when including report.
 */
#define SECINFO_ALERT_MESSAGE_INCLUDE                                         \
 "Task '$n': $e\n"                                                            \
 "\n"                                                                         \
 "After the event $e,\n"                                                      \
 "the following condition was met: $c\n"                                      \
 "\n"                                                                         \
 "This email escalation is configured to apply report format '$r'.\n"         \
 "Full details and other report formats are available on the scan engine.\n"  \
 "\n"                                                                         \
 "$t"                                                                         \
 "\n"                                                                         \
 "$i"                                                                         \
 "\n"                                                                         \
 "\n"                                                                         \
 "Note:\n"                                                                    \
 "This email was sent to you as a configured security scan escalation.\n"     \
 "Please contact your local system administrator if you think you\n"          \
 "should not have received it.\n"

/**
 * @brief Default format string for alert email, when attaching report.
 */
#define ALERT_MESSAGE_ATTACH                                                  \
 "Task '$n': $e\n"                                                            \
 "\n"                                                                         \
 "After the event $e,\n"                                                      \
 "the following condition was met: $c\n"                                      \
 "\n"                                                                         \
 "This email escalation is configured to attach report format '$r'.\n"        \
 "Full details and other report formats are available on the scan engine.\n"  \
 "\n"                                                                         \
 "$t"                                                                         \
 "\n"                                                                         \
 "Note:\n"                                                                    \
 "This email was sent to you as a configured security scan escalation.\n"     \
 "Please contact your local system administrator if you think you\n"          \
 "should not have received it.\n"

/**
 * @brief Default format string for SecInfo alert email, when attaching report.
 */
#define SECINFO_ALERT_MESSAGE_ATTACH                                          \
 "Task '$n': $e\n"                                                            \
 "\n"                                                                         \
 "After the event $e,\n"                                                      \
 "the following condition was met: $c\n"                                      \
 "\n"                                                                         \
 "This email escalation is configured to attach report format '$r'.\n"        \
 "Full details and other report formats are available on the scan engine.\n"  \
 "\n"                                                                         \
 "$t"                                                                         \
 "\n"                                                                         \
 "Note:\n"                                                                    \
 "This email was sent to you as a configured security scan escalation.\n"     \
 "Please contact your local system administrator if you think you\n"          \
 "should not have received it.\n"

/**
 * @brief Default description format string for vFire alert.
 */
#define ALERT_VFIRE_CALL_DESCRIPTION                                          \
 "GVM Task '$n': $e\n"                                                        \
 "\n"                                                                         \
 "After the event $e,\n"                                                      \
 "the following condition was met: $c\n"                                      \
 "\n"                                                                         \
 "This ticket includes reports in the following format(s):\n"                 \
 "$r.\n"                                                                      \
 "Full details and other report formats are available on the scan engine.\n"  \
 "\n"                                                                         \
 "$t"                                                                         \
 "\n"                                                                         \
 "Note:\n"                                                                    \
 "This ticket was created automatically as a security scan escalation.\n"     \
 "Please contact your local system administrator if you think it\n"           \
 "was created or assigned erroneously.\n"


/* Task global variables and preprocessor variables. */

/**
 * @brief The task currently running on the scanner.
 */
extern task_t current_scanner_task;

extern report_t global_current_report;


/* Task code specific to the representation of tasks. */

unsigned int
task_count (const get_data_t *);

int
init_task_iterator (iterator_t*, get_data_t *);

task_status_t
task_iterator_run_status (iterator_t*);

const char *
task_iterator_run_status_name (iterator_t*);

int
task_iterator_total_reports (iterator_t*);

int
task_iterator_finished_reports (iterator_t *);

const char *
task_iterator_first_report (iterator_t*);

const char *
task_iterator_last_report (iterator_t *);

report_t
task_iterator_current_report (iterator_t *);

const char *
task_iterator_hosts_ordering (iterator_t *);

scanner_t
task_iterator_scanner (iterator_t *);

const char *
task_iterator_usage_type (iterator_t *);

int
task_uuid (task_t, char **);

int
task_in_trash (task_t);

int
task_in_trash_id (const gchar *);

int
task_in_use (task_t);

int
trash_task_in_use (task_t);

int
task_writable (task_t);

int
task_alterable (task_t);

int
trash_task_writable (task_t);

int
task_average_scan_duration (task_t);

char*
task_owner_name (task_t);

char*
task_name (task_t);

char*
task_comment (task_t);

char*
task_hosts_ordering (task_t);

scanner_t
task_scanner (task_t);

int
task_scanner_in_trash (task_t);

config_t
task_config (task_t);

char*
task_config_uuid (task_t);

char*
task_config_name (task_t);

int
task_config_in_trash (task_t);

void
set_task_config (task_t, config_t);

target_t
task_target (task_t);

int
task_target_in_trash (task_t);

void
set_task_target (task_t, target_t);

#if ENABLE_AGENTS
void
set_task_agent_group_and_location (task_t task, agent_group_t agent_group);

int
agent_group_tasks_exist_by_scanner (scanner_t scanner);

int
agent_group_hidden_tasks_exist_by_scanner (scanner_t scanner);

agent_group_t
task_agent_group (task_t);

int
task_agent_group_in_trash (task_t task);

#endif /* ENABLE_AGENTS */

int
set_task_schedule_and_periods (task_t task, const gchar *schedule_id,
                               const gchar *schedule_periods);

#if ENABLE_CONTAINER_SCANNING

oci_image_target_t
task_oci_image_target (task_t);

int
task_oci_image_target_in_trash (task_t);

void
set_task_oci_image_target (task_t, oci_image_target_t);

void
clear_task_asset_preferences (task_t);

#endif /* ENABLE_CONTAINER_SCANNING */

void
set_task_hosts_ordering (task_t, const char *);

void
set_task_scanner (task_t, scanner_t);

int
task_usage_type (task_t, char**);

void
set_task_usage_type (task_t, const char *);

char*
task_description (task_t);

void
set_task_description (task_t, char*, gsize);

task_status_t
task_run_status (task_t);

void
set_task_run_status (task_t, task_status_t);

int
task_result_count (task_t, int);

report_t
task_running_report (task_t);

int
task_upload_progress (task_t);

void
set_task_start_time_epoch (task_t, int);

void
set_task_start_time_ctime (task_t, char*);

void
set_task_end_time (task_t task, char* time);

void
set_task_end_time_epoch (task_t, time_t);

void
add_task_alert (task_t, alert_t);

void
set_task_alterable (task_t, int);

int
set_task_groups (task_t, array_t*, gchar**);

int
set_task_schedule (task_t, schedule_t, int);

int
set_task_schedule_periods (const gchar *, int);

int
set_task_schedule_periods_id (task_t, int);

unsigned int
task_report_count (task_t);

int
task_last_report (task_t, report_t*);

const char *
task_iterator_trend_counts (iterator_t *, int, int, int, int, double, int, int,
                            int, int, double);
int
task_schedule_periods (task_t);

int
task_schedule_periods_uuid (const gchar *);

schedule_t
task_schedule (task_t);

schedule_t
task_schedule_uuid (const gchar *);

int
task_schedule_in_trash (task_t);

time_t
task_schedule_next_time_uuid (const gchar *);

int
task_schedule_next_time (task_t);

int
task_debugs_size (task_t);

int
task_holes_size (task_t);

int
task_infos_size (task_t);

int
task_logs_size (task_t);

int
task_warnings_size (task_t);

int
task_false_positive_size (task_t);

task_t
make_task (char*, char*, int, int);

void
make_task_complete (task_t);

int
copy_task (const char*, const char*, const char *, int, task_t*);

void
set_task_name (task_t, const char *);

gboolean
find_task_with_permission (const char*, task_t*, const char *);

gboolean
find_trash_task_with_permission (const char*, task_t*, const char *);

void
reset_task (task_t);

int
set_task_parameter (task_t, const char*, char*);

char*
task_observers (task_t);

int
set_task_observers (task_t, const gchar *);

int
request_delete_task_uuid (const char *, int);

int
request_delete_task (task_t*);

int
delete_task (task_t, int);

void
append_to_task_comment (task_t, const char*, int);

void
add_task_description_line (task_t, const char*, size_t);

void
set_scan_ports (report_t, const char*, unsigned int, unsigned int);

void
append_task_open_port (task_t task, const char *, const char*);

int
manage_task_update_file (const gchar *, const char *, const void *);

int
manage_task_remove_file (const gchar *, const char *);

int
modify_task (const gchar *, const gchar *, const gchar *, const gchar *,
             const gchar *, const gchar *, const gchar *, array_t *,
             const gchar *, array_t *, const gchar *, const gchar *,
             array_t *, const gchar *, const gchar *, const gchar *,
             gchar **, gchar **);

void
init_config_file_iterator (iterator_t*, const char*, const char*);

const char*
config_file_iterator_content (iterator_t*);

int
config_file_iterator_length (iterator_t*);

void
init_config_task_iterator (iterator_t*, config_t, int);

const char*
config_task_iterator_name (iterator_t*);

const char*
config_task_iterator_uuid (iterator_t*);

int
config_task_iterator_readable (iterator_t*);


/* General severity related facilities. */

const char *
threat_message_type (const char *);

int
severity_in_level (double, const char *);

const char*
severity_to_level (double, int);

const char*
severity_to_type (double);

/**
 * @brief Severity data for result count cache.
 */
typedef struct
{
  int* counts;       ///< Counts.
  int total;         ///< Total.
  double max;        ///< Max.
} severity_data_t;

double
severity_data_value (int);

void
init_severity_data (severity_data_t*);

void
cleanup_severity_data (severity_data_t*);

void
severity_data_add (severity_data_t*, double);

void
severity_data_add_count (severity_data_t*, double, int);

void
severity_data_level_counts (const severity_data_t*,
                            int*, int*, int*, int*, int*, int*, int*);


/* General task facilities. */

const char*
run_status_name (task_status_t);

void
set_task_interrupted (task_t, const gchar *);

int
start_task (const char *, char**);

int
stop_task (const char *);

int
resume_task (const char *, char **);

int
move_task (const char*, const char*);


/* Results. */

/**
 * @brief SQL list of LSC families.
 */
#define LSC_FAMILY_LIST                            \
  "'AIX Local Security Checks',"                   \
  " 'AlmaLinux Local Security Checks',"            \
  " 'Amazon Linux Local Security Checks',"         \
  " 'Arch Linux Local Security Checks',"           \
  " 'CentOS Local Security Checks',"               \
  " 'Citrix Xenserver Local Security Checks',"     \
  " 'Debian Local Security Checks',"               \
  " 'F5 Local Security Checks',"                   \
  " 'Fedora Local Security Checks',"               \
  " 'FortiOS Local Security Checks',"              \
  " 'FreeBSD Local Security Checks',"              \
  " 'Gentoo Local Security Checks',"               \
  " 'HCE Local Security Checks',"                  \
  " 'HP-UX Local Security Checks',"                \
  " 'Huawei EulerOS Local Security Checks',"       \
  " 'JunOS Local Security Checks',"                \
  " 'Mac OS X Local Security Checks',"             \
  " 'Mageia Linux Local Security Checks',"         \
  " 'Mandrake Local Security Checks',"             \
  " 'openEuler Local Security Checks',"            \
  " 'openSUSE Local Security Checks',"             \
  " 'Oracle Linux Local Security Checks',"         \
  " 'Palo Alto PAN-OS Local Security Checks',"     \
  " 'Red Hat Local Security Checks',"              \
  " 'Rocky Linux Local Security Checks',"          \
  " 'Slackware Local Security Checks',"            \
  " 'Solaris Local Security Checks',"              \
  " 'SuSE Local Security Checks',"                 \
  " 'VMware Local Security Checks',"               \
  " 'Ubuntu Local Security Checks',"               \
  " 'Windows : Microsoft Bulletins',"              \
  " 'Windows Local Security Checks'"

/**
 * @brief Whole only families.
 */
#define FAMILIES_WHOLE_ONLY                        \
  { "AIX Local Security Checks",                   \
    "AlmaLinux Local Security Checks",             \
    "Amazon Linux Local Security Checks",          \
    "Arch Linux Local Security Checks",            \
    "CentOS Local Security Checks",                \
    "Debian Local Security Checks",                \
    "Fedora Local Security Checks",                \
    "FreeBSD Local Security Checks",               \
    "Gentoo Local Security Checks",                \
    "HCE Local Security Checks",                   \
    "HP-UX Local Security Checks",                 \
    "Huawei EulerOS Local Security Checks",        \
    "Mageia Linux Local Security Checks",          \
    "Mandrake Local Security Checks",              \
    "openEuler Local Security Checks",             \
    "openSUSE Local Security Checks",              \
    "Oracle Linux Local Security Checks",          \
    "Red Hat Local Security Checks",               \
    "Rocky Linux Local Security Checks",           \
    "Slackware Local Security Checks",             \
    "Solaris Local Security Checks",               \
    "SuSE Local Security Checks",                  \
    "Ubuntu Local Security Checks",                \
    "Windows Local Security Checks",               \
    NULL }

gboolean
find_result_with_permission (const char*, result_t*, const char *);

int
result_uuid (result_t, char **);

int
result_detection_reference (result_t, report_t, const char *, const char *,
                            const char *, char **, char **, char **, char **,
                            char **);

/* Reports. */

/**
 * @brief Default quality of detection percentage.
 */
#define QOD_DEFAULT 75

/**
 * @brief Default size to limit note and override text to in reports.
 */
#define EXCERPT_SIZE_DEFAULT 300



void
reports_clear_count_cache_for_override (override_t, int);

void
init_report_counts_build_iterator (iterator_t *, report_t, int, int,
                                   const char*);

double
report_severity (report_t, int, int);

int
report_host_count (report_t);

int
report_result_host_count (report_t, int);

char *
report_finished_hosts_str (report_t);

char *
report_finished_container_images_str (report_t);

gboolean
find_report_with_permission (const char *, report_t *, const char *);

report_t
make_report (task_t, const char *, task_status_t);

void
manage_queued_task_actions ();

void
manage_process_report_imports ();

int
qod_from_type (const char *);

result_t
make_result (task_t, const char*, const char*, const char*, const char*,
             const char*, const char*, const char*);

result_t
make_osp_result (task_t, const char*, const char*, const char*, const char*,
                 const char *, const char *, const char *, int, const char*,
                 const char *);

result_t
make_cve_result (task_t, const char*, const char*, double, const char*);

/**
 * @brief A CREATE_REPORT result.
 */
typedef struct
{
  char *description;       ///< Description of NVT.
  char *host;              ///< Host.
  char *hostname;          ///< Hostname.
  char *nvt_oid;           ///< OID of NVT.
  char *scan_nvt_version;  ///< Version of NVT used at scan time.
  char *port;              ///< Port.
  char *qod;               ///< QoD (quality of detection).
  char *qod_type;          ///< QoD type.
  char *severity;          ///< Severity score.
  char *threat;            ///< Threat.
} create_report_result_t;

/**
 * @brief A host detail for create_report.
 */
typedef struct
{
  char *ip;           ///< IP.
  char *name;         ///< Detail name.
  char *source_desc;  ///< Source description.
  char *source_name;  ///< Source name.
  char *source_type;  ///< Source type.
  char *value;        ///< Detail value.
} host_detail_t;


/**
 * @brief A detection detail for create_report.
 */
typedef struct
{
  char *product; ///< product of detection in result.
  char *source_name; ///< source_name of detection in result.
  char *source_oid; ///< source_oid of detection in result.
  char *location; ///< location of detection in result.
} detection_detail_t;

void
host_detail_free (host_detail_t *);

void
insert_report_host_detail (report_t, const char *, const char *, const char *,
                           const char *, const char *, const char *,
                           const char *);

void
clear_duration_schedules (task_t);

void
update_duration_schedule_periods (task_t);

int
create_report (array_t*, const char *, const char *, const char *, const char *,
               array_t*, array_t*, array_t*, char **);

void
report_add_result (report_t, result_t);

void
report_add_results_array (report_t, GArray *);

char*
report_uuid (report_t);

int
task_last_resumable_report (task_t, report_t *);

gchar*
task_second_last_report_id (task_t);

gchar*
report_path_task_uuid (gchar*);

gboolean
report_task (report_t, task_t*);

void
report_compliance_by_uuid (const char *, int *, int *, int *, int *);

int
report_scan_result_count (report_t, const char*, const char*, int, const char*,
                          const char*, int, int, int*);

int
report_counts (const char*, int*, int*, int*, int*, int*, int*, double*,
               int, int);

int
report_counts_id (report_t, int*, int*, int*, int*, int*, int*, double*,
                  const get_data_t*, const char*);

int
report_counts_id_no_filt (report_t, int*, int*, int*, int*, int*, int*,
                          double*, const get_data_t*, const char*);

get_data_t*
report_results_get_data (int, int, int, int);

int
scan_start_time_epoch (report_t);

char*
scan_start_time_uuid (const char *);

char*
scan_end_time_uuid (const char *);

void
set_scan_start_time_ctime (report_t, const char*);

void
set_scan_start_time_epoch (report_t, time_t);

void
set_scan_end_time (report_t, const char*);

void
set_scan_end_time_ctime (report_t, const char*);

void
set_scan_end_time_epoch (report_t, time_t);

void
set_scan_host_start_time_ctime (report_t, const char*, const char*);

int
scan_host_end_time (report_t, const char*);

void
set_scan_host_end_time (report_t, const char*, const char*);

void
set_scan_host_end_time_ctime (report_t, const char*, const char*);

int
report_timestamp (const char*, gchar**);

int
delete_report (const char *, int);

int
report_count (const get_data_t *);

int
init_report_iterator (iterator_t*, const get_data_t *);

void
init_report_iterator_task (iterator_t*, task_t);

void
init_report_errors_iterator (iterator_t*, report_t);

void
init_report_awaiting_processing_iterator (iterator_t*, int);

const char*
report_iterator_uuid (iterator_t*);

int
result_count (const get_data_t *, report_t, const char*);

int
init_result_get_iterator (iterator_t*, const get_data_t *, report_t,
                          const char*, const gchar *);
int
init_result_get_iterator_all (iterator_t* iterator, get_data_t *get);

gboolean
next_report (iterator_t*, report_t*);

result_t
result_iterator_result (iterator_t*);

const char*
result_iterator_host (iterator_t*);

const char*
result_iterator_port (iterator_t*);

const char*
result_iterator_nvt_oid (iterator_t*);

const char*
result_iterator_nvt_name (iterator_t *);

const char*
result_iterator_nvt_summary (iterator_t *);

const char*
result_iterator_nvt_insight (iterator_t *);

const char*
result_iterator_nvt_affected (iterator_t *);

const char*
result_iterator_nvt_impact (iterator_t *);

const char*
result_iterator_nvt_solution (iterator_t *);

const char*
result_iterator_nvt_solution_type (iterator_t *);

const char*
result_iterator_nvt_solution_method (iterator_t *);

const char*
result_iterator_nvt_detection (iterator_t *);

const char*
result_iterator_nvt_family (iterator_t *);

const char*
result_iterator_nvt_cvss_base (iterator_t *);

const char*
result_iterator_nvt_tag (iterator_t *);

const char*
result_iterator_descr (iterator_t*);

task_t
result_iterator_task (iterator_t*);

report_t
result_iterator_report (iterator_t*);

const char*
result_iterator_scan_nvt_version (iterator_t*);

const char*
result_iterator_original_severity (iterator_t*);

const char*
result_iterator_severity (iterator_t *);

double
result_iterator_severity_double (iterator_t *);

const char*
result_iterator_original_level (iterator_t*);

const char*
result_iterator_level (iterator_t*);

const char*
result_iterator_solution_type (iterator_t*);

const char*
result_iterator_qod (iterator_t*);

const char*
result_iterator_qod_type (iterator_t*);

const char*
result_iterator_hostname (iterator_t*);

const char*
result_iterator_date (iterator_t*);

const char*
result_iterator_path (iterator_t*);

const char*
result_iterator_asset_host_id (iterator_t*);

int
result_iterator_may_have_notes (iterator_t*);

int
result_iterator_may_have_overrides (iterator_t*);

int
result_iterator_may_have_tickets (iterator_t*);

double
result_iterator_epss_score (iterator_t*);

double
result_iterator_epss_percentile (iterator_t*);

const char*
result_iterator_epss_cve (iterator_t*);

double
result_iterator_epss_severity (iterator_t*);

double
result_iterator_max_epss_score (iterator_t*);

double
result_iterator_max_epss_percentile (iterator_t*);

const char*
result_iterator_max_epss_cve (iterator_t*);

double
result_iterator_max_epss_severity (iterator_t*);

gchar **
result_iterator_cert_bunds (iterator_t*);

gchar **
result_iterator_dfn_certs (iterator_t*);

const char *
result_iterator_compliance (iterator_t*);

const char *
result_iterator_delta_state (iterator_t*);

const char *
result_iterator_delta_description (iterator_t*);

const char *
result_iterator_delta_severity (iterator_t*);

double
result_iterator_delta_severity_double (iterator_t*);

const char *
result_iterator_delta_compliance (iterator_t*);

const char*
result_iterator_delta_level (iterator_t*);

const char *
result_iterator_delta_original_severity (iterator_t*);

double
result_iterator_delta_original_severity_double (iterator_t*);

const char*
result_iterator_delta_original_level (iterator_t*);

const char *
result_iterator_delta_qod (iterator_t*);

const char *
result_iterator_delta_uuid (iterator_t*);

const char *
result_iterator_delta_qod_type (iterator_t*);

time_t
result_iterator_delta_creation_time (iterator_t*);

time_t
result_iterator_delta_modification_time (iterator_t*);

task_t
result_iterator_delta_task (iterator_t*);

report_t
result_iterator_delta_report (iterator_t*);

const char *
result_iterator_delta_owner_name (iterator_t*);

const char *
result_iterator_delta_path (iterator_t*);

const char *
result_iterator_delta_host_asset_id (iterator_t*);

const char *
result_iterator_delta_nvt_version (iterator_t*);

result_t
result_iterator_delta_result (iterator_t*);

int
result_iterator_delta_may_have_notes (iterator_t*);

int
result_iterator_delta_may_have_overrides (iterator_t*);

int
result_iterator_delta_may_have_tickets (iterator_t*);

const char *
result_iterator_delta_hostname (iterator_t*);

int
cleanup_result_nvts ();

void
init_report_host_iterator (iterator_t*, report_t, const char *, report_host_t);

const char*
host_iterator_host (iterator_t*);

const char*
host_iterator_start_time (iterator_t*);

const char*
host_iterator_end_time (iterator_t*);

int
host_iterator_current_port (iterator_t*);

int
host_iterator_max_port (iterator_t*);

int
collate_message_type (void* data, int, const void*, int, const void*);

void
trim_partial_report (report_t);

int
report_progress (report_t);

gchar *
manage_report (report_t, report_t, const get_data_t *,
               report_format_t, report_config_t,
               int, int, gsize *, gchar **, gchar **, gchar **, gchar **,
               gchar **);

int
manage_send_report (report_t, report_t, report_format_t, report_config_t,
                    const get_data_t *,
                    int, int, int, int, int, int,
                    gboolean (*) (const char *,
                                  int (*) (const char*, void*),
                                  void*),
                    int (*) (const char *, void*), void *, const char *,
                    const gchar *);



/* Reports. */

void
init_app_locations_iterator (iterator_t*, report_host_t, const gchar *);

const char *
app_locations_iterator_location (iterator_t*);

void
init_cpe_match_nodes_iterator (iterator_t*, const char *);

void
init_cve_cpe_match_nodes_iterator (iterator_t*, const char *);

void
init_cve_reference_iterator (iterator_t*, const char *);

const char*
cve_reference_iterator_url (iterator_t*);

const char*
cve_reference_iterator_tags (iterator_t*);

const char*
cve_reference_iterator_tags_count (iterator_t*);

long long int
cpe_match_nodes_iterator_root_id (iterator_t*);

void
init_host_details_cpe_iterator (iterator_t*, report_host_t);

const char*
host_details_cpe_iterator_cpe (iterator_t*);

void
init_cpe_match_node_childs_iterator (iterator_t*, long long int);

long long int
cpe_match_node_childs_iterator_id (iterator_t*);

void
init_cpe_match_string_iterator (iterator_t*, long long int);

const char*
cpe_match_string_iterator_criteria (iterator_t*);

const char*
cpe_match_string_iterator_match_criteria_id (iterator_t*);

const char*
cpe_match_string_iterator_status (iterator_t*);

const char*
cpe_match_string_iterator_version_start_incl (iterator_t*);

const char*
cpe_match_string_iterator_version_start_excl (iterator_t*);

const char*
cpe_match_string_iterator_version_end_incl (iterator_t*);

const char*
cpe_match_string_iterator_version_end_excl (iterator_t*);

int
cpe_match_string_iterator_vulnerable (iterator_t*);

void
init_cpe_match_string_matches_iterator (iterator_t*, const char *, const char*);

const char*
cpe_matches_cpe_name_id (iterator_t*);

const char*
cpe_matches_cpe_name (iterator_t*);

void
init_host_details_cpe_product_iterator (iterator_t*, const char *, report_host_t);

const char*
host_details_cpe_product_iterator_value (iterator_t*);

void
init_host_prognosis_iterator (iterator_t*, report_host_t);

double
prognosis_iterator_cvss_double (iterator_t*);

const char*
prognosis_iterator_cpe (iterator_t*);

const char*
prognosis_iterator_cve (iterator_t*);

const char*
prognosis_iterator_description (iterator_t*);


/* Targets. */

/**
 * @brief Absolute maximum number of IPs per target.
 *
 * The number of 70000 is chosen to cover "192.168.0.0-192.168.255.255".
 */
#define MANAGE_ABSOLUTE_MAX_IPS_PER_TARGET 70000

/**
 * @brief Default maximum number of hosts a target may specify.
 */
#define MANAGE_MAX_HOSTS 4095

/**
 * @brief Default maximum number of hosts a user host access may specify.
 */
#define MANAGE_USER_MAX_HOSTS 16777216

int
manage_max_hosts ();

int
manage_count_hosts (const char *, const char *);

gboolean
find_target_with_permission (const char *, target_t *, const char *);

int
create_target (const char*, const char*, const char*, const char*, const char*,
               const char *, const char*, credential_t, credential_t,
               const char *,
               credential_t, credential_t, credential_t, credential_t,
               const char *, const char *,
               GPtrArray *, const char *,
               const char *, target_t*);

int
copy_target (const char*, const char*, const char *, target_t*);

int
modify_target (const char*, const char*, const char*, const char*, const char*,
               const char*, const char*, const char*, const char*, const char*,
               const char*, const char*, const char*, const char*, const char*,
               GPtrArray *, const char*, const char*);

int
delete_target (const char*, int);

int
target_count (const get_data_t *);

void
init_user_target_iterator (iterator_t*, target_t);

void
init_target_iterator_one (iterator_t*, target_t);

int
init_target_iterator (iterator_t*, get_data_t *);

const char*
target_iterator_hosts (iterator_t*);

const char*
target_iterator_exclude_hosts (iterator_t*);

const char*
target_iterator_reverse_lookup_only (iterator_t*);

const char*
target_iterator_reverse_lookup_unify (iterator_t*);

const char*
target_iterator_comment (iterator_t*);

int
target_iterator_ssh_credential (iterator_t*);

const char*
target_iterator_ssh_port (iterator_t*);

int
target_iterator_smb_credential (iterator_t*);

int
target_iterator_esxi_credential (iterator_t*);

int
target_iterator_snmp_credential (iterator_t*);

int
target_iterator_ssh_elevate_credential (iterator_t*);

int
target_iterator_krb5_credential (iterator_t*);

int
target_iterator_ssh_trash (iterator_t*);

int
target_iterator_smb_trash (iterator_t*);

int
target_iterator_esxi_trash (iterator_t*);

int
target_iterator_snmp_trash (iterator_t*);

int
target_iterator_ssh_elevate_trash (iterator_t*);

int
target_iterator_krb5_trash (iterator_t*);

const char*
target_iterator_allow_simultaneous_ips (iterator_t*);

const char*
target_iterator_port_list_uuid (iterator_t*);

const char*
target_iterator_port_list_name (iterator_t*);

int
target_iterator_port_list_trash (iterator_t*);

int
target_iterator_alive_tests (iterator_t*);

char*
target_uuid (target_t);

char*
trash_target_uuid (target_t);

char*
target_name (target_t);

char*
trash_target_name (target_t);

int
trash_target_readable (target_t);

char*
target_hosts (target_t);

char*
target_exclude_hosts (target_t);

char*
target_reverse_lookup_only (target_t);

char*
target_reverse_lookup_unify (target_t);

char*
target_allow_simultaneous_ips (target_t);

char*
target_port_range (target_t);

char*
target_ssh_port (target_t);

int
target_in_use (target_t);

int
trash_target_in_use (target_t);

int
target_writable (target_t);

int
trash_target_writable (target_t);

char*
target_ssh_credential_name (const char *);

void
init_target_task_iterator (iterator_t*, target_t);

const char*
target_task_iterator_name (iterator_t*);

const char*
target_task_iterator_uuid (iterator_t*);

int
target_task_iterator_readable (iterator_t*);

credential_t
target_credential (target_t, const char*);

int
target_login_port (target_t, const char*);


/* Configs.
 *
 * These are here because they need definitions that are still in manage.h. */

int
create_task_check_scanner_type (scanner_t);

int
modify_task_check_config_scanner (task_t, const char *, const char *);


/* NVT's. */

char *
manage_nvt_name (nvt_t);

char *
nvt_name (const char *);

char*
nvts_feed_version ();

time_t
nvts_feed_version_epoch ();

void
set_nvts_feed_version (const char*);

gboolean
find_nvt (const char*, nvt_t*);

int
init_nvt_info_iterator (iterator_t*, get_data_t*, const char*);

int
init_nvt_info_iterator_all (iterator_t*, get_data_t*);

int
nvt_info_count (const get_data_t *);

int
nvt_info_count_after (const get_data_t *, time_t, gboolean);

void
init_nvt_iterator (iterator_t*, nvt_t, config_t, const char*, const char*, int,
                   const char*);

void
init_cve_nvt_iterator (iterator_t*, const char *, int, const char*);

const char*
nvt_iterator_oid (iterator_t*);

const char*
nvt_iterator_version (iterator_t*);

const char*
nvt_iterator_name (iterator_t*);

const char*
nvt_iterator_summary (iterator_t*);

const char*
nvt_iterator_insight (iterator_t*);

const char*
nvt_iterator_affected (iterator_t*);

const char*
nvt_iterator_impact (iterator_t*);

const char*
nvt_iterator_description (iterator_t*);

const char*
nvt_iterator_tag (iterator_t*);

int
nvt_iterator_category (iterator_t*);

const char*
nvt_iterator_family (iterator_t*);

const char*
nvt_iterator_cvss_base (iterator_t*);

const char*
nvt_iterator_detection (iterator_t*);

const char*
nvt_iterator_qod (iterator_t*);

const char*
nvt_iterator_qod_type ( iterator_t *iterator );

const char*
nvt_iterator_solution (iterator_t*);

const char*
nvt_iterator_solution_type (iterator_t*);

const char*
nvt_iterator_solution_method (iterator_t*);

double
nvt_iterator_epss_score (iterator_t*);

double
nvt_iterator_epss_percentile (iterator_t*);

const char*
nvt_iterator_epss_cve (iterator_t*);

double
nvt_iterator_epss_severity (iterator_t*);

gboolean
nvt_iterator_has_epss_severity (iterator_t*);

double
nvt_iterator_max_epss_score (iterator_t*);

double
nvt_iterator_max_epss_percentile (iterator_t*);

const char*
nvt_iterator_max_epss_cve (iterator_t*);

double
nvt_iterator_max_epss_severity (iterator_t*);

gboolean
nvt_iterator_has_max_epss_severity (iterator_t*);

int
nvt_iterator_discovery (iterator_t*);

char*
nvt_default_timeout (const char *);

int
family_nvt_count (const char *);


/* NVT selectors. */

/**
 * @brief NVT selector type for "all" rule.
 */
#define NVT_SELECTOR_TYPE_ALL 0

/**
 * @brief NVT selector type for "family" rule.
 */
#define NVT_SELECTOR_TYPE_FAMILY 1

/**
 * @brief NVT selector type for "NVT" rule.
 */
#define NVT_SELECTOR_TYPE_NVT 2

/**
 * @brief Special NVT selector type for selecting all types in interfaces.
 */
#define NVT_SELECTOR_TYPE_ANY 999

void
init_family_iterator (iterator_t*, int, const char*, int);

const char*
family_iterator_name (iterator_t*);

int
nvt_selector_family_growing (const char *, const char *, int);

int
nvt_selector_family_count (const char*, int);

int
nvt_selector_nvt_count (const char *, const char *, int);

void
init_nvt_selector_iterator (iterator_t*, const char*, config_t, int);

const char*
nvt_selector_iterator_nvt (iterator_t*);

const char*
nvt_selector_iterator_name (iterator_t*);

int
nvt_selector_iterator_include (iterator_t*);

int
nvt_selector_iterator_type (iterator_t*);


/* NVT preferences. */

void
manage_nvt_preference_add (const char*, const char*, const char*, const char*,
                           const char*, const char*, int);

void
manage_nvt_preferences_enable ();

void
init_nvt_preference_iterator (iterator_t*, const char*, gboolean);

const char*
nvt_preference_iterator_name (iterator_t*);

const char*
nvt_preference_iterator_value (iterator_t*);

char*
nvt_preference_iterator_config_value (iterator_t*, config_t);

char*
nvt_preference_iterator_real_name (iterator_t*);

char*
nvt_preference_iterator_type (iterator_t*);

char*
nvt_preference_iterator_oid (iterator_t*);

char*
nvt_preference_iterator_id (iterator_t*);

int
nvt_preference_count (const char *);

void
xml_append_nvt_refs (GString *, const char *, int *);

gchar*
get_nvt_xml (iterator_t*, int, int, int, const char*, config_t, int, int, int, int);

char*
task_preference_value (task_t, const char *);

int
set_task_preferences (task_t, array_t *);

void
init_task_group_iterator (iterator_t *, task_t);

const char*
task_group_iterator_name (iterator_t*);

const char*
task_group_iterator_uuid (iterator_t*);

void
init_task_role_iterator (iterator_t *, task_t);

const char*
task_role_iterator_name (iterator_t*);

const char*
task_role_iterator_uuid (iterator_t*);

/* NVT severities */
void
init_nvt_severity_iterator (iterator_t *, const char *);

const char *
nvt_severity_iterator_type (iterator_t *);

const char *
nvt_severity_iterator_origin (iterator_t *);

const char *
nvt_severity_iterator_date (iterator_t *);

double
nvt_severity_iterator_score (iterator_t *);

const char *
nvt_severity_iterator_value (iterator_t *);


/* Credentials. */

/**
 * @brief Export formats for credentials
 */
typedef enum
{
  CREDENTIAL_FORMAT_NONE = 0,   /// normal XML output
  CREDENTIAL_FORMAT_KEY = 1,    /// public key
  CREDENTIAL_FORMAT_RPM = 2,    /// RPM package
  CREDENTIAL_FORMAT_DEB = 3,    /// DEB package
  CREDENTIAL_FORMAT_EXE = 4,    /// EXE installer
  CREDENTIAL_FORMAT_PEM = 5,    /// Certificate PEM
  CREDENTIAL_FORMAT_ERROR = -1  /// Error / Invalid format
} credential_format_t;

int
check_private_key (const char *, const char *);

gboolean
find_credential_with_permission (const char*, credential_t*, const char*);

int
create_credential (const char*, const char*, const char*, const char*,
                   const char*, const char*, const char*, const char*,
                   const char*, const char*, const char*, const char*,
                   array_t*,    const char*, const char*, const char*,
                   const char*, const char*, const char*, const char*,
                   credential_t*);

int
copy_credential (const char*, const char*, const char*,
                 credential_t*);

int
modify_credential (const char*, const char*, const char*, const char*,
                   const char*, const char*, const char*, const char*,
                   const char*, const char*, const char*, const char*,
                   const char*, array_t*, const char*, const char*,
                   const char*, const char*, const char*, const char*);

int
delete_credential (const char *, int);

int
credential_count (const get_data_t *);

void
set_credential_privacy_algorithm (credential_t, const char *);

void
set_credential_public_key (credential_t, const char *);

void
init_credential_iterator_one (iterator_t*, credential_t);

int
init_credential_iterator (iterator_t*, get_data_t *);

const char*
credential_iterator_login (iterator_t*);

const char*
credential_iterator_auth_algorithm (iterator_t*);

const char*
credential_iterator_privacy_algorithm (iterator_t*);

const char*
credential_iterator_password (iterator_t*);

const char*
credential_iterator_community (iterator_t*);

const char*
credential_iterator_privacy_password (iterator_t*);

const char*
credential_iterator_public_key (iterator_t*);

const char*
credential_iterator_kdc (iterator_t*);

const char*
credential_iterator_realm (iterator_t*);

#if ENABLE_CREDENTIAL_STORES

const char*
credential_iterator_credential_store_uuid (iterator_t*);

const char*
credential_iterator_vault_id (iterator_t*);

const char*
credential_iterator_host_identifier (iterator_t*);

const char*
credential_iterator_privacy_host_identifier (iterator_t*);

#endif

const char*
credential_iterator_private_key (iterator_t*);

const char*
credential_iterator_type (iterator_t*);

int
credential_iterator_allow_insecure (iterator_t*);

const char*
credential_full_type (const char*);

char*
credential_iterator_rpm (iterator_t*);

char*
credential_iterator_deb (iterator_t*);

char*
credential_iterator_exe (iterator_t*);

const char*
credential_iterator_certificate (iterator_t*);

gboolean
credential_iterator_format_available (iterator_t*, credential_format_t);

gchar *
credential_iterator_formats_xml (iterator_t* iterator);

char*
credential_uuid (credential_t);

char*
trash_credential_uuid (credential_t);

char*
credential_name (credential_t);

char*
trash_credential_name (credential_t);

char*
credential_type (credential_t);

void
init_credential_target_iterator (iterator_t*, credential_t, int);

const char*
credential_target_iterator_uuid (iterator_t*);

const char*
credential_target_iterator_name (iterator_t*);

int
credential_target_iterator_readable (iterator_t*);

#if ENABLE_CONTAINER_SCANNING
void
init_credential_oci_image_target_iterator (iterator_t*, credential_t, int);

const char*
credential_oci_target_iterator_uuid (iterator_t*);

const char*
credential_oci_target_iterator_name (iterator_t*);

int
credential_oci_target_iterator_readable (iterator_t*);
#endif /* ENABLE_CONTAINER_SCANNING */

void
init_credential_scanner_iterator (iterator_t*, credential_t, int);

const char*
credential_scanner_iterator_uuid (iterator_t*);

const char*
credential_scanner_iterator_name (iterator_t*);

int
credential_scanner_iterator_readable (iterator_t*);

int
trash_credential_in_use (credential_t);

int
credential_in_use (credential_t);

int
trash_credential_writable (credential_t);

int
credential_writable (credential_t);

int
trash_credential_readable (credential_t);

gchar*
credential_value (credential_t, const char*);

gchar*
credential_encrypted_value (credential_t, const char*);


/* Notes. */

gboolean
find_note_with_permission (const char*, note_t*, const char *);

int
create_note (const char*, const char*, const char*, const char*, const char*,
             const char*, const char*, task_t, result_t, note_t*);

int
copy_note (const char*, note_t*);

int
delete_note (const char *, int);

int
note_uuid (note_t, char **);

int
modify_note (const gchar *, const char *, const char *, const char *,
             const char *, const char *, const char *, const char *,
             const gchar *, const gchar *);

int
note_count (const get_data_t *, nvt_t, result_t, task_t);

int
init_note_iterator (iterator_t*, const get_data_t*, nvt_t, result_t, task_t);

int
init_note_iterator_all (iterator_t* iterator, get_data_t *get);

const char*
note_iterator_nvt_oid (iterator_t*);

time_t
note_iterator_creation_time (iterator_t*);

time_t
note_iterator_modification_time (iterator_t*);

const char*
note_iterator_text (iterator_t*);

const char*
note_iterator_hosts (iterator_t*);

const char*
note_iterator_port (iterator_t*);

const char*
note_iterator_threat (iterator_t*);

task_t
note_iterator_task (iterator_t*);

result_t
note_iterator_result (iterator_t*);

time_t
note_iterator_end_time (iterator_t*);

int
note_iterator_active (iterator_t*);

const char*
note_iterator_nvt_name (iterator_t *);

const char *
note_iterator_nvt_type (iterator_t *);

const char*
note_iterator_severity (iterator_t *);


/* Overrides. */

gboolean
find_override_with_permission (const char*, override_t*, const char *);

int
create_override (const char*, const char*, const char*, const char*,
                 const char*, const char*, const char*, const char*,
                 const char*, task_t, result_t, override_t*);

int
override_uuid (override_t, char **);

int
copy_override (const char*, override_t*);

int
delete_override (const char *, int);

int
modify_override (const gchar *, const char *, const char *, const char *,
                 const char *, const char *, const char *, const char *,
                 const char *, const char *, const gchar *, const gchar *);

int
override_count (const get_data_t *, nvt_t, result_t, task_t);

int
init_override_iterator (iterator_t*, const get_data_t*, nvt_t, result_t,
                        task_t);

int
init_override_iterator_all (iterator_t* iterator, get_data_t *get);

const char*
override_iterator_nvt_oid (iterator_t*);

time_t
override_iterator_creation_time (iterator_t*);

time_t
override_iterator_modification_time (iterator_t*);

const char*
override_iterator_text (iterator_t*);

const char*
override_iterator_hosts (iterator_t*);

const char*
override_iterator_port (iterator_t*);

const char*
override_iterator_threat (iterator_t*);

const char*
override_iterator_new_threat (iterator_t*);

task_t
override_iterator_task (iterator_t*);

result_t
override_iterator_result (iterator_t*);

time_t
override_iterator_end_time (iterator_t*);

int
override_iterator_active (iterator_t*);

const char*
override_iterator_nvt_name (iterator_t *);

const char *
override_iterator_nvt_type (iterator_t *);

const char*
override_iterator_severity (iterator_t *);

const char*
override_iterator_new_severity (iterator_t *);


/* System reports. */

/**
 * @brief A system report type iterator.
 */
typedef struct
{
  gchar **start;        ///< First type.
  gchar **current;      ///< Current type.
} report_type_iterator_t;

int
init_system_report_type_iterator (report_type_iterator_t*, const char*,
                                  const char*);

void
cleanup_report_type_iterator (report_type_iterator_t*);

gboolean
next_report_type (report_type_iterator_t*);

const char*
report_type_iterator_name (report_type_iterator_t*);

const char*
report_type_iterator_title (report_type_iterator_t*);

int
manage_system_report (const char *, const char *, const char *, const char *,
                      const char *, char **);


/* Scanners. */

/**
 * @brief Default for max auto retry on connection to scanner lost.
 */
#define SCANNER_CONNECTION_RETRY_DEFAULT 3

int
manage_create_scanner (GSList *, const db_conn_info_t *, const char *,
                       const char *, const char *, const char *, const char *,
                       const char *, const char *, const char *,
                       const char *, const char *, int);

int
manage_modify_scanner (GSList *, const db_conn_info_t *, const char *,
                       const char *, const char *, const char *, const char *,
                       const char *, const char *, const char *, const char *,
                       const char *, const char *);

int
manage_delete_scanner (GSList *, const db_conn_info_t *, const gchar *);

int
manage_verify_scanner (GSList *, const db_conn_info_t *, const gchar *);

int
manage_get_scanners (GSList *, const db_conn_info_t *);


typedef enum {
  CREATE_SCANNER_INTERNAL_ERROR = -1,         ///< Internal error
  CREATE_SCANNER_SUCCESS = 0,                 ///< Success
  CREATE_SCANNER_ALREADY_EXISTS,              ///< Scanner already exists
  CREATE_SCANNER_MISSING_TYPE,                ///< Missing type
  CREATE_SCANNER_MISSING_HOST,                ///< Missing host
  CREATE_SCANNER_CREDENTIAL_NOT_FOUND,        ///< Credential not found
  CREATE_SCANNER_CREDENTIAL_NOT_CC,           ///< Credential must have type "cc"
  CREATE_SCANNER_INVALID_TYPE,                ///< Invalid type
  CREATE_SCANNER_INVALID_PORT,                ///< Invalid port
  CREATE_SCANNER_INVALID_HOST,                ///< Invalid host
  CREATE_SCANNER_INVALID_RELAY_PORT,          ///< Invalid relay port
  CREATE_SCANNER_INVALID_RELAY_HOST,          ///< Invalid relay host
  CREATE_SCANNER_UNIX_SOCKET_UNSUPPORTED,     ///< Type doesn't support UNIX sockets
  CREATE_SCANNER_OPENVASD_DISABLED,           ///< openvasd feature is disabled
  CREATE_SCANNER_AGENT_DISABLED,              ///< Agent feature is disabled
  CREATE_SCANNER_CONTAINER_SCANNING_DISABLED, ///< Container scanning feature is disabled
  CREATE_SCANNER_PERMISSION_DENIED = 99       ///< Permission denied
} create_scanner_return_t;

create_scanner_return_t
create_scanner (const char*, const char *, const char *, const char *,
                const char *, scanner_t *, const char *, const char *,
                const char *, const char *);

int
copy_scanner (const char*, const char*, const char *, scanner_t *);

typedef enum {
  MODIFY_SCANNER_INTERNAL_ERROR = -1,         ///< Internal error
  MODIFY_SCANNER_SUCCESS = 0,                 ///< Success
  MODIFY_SCANNER_ALREADY_EXISTS,              ///< Scanner already exists
  MODIFY_SCANNER_MISSING_ID,                  ///< Missing scanner id
  MODIFY_SCANNER_NOT_FOUND,                   ///< Scanner not found
  MODIFY_SCANNER_CREDENTIAL_NOT_FOUND,        ///< Credential not found
  MODIFY_SCANNER_CREDENTIAL_NOT_CC,           ///< Credential must have type "cc"
  MODIFY_SCANNER_INVALID_TYPE,                ///< Invalid type
  MODIFY_SCANNER_INVALID_PORT,                ///< Invalid port
  MODIFY_SCANNER_INVALID_HOST,                ///< Invalid host
  MODIFY_SCANNER_INVALID_RELAY_PORT,          ///< Invalid relay port
  MODIFY_SCANNER_INVALID_RELAY_HOST,          ///< Invalid relay host
  MODIFY_SCANNER_UNIX_SOCKET_UNSUPPORTED,     ///< Type doesn't support UNIX sockets
  MODIFY_SCANNER_OPENVASD_DISABLED,           ///< openvasd feature is disabled
  MODIFY_SCANNER_AGENT_DISABLED,              ///< Agent feature is disabled
  MODIFY_SCANNER_CONTAINER_SCANNING_DISABLED, ///< Container scanning feature is disabled
  MODIFY_SCANNER_PERMISSION_DENIED = 99       ///< Permission denied
} modify_scanner_return_t;

modify_scanner_return_t
modify_scanner (const char*, const char*, const char*, const char *,
                const char *, const char *, const char *, const char *,
                const char *, const char *);

int
delete_scanner (const char *, int);

gboolean
find_scanner_with_permission (const char *, scanner_t *, const char *);

int
scanner_in_use (scanner_t);

int
trash_scanner_readable (scanner_t);

int
trash_scanner_in_use (scanner_t);

int
trash_scanner_writable (scanner_t);

int
scanner_writable (scanner_t);

const char *
scanner_uuid_default ();

gboolean
scanner_has_relay (scanner_t);

char *
scanner_host (scanner_t, gboolean);

int
scanner_port (scanner_t, gboolean);

int
scanner_type (scanner_t);

char *
scanner_ca_pub (scanner_t);

char *
scanner_key_pub (scanner_t);

char *
scanner_key_priv (scanner_t);

char*
scanner_login (scanner_t);

char*
scanner_password (scanner_t);

int
scanner_count (const get_data_t *);

char *
openvas_default_scanner_host ();

int
init_scanner_iterator (iterator_t*, get_data_t *);

const char*
scanner_iterator_host (iterator_t*);

int
scanner_iterator_port (iterator_t*);

int
scanner_iterator_type (iterator_t*);

const char*
scanner_iterator_credential_name (iterator_t *);

credential_t
scanner_iterator_credential (iterator_t *);

int
scanner_iterator_credential_trash (iterator_t*);

const char*
scanner_iterator_ca_pub (iterator_t *);

const char*
scanner_iterator_key_pub (iterator_t *);

const char*
scanner_iterator_key_priv (iterator_t*);

const char*
scanner_iterator_credential_type (iterator_t *);

const char*
scanner_iterator_relay_host (iterator_t *);

int
scanner_iterator_relay_port (iterator_t *);

int
scanner_config_iterator_readable (iterator_t *);

void
init_scanner_task_iterator (iterator_t*, scanner_t);

const char*
scanner_task_iterator_uuid (iterator_t *);

const char*
scanner_task_iterator_name (iterator_t *);

const char *
scanner_task_iterator_usage_type (iterator_t *);

int
scanner_task_iterator_readable (iterator_t *);

char *
scanner_name (scanner_t);

char *
scanner_uuid (scanner_t);

char *
trash_scanner_name (scanner_t);

char *
trash_scanner_uuid (scanner_t);

int
osp_get_version_from_iterator (iterator_t *, char **, char **, char **, char **,
                               char **, char **);

int
osp_get_details_from_iterator (iterator_t *, char **, GSList **);

int
get_scanner_connection_retry ();

void
set_scanner_connection_retry (int);

int
verify_scanner (const char *, char **);

const char *
get_relay_mapper_path ();

void
set_relay_mapper_path (const char *);

gboolean
relay_supports_scanner_type (const char *, int, scanner_type_t);

int
slave_get_relay (const char *,
                 int,
                 const char *,
                 const char *,
                 gchar **,
                 int *,
                 gchar **);

int
slave_relay_connection (gvm_connection_t *, gvm_connection_t *);

/* Scheduling. */

/**
 * @brief Seconds between calls to manage_schedule.
 */
#define SCHEDULE_PERIOD 10

/**
 * @brief Seconds between calls to manage_queued_task_actions.
 */
#define QUEUE_PERIOD 5

/**
 * @brief Minimum schedule timeout seconds.
 * This value must be greater than SCHEDULE_PERIOD.
 */
#define SCHEDULE_TIMEOUT_MIN_SECS 20

/**
 * @brief Default for schedule_timeout in minutes.
 */
#define SCHEDULE_TIMEOUT_DEFAULT 60

#if ENABLE_AGENTS
  /**
  * @brief Seconds between calls to fork_agents_sync.
  */
  #define AGENT_SYNC_SCHEDULE_PERIOD 300 /* every 5 minutes */
#endif

gboolean
find_schedule_with_permission (const char*, schedule_t*, const char*);

int
create_schedule (const char *, const char*, const char *,
                 const char*, schedule_t *, gchar**);

int
copy_schedule (const char*, const char*, const char *, schedule_t *);

int
delete_schedule (const char*, int);

void
manage_auth_allow_all (int);

const gchar*
get_scheduled_user_uuid ();

void
set_scheduled_user_uuid (const gchar* uuid);

void
manage_sync (sigset_t *, int (*fork_update_nvt_cache) (pid_t*), gboolean);

int
manage_rebuild_gvmd_data_from_feed (const char *,
                                    GSList *,
                                    const db_conn_info_t *,
                                    gchar **);

int
manage_schedule (manage_connection_forker_t,
                 gboolean,
                 sigset_t *);

char *
schedule_uuid (schedule_t);

char *
trash_schedule_uuid (schedule_t);

char *
schedule_name (schedule_t);

char *
trash_schedule_name (schedule_t);

int
schedule_duration (schedule_t);

int
schedule_period (schedule_t);

int
schedule_info (schedule_t, int, gchar **, gchar **);

int
init_schedule_iterator (iterator_t*, get_data_t *);

const char*
schedule_iterator_timezone (iterator_t *);

const char*
schedule_iterator_icalendar (iterator_t *);

int
trash_schedule_in_use (schedule_t);

int
schedule_in_use (schedule_t);

int
trash_schedule_writable (schedule_t);

int
trash_schedule_readable (schedule_t);

int
schedule_writable (schedule_t);

int
schedule_count (const get_data_t *);

void
init_schedule_task_iterator (iterator_t*, schedule_t);

const char*
schedule_task_iterator_uuid (iterator_t *);

const char*
schedule_task_iterator_name (iterator_t *);

int
schedule_task_iterator_readable (iterator_t*);

int
modify_schedule (const char *, const char *, const char *, const char*,
                 const char *, gchar **);

int
get_schedule_timeout ();

void
set_schedule_timeout (int);


/* Permissions. */

int
create_permission (const char *, const char *, const char *, const char *,
                   const char *, const char *, permission_t *);

int
copy_permission (const char*, const char *, permission_t *);

char*
permission_uuid (permission_t);

int
permission_is_admin (const char *);

int
permission_in_use (permission_t);

int
trash_permission_in_use (permission_t);

int
permission_writable (permission_t);

int
trash_permission_writable (permission_t);

int
permission_count (const get_data_t *);

int
init_permission_iterator (iterator_t*, get_data_t *);

const char*
permission_iterator_resource_type (iterator_t*);

const char*
permission_iterator_resource_uuid (iterator_t*);

const char*
permission_iterator_resource_name (iterator_t*);

int
permission_iterator_resource_in_trash (iterator_t*);

int
permission_iterator_resource_orphan (iterator_t*);

int
permission_iterator_resource_readable (iterator_t*);

const char*
permission_iterator_subject_type (iterator_t*);

const char*
permission_iterator_subject_uuid (iterator_t*);

const char*
permission_iterator_subject_name (iterator_t*);

int
permission_iterator_subject_in_trash (iterator_t*);

int
permission_iterator_subject_readable (iterator_t*);

int
delete_permission (const char*, int);

int
modify_permission (const char *, const char *, const char *, const char *,
                   const char *, const char *, const char *);

/* Permission caching */

void
delete_permissions_cache_for_resource (const char*, resource_t);

void
delete_permissions_cache_for_user (user_t);


/* Schema. */

int
manage_schema (gchar *, gchar **, gsize *, gchar **, gchar **);


/* Trashcan. */

int
manage_restore (const char *);

int
manage_empty_trashcan ();


/* SecInfo */

int
manage_read_info (gchar *, gchar *, gchar *, gchar **);

int
info_name_count (const gchar *, const gchar *);

/* SCAP. */

int
manage_scap_loaded ();

int
manage_nvts_loaded ();

const char *
manage_scap_update_time ();

/* CPE. */

void
init_cpe_deprecated_by_iterator (iterator_t *, const char *);

const char *
cpe_deprecated_by_iterator_deprecated_by (iterator_t *);

void
init_cpe_cve_iterator (iterator_t *, const char *, int, const char *);

int
init_cpe_info_iterator (iterator_t*, get_data_t*, const char*);

int
init_cpe_info_iterator_all (iterator_t*, get_data_t*);

int
cpe_info_count (const get_data_t *get);

const char*
cpe_info_iterator_title (iterator_t*);

const char*
cpe_info_iterator_deprecated (iterator_t*);

const char *
cpe_info_iterator_severity (iterator_t*);

const char*
cpe_info_iterator_cve_refs (iterator_t*);

const char*
cpe_info_iterator_cpe_name_id (iterator_t*);

gchar *
cpe_details_xml (const char*);

void
init_cpe_reference_iterator (iterator_t *, const char *);

const char*
cpe_reference_iterator_href (iterator_t *);

const char*
cpe_reference_iterator_type (iterator_t *);


/* CVE. */

const char*
cve_iterator_name (iterator_t*);

const char*
cve_iterator_cvss_score (iterator_t*);

const char*
cve_info_iterator_severity (iterator_t*);

const char*
cve_info_iterator_vector (iterator_t*);

const char*
cve_info_iterator_description (iterator_t*);

const char*
cve_info_iterator_products (iterator_t*);

double
cve_info_iterator_epss_score (iterator_t*);

double
cve_info_iterator_epss_percentile (iterator_t*);

int
init_cve_info_iterator (iterator_t*, get_data_t*, const char*);


int
init_cve_info_iterator_all (iterator_t*, get_data_t*);

int
cve_info_count (const get_data_t *get);

gchar *
cve_cvss_base (const gchar *);

/* CERT data */
int
manage_cert_loaded ();

/* CERT-Bund */

int
init_cert_bund_adv_info_iterator (iterator_t*, get_data_t*, const char*);

int
init_cert_bund_adv_info_iterator_all (iterator_t*, get_data_t*);

int
cert_bund_adv_info_count (const get_data_t *get);

const char*
cert_bund_adv_info_iterator_title (iterator_t*);

const char*
cert_bund_adv_info_iterator_summary (iterator_t*);

const char*
cert_bund_adv_info_iterator_cve_refs (iterator_t*);

const char*
cert_bund_adv_info_iterator_severity (iterator_t*);

void
init_cve_cert_bund_adv_iterator (iterator_t*, const char*, int, const char*);

void
init_nvt_cert_bund_adv_iterator (iterator_t*, const char*);

const char*
nvt_cert_bund_adv_iterator_name (iterator_t*);

/* DFN-CERT */

int
init_dfn_cert_adv_info_iterator (iterator_t*, get_data_t*, const char*);

int
init_dfn_cert_adv_info_iterator_all (iterator_t*, get_data_t*);

int
dfn_cert_adv_info_count (const get_data_t *get);

const char*
dfn_cert_adv_info_iterator_title (iterator_t*);

const char*
dfn_cert_adv_info_iterator_summary (iterator_t*);

const char*
dfn_cert_adv_info_iterator_cve_refs (iterator_t*);

const char*
dfn_cert_adv_info_iterator_severity (iterator_t*);

void
init_cve_dfn_cert_adv_iterator (iterator_t*, const char*, int, const char*);

void
init_nvt_dfn_cert_adv_iterator (iterator_t*, const char*);

const char*
nvt_dfn_cert_adv_iterator_name (iterator_t*);

/* All SecInfo Data */

int
secinfo_count_after (const get_data_t *, const char *, time_t, gboolean);


/* Settings. */

int
manage_max_rows (int, int);

int
setting_count (const char *);

int
setting_is_default_ca_cert (const gchar *);

char *
setting_filter (const char *);

int
setting_excerpt_size_int ();

void
init_setting_iterator (iterator_t *, const char *, const char *, int, int, int,
                       const char *);

const char*
setting_iterator_uuid (iterator_t*);

const char*
setting_iterator_name (iterator_t*);

const char*
setting_iterator_comment (iterator_t*);

const char*
setting_iterator_value (iterator_t*);

int
modify_setting (const gchar *, const gchar *, const gchar *, gchar **);

int
manage_modify_setting (GSList *, const db_conn_info_t *, const gchar *,
                       const gchar *, const char *);

char *
manage_default_ca_cert ();


/* Users. */

gchar *
manage_user_hash (const gchar *);

int
copy_user (const char*, const char*, const char*, user_t*);

gchar *
keyfile_to_auth_conf_settings_xml (const gchar *);

int
user_count (const get_data_t*);

int
init_vuln_iterator (iterator_t*, const get_data_t*);

int
vuln_iterator_results (iterator_t*);

time_t
vuln_iterator_oldest (iterator_t*);

time_t
vuln_iterator_newest (iterator_t*);

const char*
vuln_iterator_type (iterator_t*);

int
vuln_iterator_hosts (iterator_t*);

double
vuln_iterator_severity (iterator_t*);

int
vuln_iterator_qod (iterator_t*);

int
vuln_count (const get_data_t*);

void
manage_get_ldap_info (int *, gchar **, gchar **, int *, gchar **, int *);

int
manage_set_ldap_info (int, gchar *, gchar *, int, gchar *, int);

char *
get_radius_key (gboolean *);

void
set_radius_key (const char*, gboolean);

void
manage_get_radius_info (int *, char **, char **);

void
manage_set_radius_info (int, gchar *, gchar *);


/* Tags */

char*
tag_uuid (target_t);

int
copy_tag (const char*, const char*, const char*, tag_t*);

int
create_tag (const char *, const char *, const char *, const char *,
            array_t *, const char *, const char *, tag_t *, gchar **);

int
delete_tag (const char *, int);

int
modify_tag (const char *, const char *, const char *, const char *,
            const char *, array_t *, const char *, const char *, const char*,
            gchar **);

int
init_tag_iterator (iterator_t*, get_data_t*);

int
tag_count (const get_data_t *get);

const char*
tag_iterator_resource_type (iterator_t*);

int
tag_iterator_active (iterator_t*);

const char*
tag_iterator_value (iterator_t*);

int
tag_iterator_resources (iterator_t*);

resource_t
tag_resource_iterator_id (iterator_t*);

const char*
tag_resource_iterator_uuid (iterator_t*);

int
tag_resource_iterator_location (iterator_t*);

const char*
tag_resource_iterator_name (iterator_t*);

int
tag_resource_iterator_readable (iterator_t*);

int
init_tag_name_iterator (iterator_t*, get_data_t*);

const char*
tag_name_iterator_name (iterator_t*);

int
init_resource_tag_iterator (iterator_t*, const char*, resource_t, int,
                            const char*, int);

const char*
resource_tag_iterator_uuid (iterator_t*);

const char*
resource_tag_iterator_name (iterator_t*);

const char*
resource_tag_iterator_value (iterator_t*);

const char*
resource_tag_iterator_comment (iterator_t*);

int
resource_tag_exists (const char*, resource_t, int);

int
resource_tag_count (const char*, resource_t, int);

int
tag_in_use (tag_t);

int
trash_tag_in_use (tag_t);

int
tag_writable (tag_t);

int
trash_tag_writable (tag_t);


/* Resource aggregates */

/**
 * @brief Sort data for aggregates commands.
 */
typedef struct {
  gchar *field;  ///< The field to sort by.
  gchar *stat;   ///< The statistic to sort by.
  int order;     ///< The sort order.
} sort_data_t;

void
sort_data_free (sort_data_t*);

int
init_aggregate_iterator (iterator_t*, const char *, const get_data_t *, int,
                         GArray *, const char *, const char*, GArray*, GArray*,
                         int, int, const char *, const char *);

int
aggregate_iterator_count (iterator_t*);

double
aggregate_iterator_min (iterator_t*, int);

double
aggregate_iterator_max (iterator_t*, int);

double
aggregate_iterator_mean (iterator_t*, int);

double
aggregate_iterator_sum (iterator_t*, int);

const char*
aggregate_iterator_text (iterator_t*, int, int);

const char*
aggregate_iterator_value (iterator_t*);

const char*
aggregate_iterator_subgroup_value (iterator_t*);


/* Feeds. */

#define NVT_FEED 1
#define SCAP_FEED 2
#define CERT_FEED 3
#define GVMD_DATA_FEED 4

gboolean
manage_gvmd_data_feed_dir_exists (const char *);

gboolean
manage_gvmd_data_feed_dirs_exist ();

int
get_auth_timeout ();

void
set_auth_timeout (int);

const gchar *
get_broker_address ();

void
set_broker_address (const char *);

const gchar *
get_feed_lock_path ();

void
set_feed_lock_path (const char *);

int
get_feed_lock_timeout ();

void
set_feed_lock_timeout (int);

int
get_max_concurrent_scan_updates ();

void
set_max_concurrent_scan_updates (int);

int
get_max_database_connections ();

void
set_max_database_connections (int);

int
get_max_concurrent_report_processing ();

void
set_max_concurrent_report_processing (int);

int
get_mem_wait_retries ();

void
set_mem_wait_retries (int);

int
check_min_mem_feed_update ();

int
get_min_mem_feed_update ();

void
set_min_mem_feed_update (int);

void
write_sync_start (int);

int
feed_lockfile_lock (lockfile_t *);

int
feed_lockfile_lock_timeout (lockfile_t*);

int
feed_lockfile_unlock (lockfile_t *);

int
gvm_migrate_secinfo (int);

gboolean
gvm_sync_script_perform_selftest (const gchar *, gchar **);

gboolean
gvm_get_sync_script_identification (const gchar *, gchar **, int);

gboolean
gvm_get_sync_script_description (const gchar *, gchar **);

gboolean
gvm_get_sync_script_feed_version (const gchar *, gchar **);

int
nvts_feed_info (gchar **, gchar **, gchar **, gchar **);

int
nvts_check_feed (int *, int *, gchar **);

int
manage_rebuild (GSList *, const db_conn_info_t *);

int
manage_dump_vt_verification (GSList *, const db_conn_info_t *);

int
manage_dump_asset_snapshot_counts(GSList *, const db_conn_info_t *);


/* Wizards. */

int
manage_run_wizard (const gchar *, int (*) (void*, gchar*, gchar**),
                   void *, array_t *, int, const char*,
                   gchar **, gchar **, gchar **);


/* Helpers. */

gchar *
xml_escape_text_truncated (const char *, size_t, const char *);

int
column_is_timestamp (const char*);

char*
type_columns (const char *);

char*
type_trash_columns (const char *);

gboolean
manage_migrate_needs_timezone (GSList *, const db_conn_info_t *);


/* Optimize. */

int
manage_optimize (GSList *, const db_conn_info_t *, const gchar *);


/* Signal management */

int
sql_cancel ();


/* General settings */
const char *
get_vt_verification_collation ();

void
set_vt_verification_collation (const char *);

#endif /* not _GVMD_MANAGE_H */
