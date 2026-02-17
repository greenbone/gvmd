/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_SQL_TARGETS_H
#define _GVMD_MANAGE_SQL_TARGETS_H

#include "manage_targets.h"

/**
 * @brief Filter columns for target iterator.
 */
#define TARGET_ITERATOR_FILTER_COLUMNS                                         \
 { GET_ITERATOR_FILTER_COLUMNS, "hosts", "exclude_hosts", "ips", "port_list",  \
   "ssh_credential", "smb_credential", "esxi_credential", "snmp_credential",   \
   "ssh_elevate_credential", NULL }

/**
 * @brief Target iterator columns.
 */
#define TARGET_ITERATOR_COLUMNS                                \
 {                                                             \
   GET_ITERATOR_COLUMNS (targets),                             \
   { "hosts", NULL, KEYWORD_TYPE_STRING },                     \
   { "(SELECT credential FROM targets_login_data"              \
     " WHERE target = targets.id"                              \
     " AND type = CAST ('ssh' AS text))",                      \
     NULL,                                                     \
     KEYWORD_TYPE_INTEGER },                                   \
   { "target_login_port (id, 0, CAST ('ssh' AS text))",        \
     "ssh_port",                                               \
     KEYWORD_TYPE_INTEGER },                                   \
   { "(SELECT credential FROM targets_login_data"              \
     " WHERE target = targets.id"                              \
     " AND type = CAST ('smb' AS text))",                      \
     NULL,                                                     \
     KEYWORD_TYPE_INTEGER },                                   \
   { "port_list", NULL, KEYWORD_TYPE_INTEGER },                \
   { "0", NULL, KEYWORD_TYPE_INTEGER },                        \
   { "0", NULL, KEYWORD_TYPE_INTEGER },                        \
   {                                                           \
     "(SELECT uuid FROM port_lists"                            \
     " WHERE port_lists.id = port_list)",                      \
     NULL,                                                     \
     KEYWORD_TYPE_STRING                                       \
   },                                                          \
   {                                                           \
     "(SELECT name FROM port_lists"                            \
     " WHERE port_lists.id = port_list)",                      \
     "port_list",                                              \
     KEYWORD_TYPE_STRING                                       \
   },                                                          \
   { "0", NULL, KEYWORD_TYPE_INTEGER },                        \
   { "exclude_hosts", NULL, KEYWORD_TYPE_STRING },             \
   { "reverse_lookup_only", NULL, KEYWORD_TYPE_INTEGER },      \
   { "reverse_lookup_unify", NULL, KEYWORD_TYPE_INTEGER },     \
   { "alive_test", NULL, KEYWORD_TYPE_INTEGER },               \
   { "(SELECT credential FROM targets_login_data"              \
     " WHERE target = targets.id"                              \
     " AND type = CAST ('esxi' AS text))",                     \
     NULL,                                                     \
     KEYWORD_TYPE_INTEGER },                                   \
   { "0", NULL, KEYWORD_TYPE_INTEGER },                        \
   { "(SELECT credential FROM targets_login_data"              \
     " WHERE target = targets.id"                              \
     " AND type = CAST ('snmp' AS text))",                     \
     NULL,                                                     \
     KEYWORD_TYPE_INTEGER },                                   \
   { "0", NULL, KEYWORD_TYPE_INTEGER },                        \
   { "(SELECT credential FROM targets_login_data"              \
     " WHERE target = targets.id"                              \
     " AND type = CAST ('elevate' AS text))",                  \
     NULL,                                                     \
     KEYWORD_TYPE_INTEGER },                                   \
   { "0", NULL, KEYWORD_TYPE_INTEGER },                        \
   { "(SELECT credential FROM targets_login_data"              \
     " WHERE target = targets.id"                              \
     " AND type = CAST ('krb5' AS text))",                     \
     NULL,                                                     \
     KEYWORD_TYPE_INTEGER },                                   \
   { "0", NULL, KEYWORD_TYPE_INTEGER },                        \
   { "allow_simultaneous_ips",                                 \
     NULL,                                                     \
     KEYWORD_TYPE_INTEGER },                                   \
   {                                                           \
     "(SELECT name FROM credentials"                           \
     " WHERE credentials.id"                                   \
     "       = (SELECT credential FROM targets_login_data"     \
     "          WHERE target = targets.id"                     \
     "          AND type = CAST ('ssh' AS text)))",            \
     "ssh_credential",                                         \
     KEYWORD_TYPE_STRING                                       \
   },                                                          \
   {                                                           \
     "(SELECT name FROM credentials"                           \
     " WHERE credentials.id"                                   \
     "       = (SELECT credential FROM targets_login_data"     \
     "          WHERE target = targets.id"                     \
     "          AND type = CAST ('smb' AS text)))",            \
     "smb_credential",                                         \
     KEYWORD_TYPE_STRING                                       \
   },                                                          \
   {                                                           \
     "(SELECT name FROM credentials"                           \
     " WHERE credentials.id"                                   \
     "       = (SELECT credential FROM targets_login_data"     \
     "          WHERE target = targets.id"                     \
     "          AND type = CAST ('esxi' AS text)))",           \
     "esxi_credential",                                        \
     KEYWORD_TYPE_STRING                                       \
   },                                                          \
   {                                                           \
     "(SELECT name FROM credentials"                           \
     " WHERE credentials.id"                                   \
     "       = (SELECT credential FROM targets_login_data"     \
     "          WHERE target = targets.id"                     \
     "          AND type = CAST ('snmp' AS text)))",           \
     "snmp_credential",                                        \
     KEYWORD_TYPE_STRING                                       \
   },                                                          \
   {                                                           \
     "(SELECT name FROM credentials"                           \
     " WHERE credentials.id"                                   \
     "       = (SELECT credential FROM targets_login_data"     \
     "          WHERE target = targets.id"                     \
     "          AND type = CAST ('elevate' AS text)))",        \
     "ssh_elevate_credential",                                 \
     KEYWORD_TYPE_STRING                                       \
   },                                                          \
   {                                                           \
     "(SELECT name FROM credentials"                           \
     " WHERE credentials.id"                                   \
     "       = (SELECT credential FROM targets_login_data"     \
     "          WHERE target = targets.id"                     \
     "          AND type = CAST ('krb5' AS text)))",           \
     "krb5_credential",                                        \
     KEYWORD_TYPE_STRING                                       \
   },                                                          \
   { "hosts", NULL, KEYWORD_TYPE_STRING },                     \
   { "max_hosts (hosts, exclude_hosts)",                       \
     "ips",                                                    \
     KEYWORD_TYPE_INTEGER },                                   \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                        \
 }

/**
 * @brief Target iterator columns for trash case.
 */
#define TARGET_ITERATOR_TRASH_COLUMNS                                   \
 {                                                                      \
   GET_ITERATOR_COLUMNS (targets_trash),                                \
   { "hosts", NULL, KEYWORD_TYPE_STRING },                              \
   { "target_credential (id, 1, CAST ('ssh' AS text))",                 \
     NULL,                                                              \
     KEYWORD_TYPE_INTEGER },                                            \
   { "target_login_port (id, 1, CAST ('ssh' AS text))",                 \
     "ssh_port",                                                        \
     KEYWORD_TYPE_INTEGER },                                            \
   { "target_credential (id, 1, CAST ('smb' AS text))",                 \
     NULL,                                                              \
     KEYWORD_TYPE_INTEGER },                                            \
   { "port_list", NULL, KEYWORD_TYPE_INTEGER },                         \
   { "trash_target_credential_location (id, CAST ('ssh' AS text))",     \
     NULL,                                                              \
     KEYWORD_TYPE_INTEGER },                                            \
   { "trash_target_credential_location (id, CAST ('smb' AS text))",     \
     NULL,                                                              \
     KEYWORD_TYPE_INTEGER },                                            \
   {                                                                    \
     "(CASE"                                                            \
     " WHEN port_list_location = " G_STRINGIFY (LOCATION_TRASH)         \
     " THEN (SELECT uuid FROM port_lists_trash"                         \
     "       WHERE port_lists_trash.id = port_list)"                    \
     " ELSE (SELECT uuid FROM port_lists"                               \
     "       WHERE port_lists.id = port_list)"                          \
     " END)",                                                           \
     NULL,                                                              \
     KEYWORD_TYPE_STRING                                                \
   },                                                                   \
   {                                                                    \
     "(CASE"                                                            \
     " WHEN port_list_location = " G_STRINGIFY (LOCATION_TRASH)         \
     " THEN (SELECT name FROM port_lists_trash"                         \
     "       WHERE port_lists_trash.id = port_list)"                    \
     " ELSE (SELECT name FROM port_lists"                               \
     "       WHERE port_lists.id = port_list)"                          \
     " END)",                                                           \
     NULL,                                                              \
     KEYWORD_TYPE_STRING                                                \
   },                                                                   \
   { "port_list_location = " G_STRINGIFY (LOCATION_TRASH),              \
     NULL,                                                              \
     KEYWORD_TYPE_STRING },                                             \
   { "exclude_hosts", NULL, KEYWORD_TYPE_STRING },                      \
   { "reverse_lookup_only", NULL, KEYWORD_TYPE_INTEGER },               \
   { "reverse_lookup_unify", NULL, KEYWORD_TYPE_INTEGER },              \
   { "alive_test", NULL, KEYWORD_TYPE_INTEGER },                        \
   { "target_credential (id, 1, CAST ('esxi' AS text))",                \
     NULL,                                                              \
     KEYWORD_TYPE_INTEGER },                                            \
   { "trash_target_credential_location (id, CAST ('esxi' AS text))",    \
     NULL,                                                              \
     KEYWORD_TYPE_INTEGER },                                            \
   { "target_credential (id, 1, CAST ('snmp' AS text))",                \
     NULL,                                                              \
     KEYWORD_TYPE_INTEGER },                                            \
   { "trash_target_credential_location (id, CAST ('snmp' AS text))",    \
     NULL,                                                              \
     KEYWORD_TYPE_INTEGER },                                            \
   { "target_credential (id, 1, CAST ('elevate' AS text))",             \
     NULL,                                                              \
     KEYWORD_TYPE_INTEGER },                                            \
   { "trash_target_credential_location (id, CAST ('elevate' AS text))", \
     NULL,                                                              \
     KEYWORD_TYPE_INTEGER },                                            \
   { "target_credential (id, 1, CAST ('krb5' AS text))",                \
     NULL,                                                              \
     KEYWORD_TYPE_INTEGER },                                            \
   { "trash_target_credential_location (id, CAST ('krb5' AS text))",    \
     NULL,                                                              \
     KEYWORD_TYPE_INTEGER },                                            \
   { "allow_simultaneous_ips",                                          \
     NULL,                                                              \
     KEYWORD_TYPE_INTEGER },                                            \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                 \
 }

char*
target_comment (target_t);

char*
trash_target_comment (target_t);

credential_t
target_ssh_credential (target_t);

credential_t
target_credential (target_t, const char *);

credential_t
target_smb_credential (target_t);

credential_t
target_esxi_credential (target_t);

credential_t
target_ssh_elevate_credential (target_t);

credential_t
target_krb5_credential (target_t);

#endif // not _GVMD_MANAGE_SQL_TARGETS_H
