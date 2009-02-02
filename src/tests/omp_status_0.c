/* Test 0 of OMP STATUS.
 * $Id$
 * Description: Test the OMP <status/> command.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 *
 * Copyright:
 * Copyright (C) 2009 Intevation GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define TRACE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "../tracef.h"

char* new_task_request = "<new_task><task_file># This file was automagically created by OpenVAS-Client\n\
trusted_ca = cacert.pem\n\
targets = impi\n\
protocol_version = 0\n\
cache_plugin_information = no\n\
reports_use_plugin_cache = no\n\
show_nvt_name_and_oid = yes\n\
use_client_cert = no\n\
nessusd_port = 7772\n\
paranoia_level = 1\n\
\n\
begin(SCANNER_SET)\n\
end(SCANNER_SET)\n\
\n\
begin(SERVER_PREFS)\n\
 max_hosts = 20\n\
 max_checks = 4\n\
 cgi_path = /cgi-bin:/scripts\n\
 port_range = default\n\
 auto_enable_dependencies = yes\n\
 silent_dependencies = yes\n\
 host_expansion = ip\n\
 ping_hosts = no\n\
 reverse_lookup = no\n\
 optimize_test = yes\n\
 safe_checks = yes\n\
 use_mac_addr = no\n\
 unscanned_closed = no\n\
 save_knowledge_base = yes\n\
 only_test_hosts_whose_kb_we_dont_have = no\n\
 only_test_hosts_whose_kb_we_have = no\n\
 kb_restore = no\n\
 kb_dont_replay_scanners = no\n\
 kb_dont_replay_info_gathering = no\n\
 kb_dont_replay_attacks = no\n\
 kb_dont_replay_denials = no\n\
 kb_max_age = 864000\n\
 log_whole_attack = no\n\
 language = english\n\
 checks_read_timeout = 5\n\
 non_simult_ports = 139, 445\n\
 plugins_timeout = 320\n\
 slice_network_addresses = no\n\
 nasl_no_signature_check = yes\n\
end(SERVER_PREFS)\n\
\n\
begin(CLIENTSIDE_USERRULES)\n\
end(CLIENTSIDE_USERRULES)\n\
\n\
begin(PLUGINS_PREFS)\n\
end(PLUGINS_PREFS)\n\
\n\
begin(PLUGIN_SET)\n\
end(PLUGIN_SET)\n\
\n\
begin(SERVER_INFO)\n\
 server_info_openvasd_version = 2.0.0\n\
 server_info_libnasl_version = 2.0.0.beta3.SVN\n\
 server_info_libnessus_version = 2.0.0.beta3.SVN\n\
 server_info_thread_manager = fork\n\
 server_info_os = Linux\n\
 server_info_os_version = 2.6.18-6-486\n\
end(SERVER_INFO)\n\
</task_file><identifier>omp_start_task_0</identifier><comment>Test 0 of OMP START_TASK.</comment></new_task>\n";

int
main ()
{
  int socket;
  gnutls_session_t session;

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  /* Create a task. */

  if (send_to_manager (&session, new_task_request) == -1) goto fail;

  entity_t entity = NULL;
  read_entity (&session, &entity);
  // FIX assume ok
  // FIX get id, assume 0 for now
  free_entity (entity);

  /* Start the task. */

  if (send_to_manager (&session,
                       "<start_task><task_id>0</task_id></start_task>")
      == -1)
    goto fail;

  entity = NULL;
  read_entity (&session, &entity);
  // FIX assume ok
  free_entity (entity);

  /* Request the status. */

  if (send_to_manager (&session, "<status/>") == -1)
    goto fail;

  /* Read the response. */

  entity = NULL;
  read_entity (&session, &entity);

  /* Compare to expected response. */

  entity_t expected = add_entity (NULL, "status_response", NULL);
  add_entity (&expected->entities, "status", "200");
  add_entity (&expected->entities, "task_count", "1");
  entity_t task = add_entity (&expected->entities, "task", NULL);
  add_entity (&task->entities, "task_id", "0");
  add_entity (&task->entities, "identifier", "omp_start_task_0");
  add_entity (&task->entities, "task_status", "Running");
  entity_t messages = add_entity (&task->entities, "messages", "");
  add_entity (&messages->entities, "debug", "0");
  add_entity (&messages->entities, "hole", "0");
  add_entity (&messages->entities, "info", "0");
  add_entity (&messages->entities, "log", "0");
  add_entity (&messages->entities, "warning", "0");

  if (compare_entities (entity, expected))
    {
      free_entity (entity);
      free_entity (expected);
 fail:
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  free_entity (entity);
  free_entity (expected);
  close_manager_connection (socket, session);
  return EXIT_SUCCESS;
}
