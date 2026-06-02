/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM manage layer headers: Agent installers.
 *
 * General management headers of agent installers.
 */

#if ENABLE_AGENTS

#ifndef _GVMD_MANAGE_AGENT_INSTALLERS_H
#define _GVMD_MANAGE_AGENT_INSTALLERS_H

#include <agent_controller/agent_controller.h>

instructions_lang_type_t
lang_type_from_string (const char *);

agent_controller_installer_instruction_t
get_agent_installer_instruction (const gchar *,
                                 instructions_lang_type_t);

#endif /* not _GVMD_MANAGE_AGENT_INSTALLERS_H */

#endif /* ENABLE_AGENTS */
