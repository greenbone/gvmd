/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM manage layer headers: Agent installer instructions.
 *
 * General management headers of agent installer instructions.
 */

#if ENABLE_AGENTS

#ifndef _GVMD_MANAGE_AGENT_INSTALLER_INSTRUCTIONS_H
#define _GVMD_MANAGE_AGENT_INSTALLER_INSTRUCTIONS_H

#include <agent_controller/agent_controller.h>

instructions_lang_type_t
lang_type_from_string (const char *);

agent_controller_installer_instruction_t
get_agent_installer_instruction (const gchar *,
                                 instructions_lang_type_t,
                                 const gchar *);

#endif /* not _GVMD_MANAGE_AGENT_INSTALLER_INSTRUCTIONS_H */

#endif /* ENABLE_AGENTS */
