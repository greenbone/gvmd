# Feature Flags Overview

## Where the Configuration File Is Located

**gvmd** reads runtime feature flags from:

```
/etc/gvm/gvmd.conf
```

(or system defines as `GVM_SYSCONF_DIR`)

Inside this file, feature flags appear under the `[features]` section.

---

## Example Configuration File Section

```
[features]
enable_agents = false
enable_container_scanning = false
enable_credential_store = false
enable_openvasd = false
enable_vt_metadata = false
```

Each line is optional.
If a line is missing, gvmd does not apply a value from the config file.

---

## Complete Feature Flag Table

| Feature              | **Build-Time Flag** (decides if feature exists in binary) | **Runtime Environment Variable** | **Config File Key** (inside `[features]`) |
|----------------------|-----------------------------------------------------------|----------------------------------|-------------------------------------------|
| Agents               | `ENABLE_AGENTS`                                           | `GVMD_ENABLE_AGENTS`             | `enable_agents`                           |
| Container Scanning   | `ENABLE_CONTAINER_SCANNING`                               | `GVMD_ENABLE_CONTAINER_SCANNING` | `enable_container_scanning`               |
| OpenVASd Integration | `ENABLE_OPENVASD`                                         | `GVMD_ENABLE_OPENVASD`           | `enable_openvasd`                         |
| Credential Stores    | `ENABLE_CREDENTIAL_STORES`                                | `GVMD_ENABLE_CREDENTIAL_STORES`  | `enable_credential_store`                 |
| VT Metadata Feed     | Always exists in binary                                   | `GVMD_ENABLE_VT_METADATA`        | `enable_vt_metadata`                      |

---

## Accepted Runtime Values

These values work both in environment variables and in the config file:

**Enable:**
`1`, `true`, `yes`, `on`

**Disable:**
`0`, `false`, `no`, `off`

(Case-insensitive, whitespace ignored.)

---

## How gvmd Decides the Final Value

Order of priority:

1. **Build-time flag** if a feature is not compiled in, it can never be enabled.
2. **Environment variable** overrides config file.
3. **Configuration file** used if no environment variable is set.
4. **Default** feature becomes disabled.

**NOTE**: After changing the config file or environment variables, restart **gvmd** to apply the changes.

## Disabled Commands

When a feature is disabled, gvmd automatically removes related commands from the protocol.

### Agents disabled - these commands are hidden

```
get_agents
modify_agent
delete_agent
modify_agent_control_scan_config
get_agent_groups
create_agent_group
modify_agent_group
delete_agent_group
get_agent_installers
get_agent_installer_file
```

### Container scanning disabled - these commands are hidden

```
get_oci_image_targets
create_oci_image_target
modify_oci_image_target
delete_oci_image_target
```

### Credential store disabled - these commands are hidden

```
get_credential_stores
modify_credential_store
verify_credential_store
```

## Extended get_features Response

To help clients understand which features are compiled-in and enabled at runtime, the `get_features` command now returns both fields:

**compiled_in**: whether gvmd binary was built with the feature

**enabled**: final runtime result after applying environment + config

Exact example response:

```
<get_features_response status="200" status_text="OK">
  <feature compiled_in="1" enabled="0">
  <name>ENABLE_OPENVASD</name>
  </feature>
  <feature compiled_in="1" enabled="0">
  <name>ENABLE_CONTAINER_SCANNING</name>
  </feature>
  <feature compiled_in="1" enabled="0">
  <name>ENABLE_AGENTS</name>
  </feature>
  <feature compiled_in="0" enabled="0">
  <name>ENABLE_CREDENTIAL_STORES</name>
  </feature>
  <feature compiled_in="1" enabled="0">
  <name>FEED_VT_METADATA</name>
  </feature>
</get_features_response>
```
---
