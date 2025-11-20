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
| OpenVASd Integration | `OPENVASD`                                                | `GVMD_ENABLE_OPENVASD`           | `enable_openvasd`                         |
| Credential Stores    | `ENABLE_CREDENTIAL_STORES`                                | `GVMD_ENABLE_CREDENTIAL_STORES`  | `enable_credential_store`                 |
| VT Metadata Feed     | `FEED_VT_METADATA`                                        | `GVMD_ENABLE_VT_METADATA`        | `enable_vt_metadata`                      |

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

---
