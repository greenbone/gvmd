CREATE TABLE meta (
    id integer PRIMARY KEY,
    name text UNIQUE NOT NULL,
    value text);

CREATE TABLE agents (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
    installer text,
    installer_64 text,
    installer_filename text,
    installer_signature_64 text,
    installer_trust integer,
    installer_trust_time date,
    howto_install text,
    howto_use text,
    creation_time date,
    modification_time date);

CREATE TABLE agents_trash (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
    installer text,
    installer_64 text,
    installer_filename text,
    installer_signature_64 text,
    installer_trust integer,
    installer_trust_time date,
    howto_install text,
    howto_use text,
    creation_time date,
    modification_time date);

CREATE TABLE alert_condition_data (
    id integer PRIMARY KEY,
    alert integer REFERENCES alerts (id) ON DELETE RESTRICT,
    name text,
    data text);

CREATE TABLE alert_condition_data_trash (
    id integer PRIMARY KEY,
    alert integer REFERENCES alerts (id) ON DELETE RESTRICT,
    name text,
    data text);

CREATE TABLE alert_event_data (
    id integer PRIMARY KEY,
    alert integer REFERENCES alerts (id) ON DELETE RESTRICT,
    name text,
    data text);

CREATE TABLE alert_event_data_trash (
    id integer PRIMARY KEY,
    alert integer REFERENCES alerts (id) ON DELETE RESTRICT,
    name text,
    data text);

CREATE TABLE alert_method_data (
    id integer PRIMARY KEY,
    alert integer REFERENCES alerts (id) ON DELETE RESTRICT,
    name text,
    data text);

CREATE TABLE alert_method_data_trash (
    id integer PRIMARY KEY,
    alert integer REFERENCES alerts (id) ON DELETE RESTRICT,
    name text,
    data text);

CREATE TABLE alerts (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
    event integer,
    condition integer,
    method integer,
    filter integer,
    creation_time date,
    modification_time date);

CREATE TABLE alerts_trash (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
    event integer,
    condition integer,
    method integer,
    filter integer,
    filter_location integer,
    creation_time date,
    modification_time date);

CREATE TABLE filters (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
    type text,
    term text,
    creation_time date,
    modification_time date);

CREATE TABLE filters_trash (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
    type text,
    term text,
    creation_time date,
    modification_time date);

CREATE TABLE groups (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
    creation_time date,
    modification_time date);

CREATE TABLE groups_trash (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
    creation_time date,
    modification_time date);

CREATE TABLE group_users (
    id integer PRIMARY KEY,
    group integer REFERENCES groups (id) ON DELETE RESTRICT,
    user integer REFERENCES users (id) ON DELETE RESTRICT);

CREATE TABLE group_users_trash (
    id integer PRIMARY KEY,
    group integer REFERENCES groups (id) ON DELETE RESTRICT,
    user integer REFERENCES users (id) ON DELETE RESTRICT);

CREATE TABLE roles (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
    creation_time date,
    modification_time date);

CREATE TABLE roles_trash (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
    creation_time date,
    modification_time date);

CREATE TABLE role_users (
    id integer PRIMARY KEY,
    role integer REFERENCES roles (id) ON DELETE RESTRICT,
    user integer REFERENCES users (id) ON DELETE RESTRICT);

CREATE TABLE role_users_trash (
    id integer PRIMARY KEY,
    role integer REFERENCES roles (id) ON DELETE RESTRICT,
    user integer REFERENCES users (id) ON DELETE RESTRICT);

CREATE TABLE users (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
    password text,
    timezone text,
    hosts text,
    hosts_allow integer,
	ifaces text,
	ifaces_allow boolean,
    method text,
    creation_time date,
    modification_time date);

CREATE TABLE nvt_selectors (
    id integer PRIMARY KEY,
    name text,
    exclude boolean,
    type integer,
    family_or_nvt text,
    family text);

CREATE TABLE port_lists (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
    creation_time date,
    modification_time date);

CREATE TABLE port_lists_trash (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
    creation_time date,
    modification_time date);

CREATE TABLE port_ranges (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    port_list integer REFERENCES port_lists (id) ON DELETE RESTRICT,
    type integer,
    start integer,
    end integer,
    comment text,
    end boolean);

CREATE TABLE port_ranges_trash (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    port_list integer REFERENCES port_lists_trash (id) ON DELETE RESTRICT,
    type integer,
    start integer,
    end integer,
    comment text,
    end boolean);

CREATE TABLE port_names (
    id integer PRIMARY KEY,
	number integer,
    protocol text,
    name text,
	UNIQUE (number, protocol));     -- ON CONFLICT REPLACE

CREATE TABLE targets (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    hosts text,
    exclude_hosts text,
    reverse_lookup_only integer,
    reverse_lookup_unify integer,
    comment text,
    lsc_credential integer REFERENCES lsc_credentials (id) ON DELETE RESTRICT, -- SSH
    ssh_port text,
    smb_lsc_credential integer REFERENCES lsc_credentials (id) ON DELETE RESTRICT,
    port_list integer REFERENCES port_lists (id) ON DELETE RESTRICT,
    alive_test integer,
    creation_time date,
    modification_time date);

CREATE TABLE targets_trash (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    hosts text,
    exclude_hosts text,
    reverse_lookup_only integer,
    reverse_lookup_unify integer,
    comment text,
    lsc_credential integer REFERENCES lsc_credentials (id) ON DELETE RESTRICT, -- SSH
    smb_lsc_credential integer REFERENCES lsc_credentials (id) ON DELETE RESTRICT,
    port_list integer REFERENCES port_lists (id) ON DELETE RESTRICT,
    ssh_location integer,
    smb_location integer,
    port_list_location integer,
    creation_time date,
    modification_time date);

CREATE TABLE configs (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    nvt_selector text REFERENCES nvt_selectors (name) ON DELETE RESTRICT,
    comment text,
    family_count integer,
    nvt_count integer,
    families_growing integer,
    nvts_growing integer,
    creation_time date,
    modification_time date);

CREATE TABLE configs_trash (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    nvt_selector text REFERENCES nvt_selectors (name) ON DELETE RESTRICT,
    comment text,
    family_count integer,
    nvt_count integer,
    families_growing integer,
    nvts_growing integer,
    creation_time date,
    modification_time date);

CREATE TABLE config_preferences (
    config integer PRIMARY KEY REFERENCES configs (id) ON DELETE RESTRICT,
    type text PRIMARY KEY, -- openvasrc section name or NULL for top-level prefs
    name text PRIMARY KEY,
    value text);

CREATE TABLE config_preferences_trash (
    config integer PRIMARY KEY REFERENCES configs (id) ON DELETE RESTRICT,
    type text PRIMARY KEY, -- openvasrc section name or NULL for top-level prefs
    name text PRIMARY KEY,
    value text);

CREATE TABLE tasks (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text,
    hidden integer,
    comment text,
    description text, -- RC file
    run_status integer,
    start_time date,
    end_time date,
    config integer REFERENCES configs (id) ON DELETE RESTRICT,
    target integer REFERENCES targets (id) ON DELETE RESTRICT,
    schedule integer REFERENCES schedules (id) ON DELETE RESTRICT,
    schedule_next_time date,
    slave integer REFERENCES slaves (id) ON DELETE RESTRICT,
    config_location integer,
    target_location integer,
    schedule_location integer,
    slave_location integer,
    upload_result_count integer,
    hosts_ordering text,
    alterable integer,
    creation_time date,
    modification_time date);

CREATE TABLE task_files (
    id integer PRIMARY KEY,
    task integer REFERENCES tasks (id) ON DELETE RESTRICT,
    name text,
    content text);

CREATE TABLE task_alerts (
    id integer PRIMARY KEY,
    task integer REFERENCES tasks (id) ON DELETE RESTRICT,
    alert integer REFERENCES alerts (id) ON DELETE RESTRICT,
    alert_location integer);

CREATE TABLE task_preferences (
    task integer PRIMARY KEY REFERENCES tasks (id) ON DELETE RESTRICT,
    name text PRIMARY KEY,
    value text);

CREATE TABLE results (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    task integer REFERENCES tasks (id) ON DELETE RESTRICT,
    host text,
    port text,
    nvt text,  -- OID of NVT
    type text,
    description text,
    report integer REFERENCES reports (id) ON DELETE RESTRICT,
	nvt_ersion text,
	severity real);

CREATE TABLE reports (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    hidden integer,
    task integer REFERENCES tasks (id) ON DELETE RESTRICT,
    date date,
    start_time date,
    end_time date,
    nbefile text,
    comment text,
    scan_run_status integer,
    slave_progress text,
    slave_task_uuid text,
    slave_uuid text,
    slave_name text,
    slave_host text,
    slave_port integer,
    source_iface text);

CREATE TABLE report_counts (
    id integer PRIMARY KEY,
    report integer REFERENCES reports (id) ON DELETE RESTRICT,
    user integer REFERENCES users (id) ON DELETE RESTRICT,
    severity decimal,
    count integer,
    override integer,
    end_time integer);

CREATE TABLE report_format_params (
    id integer PRIMARY KEY,
    report_format integer REFERENCES report_formats (id) ON DELETE RESTRICT,
    name text,
    type integer,
    value text,
    type_min integer,
    type_max integer,
    type_regex text,
    fallback text);

CREATE TABLE report_format_params_trash (
    id integer PRIMARY KEY,
    report_format integer REFERENCES report_formats (id) ON DELETE RESTRICT,
    name text,
    type integer,
    value text,
    type_min integer,
    type_max integer,
    type_regex text,
    fallback text);

CREATE TABLE report_format_param_options (
    id integer PRIMARY KEY,
    report_format_param integer REFERENCES report_format_params (id) ON DELETE RESTRICT,
    value text);

CREATE TABLE report_format_param_options_trash (
    id integer PRIMARY KEY,
    report_format_param integer REFERENCES report_format_params (id) ON DELETE RESTRICT,
    value text);

CREATE TABLE report_formats (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    extension text,
    content_type text,
    summary text,
    description text,
    signature text,
    trust integer,
    trust_time date,
    flags integer,
    creation_time date,
    modification_time date);

CREATE TABLE report_formats_trash (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    extension text,
    content_type text,
    summary text,
    description text,
    signature text,
    trust integer,
    trust_time date,
    flags integer,
    creation_time date,
    modification_time date);

CREATE TABLE report_hosts (
    id integer PRIMARY KEY,
    report integer REFERENCES reports (id) ON DELETE RESTRICT,
    host text,
    start_time date,
    end_time date,
    attack_state INTEGER,
    current_port text,
    max_port text);

CREATE TABLE report_host_details (
    id integer PRIMARY KEY,
    report_host integer REFERENCES report_hosts (id) ON DELETE RESTRICT,
    source_type text,
    source_name text,
    source_description text,
    name text,
    value text);

CREATE TABLE report_results (
    report integer PRIMARY KEY REFERENCES reports (id) ON DELETE RESTRICT,
    result integer PRIMARY KEY REFERENCES results (id) ON DELETE RESTRICT);

CREATE TABLE nvt_preferences (
    id integer PRIMARY KEY,
    name text UNIQUE NOT NULL,
    value text);

CREATE TABLE nvts (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    oid text UNIQUE NOT NULL,
    version text,
    name text,
    comment text,
    summary text,
    copyright text,
    cve text,
    bid text,
    xref text,
    tag text,
    category text,
    family text,
    cvss_base text,
    creation_time date,
    modification_time date);

CREATE TABLE nvt_cves (
    id integer PRIMARY KEY,
    nvt integer REFERENCES nvts (id) ON DELETE RESTRICT,
    oid text,
	cve_name text);

--
-- Local Security Check Credentials.
--
-- This table stores the credentials for LSCs.  In addition the names
-- for packages or tools to be installed on the targets are stored.
--
CREATE TABLE lsc_credentials (
    id integer PRIMARY KEY,
        uuid text UNIQUE NOT NULL,
	owner integer REFERENCES users (id) ON DELETE RESTRICT,
        -- The OpenVAS name for this credential.
	name text NOT NULL,
        -- The name of the account.
	login text,
        -- We have 3 uses for the password field:
        -- 1. If private_key is NULL, this is a simple password.
        -- 2. If private key is not NULL and its values is not ";;encrypted;;"
        --    this is the passphrase to protect the private key.
        -- 3. If private_key has the value ";;encrypted;;" this
        --    is an encrypted container for a password or a private key.
        --    The format of this container is a list of name-value pairs.
        --    For example:
        --     <len(8)> "password" <len> <value>
        --     <len(10)> "private_key" <len> <value>
        --    The len fields are encoded as 32 bit big endian unsigned
        --    integer values.  A value of 0 for the value length is is
        --    allowed and indicates and empty string.  A missing name
        --    (e.g. "password", indicates a NULL value for that name.
        --    This format closely resembles an unencrypted
        --    lsc_credential.  However, recursive encryption is not
        --    supported.  The container itself is OpenPGP encrypted
        --    with the binary OpenPGP format wrapped into a standard
        --    base64 encoding without linefeeds or checksums (i.e. it
        --    is not the armor format).
	password text,
        -- A comment describing this credential.
	comment text,
        -- Public and private parts for public key encryption.
        -- Commonly used with ssh.  The need for both fields is due to
        -- an implementation peculiarity of old OpenVAS versions,
        -- which were not able to extract the public part from the
        -- private part.  We keep the "public_key" field to be
        -- prepared for future authentication schemes.  A flag value
        -- of ";;encrypted;;" in the private_key field is used to
        -- indicate an encrypted credential.  Note: We can't use the
        -- password field for the flag value because the password
        -- field is allowed to contain arbitrary data; the private_key
        -- field however is a structured value (for example PEM or
        -- plain base64).
	public_key text,
	private_key text,
        -- Fixme.  (Tools to be installed on the target)
	rpm bytea,
	deb bytea,
	exe bytea,
	creation_time date,
	modification_time date);

--
-- Trashcan for lsc_credentials.
--
CREATE TABLE lsc_credentials_trash (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    login text,
    password text,
    comment text,
    public_key text,
    private_key text,
    rpm bytea,
    deb bytea,
    exe bytea,
    creation_time date,
    modification_time date);

CREATE TABLE notes (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    nvt text NOT NULL,  -- OID of NVT
    creation_time date,
    modification_time date,
    text text,
    hosts text,
    port text,
    severity text,
    task integer REFERENCES tasks (id) ON DELETE RESTRICT,
    result integer REFERENCES results (id) ON DELETE RESTRICT,
    end_time integer);

CREATE TABLE notes_trash (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    nvt text NOT NULL,  -- OID of NVT
    creation_time date,
    modification_time date,
    text text,
    hosts text,
    port text,
    severity text,
    task integer REFERENCES tasks (id) ON DELETE RESTRICT,
    result integer REFERENCES results (id) ON DELETE RESTRICT,
    end_time integer);

CREATE TABLE overrides (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    nvt text NOT NULL,  -- OID of NVT
    creation_time date,
    modification_time date,
    text text,
    hosts text,
    new_severity text,
    port text,
    severity text,
    task integer REFERENCES tasks (id) ON DELETE RESTRICT,
    result integer REFERENCES results (id) ON DELETE RESTRICT,
    end_time integer);

CREATE TABLE overrides_trash (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    nvt text NOT NULL,  -- OID of NVT
    creation_time date,
    modification_time date,
    text text,
    hosts text,
    new_severity text,
    port text,
    severity text,
    task integer REFERENCES tasks (id) ON DELETE RESTRICT,
    result integer REFERENCES results (id) ON DELETE RESTRICT,
    end_time integer);

CREATE TABLE permissions (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
	resource_type text,
	resource integer,
	resource_uuid text,
	resource_location integer,
	subject_type text,
	subject integer,
	subject_location integer,
    creation_time date,
    modification_time date);

CREATE TABLE permissions_trash (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
	resource_type text,
	resource integer,
	resource_uuid text,
	resource_location integer,
	subject_type text,
	subject integer,
	subject_location integer,
    creation_time date,
    modification_time date);

CREATE TABLE schedules (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
    first_time date,
    period integer,
    period_months integer,
    timezone text,
    initial_offset integer,
    creation_time date,
    modification_time date);

CREATE TABLE schedules_trash (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
    first_time date,
    period integer,
    period_months integer,
    duration integer,
    creation_time date,
    modification_time date);

CREATE TABLE settings (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
    value text);

CREATE TABLE slaves (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
    host text,
    port text,
    login text,
    password text,
    creation_time date,
    modification_time date);

CREATE TABLE slaves_trash (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
    host text,
    port text,
    login text,
    password text,
    creation_time date,
    modification_time date);

CREATE TABLE tags (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
	resource_type text,
	resource integer,
	resource_uuid text,
	resource_location integer,
    creation_time date,
    modification_time date);

CREATE TABLE tags_trash (
    id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    owner integer REFERENCES users (id) ON DELETE RESTRICT,
    name text NOT NULL,
    comment text,
	resource_type text,
	resource integer,
	resource_uuid text,
	resource_location integer,
    creation_time date,
    modification_time date);
