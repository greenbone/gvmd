# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [8.0.2] (unreleased)

### Added
- Command cleanup-report-formats for --optimize option [#651](https://github.com/greenbone/gvmd/pull/651)
- Document container tasks in GMP doc [#690](https://github.com/greenbone/gvmd/pull/690)
- New columns Ports, Apps, Distance, and Auth in the CSV Hosts report format [#734](https://github.com/greenbone/gvmd/pull/734)
- Allow use of public key auth in SCP alert [#846](https://github.com/greenbone/gvmd/pull/846)

### Changes
- Check and create default permissions individually [#672](https://github.com/greenbone/gvmd/pull/672)
- Add -f arg to sendmail call in email alert [#677](https://github.com/greenbone/gvmd/pull/677) [#679](https://github.com/greenbone/gvmd/pull/679)
- Change get_tickets to use the status text for filtering. [#698](https://github.com/greenbone/gvmd/pull/698)
- Also consider 0 of n NVTS as busy loading [#706](https://github.com/greenbone/gvmd/pull/706)
- Check whether hosts are alive and have results when adding them in slave scans. [#718](https://github.com/greenbone/gvmd/pull/718) [#737](https://github.com/greenbone/gvmd/pull/737)
- Change rows of built-in default filters to -2 (use "Rows Per Page" setting) [#897](https://github.com/greenbone/gvmd/pull/897)
- Update SCAP and CERT feed info in sync scripts [#808](https://github.com/greenbone/gvmd/pull/808)

### Fixed
- Allow to migrate gvmd 8 sqlite3 database to postgres with gvm-migrate-to-postgres script
  [#820](https://github.com/greenbone/gvmd/pull/820)
- A PostgreSQL statement order issue [#611](https://github.com/greenbone/gvmd/issues/611) has been addressed [#691](https://github.com/greenbone/gvmd/pull/691)
- Fix iCalendar recurrence and timezone handling [#653](https://github.com/greenbone/gvmd/pull/653)
- Fix issues with some scheduled tasks by using iCalendar more instead of old period fields [#655](https://github.com/greenbone/gvmd/pull/655)
- Fix an issue in getting the reports from GMP scanners [#658](https://github.com/greenbone/gvmd/pull/658) [#666](https://github.com/greenbone/gvmd/pull/666)
- Fix GET_SYSTEM_REPORTS using slave_id [#667](https://github.com/greenbone/gvmd/pull/667)
- Fix RAW_DATA when calling GET_INFO with type NVT without attributes name or info_id [#682](https://github.com/greenbone/gvmd/pull/682)
- Fix assignment of orphaned tickets to the current user [#686](https://github.com/greenbone/gvmd/pull/686)
- Fix ORPHAN calculations in GET_TICKETS [#687](https://github.com/greenbone/gvmd/pull/687) [#700](https://github.com/greenbone/gvmd/pull/700)
- Fix response from GET_VULNS when given vuln_id does not exists [#699](https://github.com/greenbone/gvmd/pull/699)
- Make bulk tagging with a filter work if the resources are already tagged [#712](https://github.com/greenbone/gvmd/pull/712)
- Fix columnless search phrase filter keywords with quotes [#716](https://github.com/greenbone/gvmd/pull/716)
- Fix issues importing results or getting them from slaves if they contain "%s" [#724](https://github.com/greenbone/gvmd/pull/724)
- A possible database migration issue from GVMd-7 to GVMd-8 has been addressed [#742](https://github.com/greenbone/gvmd/pull/742)
- Fix escaping that was preventing start_task from running [#758](https://github.com/greenbone/gvmd/pull/758)
- Fix array index error when modifying roles and groups [#763](https://github.com/greenbone/gvmd/pull/763)
- Fix percent sign escaping in report_port_count [#781](https://github.com/greenbone/gvmd/pull/781)
- Consider results_trash when deleting users [#804](https://github.com/greenbone/gvmd/pull/804)
- Fix asset host details insertion SQL [#840](https://github.com/greenbone/gvmd/pull/840)
- Fix creation of "Super" permissions [#893](https://github.com/greenbone/gvmd/pull/893)
- Init comment for MODIFY_USER/COMMENT, in case it's empty [#894](https://github.com/greenbone/gvmd/pull/894)
- Init comment for MODIFY_PERMISSION, in case it's empty [#919](https://github.com/greenbone/gvmd/pull/919)

### Removed

[8.0.2]: https://github.com/greenbone/gvmd/compare/v8.0.1...gvmd-8.0

## [8.0.1] (2019-07-17)

### Added
- Special characters in credential login names are allowed. [#475](https://github.com/greenbone/gvmd/pull/475)
- Add type filter column to GET_CONFIGS. [#486](https://github.com/greenbone/gvmd/pull/486)
- Filter settings for groups, scanners, tickets, users and vulnerabilities have been added. [#497](https://github.com/greenbone/gvmd/pull/497)
- Multiple certificate formats for S/MIME are allowed. [#551](https://github.com/greenbone/gvmd/pull/551)

### Changes
- Functions config_in_use, trash_config_in_use and port_list_in_use
returned a count instead of the expected 1 or 0. [#460](https://github.com/greenbone/gvmd/pull/460)
- The cache is rebuild for each chunk in CREATE_REPORT. [#469](https://github.com/greenbone/gvmd/pull/469)
- Hosts without HOST_START are added in CREATE_REPORT. [#479](https://github.com/greenbone/gvmd/pull/479)
- Use host details for login failure in ticket check. [#483](https://github.com/greenbone/gvmd/pull/483)
- In create_target() and modify_target() exclude_hosts is cleaned up to be in a consistent format like the included hosts are. [#488](https://github.com/greenbone/gvmd/pull/488).
- Check that roles exist earlier. [#493](https://github.com/greenbone/gvmd/pull/493)
- Anonymize more IPs and hostnames in Anonymous XML. [#496](https://github.com/greenbone/gvmd/pull/496) [#535](https://github.com/greenbone/gvmd/pull/535)
- Ensure that authentication always works for Start Task alerts. [#515](https://github.com/greenbone/gvmd/pull/515)
- Get content type when emailing an attached report. [#517](https://github.com/greenbone/gvmd/pull/517)
- Allow vuln_iterator_opts_from_filter filter to be NULL. [#527](https://github.com/greenbone/gvmd/pull/527)
- Wrap PostgreSQL exclusive table lock in function to prevent error messages in the PostgreSQL log if the lock is not available. [#542](https://github.com/greenbone/gvmd/pull/542)
- Trim whole report when resuming slave scans [#549](https://github.com/greenbone/gvmd/pull/549)
- Documentation has been improved. [#569](https://github.com/greenbone/gvmd/pull/569) [#567](https://github.com/greenbone/gvmd/pull/567) [#588](https://github.com/greenbone/gvmd/pull/588)
- Update command line options in gvmd man page [#565](https://github.com/greenbone/gvmd/pull/565)
- Clean special option keywords in filters. [#571](https://github.com/greenbone/gvmd/pull/571) [#578](https://github.com/greenbone/gvmd/pull/578) [#576](https://github.com/greenbone/gvmd/pull/576)
- If the schedule of a task is available, GET_TASKS will always return the
long schedule XML, not just if only the schedules are requested. [#500](https://github.com/greenbone/gvmd/pull/500)
- References to OpenVAS have been replaced with GSM [#529](https://github.com/greenbone/gvmd/pull/529)
- Buffer inserts when adding results from a slave [#641](https://github.com/greenbone/gvmd/pull/641)

### Fixed
- Checks on 'type' in GET_FEEDS has been fixed. [#462](https://github.com/greenbone/gvmd/pull/462)
- An issue which caused a race condition using the WHERE NOT EXISTS SQL has been addressed. [#472](https://github.com/greenbone/gvmd/pull/472)
- A missing argument in check_tickets is added. [#477](https://github.com/greenbone/gvmd/pull/477)
- Add missing filter case to result_count. [#548](https://github.com/greenbone/gvmd/pull/548)
- Fix create_report cache update at end of results. [#490](https://github.com/greenbone/gvmd/pull/490)
- Fix permission checks for trash reports [#503](https://github.com/greenbone/gvmd/pull/503)
- Fix MODIFY_TAG and CREATE_TAG responses. [#520](https://github.com/greenbone/gvmd/pull/520)
- Fix MODIFY_TAG for all types when given a filter. [#523](https://github.com/greenbone/gvmd/pull/523)
- Fix email field validation in create_alert and modify_alert. [#534](https://github.com/greenbone/gvmd/pull/534) [#545](https://github.com/greenbone/gvmd/pull/545)
- Fix --slave-commit-size option. [#555](https://github.com/greenbone/gvmd/pull/555)
- Fix TippingPoint error handling [#592] (https://github.com/greenbone/gvmd/pull/592)
- Apply ignore_pagination in delta reports [#597](https://github.com/greenbone/gvmd/pull/597)
- Fix getting single unowned resources [#607](https://github.com/greenbone/gvmd/pull/607)
- Fix the "Host Authentications" section in PDF / LaTeX reports. [#640](https://github.com/greenbone/gvmd/pull/640)

### Removed
- Remove -m SMB3 for smbclient in SMB alert, which allows changing the maximum protocol version via the smbclient config instead of forcing a particular one in the alert script. [#505](https://github.com/greenbone/gvmd/pull/505)
- Remove "slave" from valid_db_resource_type. [#558](https://github.com/greenbone/gvmd/pull/558)

[8.0.1]: https://github.com/greenbone/gvmd/compare/v8.0.0...v8.0.1

## [8.0.0] (2019-04-05)

### Added
- The new alert method "Alemba vFire" has been added.
- The file extension from the report format will now be added by SMB alerts.
- Handling of SSH private keys has been improved, allowing use of EC keys.
- The `--modify-scanner` option now also accepts UNIX sockets.
- Support for report content composition has been added.
- Remediation support has been added (GMP CREATE_TICKET, GET_TICKETS, etc).
- The --slave-commit-size option has been added, which can help prevent large updates from GMP scanners blocking the database for a long time.
- Settings "Hosts Filter" and "Operating Systems Filter" have been added.
- Performance of GET_REPORTS retrieving the results has been improved.
- A section about deprecated GMP elements has been added to the documentation.
- The Sourcefire alert now accepts a password credential for PKCS12 decryption.
- A new password-only credential type has been added
- Handling of failed/successful SNMP Authentication has been added to the HTML, LaTeX and PDF report formats.

### Changed
- GMP CREATE_ASSET, its GMP doc and usage by GSA are now more consistent.
- The file path of SMB alerts can now be set to a directory, using the default report filename from the user's settings.
- The tag "smb-alert:file_path" on tasks will override the file path of SMB alerts.
- CREATE_TASK now requires a name.
- TEST_ALERT now also works if NVTs are missing.
- LSC errors are now logged as warnings.
- Missing data in credentials no longer prevents slave tasks from starting. Instead the scan will start without the credential.
- The GET_TASKS command now only returns the progress of individual hosts when details are requested.
- The predefined "Discovery", "Host Discovery" and "System Discovery" now mark unreachable hosts as dead.
- Users will automatically get read permission for themselves.
- Updates of the NVTs will now ignore duplicate preferences instead of failing.
- GET_REPORTS will only return Tags of results if requested with the new result_tags attribute.
- Targets now use TCP-SYN without TCP-ACK when pinging hosts when configured to do so.
- The source code and GMP documentation have been cleaned up.

### Fixed
- An issue with deleting users has been fixed.
- An issue with GET_FEEDS returning the wrong feed types has been addressed.
- Various other code cleanups and improvements.
- Issues with the predefined report formats not handling hosts and hostnames correctly have been addressed.
- An issue with incomplete NVT info after feed updates has been addressed.
- MODIFY_SETTING now checks if text values can be decoded to valid UTF-8.
- An issue with alert emails missing a line break has been addressed.
- An issue preventing "Start Task" alerts from running has been fixed.

### Removed
- The option `--optimize remove-open-port-results` has been removed.
- The compile-time LOG option has been removed.
- Report format special case has been removed from send_get_common [#456](https://github.com/greenbone/gvmd/pull/456)

[8.0.0]: https://github.com/greenbone/gvmd/compare/v8.0+beta2...v8.0.0
