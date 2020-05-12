# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [9.0.1] (2020-05-12)

### Added
- Add option --optimize migrate-relay-sensors [#827](https://github.com/greenbone/gvmd/pull/827)
- Add host_id filter for tls_certificates [#835](https://github.com/greenbone/gvmd/pull/835)
- Allow use of public key auth in SCP alert [#845](https://github.com/greenbone/gvmd/pull/845)
- Refuse to import config with missing NVT preference ID [#856](https://github.com/greenbone/gvmd/pull/856) [#860](https://github.com/greenbone/gvmd/pull/860)
- Add "Base" scan config [#862](https://github.com/greenbone/gvmd/pull/862)
- Add setting "BPM Data" [#914](https://github.com/greenbone/gvmd/pull/914)
- Add --optimize option cleanup-result-encoding [#1014](https://github.com/greenbone/gvmd/pull/1014) [#1031](https://github.com/greenbone/gvmd/pull/1031)
- Add --rebuild [#1016](https://github.com/greenbone/gvmd/pull/1016)
- Lock a file around the NVT sync [#1017](https://github.com/greenbone/gvmd/pull/1017)
- Add --rebuild-scap option [#1050](https://github.com/greenbone/gvmd/pull/1050)


### Changed
- Extend command line options for managing scanners [#815](https://github.com/greenbone/gvmd/pull/815)
- Update SCAP and CERT feed info in sync scripts [#809](https://github.com/greenbone/gvmd/pull/809)
- Try authentication when verifying GMP scanners [#837](https://github.com/greenbone/gvmd/pull/837)
- Try importing private keys with libssh if GnuTLS fails [#841](https://github.com/greenbone/gvmd/pull/841)
- Allow resuming OSPd-based OpenVAS tasks [#869](https://github.com/greenbone/gvmd/pull/869)
- Require PostgreSQL 9.6 as a minimum [#872](https://github.com/greenbone/gvmd/pull/872)
- Speed up the SCAP sync [#875](https://github.com/greenbone/gvmd/pull/875) [#877](https://github.com/greenbone/gvmd/pull/877) [#879](https://github.com/greenbone/gvmd/pull/879) [#881](https://github.com/greenbone/gvmd/pull/881) [#883](https://github.com/greenbone/gvmd/pull/883) [#887](https://github.com/greenbone/gvmd/pull/887) [#889](https://github.com/greenbone/gvmd/pull/889) [#890](https://github.com/greenbone/gvmd/pull/890) [#891](https://github.com/greenbone/gvmd/pull/891) [#901](https://github.com/greenbone/gvmd/pull/901)
- Change rows of built-in default filters to -2 (use "Rows Per Page" setting) [#896](https://github.com/greenbone/gvmd/pull/896)
- Force NVT update in migrate_219_to_220 [#895](https://github.com/greenbone/gvmd/pull/895)
- Use temp tables to speed up migrate_213_to_214 [#911](https://github.com/greenbone/gvmd/pull/911)
- Add a delay for re-requesting scan information via osp [#1009](https://github.com/greenbone/gvmd/pull/1009)
- Count only best OS matches for OS asset hosts [#1028](https://github.com/greenbone/gvmd/pull/1028)
- Clean up NVTs set to name in cleanup-result-nvts [#1038](https://github.com/greenbone/gvmd/pull/1038)
- New Community Feed download URL in sync tools [#1042](https://github.com/greenbone/gvmd/pull/1042)
- Do not ignore empty hosts_allow and ifaces_allow [#1063](https://github.com/greenbone/gvmd/pull/1063)

### Fixed
- Consider results_trash when deleting users [#799](https://github.com/greenbone/gvmd/pull/799)
- Try to get NVT preferences by id in create_config [#821](https://github.com/greenbone/gvmd/pull/821)
- Fix preference ID in "Host Discovery" config [#828](https://github.com/greenbone/gvmd/pull/828)
- Fix order of fingerprints in get_tls_certificates [#833](https://github.com/greenbone/gvmd/pull/833)
- Update config preferences after updating NVTs [#832](https://github.com/greenbone/gvmd/pull/832)
- Fix asset host details insertion SQL [#839](https://github.com/greenbone/gvmd/pull/839)
- Fix notes XML for lean reports [#836](https://github.com/greenbone/gvmd/pull/836)
- MODIFY_USER saves comment when COMMENT is empty [#842](https://github.com/greenbone/gvmd/pull/842)
- MODIFY_PERMISSION saves comment when COMMENT is empty [#918](https://github.com/greenbone/gvmd/pull/918)
- Fix result diff generation to ignore white space in delta reports [#861](https://github.com/greenbone/gvmd/pull/861)
- Fix resource type checks for permissions [#863](https://github.com/greenbone/gvmd/pull/863)
- Fix result_nvt for new OSP and slave results [#865](https://github.com/greenbone/gvmd/pull/865)
- Use right format specifier for merge_ovaldef version [#874](https://github.com/greenbone/gvmd/pull/874)
- Fix creation of "Super" permissions [#892](https://github.com/greenbone/gvmd/pull/892)
- Setup general task preferences to launch an osp openvas task. [#898](https://github.com/greenbone/gvmd/pull/898)
- Add tags used for result NVTs to update_nvti_cache [#916](https://github.com/greenbone/gvmd/pull/916)
- Apply usage_type of tasks in get_aggregates [#912](https://github.com/greenbone/gvmd/pull/912)
- Setup target's alive test setting to launch an osp openvas task [#936](https://github.com/greenbone/gvmd/pull/936)
- Remove incorrect duplicates from config preference migrator [#940](https://github.com/greenbone/gvmd/pull/940)
- Correct pref ID in migrate_219_to_220 [#941](https://github.com/greenbone/gvmd/pull/941)
- Fix alive test. Target's alive test setting has priority over scan config [#943](https://github.com/greenbone/gvmd/pull/943)
- Set run status only after getting OSP-OpenVAS scan [#948](https://github.com/greenbone/gvmd/pull/948) [#951](https://github.com/greenbone/gvmd/pull/951)
- Fix get_system_reports for GMP scanners [#949](https://github.com/greenbone/gvmd/pull/949)
- Use stop_osp_task for SCANNER_TYPE_OSP_SENSOR [#955](https://github.com/greenbone/gvmd/pull/955)
- Setup target's reverse_lookup_* settings to launch an osp openvas task [#958](https://github.com/greenbone/gvmd/pull/958)
- Always use details testing alerts with a report [#964](https://github.com/greenbone/gvmd/pull/964)
- Remove extra XML declaration in Anonymous XML [#965](https://github.com/greenbone/gvmd/pull/965)
- Fix Verinice ISM report format and update version [#962](https://github.com/greenbone/gvmd/pull/962)
- Fix SCP alert authentication and logging [#972](https://github.com/greenbone/gvmd/pull/972)
- Accept expanded scheme OIDs in parse_osp_report [#983](https://github.com/greenbone/gvmd/pull/983)
- Fix SCAP update not finishing when CPEs are older [#985](https://github.com/greenbone/gvmd/pull/985)
- Add user limits on hosts and ifaces to OSP prefs [#1032](https://github.com/greenbone/gvmd/pull/1032)
- Fix scanner_options not inserted correctly when starting ospd task [#1056](https://github.com/greenbone/gvmd/pull/1056)
- Fix QoD handling in NVTi cache and sensor scans [#1060](https://github.com/greenbone/gvmd/pull/1060)
- Fix doc of get_tasks in GMP doc [#1065](https://github.com/greenbone/gvmd/pull/1065)
- Fix deletion of OVAL definition data [#1080](https://github.com/greenbone/gvmd/pull/1080)

### Removed
- Remove 1.3.6.1.4.1.25623.1.0.90011 from Discovery config (9.0) [#847](https://github.com/greenbone/gvmd/pull/847)

[9.0.1]: https://github.com/greenbone/gvmd/compare/v9.0.0...v9.0.1

## [9.0.0] (2019-10-11)

### Added
- Added TLS certificates as a new resource type [#585](https://github.com/greenbone/gvmd/pull/585) [#663](https://github.com/greenbone/gvmd/pull/663) [#673](https://github.com/greenbone/gvmd/pull/673) [#674](https://github.com/greenbone/gvmd/pull/674) [#689](https://github.com/greenbone/gvmd/pull/689) [#695](https://github.com/greenbone/gvmd/pull/695) [#703](https://github.com/greenbone/gvmd/pull/703) [#728](https://github.com/greenbone/gvmd/pull/728) [#732](https://github.com/greenbone/gvmd/pull/732) [#750](https://github.com/greenbone/gvmd/pull/750) [#752](https://github.com/greenbone/gvmd/pull/752) [#774](https://github.com/greenbone/gvmd/pull/774) [#792](https://github.com/greenbone/gvmd/pull/792)
- Update NVTs via OSP [#392](https://github.com/greenbone/gvmd/pull/392) [#609](https://github.com/greenbone/gvmd/pull/609) [#626](https://github.com/greenbone/gvmd/pull/626) [#753](https://github.com/greenbone/gvmd/pull/753) [#767](https://github.com/greenbone/gvmd/pull/767)
- Handle addition of ID to NVT preferences. [#413](https://github.com/greenbone/gvmd/pull/413) [#744](https://github.com/greenbone/gvmd/pull/744)
- Add setting 'OMP Slave Check Period' [#491](https://github.com/greenbone/gvmd/pull/491)
- Document switching between releases when using PostgreSQL. [#563](https://github.com/greenbone/gvmd/pull/563)
- Cgreen based unit tests for gvmd has been added. [#579](https://github.com/greenbone/gvmd/pull/579)
- New usage_type property to distinguish normal scan tasks and configs from compliance audits and policies [#613](https://github.com/greenbone/gvmd/pull/613) [#625](https://github.com/greenbone/gvmd/pull/625) [#633](https://github.com/greenbone/gvmd/pull/633)
- Command cleanup-report-formats for --optimize option [#652](https://github.com/greenbone/gvmd/pull/652)
- Enable SecInfo alert checks [#670](https://github.com/greenbone/gvmd/pull/670)
- Add an explicit solution column to NVTs [#681](https://github.com/greenbone/gvmd/pull/681) [#702](https://github.com/greenbone/gvmd/pull/702) [#730](https://github.com/greenbone/gvmd/pull/730)
- Document container tasks in GMP doc [#688](https://github.com/greenbone/gvmd/pull/688)
- Add explicit columns for the NVT tags "summary", "insight", "detection", "impact" and "affected" [#719](https://github.com/greenbone/gvmd/pull/719) [#746](https://github.com/greenbone/gvmd/pull/746)
- Add lean option to GET_REPORTS [#745](https://github.com/greenbone/gvmd/pull/745)
- Add scanner relays and OSP sensor scanner type [#756](https://github.com/greenbone/gvmd/pull/756) [#759](https://github.com/greenbone/gvmd/pull/759)

### Changed
- Always convert iCalendar strings to use UTC. [#777](https://github.com/greenbone/gvmd/pull/777)
- Check if NVT preferences exist before inserting. [#406](https://github.com/greenbone/gvmd/pull/406)
- Raise minimum version for SQL functions. [#420](https://github.com/greenbone/gvmd/pull/420)
- Run OpenVAS scans via OSP instead of OTP. [#422](https://github.com/greenbone/gvmd/pull/422) [#584](https://github.com/greenbone/gvmd/pull/584) [#623](https://github.com/greenbone/gvmd/pull/623) [#636](https://github.com/greenbone/gvmd/pull/636) [#704](https://github.com/greenbone/gvmd/pull/704) [#729](https://github.com/greenbone/gvmd/pull/729)
- Request nvti_cache update only at very end of NVT update. [#426](https://github.com/greenbone/gvmd/pull/426)
- Consolidate NVT references into unified "refs" element. [#427](https://github.com/greenbone/gvmd/pull/427) [#739](https://github.com/greenbone/gvmd/pull/739)
- Update gvm-libs version requirements to v11.0. [#480](https://github.com/greenbone/gvmd/pull/480)
- Adjust to use new API for vt references. [#526](https://github.com/greenbone/gvmd/pull/526)
- Expect NVT sync script in bin directory. [#546](https://github.com/greenbone/gvmd/pull/546)
- Change internal handling of NVT XML to use nvti_t. [#562](https://github.com/greenbone/gvmd/pull/562)
- Change NVT references like CVEs and BID to general vt_refs. [#570](https://github.com/greenbone/gvmd/pull/570) [#574](https://github.com/greenbone/gvmd/pull/574) [#582](https://github.com/greenbone/gvmd/pull/582)
- Update SQLite to PostgreSQL migration script and documentation. [#581](https://github.com/greenbone/gvmd/pull/581) [#601](https://github.com/greenbone/gvmd/pull/601) [#604](https://github.com/greenbone/gvmd/pull/604) [#605](https://github.com/greenbone/gvmd/pull/605)
- Update result diff generation at delta reports [#650](https://github.com/greenbone/gvmd/pull/650)
- Check and create default permissions individually [#671](https://github.com/greenbone/gvmd/pull/671)
- Add -f arg to sendmail call in email alert [#676](https://github.com/greenbone/gvmd/pull/676) [#678](https://github.com/greenbone/gvmd/pull/678)
- Change get_tickets to use the status text for filtering. [#697](https://github.com/greenbone/gvmd/pull/697)
- Made checks to prevent duplicate user names stricter. [#708](https://github.com/greenbone/gvmd/pull/708) [#722](https://github.com/greenbone/gvmd/pull/722)
- Send delete command to ospd after stopping the task. [#710](https://github.com/greenbone/gvmd/pull/710)
- Check whether hosts are alive and have results when adding them in slave scans. [#717](https://github.com/greenbone/gvmd/pull/717) [#726](https://github.com/greenbone/gvmd/pull/726) [#736](https://github.com/greenbone/gvmd/pull/736) [#771](https://github.com/greenbone/gvmd/pull/771)
- Use explicit nvti timestamps [#725](https://github.com/greenbone/gvmd/pull/725)
- New columns Ports, Apps, Distance, and Auth in the CSV Hosts report format [#733](https://github.com/greenbone/gvmd/pull/733)
- The details attribute of GET_REPORTS now defaults to 0 [#747](https://github.com/greenbone/gvmd/pull/747)
- Incoming VT timestamps via OSP are now assumed to be seconds since epoch [#754](https://github.com/greenbone/gvmd/pull/754)
- Accelerate NVT feed update [#757](https://github.com/greenbone/gvmd/pull/757)

### Fixed
- Make get_settings return only one setting when setting_id is given [#779](https://github.com/greenbone/gvmd/pull/779)
- A PostgreSQL statement order issue [#611](https://github.com/greenbone/gvmd/issues/611) has been addressed [#642](https://github.com/greenbone/gvmd/pull/642)
- Fix iCalendar recurrence and timezone handling [#654](https://github.com/greenbone/gvmd/pull/654)
- Fix issues with some scheduled tasks by using iCalendar more instead of old period fields [#656](https://github.com/greenbone/gvmd/pull/655)
- Fix an issue in getting the reports from GMP scanners [#659](https://github.com/greenbone/gvmd/pull/659) [#665](https://github.com/greenbone/gvmd/pull/665)
- Fix GET_SYSTEM_REPORTS using slave_id [#668](https://github.com/greenbone/gvmd/pull/668)
- Fix RAW_DATA when calling GET_INFO with type NVT without attributes name or info_id [#682](https://github.com/greenbone/gvmd/pull/682)
- Fix ORPHAN calculations in GET_TICKETS [#684](https://github.com/greenbone/gvmd/pull/684) [#692](https://github.com/greenbone/gvmd/pull/692)
- Fix assignment of orphaned tickets to the current user [#685](https://github.com/greenbone/gvmd/pull/685)
- Fix response from GET_VULNS when given vuln_id does not exists [#696](https://github.com/greenbone/gvmd/pull/696)
- Make bulk tagging with a filter work if the resources are already tagged [#711](https://github.com/greenbone/gvmd/pull/711)
- Check if the scan finished before deleting it and ensure that the task is set to done [#714](https://github.com/greenbone/gvmd/pull/714)
- Fix columnless search phrase filter keywords with quotes [#715](https://github.com/greenbone/gvmd/pull/715)
- Fix issues importing results or getting them from slaves if they contain "%s" [#723](https://github.com/greenbone/gvmd/pull/723)
- Fix sorting by numeric filter columns [#751](https://github.com/greenbone/gvmd/pull/751)
- Fix array index error when modifying roles and groups [#762](https://github.com/greenbone/gvmd/pull/762)
- Add NULL check in nvts_feed_version_epoch [#773](https://github.com/greenbone/gvmd/pull/773)
- Fix percent sign escaping in report_port_count [#782](https://github.com/greenbone/gvmd/pull/782)
- If the nvt preference is "file" type, encode it into Base64 format [#785](https://github.com/greenbone/gvmd/pull/785)
- Fix missing report ids in alert filenames [#966](https://github.com/greenbone/gvmd/pull/966)

### Removed
- The handling of NVT updates via OTP has been removed. [#575](https://github.com/greenbone/gvmd/pull/575)
- Bid and xref have been removed from table nvts. [#582](https://github.com/greenbone/gvmd/pull/582)
- Database migration from revisions before 185 has been removed. [#411](https://github.com/greenbone/gvmd/pull/411) [#622](https://github.com/greenbone/gvmd/pull/622)
- Drop SQLite support [#610](https://github.com/greenbone/gvmd/pull/610) [#612](https://github.com/greenbone/gvmd/pull/612) [#614](https://github.com/greenbone/gvmd/pull/614)
- Remove create report task creation [#616](https://github.com/greenbone/gvmd/pull/616)
- Remove --backup command line option [#615](https://github.com/greenbone/gvmd/pull/615)
- Remove GET_REPORTS type "assets" [#617](https://github.com/greenbone/gvmd/pull/617) [#620](https://github.com/greenbone/gvmd/pull/620)
- Remove errors for unknown elements [#619](https://github.com/greenbone/gvmd/pull/619)
- Remove unused reports column nbefile [#675](https://github.com/greenbone/gvmd/pull/675)
- Eliminate get_tag() and parse_tags() [#743](https://github.com/greenbone/gvmd/pull/743)
- Remove helper functions and other code for handling OTP [#705](https://github.com/greenbone/gvmd/pull/705) [#709](https://github.com/greenbone/gvmd/pull/709) [#713](https://github.com/greenbone/gvmd/pull/713) [#735](https://github.com/greenbone/gvmd/pull/735) [#748](https://github.com/greenbone/gvmd/pull/748) [#749](https://github.com/greenbone/gvmd/pull/749)
- Remove stray prototype nvt_iterator_copyright [#721](https://github.com/greenbone/gvmd/pull/721)

[9.0.0]: https://github.com/greenbone/gvmd/compare/v8.0.1...v9.0.0

## [8.0.1] (2019-07-17)

### Added
- Special characters in credential login names are allowed. [#475](https://github.com/greenbone/gvmd/pull/475)
- Add type filter column to GET_CONFIGS. [#486](https://github.com/greenbone/gvmd/pull/486)
- Filter settings for groups, scanners, tickets, users and vulnerabilities have been added. [#497](https://github.com/greenbone/gvmd/pull/497)
- Multiple certificate formats for S/MIME are allowed. [#551](https://github.com/greenbone/gvmd/pull/551)

### Changed
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
