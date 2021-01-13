# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [21.4] (unreleased)

### Added
- Extend GMP for extended severities [#1326](https://github.com/greenbone/gvmd/pull/1326) [#1329](https://github.com/greenbone/gvmd/pull/1329) [#1359](https://github.com/greenbone/gvmd/pull/1359) [#1371](https://github.com/greenbone/gvmd/pull/1371)
- Parameter `--db-user` to set a database user [#1327](https://github.com/greenbone/gvmd/pull/1327)
- Add `allow_simult_ips_same_host` field for targets [#1346](https://github.com/greenbone/gvmd/pull/1346)
- Speed up GET_VULNS [#1354](https://github.com/greenbone/gvmd/pull/1354) [#1355](https://github.com/greenbone/gvmd/pull/1354)
- Speed up result counting iterator [#1358](https://github.com/greenbone/gvmd/pull/1358) [#1361](https://github.com/greenbone/gvmd/pull/1361)
- Speed up result iterator [#1370](https://github.com/greenbone/gvmd/pull/1358) [#1361](https://github.com/greenbone/gvmd/pull/1370)
- Improve GMP docs around users [#1363](https://github.com/greenbone/gvmd/pull/1363)
- Cache report counts when Dynamic Severity is enabled [#1389](https://github.com/greenbone/gvmd/pull/1389)

### Changed
- Move EXE credential generation to a Python script [#1260](https://github.com/greenbone/gvmd/pull/1260) [#1262](https://github.com/greenbone/gvmd/pull/1262)
- Clarify documentation for --scan-host parameter [#1277](https://github.com/greenbone/gvmd/pull/1277)
- In result iterator access severity directly if possible [#1321](https://github.com/greenbone/gvmd/pull/1321)
- Change SCAP and CERT data to use new severity scoring [#1333](https://github.com/greenbone/gvmd/pull/1333) [#1357](https://github.com/greenbone/gvmd/pull/1357) [#1365](https://github.com/greenbone/gvmd/pull/1365)
- Expect report format scripts to exit with code 0 [#1383](https://github.com/greenbone/gvmd/pull/1383)
- Send entire families to ospd-openvas using VT_GROUP [#1384](https://github.com/greenbone/gvmd/pull/1384)
- The internal list of current Local Security Checks for the 'Closed CVEs' feature was updated [#1381](https://github.com/greenbone/gvmd/pull/1381)
- Limit "whole-only" config families to "growing" and "every nvt" [#1386](https://github.com/greenbone/gvmd/pull/1386)

### Fixed
- Use GMP version with leading zero for feed dirs [#1287](https://github.com/greenbone/gvmd/pull/1287)
- Check db version before creating SQL functions [#1304](https://github.com/greenbone/gvmd/pull/1304)
- Fix severity_in_level SQL function [#1312](https://github.com/greenbone/gvmd/pull/1312)
- Fix and simplify SecInfo migration [#1331](https://github.com/greenbone/gvmd/pull/1331)
- Prevent CPE/NVD_ID from being "(null)" [#1369](https://github.com/greenbone/gvmd/pull/1369)
- Check DB versions before CERT severity updates [#1376](https://github.com/greenbone/gvmd/pull/1376)

### Removed
- Remove solution element from VT tags [#886](https://github.com/greenbone/gvmd/pull/886)
- Drop GMP scanners [#1269](https://github.com/greenbone/gvmd/pull/1269)
- Reduce Severity Classes [#1285](https://github.com/greenbone/gvmd/pull/1285)
- Removed Severity Classes [#1288](https://github.com/greenbone/gvmd/pull/1288)
- Remove remaining use of "Severity Class" in where_levels_auto [#1311](https://github.com/greenbone/gvmd/pull/1311)
- Remove the functionality "autofp" (Auto False Positives) [#1300](https://github.com/greenbone/gvmd/pull/1300)
- Remove severity type "debug" [#1316](https://github.com/greenbone/gvmd/pull/1316)
- Remove element "threat" of element "notes" [#1324](https://github.com/greenbone/gvmd/pull/1324)

[21.4]: https://github.com/greenbone/gvmd/compare/gvmd-20.08...master

## [20.8.1] (unreleased)

### Added
- Added ability to enter Subject Alternative Names (SAN) when generating a CSR [#1246](https://github.com/greenbone/gvmd/pull/1246)
- Add filter term 'predefined' [#1263](https://github.com/greenbone/gvmd/pull/1263)
- Add missing elements in get_nvts and get_preferences GMP doc [#1307](https://github.com/greenbone/gvmd/pull/1307)
- Add command line options db-host and db-port [#1308](https://github.com/greenbone/gvmd/pull/1308)
- Add missing config and target to modify_task GMP doc [#1310](https://github.com/greenbone/gvmd/pull/1310)
- Add version for NVTs and CVEs in make_osp_result [#1335](https://github.com/greenbone/gvmd/pull/1335)
- Add check if gvmd data feed dir exists [#1360](https://github.com/greenbone/gvmd/pull/1360) [#1362](https://github.com/greenbone/gvmd/pull/1362)

### Changed
- Extended the output of invalid / missing --feed parameter given to greenbone-feed-sync [#1255](https://github.com/greenbone/gvmd/pull/1255)
- The xsltproc binary is now marked as mandatory [#1259](https://github.com/greenbone/gvmd/pull/1259)
- Check feed status without acquiring lock [#1266](https://github.com/greenbone/gvmd/pull/1266)

### Fixed
- Add dummy functions to allow restoring old dumps [#1251](https://github.com/greenbone/gvmd/pull/1251)
- Fix delta sorting for unusual filter sort terms [#1249](https://github.com/greenbone/gvmd/pull/1249)
- Fix SCP alert authentication and logging [#1264](https://github.com/greenbone/gvmd/pull/1264)
- Set file mode creation mask for feed lock handling [#1265](https://github.com/greenbone/gvmd/pull/1265)
- Ignore min_qod when getting single results by UUID [#1276](http://github.com/greenbone/gvmd/pull/1276)
- Fix alternative options for radio type preferences when exporting a scan_config [#1278](http://github.com/greenbone/gvmd/pull/1278)
- Replace deprecated sys_siglist with strsignal [#1280](https://github.com/greenbone/gvmd/pull/1280)
- Copy instead of moving when migrating predefined report formats [#1286](https://github.com/greenbone/gvmd/pull/1286)
- Skip DB check in helpers when main process is running [#1291](https://github.com/greenbone/gvmd/pull/1291)
- Recreate vulns after sync [#1292](https://github.com/greenbone/gvmd/pull/1292)
- Add SecInfo case to alert check in MODIFY_FILTER [#1293](https://github.com/greenbone/gvmd/pull/1293)
- For radio prefs in GMP exclude value and include default [#1296](https://github.com/greenbone/gvmd/pull/1296)
- Add permission check on host in OS host count [#1301](https://github.com/greenbone/gvmd/pull/1301)
- Auto delete at the start of scheduling so it always runs [#1302](https://github.com/greenbone/gvmd/pull/1302)
- Fix create_credential for snmpv3. [#1305](https://github.com/greenbone/gvmd/pull/1305)
- Remove extra spaces when parsing report format param type [#1309](https://github.com/greenbone/gvmd/pull/1309)
- Correct arg to alert_uuid [#1313](https://github.com/greenbone/gvmd/pull/1313)
- Switch result filter column 'task' from task ID to name task name [#1317](https://github.com/greenbone/gvmd/pull/1317)
- Correct check of get_certificate_info return [#1318](https://github.com/greenbone/gvmd/pull/1318)
- Fix GMP doc text of `active` elem for notes and overrides [#1323](https://github.com/greenbone/gvmd/pull/1323)
- Move feed object in trash checks to startup [#1325](https://github.com/greenbone/gvmd/pull/1325)
- Do not inherit settings from deleted users [#1328](https://github.com/greenbone/gvmd/pull/1328)
- Delete TLS certificate sources when deleting users [#1334](https://github.com/greenbone/gvmd/pull/1334)
- Fix SQL errors in SCAP and CERT update [#1343](https://github.com/greenbone/gvmd/pull/1343)
- Always check for 'All' when deleting selectors [#1342](https://github.com/greenbone/gvmd/pull/1342)
- Account for -1 of orphans when deleting permission [#1345](https://github.com/greenbone/gvmd/pull/1345)
- Allow config to sync even if NVT family is not available [#1347](https://github.com/greenbone/gvmd/pull/1347)
- Check private key when modifying credential [#1351](https://github.com/greenbone/gvmd/pull/1351)
- Clean up hosts strings before using them [#1352](https://github.com/greenbone/gvmd/pull/1352)
- Improve SCP username and destination path handling [#1350](https://github.com/greenbone/gvmd/pull/1350)
- Fix response memory handling in handle_osp_scan [#1364](https://github.com/greenbone/gvmd/pull/1364)
- Allow config to sync even if NVT family is not available [#1366](https://github.com/greenbone/gvmd/pull/1366)
- Delete report format dirs last when deleting a user [#1368](https://github.com/greenbone/gvmd/pull/1368)
- Fix sorting in get_aggregates and its documentation [#1375](https://github.com/greenbone/gvmd/pull/1375)

### Removed
- Remove DROP from vulns creation [#1281](http://github.com/greenbone/gvmd/pull/1281)

[20.8.1]: https://github.com/greenbone/gvmd/compare/v20.8.0...gvmd-20.08

## [20.8.0] (2020-08-11)

### Added
- Add setting "BPM Dashboard Configuration" [#764](https://github.com/greenbone/gvmd/pull/764)
- Faster SecInfo REF retrieval for GET_REPORTS [#793](https://github.com/greenbone/gvmd/pull/793)
- Improve performance of GET_REPORTS [#801](https://github.com/greenbone/gvmd/pull/801) [#811](https://github.com/greenbone/gvmd/pull/811) [#817](https://github.com/greenbone/gvmd/pull/817)
- Speed up the HELP 'brief' case [#807](https://github.com/greenbone/gvmd/pull/807)
- Faster startup [#826](https://github.com/greenbone/gvmd/pull/826)
- Add option --optimize migrate-relay-sensors [#827](https://github.com/greenbone/gvmd/pull/827)
- Add host_id filter for tls_certificates [#835](https://github.com/greenbone/gvmd/pull/835)
- Allow use of public key auth in SCP alert [#845](https://github.com/greenbone/gvmd/pull/845)
- Refuse to import config with missing NVT preference ID [#853](https://github.com/greenbone/gvmd/pull/853) [#860](https://github.com/greenbone/gvmd/pull/860)
- Add "Base" scan config [#862](https://github.com/greenbone/gvmd/pull/862)
- Add setting "BPM Data" [#915](https://github.com/greenbone/gvmd/pull/915)
- Automatically load predefined configs from the feed [#931](https://github.com/greenbone/gvmd/pull/931) [#933](https://github.com/greenbone/gvmd/pull/933) [#934](https://github.com/greenbone/gvmd/pull/934)
- Automatically load predefined port lists from the feed [#950](https://github.com/greenbone/gvmd/pull/950) [#952](https://github.com/greenbone/gvmd/pull/952)
- Automatically load predefined report formats from the feed [#968](https://github.com/greenbone/gvmd/pull/968) [#970](https://github.com/greenbone/gvmd/pull/970)
- Print UUIDs in --get-users when --verbose given [#991](https://github.com/greenbone/gvmd/pull/991)
- Add --get-roles [#992](https://github.com/greenbone/gvmd/pull/992)
- Add --rebuild [#998](https://github.com/greenbone/gvmd/pull/998)
- Lock a file around the NVT sync [#1002](https://github.com/greenbone/gvmd/pull/1002)
- Add a delay for re-requesting scan information via osp [#1012](https://github.com/greenbone/gvmd/pull/1012)
- Add --optimize option cleanup-result-encoding [#1013](https://github.com/greenbone/gvmd/pull/1013)
- Perform integrity check of VTs after updates [#1024](https://github.com/greenbone/gvmd/pull/1024) [#1035](https://github.com/greenbone/gvmd/pull/1035)
- Ensure path of listening UNIX socket exists [#1040](https://github.com/greenbone/gvmd/pull/1040)
- Add --rebuild-scap option [#1051](https://github.com/greenbone/gvmd/pull/1051)
- Stop current scheduling of task when permission denied [#1058](https://github.com/greenbone/gvmd/pull/1058)
- Trim malloc heap after updating cache [#1085](https://github.com/greenbone/gvmd/pull/1085)
- Handle QUEUED osp scan status. [#1113](https://github.com/greenbone/gvmd/pull/1113)
- Add time placeholders for SCP path [#1164](https://github.com/greenbone/gvmd/pull/1164)
- Expand detection information of results [#1182](https://github.com/greenbone/gvmd/pull/1182)
- Add filter columns for special NVT tags [#1199](https://github.com/greenbone/gvmd/pull/1199)
- Add currently_syncing for NVTs in GMP get_feeds [#1210](https://github.com/greenbone/gvmd/pull/1210)
- Add logging for ANALYZE at end of migration [#1211](https://github.com/greenbone/gvmd/pull/1211)
- Basic systemd, logrotate and config files have been added [#1240](https://github.com/greenbone/gvmd/pull/1240)

### Changed
- Update SCAP and CERT feed info in sync scripts [#810](https://github.com/greenbone/gvmd/pull/810)
- Extend command line options for managing scanners [#815](https://github.com/greenbone/gvmd/pull/815)
- Try authentication when verifying GMP scanners [#837](https://github.com/greenbone/gvmd/pull/837)
- Try importing private keys with libssh if GnuTLS fails [#841](https://github.com/greenbone/gvmd/pull/841)
- Extend GMP API for nvt object to carry a explicit solution element [#849](https://github.com/greenbone/gvmd/pull/849) [#1143](https://github.com/greenbone/gvmd/pull/1143)
- Allow resuming OSPd-based OpenVAS tasks [#869](https://github.com/greenbone/gvmd/pull/869)
- Require PostgreSQL 9.6 as a minimum [#872](https://github.com/greenbone/gvmd/pull/872)
- Speed up the SCAP sync [#875](https://github.com/greenbone/gvmd/pull/875) [#877](https://github.com/greenbone/gvmd/pull/877) [#879](https://github.com/greenbone/gvmd/pull/879) [#881](https://github.com/greenbone/gvmd/pull/881) [#883](https://github.com/greenbone/gvmd/pull/883) [#887](https://github.com/greenbone/gvmd/pull/887) [#889](https://github.com/greenbone/gvmd/pull/889) [#890](https://github.com/greenbone/gvmd/pull/890) [#891](https://github.com/greenbone/gvmd/pull/891) [#901](https://github.com/greenbone/gvmd/pull/901)
- Change rows of built-in default filters to -2 (use "Rows Per Page" setting) [#896](https://github.com/greenbone/gvmd/pull/896)
- Force NVT update in migrate_219_to_220 [#895](https://github.com/greenbone/gvmd/pull/895)
- Use temp tables to speed up migrate_213_to_214 [#911](https://github.com/greenbone/gvmd/pull/911)
- Allow "Start Task" alert method for SecInfo events [#960](https://github.com/greenbone/gvmd/pull/960)
- New Community Feed download URL in sync tools [#982](https://github.com/greenbone/gvmd/pull/982)
- Change setting UUID to correct length [#1018](https://github.com/greenbone/gvmd/pull/1018)
- Change licence to AGPL-3.0-or-later [#1026](https://github.com/greenbone/gvmd/pull/1026)
- Count only best OS matches for OS asset hosts [#1029](https://github.com/greenbone/gvmd/pull/1029)
- Clean up NVTs set to name in cleanup-result-nvts [#1039](https://github.com/greenbone/gvmd/pull/1039)
- Improve validation of note and override ports [#1045](https://github.com/greenbone/gvmd/pull/1045)
- The internal list of current Local Security Checks for the Auto-FP feature was updated [#1054](https://github.com/greenbone/gvmd/pull/1054)
- Simplify sync lockfile handling [#1059](https://github.com/greenbone/gvmd/pull/1059)
- Do not ignore empty hosts_allow and ifaces_allow [#1064](https://github.com/greenbone/gvmd/pull/1064)
- Reduce the memory cache of NVTs [#1076](https://github.com/greenbone/gvmd/pull/1076)
- Sync SCAP using a second schema [#1111](https://github.com/greenbone/gvmd/pull/1111)
- Use error variable in osp_get_vts_version(). [#1159](https://github.com/greenbone/gvmd/pull/1159)
- Include unknown preferences when uploading or syncing configs [#1005](https://github.com/greenbone/gvmd/pull/1005)
- Set the default OSPD unix socket path to /var/run/ospd/ospd.sock [#1238](https://github.com/greenbone/gvmd/pull/1238)
- The default OSPD unix path is now configurable [#1244](https://github.com/greenbone/gvmd/pull/1244)

### Fixed
- Add NULL check in nvts_feed_version_epoch [#768](https://github.com/greenbone/gvmd/pull/768)
- Faster counting in GET_REPORTS when ignoring pagination [#795](https://github.com/greenbone/gvmd/pull/795)
- Improve performance of GET_REPORTS [#797](https://github.com/greenbone/gvmd/pull/797)
- Consider results_trash when deleting users [#800](https://github.com/greenbone/gvmd/pull/800)
- Update to gvm-portnames-update to use new nomenclature [#802](https://github.com/greenbone/gvmd/pull/802)
- Escaping correctly the percent sign in sql statements  [#818](https://github.com/greenbone/gvmd/pull/818)
- Try to get NVT preferences by id in create_config [#821](https://github.com/greenbone/gvmd/pull/821)
- Remove incorrect duplicates from config preference migrator [#830](https://github.com/greenbone/gvmd/pull/830)
- Update config preferences after updating NVTs [#832](https://github.com/greenbone/gvmd/pull/832)
- Fix order of fingerprints in get_tls_certificates [#833](https://github.com/greenbone/gvmd/pull/833)
- Fix notes XML for lean reports [#836](https://github.com/greenbone/gvmd/pull/836)
- Fix asset host details insertion SQL [#839](https://github.com/greenbone/gvmd/pull/839)
- MODIFY_USER saves comment when COMMENT is empty [#838](https://github.com/greenbone/gvmd/pull/838)
- Prevent HOSTS_ORDERING from being '(null)' [#859](https://github.com/greenbone/gvmd/pull/859)
- Fix result diff generation to ignore white space in delta reports [#861](https://github.com/greenbone/gvmd/pull/861)
- Fix resource type checks for permissions [#863](https://github.com/greenbone/gvmd/pull/863)
- Fix result_nvt for new OSP and slave results [#865](https://github.com/greenbone/gvmd/pull/865)
- Fix preference ID in "Host Discovery" config [#867](https://github.com/greenbone/gvmd/pull/867)
- Fix SQL for tickets with overrides [#871](https://github.com/greenbone/gvmd/pull/871)
- Fix result_nvt for new OSP and slave results [#873](https://github.com/greenbone/gvmd/pull/873)
- Use right format specifier for merge_ovaldef version [#874](https://github.com/greenbone/gvmd/pull/874)
- Fix creation of "Super" permissions [#892](https://github.com/greenbone/gvmd/pull/892)
- Add tags used for result NVTs to update_nvti_cache [#916](https://github.com/greenbone/gvmd/pull/916)
- Apply usage_type of tasks in get_aggregates (9.0) [#912](https://github.com/greenbone/gvmd/pull/912)
- Add target's alive test method before starting a scan. [#947](https://github.com/greenbone/gvmd/pull/947)
- Set run status only after getting OSP-OpenVAS scan [#948](https://github.com/greenbone/gvmd/pull/948) [#951](https://github.com/greenbone/gvmd/pull/951)
- Fix get_system_reports for GMP scanners [#949](https://github.com/greenbone/gvmd/pull/949)
- Fix QoD handling in nvti cache and test_alert [#954](https://github.com/greenbone/gvmd/pull/954)
- Use stop_osp_task for SCANNER_TYPE_OSP_SENSOR [#955](https://github.com/greenbone/gvmd/pull/955)
- Add target's reverse_lookup_* options [#959](https://github.com/greenbone/gvmd/pull/959)
- Fix "Start Task" alerts by using alert owner [#957](https://github.com/greenbone/gvmd/pull/957)
- Fix Verinice ISM report format and update version [#962](https://github.com/greenbone/gvmd/pull/962)
- Always use details testing alerts with a report [#964](https://github.com/greenbone/gvmd/pull/964)
- Remove extra XML declaration in Anonymous XML [#965](https://github.com/greenbone/gvmd/pull/965)
- Fix SecInfo alert filter conditions [#971](https://github.com/greenbone/gvmd/pull/971)
- Accept expanded scheme OIDs in parse_osp_report [#984](https://github.com/greenbone/gvmd/pull/984)
- Fix SCAP update not finishing when CPEs are older [#986](https://github.com/greenbone/gvmd/pull/986)
- Move report format dirs when inheriting user [#989](https://github.com/greenbone/gvmd/pull/989)
- Delete report format dirs when deleting user [#993](https://github.com/greenbone/gvmd/pull/993)
- Put 'lean' back to 0 for GET_RESULTS [#1001](https://github.com/greenbone/gvmd/pull/1001)
- Improve handling of removed NVT prefs [#1003](https://github.com/greenbone/gvmd/pull/1003)
- Ensure parent exists when moving report format dir [#1019](https://github.com/greenbone/gvmd/pull/1019)
- Use nvti_qod instead of the old nvti_get_tag() [#1022](https://github.com/greenbone/gvmd/pull/1022)
- Remove active clause when filtering resources by tag [#1025](https://github.com/greenbone/gvmd/pull/1025)
- Add user limits on hosts and ifaces to OSP prefs [#1033](https://github.com/greenbone/gvmd/pull/1033)
- Fix order of tar options in gvm-lsc-deb-creator.sh [#1034](https://github.com/greenbone/gvmd/pull/1034)
- Fix handling of termination signals [#1034](https://github.com/greenbone/gvmd/pull/1034)
- Remove db init warning that no longer makes sense [#1044](https://github.com/greenbone/gvmd/pull/1044)
- Use correct elements to get task ID in wizards [#1004](https://github.com/greenbone/gvmd/pull/1004) [#1046](https://github.com/greenbone/gvmd/pull/1046)
- Use current row for iterator_null, instead of first row [#1047](https://github.com/greenbone/gvmd/pull/1047)
- Setup general task preferences to launch an osp openvas task. [#1055](https://github.com/greenbone/gvmd/pull/1055)
- Fix doc of get_tasks in GMP doc [#1066](https://github.com/greenbone/gvmd/pull/1066)
- Improve refs and error handling in NVTs update [#1067](https://github.com/greenbone/gvmd/pull/1067)
- Fix failure detection for xml_split command [#1074](https://github.com/greenbone/gvmd/pull/1074)
- Fix deletion of OVAL definition data [#1079](https://github.com/greenbone/gvmd/pull/1079)
- Fix feed lock in sync script [#1088](https://github.com/greenbone/gvmd/pull/1088)
- Handle removed CPEs and CVEs in SCAP sync [#1097](https://github.com/greenbone/gvmd/pull/1097)
- Fix NVTs list in CVE details [#1100](https://github.com/greenbone/gvmd/pull/1100)
- Fix handling of duplicate settings [#1106](https://github.com/greenbone/gvmd/pull/1106)
- Fix XML escaping in setting up GMP scans [#1122](https://github.com/greenbone/gvmd/pull/1122)
- Fix and simplify parse_iso_time and add tests [#1129](https://github.com/greenbone/gvmd/pull/1129)
- Fix gvm-manage-certs. [#1140](https://github.com/greenbone/gvmd/pull/1140)
- Fix CVE scanner and results handling [#1141](https://github.com/greenbone/gvmd/pull/1141)
- Remove user from tags when deleting user [#1161](https://github.com/greenbone/gvmd/pull/1161)
- Handle INTERRUPTED scans [#1146](https://github.com/greenbone/gvmd/pull/1146)
- Check hosts in MODIFY_OVERRIDE, as in CREATE_OVERRIDE [#1162](https://github.com/greenbone/gvmd/pull/1162)
- Preserve task "once" value [#1176](https://github.com/greenbone/gvmd/pull/1176)
- Check number of args to ensure period_offsets is 0 [#1175](https://github.com/greenbone/gvmd/pull/1175)
- Fix name handling when creating host assets [#1183](https://github.com/greenbone/gvmd/pull/1183) [#1214](https://github.com/greenbone/gvmd/pull/1214)
- Outdated references to "openvassd" have been updated to "openvas" [#1189](https://github.com/greenbone/gvmd/pull/1189)
- Quote identifiers in SQL functions using EXECUTE [#1192](https://github.com/greenbone/gvmd/pull/1192)
- Fix handling of interrupted tasks [#1207](https://github.com/greenbone/gvmd/pull/1207)
- Allow group access to lockfile and fix growing or empty timestamp [#1213](https://github.com/greenbone/gvmd/pull/1213)
- Ignore whitespace when checking for changed delta results [#1219](https://github.com/greenbone/gvmd/pull/1219)
- Check permissions when applying tag in filter [#1222](https://github.com/greenbone/gvmd/pull/1222)
- Add missing min_qod to FILTERS in GET_VULNS response [#1224](https://github.com/greenbone/gvmd/pull/1224)
- Improve EXE installer NSIS script generation [#1226](https://github.com/greenbone/gvmd/pull/1226)
- Add qod as name in results columns, for sorting [#1243](https://github.com/greenbone/gvmd/pull/1243)

### Removed
- Remove support for "All SecInfo": removal of "allinfo" for type in get_info [#790](https://github.com/greenbone/gvmd/pull/790)
- Removed tag_value() by using nvti_get_tag() [#825](https://github.com/greenbone/gvmd/pull/825)
- Remove support for "MODIFY_REPORT" GMP command [#823](https://github.com/greenbone/gvmd/pull/823)
- Remove 1.3.6.1.4.1.25623.1.0.90011 from Discovery config (9.0) [#847](https://github.com/greenbone/gvmd/pull/847)
- Removed migration tool "gvm-migrate-to-postgres" including the man page [#905](https://github.com/greenbone/gvmd/pull/905)
- Remove agents [#922](https://github.com/greenbone/gvmd/pull/922)
- Remove GMP COMMANDS [#923](https://github.com/greenbone/gvmd/pull/923)
- Remove unused port names facility [#1041](https://github.com/greenbone/gvmd/pull/1041)
- Add migrator to remove dead hosts [#1071](https://github.com/greenbone/gvmd/pull/1071)
- Remove classic schedules elements from GMP [#1116](https://github.com/greenbone/gvmd/pull/1116) [#1121](https://github.com/greenbone/gvmd/pull/1121)
- Remove parallel from target options. [#1119](https://github.com/greenbone/gvmd/pull/1119)
- Remove default port list from CREATE_TARGET [#1151](https://github.com/greenbone/gvmd/pull/1151)

[20.8.0]: https://github.com/greenbone/gvmd/compare/v9.0.0...v20.8.0

## [9.0.0] (2019-10-11)

### Added
- Added TLS certificates as a new resource type [#585](https://github.com/greenbone/gvmd/pull/585) [#663](https://github.com/greenbone/gvmd/pull/663) [#673](https://github.com/greenbone/gvmd/pull/673) [#674](https://github.com/greenbone/gvmd/pull/674) [#689](https://github.com/greenbone/gvmd/pull/689) [#695](https://github.com/greenbone/gvmd/pull/695) [#703](https://github.com/greenbone/gvmd/pull/703) [#728](https://github.com/greenbone/gvmd/pull/728) [#732](https://github.com/greenbone/gvmd/pull/732) [#750](https://github.com/greenbone/gvmd/pull/750) [#752](https://github.com/greenbone/gvmd/pull/752) [#775](https://github.com/greenbone/gvmd/pull/775) [#796](https://github.com/greenbone/gvmd/pull/796)
- Update NVTs via OSP [#392](https://github.com/greenbone/gvmd/pull/392) [#609](https://github.com/greenbone/gvmd/pull/609) [#626](https://github.com/greenbone/gvmd/pull/626) [#753](https://github.com/greenbone/gvmd/pull/753) [#766](https://github.com/greenbone/gvmd/pull/766)
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
- Add setting "BPM Data" [#914](https://github.com/greenbone/gvmd/pull/914)

### Changed
- Always convert iCalendar strings to use UTC. [#778](https://github.com/greenbone/gvmd/pull/778)
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
- Check whether hosts are alive and have results when adding them in slave scans. [#717](https://github.com/greenbone/gvmd/pull/717) [#726](https://github.com/greenbone/gvmd/pull/726) [#731](https://github.com/greenbone/gvmd/pull/731) [#736](https://github.com/greenbone/gvmd/pull/736)
- Use explicit nvti timestamps [#725](https://github.com/greenbone/gvmd/pull/725)
- New columns Ports, Apps, Distance, and Auth in the CSV Hosts report format [#733](https://github.com/greenbone/gvmd/pull/733)
- The details attribute of GET_REPORTS now defaults to 0 [#747](https://github.com/greenbone/gvmd/pull/747)
- Incoming VT timestamps via OSP are now assumed to be seconds since epoch [#754](https://github.com/greenbone/gvmd/pull/754)
- Accelerate NVT feed update [#757](https://github.com/greenbone/gvmd/pull/757)
- Combine sync scripts and add GVMd data sync [#1155](https://github.com/greenbone/gvmd/pull/1155) [#1201](https://github.com/greenbone/gvmd/pull/1201)

### Fixed
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
- Add NULL check in nvts_feed_version_epoch [#768](https://github.com/greenbone/gvmd/pull/768)
- Make get_settings return only one setting when setting_id is given [#780](https://github.com/greenbone/gvmd/pull/780)
- Fix percent sign escaping in report_port_count [#783](https://github.com/greenbone/gvmd/pull/783)
- If the nvt preference is "file" type, encode it into Base64 format [#784](https://github.com/greenbone/gvmd/pull/784)

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
