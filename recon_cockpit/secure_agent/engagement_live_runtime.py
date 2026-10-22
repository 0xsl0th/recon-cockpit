"""Fixed S4.2c runtime custody and process boundaries.

Only fixed reviewed roles may be built. Host-side inspection/spawning imports are
lazy, so importing this module in a leaf does not import a builder or authority.
"""
from __future__ import annotations

from contextvars import ContextVar

import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

SPEC = {'apis': {'client.prepare': 'prepare_client(*, runtime, prepared, endpoint_identity, scope, '
                            'control) -> WaitingClient; assumes inherited sessionnet; '
                            '.ready/.release(release,control)/.observe_native(control)/.collect(control)/.close(); '
                            'release is launcher-validated one-time GO projection',
          'context.validate': 'validate_live_context(value) -> detached validated context; pure '
                              'consistency checker, no process/network/store execution',
          'endpoint.arm': 'arm_endpoint(channel, *, release, endpoint_identity, control) -> exact '
                          'ack; callable only by inherited launcher ARM peer; no host duplicate '
                          'writer',
          'endpoint.prepare': 'prepare_endpoint(*, runtime, session_binding, broker_peer, '
                              'arm_peer, control) -> EndpointOwner; .ready receipt/.namespace_fds '
                              'for host startup only; .progress(control)/.close(); host never '
                              'writes ARM or reads broker-owned channel',
          'parser.parse': 'parse(*, tool_id, raw, stderr, scope, truncated, control, runtime) -> '
                          '(validated unchanged parsed result, parser_receipt)',
          'runtime.bootstrap_role': 'bootstrap_role(*, role, entry, runtime_manifest, '
                                    'expected_fds, deadline_ns) -> worker_ready. '
                                    'Calledafterfixedendpointsetup orGUIwarmup, beforeREADY: '
                                    'verifyallowedstartupdelta; closeallstagingFDs; setrolelimits; '
                                    'dropallcaps andNNP; installrolefilter andwitnesses. '
                                    'GUIterminal accepted seal helpers mayfurtherrestrictIO '
                                    'beforeemittingfinalREADY. No '
                                    'unchangedplanner_worker._bootstrap UID0assumption. '
                                    'Host-onlyimports inruntimefunctions remainlazy.',
          'runtime.check_role_entry': 'check_role_entry(*, role, bootstrap, expected_fds, '
                                      'observer) -> EntryIdentity. '
                                      'Calledafterfixedfirstinitialtransfer, verifying '
                                      'exactcompletepostbootstrapFDinventory/actualnamespaces/mapping/runtimecommitment. '
                                      'Minimalroleentry independently '
                                      'verified0/1/2beforeimports/transfer. EntryIdentity stores '
                                      'fixed pre-setupdescriptor/tasksets; required '
                                      'GUIwarmup/endpointsetup thenbootstrap_role seals. No '
                                      'additionaltransferallowed.',
          'runtime.cleanup': 'cleanup_owned(processes, pins, *, deadline=None) -> cleanup; '
                             'inputprocesses list of owned subprocess objects, pins corresponding '
                             'PinnedProcess orNone. Computeone max2s emergencydeadline '
                             'optionallynarrowedby supplied emergencydeadline, never renewed '
                             'perrole; close everypin/procdir/stream evenifcleanupfails. '
                             'Workdeadlines mayexpire but no successreturned; descriptorownership '
                             'explicit.',
          'runtime.inspect_runtime': 'inspect_runtime(control) -> validated runtime bundle (no '
                                     'role launch)',
          'runtime.observe_native': 'observe_native(pin, manifest, *, waiting_image, control) -> '
                                    'detached native image observation; no retry/exec; bounded '
                                    'waiting only for same PID image transition',
          'runtime.observe_process': 'observe_process(*, info_raw, process, role, bundle, '
                                     'observer, expected_net, control) -> PinnedProcess; holds '
                                     'pidfd+procdir, .receipt is parent_observation; '
                                     '.check_alive(); .close(); role boundaries and '
                                     'actualworkerREADY later combined by validate_readiness',
          'runtime.snapshot_role': 'snapshot_role(bundle, role, control) -> RoleSnapshot context '
                                   'manager: .sources/.native/.extensions exact '
                                   'destination->sealedFD maps, .manifest detached selected role '
                                   'manifest, .stdlib fixedreadonlypath; .mounts(argv) mutates and '
                                   'returns same list, adds exact sealed --ro-bind-data mounts '
                                   'plus controlled stdlib/lib-dynloadoverlay; caller closes '
                                   'snapshot after successful/failedPopen; '
                                   'nevertransferownershipimplicitly.',
          'runtime.validate_manifest': 'validate_runtime(value) -> detached closed runtime bundle; '
                                       'runtime_digest(value) -> SHA256 canonical bundle; '
                                       'validate_readiness exact names and role source/native '
                                       'manifest bindings.',
          'runtime.validate_readiness': 'validate_readiness(role, value, bundle, *, '
                                        'expected_binding=None) -> detached strict role_readiness; '
                                        'no process launch; compoundreceipt<=16384, '
                                        'workerline<=8192'},
 'closed_objects': {'ancestry_row': {'fields': ['pid', 'parent_pid', 'start_time_ticks'],
                                     'ordering': 'payload first, supervised wrapper last; starts '
                                                 'nonincreasing toward ancestor, '
                                                 'eachparentlinksnext; actual reread before/after '
                                                 'pinned process check'},
                    'bootstrap_descriptor': {'fd': 'strictinteger0..255; uniquefd/purpose; '
                                                   'expectedroleinitialrights table exactly; '
                                                   'actualfstat/flags/typeverified '
                                                   'immediatelyafter singleinitialtransfer; no '
                                                   'laterancillary.',
                                             'fields': ['fd',
                                                        'purpose',
                                                        'device',
                                                        'inode',
                                                        'mode',
                                                        'flags']},
                    'bootstrap_payloads': {'admission': ['prepared',
                                                         'endpoint_identity',
                                                         'launcher_id'],
                                           'broker': 'exact authority-owned BrokerBootstrap '
                                                     'object; only fixed /store/engagement '
                                                     'operator '
                                                     'mount,2preallocatedslots,actualreviewerIDs/modes '
                                                     'andoriginalbrokerstop; authoritymachine '
                                                     'object supplies exactfieldset',
                                           'constraints': 'roe/scope/policy and Prepared '
                                                          'useunchangedclosedvalidators '
                                                          'andauthoritysession_binding. terminal '
                                                          'mode=terminal; '
                                                          'graphicalmode=graphical_v1, '
                                                          'exactXsocket andselectedcookiefile '
                                                          'undernewbuilder. '
                                                          'Brokerpayloadownedauthority '
                                                          'toavoidconflictingduplicate schema. '
                                                          'Parser receives '
                                                          'actualrawinputonlyafterparentpinsREADY. '
                                                          'Client scope is the unchanged accepted '
                                                          'closed scope; its digest equals '
                                                          'Prepared.envelope.scope_sha256 and the '
                                                          'derived fixed slot action equals '
                                                          'Prepared.action. Actual configured SSH '
                                                          'denial uses this scope. Scope supplies '
                                                          'data only, never request/grant '
                                                          'authority.',
                                           'endpoint': ['session_binding',
                                                        'roe',
                                                        'scope',
                                                        'policy',
                                                        'endpoint_id'],
                                           'graphical': ['session_binding',
                                                         'roe',
                                                         'scope',
                                                         'policy',
                                                         'reviewer_id',
                                                         'review_mode',
                                                         'display',
                                                         'display_socket',
                                                         'authority_sha256'],
                                           'headers': ['prepared', 'endpoint_identity', 'scope'],
                                           'launcher': ['session_binding',
                                                        'roe',
                                                        'scope',
                                                        'policy',
                                                        'endpoint_identity'],
                                           'nmap': ['prepared', 'endpoint_identity', 'scope'],
                                           'parser': ['slot', 'scope'],
                                           'terminal': ['session_binding',
                                                        'roe',
                                                        'scope',
                                                        'policy',
                                                        'reviewer_id',
                                                        'review_mode',
                                                        'tty_identity']},
                    'boundary_checks': {'common': ['namespaces_private',
                                                   'mapping_bound',
                                                   'capabilities_dropped',
                                                   'no_new_privs',
                                                   'root_read_only',
                                                   'descriptors_private',
                                                   'process_creation_blocked',
                                                   'namespace_creation_blocked'],
                                        'notes': 'Forlauncher common process_creation_blocked and '
                                                 'namespace_creation_blocked are replaced by '
                                                 'bounded_child_creation and '
                                                 'fixed_namespace_builder; supervisorcancreate '
                                                 'onlydeclared childpaths '
                                                 'undertrustedfixedbuilder, no claim '
                                                 'seccompforbids allneeded fork/unshare while '
                                                 'childbwrapneeds them. Nativeleaves andotherroles '
                                                 'retainactualdeny witnesses.',
                                        'required': 'all requiredtrue forREADY; parent '
                                                    'observations '
                                                    'independentlyverifyphysicalidentity; checks '
                                                    'neverusedas soleevidence fornative gate',
                                        'role_specific': {'admission': ['network_creation_blocked',
                                                                        'authority_absent'],
                                                          'broker': ['network_creation_blocked',
                                                                     'store_path_bound'],
                                                          'endpoint': ['outgoing_connect_blocked',
                                                                       'fastopen_sendto_blocked',
                                                                       'fastopen_sendmsg_blocked',
                                                                       'fastopen_sendmmsg_blocked',
                                                                       'listener_bound',
                                                                       'landlock_applied'],
                                                          'graphical': ['network_creation_blocked',
                                                                        'display_bound',
                                                                        'graphical_input_owned',
                                                                        'remote_interpreter_disabled',
                                                                        'task_set_sealed'],
                                                          'headers': ['forbidden_target_blocked',
                                                                      'forbidden_port_blocked',
                                                                      'ssh_endpoint_blocked',
                                                                      'raw_sockets_blocked',
                                                                      'landlock_applied'],
                                                          'launcher': ['network_creation_blocked',
                                                                       'fixed_child_inventory'],
                                                          'nmap': ['forbidden_target_blocked',
                                                                   'forbidden_port_blocked',
                                                                   'ssh_endpoint_blocked',
                                                                   'raw_sockets_blocked',
                                                                   'landlock_applied'],
                                                          'parser': ['network_creation_blocked',
                                                                     'filesystem_creation_blocked',
                                                                     'authority_absent',
                                                                     'landlock_applied'],
                                                          'terminal': ['network_creation_blocked',
                                                                       'terminal_bound',
                                                                       'terminal_input_owned']},
                                        'shape': 'exact role-specific boolean map'},
                    'cleanup': {'fields': ['schema_version',
                                           'started_at_ns',
                                           'finished_at_ns',
                                           'deadline_ns',
                                           'status',
                                           'processes',
                                           'descriptors_closed'],
                                'processes_max': 26,
                                'required': 'one shared2s budget, allknownpayloads signalled '
                                            'first, wrappers reaped; success only all '
                                            'payloadpidfdsHUP and wrapperswait; descriptorclosure '
                                            'evenerror; emptyprocesses only neverstarted, '
                                            'notmissingobservation',
                                'status': ['complete', 'failed', 'unknown']},
                    'cleanup_process': {'fields': ['role',
                                                   'pid',
                                                   'start_time_ticks',
                                                   'pin_verified',
                                                   'signal_attempted',
                                                   'exit_observed',
                                                   'reaped_observed',
                                                   'wrapper_pid',
                                                   'wrapper_returncode'],
                                        'nulls': 'pid/start/wrapper nullable only no trusted '
                                                 'identity; returncode nullable ifunknown; '
                                                 'unverified pin never signalled, bounded '
                                                 'non-signallingHUP check afterwrappertermination'},
                    'descriptor': {'fields': ['fd',
                                              'purpose',
                                              'kind',
                                              'device',
                                              'inode',
                                              'mode',
                                              'flags'],
                                   'kernel_kinds': 'pidfd from actual held pidfd_open, eventpoll '
                                                   'selector, proc_directory actualheldprocdir; '
                                                   'kernelanon inode descriptors mustmatchpinned '
                                                   'syscall-created identityandphasepurpose, '
                                                   'notarbitrary anon_inode acceptance.',
                                   'kind': ['pipe',
                                            'seqpacket',
                                            'stream_socket',
                                            'listener',
                                            'regular',
                                            'directory',
                                            'character',
                                            'eventfd',
                                            'eventpoll',
                                            'pidfd',
                                            'proc_directory'],
                                   'purpose': 'finite role-phase inventory; actual '
                                              'rights/nonblocking/close-on-exec and peer/listener '
                                              'address checked against fixed rolebinding, not '
                                              'inferred frompurpose string'},
                    'file_identity': {'fields': ['destination',
                                                 'device',
                                                 'inode',
                                                 'mode',
                                                 'size',
                                                 'sha256'],
                                      'notes': 'hash compared to exact staged source/native '
                                               'manifest; device/inode from actual process root or '
                                               'pinned exe, not merely supplied source path'},
                    'identity_values': {'groups': 'bounded0..64 repeated65534 values allowed; '
                                                  'immutable current inventory',
                                        'uids_gids': 'each exact4 integer list from /proc status'},
                    'initial_bootstrap': {'descriptor_rows_max': 32,
                                          'encoded_bytes_max': 32768,
                                          'expected_namespaces': 'exact user/net/mnt/pid '
                                                                 'identityoftrustedobserver plus '
                                                                 'expected sessionnet '
                                                                 'whereapplicable; worker '
                                                                 'mustprivateuser/mnt/pid, '
                                                                 'netprivateexceptsessionlauncher/client. '
                                                                 'Full parentcheck independent.',
                                          'fields': ['schema_version',
                                                     'role',
                                                     'worker_id',
                                                     'observer',
                                                     'expected_namespaces',
                                                     'deadline_ns',
                                                     'runtime_sha256',
                                                     'role_manifest_sha256',
                                                     'source_sha256',
                                                     'descriptors',
                                                     'payload'],
                                          'payload': 'closed discriminated object indexed byrole '
                                                     'below; no arbitrarydictionary, absolute '
                                                     'path, argv, clockfunction or permit'},
                    'mapped_image': {'fields': ['destination', 'device', 'inode'],
                                     'notes': 'fixed manifest path, sortedunique; require actual '
                                              'executable+ELFinterpreter and full required '
                                              'nativeDT_NEEDED closure before ARM; unknown '
                                              'file-backed executable mapping refuses; '
                                              'vdso/vsyscall kernel mappings explicitly classified '
                                              'without claiming filehash'},
                    'mapping_rows': {'required': 'inside65534,length1 for newroles; outside equals '
                                                 'actual observing parent uid/gid; retain '
                                                 'composition to hostnonzero. Unchanged accepted '
                                                 'audit mapping validated under its existing '
                                                 'contract.',
                                     'shape': 'one row [inside,outside,length] per uid/gid map'},
                    'namespaces': {'fields': ['user', 'net', 'mnt', 'pid'],
                                   'values': 'exact kernel namespace strings e.g net:[integer], '
                                             'independent expected equality/private difference '
                                             'checks'},
                    'native_readiness': {'fields': ['schema_version',
                                                    'role',
                                                    'waiting_image',
                                                    'parent_observation',
                                                    'observed_at_ns'],
                                         'required': 'same pinned waitingpayload '
                                                     'PID/start/existingpidfd; executable differs '
                                                     'from waitingPython and '
                                                     'exactlymatchesfixedNmap; before first ARM',
                                         'role': 'nmap'},
                    'observer': {'fields': ['pid', 'uid', 'gid', 'namespaces']},
                    'parent_observation': {'bounds': {'ancestry': 16,
                                                      'descriptors': 32,
                                                      'groups': 64,
                                                      'mapped_images': 64,
                                                      'task_ids': 2},
                                           'fields': ['schema_version',
                                                      'role',
                                                      'observer',
                                                      'wrapper',
                                                      'payload',
                                                      'ancestry',
                                                      'namespaces',
                                                      'uid_map',
                                                      'gid_map',
                                                      'uids',
                                                      'gids',
                                                      'groups',
                                                      'task_ids',
                                                      'descriptors',
                                                      'executable',
                                                      'mapped_images',
                                                      'status',
                                                      'sampled_at_ns',
                                                      'stage'],
                                           'notes': 'launcher observation descriptor set only '
                                                    'non-snapshot steady phase; phase temporary '
                                                    'snapshot inventory separate and max160. '
                                                    'Native tasks<=1; GUI<=2exactTIDset; '
                                                    'allothers1. Parent observations for '
                                                    'nesteduserns chain to accepted host parent '
                                                    'identity. Startuprefusal observations '
                                                    'explicitlytagstage beforeseal; '
                                                    'absentcompleteREADY '
                                                    'neverfabricatedasallchecks true. '
                                                    'Nativecasepredicate '
                                                    'usesactualrefusal/staging/pairedcontrol '
                                                    'evidence, notclaimedusefulness.',
                                           'stage_enum': ['entry', 'prepared', 'sealed', 'native']},
                    'prepare_observations': {'bound_bytes': 65536,
                                             'fields': ['schema_version',
                                                        'session_id',
                                                        'dispatch_id',
                                                        'envelope_sha256',
                                                        'runtime_sha256',
                                                        'launcher_readiness',
                                                        'endpoint_readiness',
                                                        'client_readiness',
                                                        'admission_sha256',
                                                        'prepared_at_ns'],
                                             'notes': 'Retainedcompoundphysicalobservations<=65536; '
                                                      'authority-owned compactprepare_receipt '
                                                      'contains exacthashreferences, '
                                                      'withoutprematureadmissioncleanup. Objects '
                                                      'mustbe retainedbefore accepting '
                                                      'theirhashes.'},
                    'process_identity': {'fields': ['pid', 'parent_pid', 'start_time_ticks'],
                                         'pid': '1..2^31-1'},
                    'process_status': {'fields': ['cap_inheritable',
                                                  'cap_permitted',
                                                  'cap_effective',
                                                  'cap_bounding',
                                                  'cap_ambient',
                                                  'no_new_privs',
                                                  'seccomp_mode'],
                                       'required': 'caps0/no_new_privs1/seccomp2 after leafseal; '
                                                   'launcher allows only its fixed child '
                                                   'construction path and retained source '
                                                   'inventory, all network creation denied'},
                    'role_readiness': {'bound_bytes': 16384,
                                       'fields': ['schema_version',
                                                  'role',
                                                  'worker_ready',
                                                  'parent_observation'],
                                       'notes': 'parent-owned compound receipt retained as '
                                                'evidence; not the8192-byte worker READY line'},
                    'rules': 'All listedfieldsrequired/no unknownkeys; null onlyexpresslyallowed. '
                             'Defaultstrict nonbool integers0..2^63-1. Signedexceptions: syscall '
                             'return_value/network_return/filesystem_return/process_return=-1 '
                             'or0..32768; subprocess wrapper_returncode andexit_code=-255..255; '
                             'errno0..4095. Filedevice/inode unsigned0..2^64-1; pid/tid1..2^31-1; '
                             'uid/gid0..2^32-1. schema_version literalstring1; digests '
                             'lowercase64hex; UUIDscanonical4. Arrays and encodedbytecaps '
                             'independent, no floats/nonfinite/booleans-as-integers.',
                    'worker_ready': {'bound_bytes': 8192,
                                     'fields': ['schema_version',
                                                'role',
                                                'worker_id',
                                                'bootstrap_sha256',
                                                'runtime_sha256',
                                                'source_sha256',
                                                'stage',
                                                'namespaces',
                                                'uid',
                                                'gid',
                                                'groups',
                                                'task_ids',
                                                'descriptor_sha256',
                                                'boundary_checks'],
                                     'notes': 'worker self-report is corroborated by parent actual '
                                              'observation before any authority-consuming release; '
                                              'worker booleans alone never establish custody',
                                     'stage': ['sealed_waiting',
                                               'sealed_endpoint',
                                               'sealed_reviewer',
                                               'sealed_launcher',
                                               'sealed_broker',
                                               'sealed_parser',
                                               'sealed_admission']}},
 'elf_inventory': {'files': 64,
                   'path': '/home/sloth/Code/recon-cockpit/.secure-agent/pr102-review-20261021/s42c-static-runtime-inspection/inventory-v2.json',
                   'sha256': '19fc526df668821cad64ad3f2bbd210a4c2a3561003f9a69450a5d8041b7ddfa'},
 'entry_conventions': {'argv': ['/usr/bin/python3',
                                '-I',
                                '-S',
                                '/app/recon_cockpit/secure_agent/{fixed_role_worker}.py',
                                '{worker_uuid}',
                                '{bootstrap_sha256}'],
                       'bootstrap': 'One canonical<=32768-byte initial frame on '
                                    'inheritedstdinSEQPACKET; exact initial PER-ROLE rights '
                                    'transfer only, pertable below. Allpairsprecreated '
                                    'beforebrokerstartup. Payloadexec entryhas0/1/2only; worker '
                                    'checksbeforeimports, closesanyverifiedlibffibootstrapresidue, '
                                    'receivesexactrights once, thencheck_role_entry '
                                    'verifiescompletepostbootstrapinventory. No later '
                                    'SCM_RIGHTS/ancillaryaccepted. '
                                    'Childcomputesbootstrapdigestagainstargvcommitment; '
                                    'rolemanifest fromfixedsealedmount.',
                       'bwrap_info': 'Separate inherited info writeFD, closed afterPopen inparent; '
                                     'collect<=4096 exact JSONchildPID; parent owns readFD and '
                                     'closes it after observation. No infoFD reaches final worker '
                                     'inventory.',
                       'client_io_exception': 'After READY and one parent release, clientstdout '
                                              'contains raw Nmap/HTTP bytes and stderr raw '
                                              'diagnostics; remove exact READY bytes before '
                                              'applying shared8192/2048 capture cap. '
                                              'Waitingclientstdin receives only bounded '
                                              'launcherrelease projection, no approval/audit '
                                              'endpoint.',
                       'interpreter': '/usr/bin/python3',
                       'ordinary_io': 'stdinSEQPACKET bidirectionalRPC; stdout exactly one READY '
                                      'line prefix RECON_ENGAGEMENT_LIVE_READY_V1 plus canonical '
                                      'worker_ready JSON plus newline, then quiet; stderr '
                                      'bounded4096 startup diagnostics, failureclosed and '
                                      'neverecho arbitrary input.',
                       'package_files': ['/app/recon_cockpit/__init__.py',
                                         '/app/recon_cockpit/secure_agent/__init__.py'],
                       'package_source': 'Both use exact inert accepted secure_agent/__init__.py '
                                         'bytes',
                       'parser_io': 'READYstdout thenquiet; request/reply via '
                                    'inheritedstdinSEQPACKET, no raw output onstdout; '
                                    'response<=4096.',
                       'source_directory': '/app/recon_cockpit/secure_agent'},
 'fd_inventory': {'admission': ['stdio:3'],
                  'admission_max': 3,
                  'audit': ['stdio:3 (stdin is producer channel)',
                            'append_file:1',
                            'one_way_witness:1'],
                  'audit_max': 5,
                  'broker_max': 21,
                  'broker_phase_rule': 'One bootstrap/runtime FD may exist only before opening '
                                       'store/SQLite descriptors and must close first. Three '
                                       'writable memfds transferred only at initial bootstrap; '
                                       'host retains independently reopened O_RDONLY peers, broker '
                                       'sole writer until F_SEAL_WRITE|GROW|SHRINK|SEAL. Audit '
                                       'producer remains host-owned; broker only witness reader.',
                  'broker_proposed': ['stdio:3',
                                      'host_lifecycle:1',
                                      'submitter:2',
                                      'launcher_control:2',
                                      'endpoint_control:2',
                                      'review_witness:2',
                                      'audit_witness:1',
                                      'initial_export_memfd:1',
                                      'final_export_memfd:1',
                                      'transcript_memfd:1',
                                      'held_parent_directory:1',
                                      'held_store_directory:1',
                                      'sqlite_main:1',
                                      'transient_rollback_journal:1',
                                      'selector:1'],
                  'common': 'stdio0/1/2 explicitly typed; no implicit inherited extras. Startup '
                            'sealed memfds/infoFD closed before leaf READY/limit application.',
                  'endpoint': ['stdio:3',
                               'broker_control:1',
                               'launcher_arm:1',
                               'listener:1',
                               'accepted_tcp:1'],
                  'endpoint_max': 7,
                  'ephemeral_observation_fds': 'A scoped /proc/fd enumerator/readback FD may exist '
                                               'during observation and is closed before final '
                                               'steady inventory; record separately, do not hide '
                                               'arbitrary descriptors.',
                  'graphical': ['stdio:3',
                                'one_way_witness:1',
                                'exact_preopened_X11_socket:1',
                                'at most2 notifier wake descriptors created during pinned Tk '
                                'warmup, type pipe/eventfd and identities fixed before seal'],
                  'graphical_max': 7,
                  'graphical_note': 'Initial worker inventory rejects all unexpected FDs before '
                                    'Tk. Record exact post-warmup delta, including any notifier '
                                    'pipes/eventfd, then require unchanged identities. A spare '
                                    'anonymous FD is not accepted merely because total<=8.',
                  'headers': ['stdio:3', 'selected_ipv4_tcp:1'],
                  'headers_max': 4,
                  'launcher': ['stdio:3',
                               'broker_control:1',
                               'endpoint_arm:1',
                               'up_to_two_children: bounded stdin/stdout/stderr/info/pidfd/procdir '
                               'inventory',
                               'temporary sealed-role FDs<=128; closed after child Popen'],
                  'launcher_non_snapshot_max': 32,
                  'launcher_total_max': 160,
                  'nmap': 'stdio plus at most one selected IPv4 TCP socket and read-only '
                          'descriptors to exact manifest files; all authority/channel/namespace '
                          'descriptors absent; observed live fd count<=16, RLIMIT64',
                  'parser': ['stdio:3'],
                  'parser_max': 3,
                  'terminal': ['stdio:3', 'intentional_tty:1', 'one_way_witness:1'],
                  'terminal_max': 5,
                  'waiting_client': ['stdio:3'],
                  'waiting_client_max': 3},
 'frontend_mode_enum': ['terminal', 'graphical_v1'],
 'gui_resources': {'bytes': 17064478,
                   'files': 423,
                   'max_bytes': 33554432,
                   'max_files': 512,
                   'mode': 'fixedreadonlymounts+boundedbefore/afteridentity/hashinventory; '
                           'distinct from sealedimplementation/ELF files',
                   'path': '/home/sloth/Code/recon-cockpit/.secure-agent/pr102-review-20261021/s42c-static-runtime-inspection/gui-resources.json',
                   'sha256': '0f7a2d0ac5c139b83d5816714b263d902628b7a90b8023491c20f9eebcc89c07'},
 'http_grammar': {'headers_request_template': 'GET / HTTP/1.1\r\n'
                                              'Host: {validated_ipv4}:{validated_port}\r\n'
                                              'Connection: close\r\n'
                                              '\r\n',
                  'headers_response_basis': 'exact accepted '
                                            'configurable_lab_worker.header_response(): vulnerable '
                                            'HarborDesk portal response; response fixture '
                                            'independent of requested path, no request reflection',
                  'identify_connections': 'at most3, one or two initial scan/NULL empty-EOF/reset '
                                          'connections before exactly one fixed GET; GET must be '
                                          'connection2 or3 as accepted configurable fixture; no '
                                          'other payload/response.',
                  'identify_request_ascii': 'GET / HTTP/1.0\r\n\r\n',
                  'identify_response_ascii': 'HTTP/1.0 200 OK\r\n'
                                             'Server: nginx/1.26.0\r\n'
                                             'Content-Length: 2\r\n'
                                             'Connection: close\r\n'
                                             '\r\n'
                                             'OK',
                  'nmap_argv': ['/tool/nmap',
                                '--unprivileged',
                                '-sT',
                                '-sV',
                                '--version-intensity',
                                '1',
                                '-Pn',
                                '-n',
                                '-p',
                                '{validated_port}',
                                '--max-retries',
                                '0',
                                '--max-parallelism',
                                '1',
                                '--host-timeout',
                                '3s',
                                '--datadir',
                                '/tool/data',
                                '--no-stylesheet',
                                '-oX',
                                '-',
                                '{validated_ipv4}'],
                  'nmap_data': 'exact four accepted NMAP_SERVICE_SERVICES, NMAP_SERVICE_PROTOCOLS, '
                               'NMAP_SERVICE_PROBES and NMAP_SERVICE_NSE_SHIM byte constants from '
                               'network_tools_runtime.py; no probe/port/timing rewrite',
                  'path': '/',
                  'rules': ['one request per admitted connection; no pipeline/body/extra bytes '
                            'accepted',
                            'buffer entire exact expected request before response',
                            'recv bound never exceeds remaining fixed request budget',
                            'send bound never exceeds remaining fixed response budget',
                            'no over-cap sentinel read',
                            'strict cap exhaustion terminates; unread queued kernel bytes remain '
                            'unknown',
                            'Nmap malformed and extra traffic refuses without positive parsed '
                            'completion']},
 'implementation_authorized': False,
 'initial_rights_table': {'admission': {'count': 0, 'rights': []},
                          'audit': {'count': 2,
                                    'phase': 'unchanged accepted auditbootstrap grammar',
                                    'rights': ['append_file', 'audit_witness']},
                          'broker': {'count': 14,
                                     'phase': 'runtime_input closes beforeSQLite/store open; host '
                                              'onlyO_RDONLY memfdpeers; all other authority-owned '
                                              'fields match authorityBrokerBootstrap',
                                     'rights': ['host_lifecycle',
                                                'ingress0',
                                                'ingress1',
                                                'launcher0',
                                                'launcher1',
                                                'endpoint0',
                                                'endpoint1',
                                                'review_witness0',
                                                'review_witness1',
                                                'audit_witness',
                                                'initial_export_memfd',
                                                'final_export_memfd',
                                                'transcript_memfd',
                                                'runtime_input']},
                          'endpoint': {'count': 2, 'rights': ['broker_control', 'launcher_arm']},
                          'graphical': {'count': 1, 'rights': ['review_witness']},
                          'headers': {'count': 0, 'rights': []},
                          'launcher': {'count': 2, 'rights': ['broker_control', 'endpoint_arm']},
                          'nmap': {'count': 0, 'rights': []},
                          'parser': {'count': 0, 'rights': []},
                          'terminal': {'count': 2,
                                       'rights': ['intentional_tty', 'review_witness']}},
 'launcher_runtime_bundle': {'bytes_max': 2097152,
                             'destination': '/run/engagement-runtime-bundle.json',
                             'mode': 292,
                             'rules': ['Launcher-only sealed data mount under existing128 '
                                       'temporary snapshot files/128MiB cap; snapshot FD consumed '
                                       'and closed before worker entry.',
                                       'Launcher bounded-reads and validates this full bundle '
                                       'before confinement; SHA256 canonical bundle equals actual '
                                       'bootstrap.runtime_sha256, selected launcher role manifest '
                                       'equals mounted role manifest.',
                                       'Trusted parent independently rereads mounted full runtime '
                                       'bytes through pinned actual launcher process root and '
                                       'compares size/hash to expected canonical bundle.',
                                       'Other roles receive only their selected role manifests. No '
                                       'new steady descriptor, SCM transfer, executable, resource '
                                       'cap or child selection is introduced.'],
                             'seals': 15,
                             'snapshot_fds_added': 1,
                             'source': 'canonical(validate_runtime(full inspected bundle))',
                             'steady_fds_added': 0},
 'limits': {'bootstrap_fd_limit': 256,
            'bootstrap_non_snapshot_fds_max': 64,
            'bootstrap_snapshot_fds_max': 128,
            'bwrap_info_bytes': 4096,
            'control_packet_bytes': 4096,
            'control_poll_ms': 50,
            'owned_role_setup_seconds': 10,
            'parser_input_bytes': 16384,
            'parser_reply_bytes': 4096,
            'preflight_seconds': 15,
            'readiness_line_bytes': 8192,
            'role_packet_bytes': 32768,
            'shared_emergency_cleanup_seconds': 2,
            'snapshot_file_max_bytes': 16777216,
            'snapshot_manifest_max_bytes': 131072,
            'snapshot_max_files': 128,
            'snapshot_total_max_bytes': 134217728,
            'source_file_max_bytes': 262144,
            'source_manifest_max_bytes': 65536,
            'source_total_max_bytes': 8388608,
            'startup_poll_ms': 10,
            'watch_and_cleanup_ms': 6100,
            'watch_detection_ms': 4100,
            'watch_schedule_ms': 100},
 'mandatory_watch_witness': 'External v2 revoke commits just after observed watch; hold one actual '
                            'bounded synchronous phase; observe next fresh DB read/refusal or '
                            'failed read, actual endpoint stop and pinned payload/wrapper '
                            'reaping<=4100+2000ms. Record actual commit/phase/read/cancel/reap '
                            'monotonic timestamps; pure clock arithmetic or direct broker EOF is '
                            'insufficient.',
 'namespace_construction': ['Preallocate all role channel pairs before broker bootstrap; broker '
                            'creates SIDs in READY; bind exact full current ROE/scope/policy in '
                            'later role bootstrap.',
                            'Create endpoint with its own user/net/mnt/pid namespaces. Host starts '
                            'launcher by entering endpoint user/net first, then launcher creates '
                            'private user/mnt/pid while inheriting only endpoint net.',
                            'Launcher children inherit that net directly; each gets private '
                            'user/mnt/pid. Parser and admission additionally unshare net. No '
                            'post-seal sibling/ancestor setns is needed.',
                            'Network namespace FDs are host-startup-only; never retained in '
                            'client/parser/broker/reviewer. Launcher cannot create sockets; only '
                            'its fixed children use selected network.',
                            'Retain observer namespace/UID plus actual nested UID/GID map '
                            'composition to host nonzero UID. Do not mislabel an immediate-parent '
                            'map as direct host map. New workers use65534; bounded all65534 '
                            'supplementary groups retained, not silently assumed empty.'],
 'native_runtime': {'native_compiled_files': ['/tool/data/nmap-services',
                                              '/tool/data/nmap-protocols',
                                              '/tool/data/nmap-service-probes',
                                              '/tool/data/nse_main.lua'],
                    'nmap_elf_candidates': ['/usr/bin/nmap', '/usr/lib/nmap/nmap'],
                    'process_identity': 'before input/GO pin actual payload via infoFD->pidfd and '
                                        '/proc directory with validated integerPID, ancestry<=16, '
                                        'start ticks and liveness before/after; retain '
                                        'maps/namespace/UID/GID/caps/task/fd readback. Native '
                                        'observation requires exact executable+interpreter+mapped '
                                        'manifest libraries and same pinned waiting PID, no '
                                        'unknown executable mapping.',
                    'python_filesystem': 'Read-only distribution stdlib with lib-dynload replaced '
                                         'by an empty mount then only fixed role extension files; '
                                         'exact ELF interpreter/needed libraries and '
                                         'implementation sources sealed; no claim full '
                                         'stdlib/open-syscall trace.',
                    'role_extensions': {'broker_extra': ['_sqlite3'],
                                        'common': ['_ctypes',
                                                   '_hashlib',
                                                   '_hmac',
                                                   '_uuid',
                                                   '_queue',
                                                   'resource'],
                                        'graphical_extra': ['_tkinter'],
                                        'terminal_extra': ['termios']},
                    'role_specific_mounts': 'Only broker mounts explicit store directory; only '
                                            'graphical gets fixed Tcl/Tk/DejaVu/fontconfig '
                                            'resources and exact X socket+one selected cookie; '
                                            'only endpoint setup gets nft; only launcher gets '
                                            'fixed bwrap child builder. No Nmap/SSH/TLS executable '
                                            'in parser/endpoint/reviewer/broker.',
                    'seal': 'MFD_ALLOW_SEALING plus F_SEAL_WRITE|GROW|SHRINK|SEAL, inspect actual '
                            'content hash/size/inode and seal flags; no mutable bind fallback for '
                            'pinned files; close stage descriptors after mounts.',
                    'selected_inspected_elf': '/usr/lib/nmap/nmap',
                    'shell_wrapper_refused': True},
 'output_and_evidence': {'capture': 'aggregate both pipes concurrently under original cap; if '
                                    'truncation occurs refuse usefulness and retain exact captured '
                                    'bytes+truncation marker; no unlimited diagnostics',
                         'headers_stdout': 'exact raw HTTP response; worker JSON/base64 frame '
                                           'overhead is separately bounded protocol data, never '
                                           'folded into raw HTTP budget',
                         'headers_stdout_plus_stderr_max': 2048,
                         'identify_stdout_plus_stderr_max': 8192,
                         'live_result_meter': 'compact final meter_summary only; full raw/events '
                                              'belong to independently received direct endpoint '
                                              'transcript and are bound by transcript_sha256. '
                                              'Never nest full32KiB transcript inside32KiB result.',
                         'meter_before_effect_rule': 'Before each nonterminal I/O, reserve room '
                                                     'for its worst-case retained bytes/event '
                                                     'plus4 terminal events and2048 encoded bytes. '
                                                     'Refuse/cancel before an event or payload '
                                                     'cannot be retained. Exact encoded<=32768 is '
                                                     'independently checked; no silent drop.',
                         'meter_encoded_bytes_max': 32768,
                         'meter_event_exact_fields': ['sequence',
                                                      'connection',
                                                      'kind',
                                                      'monotonic_ns',
                                                      'requested_bytes',
                                                      'actual_bytes',
                                                      'remaining_before',
                                                      'remaining_after',
                                                      'reason'],
                         'meter_event_kind': ['arm',
                                              'accept',
                                              'recv',
                                              'send',
                                              'eof',
                                              'cancel',
                                              'cap',
                                              'close'],
                         'meter_event_reason': 'null or one closed stop_reason; no arbitrary '
                                               'exception text',
                         'meter_events_max': 64,
                         'meter_exact_fields': ['schema_version',
                                                'endpoint_id',
                                                'session_id',
                                                'dispatch_id',
                                                'envelope_sha256',
                                                'go_sha256',
                                                'arm_sequence',
                                                'slot',
                                                'accepted_connections',
                                                'received_request_bytes',
                                                'sent_response_bytes',
                                                'request_sha256',
                                                'response_sha256',
                                                'request_base64',
                                                'response_base64',
                                                'reason',
                                                'delivery_known',
                                                'armed_at_ns',
                                                'finished_at_ns',
                                                'events'],
                         'meter_nulls': 'No acknowledged final settlement means final '
                                        'counters/finished_at/complete delivery are null/unknown; '
                                        'retained last ack is separate, never promoted to '
                                        'finalzero.',
                         'meter_raw_payload_caps': {'http_headers': {'combined': 2304,
                                                                     'request': 256,
                                                                     'response': 2048},
                                                    'http_identify': {'combined': 8192,
                                                                      'request': 4096,
                                                                      'response': 4096}},
                         'meter_summary_exact_fields': ['schema_version',
                                                        'endpoint_id',
                                                        'session_id',
                                                        'dispatch_id',
                                                        'envelope_sha256',
                                                        'go_sha256',
                                                        'arm_sequence',
                                                        'slot',
                                                        'accepted_connections',
                                                        'received_request_bytes',
                                                        'sent_response_bytes',
                                                        'request_sha256',
                                                        'response_sha256',
                                                        'reason',
                                                        'delivery_known',
                                                        'armed_at_ns',
                                                        'finished_at_ns',
                                                        'transcript_sha256'],
                         'meter_terminal_bytes_reserve': 2048,
                         'meter_terminal_event_reserve': 4,
                         'parser_receipt_exact_fields': ['schema_version',
                                                         'slot',
                                                         'input_sha256',
                                                         'output_sha256',
                                                         'input_bytes',
                                                         'output_bytes',
                                                         'elapsed_ms',
                                                         'readiness',
                                                         'cleanup'],
                         'parser_receipt_readiness': 'readiness field is SHA256 of '
                                                     'separatelyretained completeparser '
                                                     'role_readiness, notanother16KiBnestedobject; '
                                                     'cleanupfield is thatoneparser cleanup '
                                                     'object.',
                         'parser_reply_exact_fields': ['schema_version', 'slot', 'parsed'],
                         'parser_request_exact_fields': ['schema_version',
                                                         'slot',
                                                         'scope',
                                                         'raw_base64',
                                                         'stderr_base64',
                                                         'truncated'],
                         'parser_result_schema': 'unchanged configurable_parser result for NMAP or '
                                                 'HEADERS only; no SSH endpoint/tool accepted',
                         'parser_timing': 'successful elapsed includes cleanup and<=2000ms; '
                                          'original action/inspection control checked after '
                                          'cleanup and validation; emergency reaping may consume2s '
                                          'after refusal but cannot produce late success.',
                         'raw_dispatches_max': 4,
                         'raw_files': ['client-{dispatch_id}.stdout.bin',
                                       'client-{dispatch_id}.stderr.bin'],
                         'reason_enum': ['complete',
                                         'cancelled',
                                         'timeout',
                                         'window_closed',
                                         'clock_invalid',
                                         'revoked',
                                         'revision_changed',
                                         'budget_denied',
                                         'connection_limit',
                                         'request_limit',
                                         'response_limit',
                                         'output_limit',
                                         'transcript_limit',
                                         'malformed_request',
                                         'peer_eof',
                                         'channel_eof',
                                         'native_failed',
                                         'invalid_observation',
                                         'cleanup_failed',
                                         'unresolved'],
                         'result_constraints': 'exit_code null if not observed else '
                                               'integer-255..255; stop_reason null only success; '
                                               'success requires exit0, no truncation, complete '
                                               'settled known-delivery meter, valid matching '
                                               'parser, full cleanup and original deadline live. '
                                               'Failure parsed/parser_receipt null unless a '
                                               'complete valid parse is retained explicitly as '
                                               'non-authoritative diagnostic; no eligible '
                                               'predecessor from a failure.',
                         'result_exact_fields': ['schema_version',
                                                 'dispatch_id',
                                                 'envelope_sha256',
                                                 'runtime_sha256',
                                                 'slot',
                                                 'status',
                                                 'exit_code',
                                                 'stop_reason',
                                                 'stdout_sha256',
                                                 'stderr_sha256',
                                                 'stdout_bytes',
                                                 'stderr_bytes',
                                                 'truncated',
                                                 'readiness',
                                                 'meter',
                                                 'parsed',
                                                 'parser_receipt',
                                                 'cleanup'],
                         'result_readiness': 'Closed summary {client_sha256,native_sha256}; '
                                             'native_sha256 null forheaders or '
                                             'missingnativeobservation. '
                                             'Fullrole_readiness/native_readiness '
                                             'separatelyretained and verifiedbyactualparent; '
                                             'immutablecontextrequiresmatchingobjects. This '
                                             'prevents oversizednestedparentobjects in32KiB '
                                             'result.',
                         'result_status_enum': ['succeeded',
                                                'failed',
                                                'cancelled',
                                                'timeout',
                                                'output_limit',
                                                'unresolved']},
 'owned_meter_connection_fixture': {'allowed_evidence_class': 'owned_gate',
                                    'baseline_steady_descriptors': 6,
                                    'cases': {'S42C-X45': {'derived_transient_peak': 12,
                                                           'preconnected_peers': 4,
                                                           'slot': 'http_identify',
                                                           'steady_descriptors': 11,
                                                           'variant': 'meter_connection_cap_identify'},
                                              'S42C-X46': {'derived_transient_peak': 10,
                                                           'preconnected_peers': 2,
                                                           'slot': 'http_headers',
                                                           'steady_descriptors': 9,
                                                           'variant': 'meter_connection_cap_headers'}},
                                    'creation_phase': 'After unchanged initial '
                                                      'bootstrap/entry-rights validation and '
                                                      'production network setup, before role '
                                                      'sealing. All listener/peer sockets are '
                                                      'created and connected before sealing. No '
                                                      'post-seal new socket permission.',
                                    'fixture_listener_count': 1,
                                    'fixture_transport': 'AF_UNIX/SOCK_STREAM abstract address in '
                                                         'the endpoint private network namespace; '
                                                         'fixed owned primitive traffic only',
                                    'live_validation': 'Only the fixed per-case sealed endpoint '
                                                       'and runtime source variants select the '
                                                       'exception. Worker steady inventory and '
                                                       'trusted parent readback retain every '
                                                       'actual descriptor and exact '
                                                       'source/runtime/role commitments. Baseline '
                                                       'runtime endpoint_max remains 7; no '
                                                       'ordinary caller-supplied fd_max, skip flag '
                                                       'or additional inherited right.',
                                    'ordinary_endpoint_max': 7,
                                    'other_meter_cases': 'The other nine byte/partial/clock '
                                                         'primitive cases use the already '
                                                         'inherited stdin socket and add zero '
                                                         'descriptors. All primitive fixture '
                                                         'traffic is labelled injected, cannot '
                                                         'establish native HTTP usefulness, and is '
                                                         'derived from actual saved metering '
                                                         'events.',
                                    'peak_evidence': 'READY/readback establishes the actual steady '
                                                     'inventory of 11/9. The transient 12/10 is a '
                                                     'source-derived upper bound with one accepted '
                                                     'stream at a time, not a measured READY '
                                                     'count. A measured peak claim additionally '
                                                     'requires actual peak-time complete FD '
                                                     'inventory retained as a bounded private '
                                                     'artifact with its exact hash in the native '
                                                     'validation receipt; no fabricated canonical '
                                                     'field or omitted FD.',
                                    'retained_validation': {'entrypoint': 'private '
                                                                          '_retained_fixture_validation(loaded) '
                                                                          'after structural member '
                                                                          'loading',
                                                            'fail_closed': 'Unknown case/role, '
                                                                           'missing or conflicting '
                                                                           'source/configuration '
                                                                           'binding, ordinary '
                                                                           'production evidence, '
                                                                           'missing/extra '
                                                                           'descriptors or absent '
                                                                           'proof cannot select '
                                                                           'the exception. The '
                                                                           'private '
                                                                           'retained-validation '
                                                                           'allowance changes only '
                                                                           'pure descriptor '
                                                                           'validation for that '
                                                                           'exact endpoint '
                                                                           'fixture; all other '
                                                                           'role, entry, '
                                                                           'namespace, source, '
                                                                           'process, deadline, '
                                                                           'cleanup and meter '
                                                                           'checks remain '
                                                                           'required.',
                                                            'required_binding': ['manifest '
                                                                                 'evidence_class '
                                                                                 'is owned_gate '
                                                                                 'and exact '
                                                                                 'case_id X45 or '
                                                                                 'X46',
                                                                                 'configuration '
                                                                                 'equals the fixed '
                                                                                 'case variant and '
                                                                                 'role endpoint '
                                                                                 'with its '
                                                                                 'canonical '
                                                                                 'configuration '
                                                                                 'SHA256',
                                                                                 'both sealed '
                                                                                 'endpoint and '
                                                                                 'runtime source '
                                                                                 'SHA256 '
                                                                                 'commitments '
                                                                                 'match runtime '
                                                                                 'source inventory '
                                                                                 'and selected '
                                                                                 'endpoint role '
                                                                                 'closure',
                                                                                 'all actual '
                                                                                 'sealed fixture '
                                                                                 'descriptor rows '
                                                                                 'are retained, '
                                                                                 'named and '
                                                                                 'compared between '
                                                                                 'worker hash and '
                                                                                 'actual parent '
                                                                                 'readback; exact '
                                                                                 '11 or 9 steady '
                                                                                 'descriptors',
                                                                                 'case proof, '
                                                                                 'control '
                                                                                 'readiness and '
                                                                                 'actual meter '
                                                                                 'observation '
                                                                                 'resolve to the '
                                                                                 'same runtime and '
                                                                                 'fixture '
                                                                                 'configuration'],
                                                            'scope': 'Bounded context manager '
                                                                     'around context, '
                                                                     'authority/transcript, parser '
                                                                     'replay and report '
                                                                     'validation; equivalent '
                                                                     'writer validation; reset on '
                                                                     'success and every failure. '
                                                                     'No live authority is '
                                                                     'returned.'},
                                    'role': 'endpoint',
                                    'simultaneous_accepted_streams_max': 1,
                                    'steady_descriptor_purposes': {'0': 'stdin',
                                                                   '1': 'stdout',
                                                                   '10': 'fixture_peer_4 (X45 '
                                                                         'only)',
                                                                   '2': 'stderr',
                                                                   '3': 'broker_control',
                                                                   '4': 'launcher_arm',
                                                                   '5': 'observed production '
                                                                        'listener',
                                                                   '6': 'fixture_listener',
                                                                   '7': 'fixture_peer_1',
                                                                   '8': 'fixture_peer_2',
                                                                   '9': 'fixture_peer_3 (X45 '
                                                                        'only)'},
                                    'unchanged': {'all_case_ids': 288,
                                                  'authority_targets_deadlines_and_byte_caps': True,
                                                  'endpoint_rlimit_nofile': 64,
                                                  'initial_rights': True,
                                                  'native_case_ids': 113,
                                                  'new_inherited_descriptors': 0,
                                                  'new_processes': 0,
                                                  'parent_readback_descriptors': 32,
                                                  'production_endpoint_max': 7}},
 'portable_inventory': {'path': '/home/sloth/Code/recon-cockpit/.secure-agent/pr102-review-20261021/s42c-runtime-portable-cases.json',
                        'sha256': 'cd249b14cf2d8986f4f210d2a5d8d118a9ca23a53d6f83e7a06f98a1ea9b319e'},
 'process_graph': {'broker_instances_per_bundle_max': 2,
                   'client_dispatches_per_bundle_max': 4,
                   'cumulative_basis': 'Conservative upper '
                                       'bound20payload+21bwrap/reaper+4nft+2nsenter image-start '
                                       'entries perbroker. Execchain stages sharingPID/start '
                                       'collapse to oneactualprocessidentity, '
                                       'neverinflateobserveduniqueprocesscount. Two brokers '
                                       'strictlysequential, fullyreapedbeforefreshstart; '
                                       'peak26/28notdoubled.',
                   'cumulative_process_identities_per_broker_max': 47,
                   'cumulative_process_identities_per_bundle_max': 94,
                   'cumulative_rule': 'rawclientpairs4/parserruns4/cost/outputcaps applyacross '
                                      'bothinstances. Per-callcleanup.processes<=26; '
                                      'aggregateevidence mayretain<=94 distinctPID/start '
                                      'identities plusphaseobservations referencingthem. No '
                                      'hiddenautomaticrestart or thirdbroker.',
                   'host_supervisor_note': 'outside isolated descendant sum; external X '
                                           'server/compositor and scripted test drivers separately '
                                           'disclosed, not silently included',
                   'host_supervisor_processes': 1,
                   'invocation_basis': 'eight persistent roles + four actions times '
                                       'admission/client/parser; host nsenter only to create two '
                                       'launchers in endpoint nets; nft check+install per endpoint',
                   'limits_note': 'Observed bounded role graph plus explicit builder inventory; no '
                                  'claim to arbitrary process/exec syscall tracing. No retry on '
                                  'failed spawn/exec/image observation.',
                   'new_role_bwrap_flags': ['--as-pid-1', '--die-with-parent'],
                   'owned_descendant_processes_max': 26,
                   'owned_descendant_tasks_max': 28,
                   'payloads_max': 12,
                   'persistent_payloads': {'audit': 1,
                                           'broker': 1,
                                           'endpoint': 2,
                                           'launcher': 2,
                                           'reviewer': 2},
                   'serialized_setup_helpers_max': 1,
                   'sessions_max': 2,
                   'simultaneous_brokers_max': 1,
                   'successful_two_session_invocations_max': {'bwrap': 20, 'nft': 4, 'nsenter': 2},
                   'transient_payloads': {'nested_admission_until_actual_GO_redemption': 2,
                                          'waiting_or_active_client_or_parser': 2},
                   'wrapper_basis': 'one bwrap supervisor per new-role payload; unchanged audit '
                                    'may retain outer supervisor plus PID1 reaper',
                   'wrapper_processes_max': 13},
 'remaining_coordination': ['Authority/evidence public integration mustretain exactsigned '
                            'numericexceptions, initial PER-ROLE transfer table '
                            'andclosednmap/headers roles; no furtherAPI decision intended.',
                            'RootGUI payloadfields/authoritybrokerpayload '
                            'authoritativeclosedobjects confirmed; this '
                            'proposalreferencesauthorityBrokerBootstrap explicitly.',
                            'No code/tests/nativeexecution authorizeduntil reviewed '
                            'contractcommit.'],
 'resources': {'admission': {'as_mib': 256,
                             'cpu_seconds': 7,
                             'fsize_bytes': 0,
                             'lifetime_rule': 'Originalaction-clipped lifetime<=30s, also clipped '
                                              'tooriginalsession/brokerstop; '
                                              'actualissue/redemptionworkphase<=2s '
                                              'underthatsameoriginalbudget, CPU7total. '
                                              'Alivealongsidewaitingclient throughconsumeandGO; '
                                              'actualone-usepermit '
                                              'redeemedthenworkerreapedbeforeclientexec/ARM; '
                                              'CANCEL/EOF whileidle checked<=50ms; '
                                              'nofreshdeadlineonredemption.',
                             'nofile': 64,
                             'nproc': 1,
                             'phase_seconds': 2,
                             'tasks': 1,
                             'wall_seconds': 30},
               'audit': {'as_mib': 256,
                         'cpu_seconds': 7,
                         'fsize_bytes': 1048576,
                         'implementation': 'unchanged accepted audit_worker boundary',
                         'nofile': 64,
                         'nproc': 1,
                         'tasks': 1,
                         'wall_seconds': 120},
               'broker': {'as_mib': 256,
                          'cpu_seconds': 120,
                          'fsize_bytes': 16777216,
                          'nofile': 64,
                          'nproc': 1,
                          'tasks': 1,
                          'wall_seconds': 120},
               'endpoint': {'as_mib': 256,
                            'cpu_seconds': 5,
                            'fsize_bytes': 0,
                            'nofile': 64,
                            'nproc': 1,
                            'tasks': 1,
                            'wall_seconds': 60},
               'graphical': {'as_mib': 256,
                             'cpu_seconds': 7,
                             'fsize_bytes': 1048576,
                             'nofile': 64,
                             'nproc': 1,
                             'tasks_max': 2,
                             'tasks_note': 'warm up Tk before seal; retain actual main/notifier '
                                           'TIDs; exact set unchanged after TSYNC no-new-task '
                                           'filter',
                             'wall_seconds': 60},
               'headers': {'as_mib': 256,
                           'cpu_seconds': 5,
                           'fsize_bytes': 0,
                           'nofile': 64,
                           'nproc': 1,
                           'output_bytes': 2048,
                           'tasks': 1,
                           'wall_seconds': 1},
               'launcher': {'as_mib': 256,
                            'children': 'at most waitingclient+admission untilGO; actualpermit '
                                        'redeemedthenadmissionreapedbeforeclientexec; '
                                        'afterclientreaped atmostoneparser',
                            'cpu_seconds': 15,
                            'fsize_bytes': 0,
                            'nofile': 256,
                            'nproc': 8,
                            'tasks': 1,
                            'wall_seconds': 60},
               'nmap': {'as_mib': 256,
                        'cpu_seconds': 5,
                        'fsize_bytes': 0,
                        'nofile': 64,
                        'nproc': 1,
                        'output_bytes': 8192,
                        'tasks': 1,
                        'wall_seconds': 5},
               'parser': {'as_mib': 128,
                          'cpu_seconds': 2,
                          'fsize_bytes': 0,
                          'nofile': 32,
                          'nproc': 1,
                          'output_bytes': 4096,
                          'tasks': 1,
                          'wall_seconds': 2},
               'setup_helper': {'as_mib': 256,
                                'cpu_seconds': 2,
                                'fsize_bytes': 0,
                                'nofile': 64,
                                'nproc': 1,
                                'program': 'fixed nft check/install only; serialized',
                                'tasks': 1,
                                'wall_seconds': 2},
               'terminal': {'as_mib': 256,
                            'cpu_seconds': 7,
                            'fsize_bytes': 1048576,
                            'nofile': 64,
                            'nproc': 1,
                            'tasks': 1,
                            'wall_seconds': 60}},
 'role_boundary_proofs': {'case_id': 'one exact X01..X59 mappedcase; observation_sha256 references '
                                     'thekind-specific actualkernel/file/processobservation. '
                                     'Forstartuprefusal no completeREADYis invented; retain '
                                     'actualchangedsealedFD/sourceinput '
                                     'andchildrefusal/pairedcontrol, explicitlynonuseful.',
                          'checks': 'Exact one-key map {<fixedcasevariant>:boolean}. Booleantrue '
                                    'is independently derived fromthatcase required_proof plus '
                                    'closedkindrawobservations, '
                                    'parentreadiness/custody/pairedcontrol andstop/cleanup '
                                    'predicates. A suppliedtrue without thoseinputs neverpasses. '
                                    'Machinecase.required_checks must containthatexactvariant; no '
                                    'inventedstrings afterpin.',
                          'common_fields': ['schema_version',
                                            'case_id',
                                            'role',
                                            'kind',
                                            'runtime_sha256',
                                            'source_sha256',
                                            'observation_sha256',
                                            'control_observation_sha256',
                                            'started_at_ns',
                                            'finished_at_ns',
                                            'checks'],
                          'instrumentation_schema': {'behavior': 'faultvalues andclocks compiled '
                                                                 'into '
                                                                 'sealedtestsource/nativebytes '
                                                                 'andcommitted inexecutionruntime; '
                                                                 'caller dictionary cannot '
                                                                 'addtimings/addresses/argv/commands',
                                                     'case_id': 'exactdeclared X/N case ID',
                                                     'fields': ['case_id', 'variant', 'role'],
                                                     'role': 'declaredtestrolelabel; maps '
                                                             'toclosedruntime role '
                                                             'usingfixedcasepredicate',
                                                     'variant': 'exactmachinecasevariant'},
                          'kinds': {'clock_boundary': {'constraints': 'sealedtrustedworker '
                                                                      'clockstimulus '
                                                                      'withsynchronizedtestroles; '
                                                                      'nohostclockchange/nocallerclock; '
                                                                      'actualsyscall '
                                                                      'boundaryobserved',
                                                       'fields': ['stimulus',
                                                                  'clock_source_sha256',
                                                                  'triggered_at_ns',
                                                                  'meter_transcript_sha256',
                                                                  'accepted_before',
                                                                  'accepted_after',
                                                                  'sent_before',
                                                                  'sent_after',
                                                                  'refused'],
                                                       'stimulus': ['forward_before_recv',
                                                                    'forward_before_send',
                                                                    'deadline_after_partial']},
                                    'creation_denial': {'constraints': 'realdeniedsyscall '
                                                                       'andunchangedobservedtaskset; '
                                                                       'role-specific '
                                                                       'no-newprocess/namespace '
                                                                       'claim',
                                                        'fields': ['operation',
                                                                   'flags',
                                                                   'return_value',
                                                                   'errno',
                                                                   'tasks_before',
                                                                   'tasks_after'],
                                                        'operation': ['fork',
                                                                      'clone',
                                                                      'clone3',
                                                                      'unshare',
                                                                      'setns',
                                                                      'execve']},
                                    'descriptor_custody': {'changed_descriptor': 'exactdescriptor '
                                                                                 'schema; '
                                                                                 'missingdescriptor '
                                                                                 'retains '
                                                                                 'expectedbounddescriptor, '
                                                                                 'notfabricatedactualentry',
                                                           'fields': ['phase',
                                                                      'expected_inventory_sha256',
                                                                      'actual_inventory_sha256',
                                                                      'changed_descriptor',
                                                                      'refused']},
                                    'image_identity': {'fields': ['expected_image_sha256',
                                                                  'observed_image_sha256',
                                                                  'waiting_observation_sha256',
                                                                  'native_observation_sha256',
                                                                  'arm_emitted',
                                                                  'refused'],
                                                       'nulls': 'nativeobservation/observedhash '
                                                                'null ifmissing; '
                                                                'actualsamepayloadobservationrequired '
                                                                'forpositivecontrol'},
                                    'lifecycle': {'constraints': 'actualEOF/process '
                                                                 'event+pidfdHUP/wrapperwaitreceipt; '
                                                                 'lastack notfinalzero ifmissing',
                                                  'fields': ['origin',
                                                             'triggered_at_ns',
                                                             'cleanup_sha256',
                                                             'meter_transcript_sha256',
                                                             'last_ack_sha256',
                                                             'cleanup_finished_at_ns'],
                                                  'origin': ['broker_eof',
                                                             'endpoint_eof',
                                                             'launcher_eof',
                                                             'payload_and_wrapper_cleanup']},
                                    'meter_boundary': {'constraints': 'actualisolatedsocketpeer '
                                                                      'andendpoint '
                                                                      'syscallreturn/meter stream; '
                                                                      'instrumentedprimitivecapbytesexplicitly '
                                                                      'notvalidusefulHTTP '
                                                                      'daemonoutput',
                                                       'fields': ['slot',
                                                                  'metric',
                                                                  'stimulus_bytes',
                                                                  'meter_transcript_sha256',
                                                                  'input_sha256',
                                                                  'output_sha256',
                                                                  'delivery_known',
                                                                  'refused'],
                                                       'metric': ['connections',
                                                                  'request',
                                                                  'response',
                                                                  'partial_request',
                                                                  'partial_response']},
                                    'parser_absence': {'constraints': 'fixedprobeonly '
                                                                      'withinisolatedparser; '
                                                                      'parentidentity+exactFDreceipt '
                                                                      'required',
                                                       'fields': ['network_return',
                                                                  'network_errno',
                                                                  'filesystem_return',
                                                                  'filesystem_errno',
                                                                  'process_return',
                                                                  'process_errno',
                                                                  'authority_fds_absent']},
                                    'pin_mutation': {'fields': ['destination',
                                                                'before_sha256',
                                                                'after_sha256',
                                                                'expected_seals',
                                                                'observed_seals',
                                                                'rejected_stage',
                                                                'ready_emitted',
                                                                'arm_emitted'],
                                                     'stage': ['source_snapshot',
                                                               'native_snapshot',
                                                               'role_manifest',
                                                               'worker_entry',
                                                               'parent_image']},
                                    'socket_denial': {'constraints': 'AF_INET=2/TCPstream1/protocol0or6; '
                                                                     'fixeddeclared/forbiddenwitnessIPport; '
                                                                     'MSG_FASTOPENflags '
                                                                     'includes0x20000000; '
                                                                     'actualEPERM '
                                                                     'requiredforseccompcases, no '
                                                                     'hostoutboundaddress',
                                                      'fields': ['operation',
                                                                 'family',
                                                                 'socket_type',
                                                                 'protocol',
                                                                 'target',
                                                                 'port',
                                                                 'flags',
                                                                 'return_value',
                                                                 'errno',
                                                                 'paired_control_connected',
                                                                 'listener_accepts',
                                                                 'listener_payload_bytes'],
                                                      'operation': ['connect',
                                                                    'sendto',
                                                                    'sendmsg',
                                                                    'sendmmsg']}},
                          'required_checks_by_variant': {'actual_payload_and_wrapper_reaped': ['actual_payload_and_wrapper_reaped'],
                                                         'creation_denied_broker': ['creation_denied_broker'],
                                                         'creation_denied_client': ['creation_denied_client'],
                                                         'creation_denied_endpoint': ['creation_denied_endpoint'],
                                                         'creation_denied_graphical': ['creation_denied_graphical'],
                                                         'creation_denied_parser': ['creation_denied_parser'],
                                                         'creation_denied_terminal': ['creation_denied_terminal'],
                                                         'endpoint_clock_forward_before_recv': ['endpoint_clock_forward_before_recv'],
                                                         'endpoint_clock_forward_before_send': ['endpoint_clock_forward_before_send'],
                                                         'endpoint_deadline_before_send_after_partial': ['endpoint_deadline_before_send_after_partial'],
                                                         'endpoint_denies_connect': ['endpoint_denies_connect'],
                                                         'endpoint_denies_fastopen_sendmmsg': ['endpoint_denies_fastopen_sendmmsg'],
                                                         'endpoint_denies_fastopen_sendmsg': ['endpoint_denies_fastopen_sendmsg'],
                                                         'endpoint_denies_fastopen_sendto': ['endpoint_denies_fastopen_sendto'],
                                                         'forbidden_destination_ssh_endpoint': ['forbidden_destination_ssh_endpoint'],
                                                         'forbidden_destination_wrong_port': ['forbidden_destination_wrong_port'],
                                                         'forbidden_destination_wrong_target': ['forbidden_destination_wrong_target'],
                                                         'meter_connection_cap_headers': ['meter_connection_cap_headers'],
                                                         'meter_connection_cap_identify': ['meter_connection_cap_identify'],
                                                         'meter_partial_request': ['meter_partial_request'],
                                                         'meter_partial_response': ['meter_partial_response'],
                                                         'meter_request_cap_headers': ['meter_request_cap_headers'],
                                                         'meter_request_cap_identify': ['meter_request_cap_identify'],
                                                         'meter_response_cap_headers': ['meter_response_cap_headers'],
                                                         'meter_response_cap_identify': ['meter_response_cap_identify'],
                                                         'missing_descriptor_broker': ['missing_descriptor_broker'],
                                                         'missing_descriptor_endpoint': ['missing_descriptor_endpoint'],
                                                         'missing_descriptor_graphical': ['missing_descriptor_graphical'],
                                                         'missing_descriptor_launcher': ['missing_descriptor_launcher'],
                                                         'missing_descriptor_terminal': ['missing_descriptor_terminal'],
                                                         'native_image_observation_missing_no_ARM': ['native_image_observation_missing_no_ARM'],
                                                         'parent_observed_identity_endpoint_mismatch': ['parent_observed_identity_endpoint_mismatch'],
                                                         'parent_observed_identity_nmap_mismatch': ['parent_observed_identity_nmap_mismatch'],
                                                         'parent_observed_identity_parser_mismatch': ['parent_observed_identity_parser_mismatch'],
                                                         'parent_observed_identity_waiting_python_mismatch': ['parent_observed_identity_waiting_python_mismatch'],
                                                         'parser_network_filesystem_authority_absent': ['parser_network_filesystem_authority_absent'],
                                                         'role_EOF_broker': ['role_EOF_broker'],
                                                         'role_EOF_endpoint': ['role_EOF_endpoint'],
                                                         'role_EOF_launcher': ['role_EOF_launcher'],
                                                         'role_manifest_client_to_parser': ['role_manifest_client_to_parser'],
                                                         'role_manifest_endpoint_to_broker': ['role_manifest_endpoint_to_broker'],
                                                         'sealed_broker_sqlite_library_changed': ['sealed_broker_sqlite_library_changed'],
                                                         'sealed_graphical_tk_library_changed': ['sealed_graphical_tk_library_changed'],
                                                         'sealed_nmap_executable_changed': ['sealed_nmap_executable_changed'],
                                                         'sealed_nmap_library_changed': ['sealed_nmap_library_changed'],
                                                         'sealed_source_broker_changed': ['sealed_source_broker_changed'],
                                                         'sealed_source_client_changed': ['sealed_source_client_changed'],
                                                         'sealed_source_endpoint_changed': ['sealed_source_endpoint_changed'],
                                                         'sealed_source_graphical_changed': ['sealed_source_graphical_changed'],
                                                         'sealed_source_launcher_changed': ['sealed_source_launcher_changed'],
                                                         'sealed_source_parser_changed': ['sealed_source_parser_changed'],
                                                         'sealed_source_terminal_changed': ['sealed_source_terminal_changed'],
                                                         'unexpected_descriptor_broker': ['unexpected_descriptor_broker'],
                                                         'unexpected_descriptor_client': ['unexpected_descriptor_client'],
                                                         'unexpected_descriptor_endpoint': ['unexpected_descriptor_endpoint'],
                                                         'unexpected_descriptor_graphical': ['unexpected_descriptor_graphical'],
                                                         'unexpected_descriptor_launcher': ['unexpected_descriptor_launcher'],
                                                         'unexpected_descriptor_parser': ['unexpected_descriptor_parser'],
                                                         'unexpected_descriptor_terminal': ['unexpected_descriptor_terminal']}},
 'role_discrimination': {'accepted_observer_only_role': 'audit',
                         'case_role_labels': 'client/waiting_python/all are descriptive testlabels '
                                             'only, never runtime selector; testclient label '
                                             'selects exactnmap orheaders role '
                                             'fromsealedcasevariant',
                         'entrypoint_module_by_role': {'admission': 'engagement_live_admission_worker',
                                                       'broker': 'engagement_live_broker_worker',
                                                       'endpoint': 'engagement_live_endpoint_worker',
                                                       'graphical': 'engagement_live_approval_worker',
                                                       'headers': 'engagement_live_client_worker',
                                                       'launcher': 'engagement_live_launcher_worker',
                                                       'nmap': 'engagement_live_client_worker',
                                                       'parser': 'engagement_live_parser_worker',
                                                       'terminal': 'engagement_live_approval_worker'},
                         'graphical_frontend_value': 'graphical_v1',
                         'new_bootstrap_and_readiness_roles': ['broker',
                                                               'terminal',
                                                               'graphical',
                                                               'launcher',
                                                               'endpoint',
                                                               'nmap',
                                                               'headers',
                                                               'parser',
                                                               'admission']},
 'runtime_digest': {'algorithm': 'SHA256',
                    'domain_prefix_hex': '',
                    'evidence_wrapper_fields': ['schema_version', 'runtime', 'instrumentation'],
                    'excluded': ['actualprocessPID/FD/clockobservations',
                                 'diagnosticinstrumentationlabels',
                                 'runtime.jsonwrapper'],
                    'included': 'closed execution bundle contains '
                                'profile/version/fixedpaths/native+sourcehashes/rolepartitions',
                    'input': 'canonical(validate_runtime(execution_bundle))',
                    'instrumentation_binding': 'Changedworker/nativebehavior must be in '
                                               'sealedsource/nativepins insideexecutionbundle; '
                                               'unbound metadata configuration never selects '
                                               'liveclock/native behavior.',
                    'runtime_file_sha256': 'independent fullfileSHA in evidence members map; never '
                                           'confused with execution runtime_sha256'},
 'runtime_manifest_schema': {'builtin_modules': 'sorted exact observed '
                                                'distributionPythonbuiltinlist, finite count<=128; '
                                                'requiredimports must be present '
                                                'eitherfixedbuiltins orroleextensionallowlist, no '
                                                'guessed portableextensionlayout',
                             'bundle_fields': ['schema_version',
                                               'profile',
                                               'platform',
                                               'python',
                                               'stdlib',
                                               'sources',
                                               'roles',
                                               'helpers',
                                               'compiled'],
                             'compiled_schema': {'bytes': 'first4 '
                                                          'exactacceptednetwork_tools_runtime '
                                                          'constants; graphical_fontconfig exact '
                                                          'accepted '
                                                          'graphical_approval_isolation.FONT_CONFIG '
                                                          'bytes mounted at '
                                                          'graphical_approval_protocol.FONTCONFIG_PATH '
                                                          '(/run/reviewer-fonts.conf); no '
                                                          'callerXML. Copyconstant '
                                                          'intoadditivebuilder or read '
                                                          'acceptedhostconstant '
                                                          'withoutmountingitsisolationmoduleinreviewer.',
                                                 'count': 5,
                                                 'destinations': ['/tool/data/nmap-services',
                                                                  '/tool/data/nmap-protocols',
                                                                  '/tool/data/nmap-service-probes',
                                                                  '/tool/data/nse_main.lua',
                                                                  '/run/reviewer-fonts.conf'],
                                                 'max_file_bytes': 16384,
                                                 'names': ['nmap_services',
                                                           'nmap_protocols',
                                                           'nmap_service_probes',
                                                           'nmap_nse_shim',
                                                           'graphical_fontconfig'],
                                                 'note': 'SelectedephemeralXauthoritycookie is '
                                                         'separatelycustodiedsessioncapability, '
                                                         'notcompiledstaticruntimefile, '
                                                         'neverexportsecretbytes.',
                                                 'row_fields': ['name',
                                                                'destination',
                                                                'size',
                                                                'sha256'],
                                                 'type': 'list'},
                             'file_row_fields': ['source', 'destination', 'size', 'sha256'],
                             'file_rules': 'exact pathinventory fromfixedrole, stable fstat '
                                           'dev/ino/mode/size/mtime_ns/ctime_ns aroundboundedread, '
                                           'sealsrequired; filepath aliases resolved '
                                           'underfixedstandard roots, no caller path',
                             'helpers_schema': {'count': 4,
                                                'destinations': {'bwrap': '/usr/bin/bwrap',
                                                                 'nft': '/usr/sbin/nft',
                                                                 'nsenter': '/usr/bin/nsenter',
                                                                 'readelf': '/usr/bin/readelf'},
                                                'executable': 'file_row',
                                                'files': 'sorteduniquefile_rowlist,<=32/helper,exactinspectedDT_NEEDEDclosure; '
                                                         'readonlyrootstockpaths only',
                                                'interpreter': 'exact ELFinterpreterdestination',
                                                'names': ['bwrap', 'nsenter', 'nft', 'readelf'],
                                                'roles': 'readelf hostpreflightonly; nsenter '
                                                         'hosttwo launcherstarts; nft '
                                                         'endpointfixedsetup only; bwrap '
                                                         'supervisorfixedchildren only; no '
                                                         'arbitraryhelperargv/role mounting',
                                                'row_fields': ['name',
                                                               'executable',
                                                               'interpreter',
                                                               'files'],
                                                'type': 'list'},
                             'platform': 'linux-x86_64',
                             'profile': 'engagement-live-runtime-v1',
                             'python': 'exactsystemdistributionPython path/version/image/hash; '
                                       'nativevalidation uses inspected3.14 layout, portabletests '
                                       'simulate unavailableLinux APIs',
                             'python_fields': ['source',
                                               'destination',
                                               'size',
                                               'sha256',
                                               'version',
                                               'builtin_modules'],
                             'resource_fields': ['kind',
                                                 'source',
                                                 'destination',
                                                 'device',
                                                 'inode',
                                                 'mode',
                                                 'files_sha256'],
                             'resource_rules': 'fixedGUI Tcl/Tk/fonts/fontconfigdirs read-only; '
                                               'boundedfileinventory/hashbeforeandafterstartup, no '
                                               'recursivehostrootbind; Xsocket exactidentity '
                                               'andselected16-bytecookie are separatelycustodied, '
                                               'cookiebytesneverretainedinevidence',
                             'role_fields': ['role',
                                             'entrypoint',
                                             'sources',
                                             'executable',
                                             'interpreter',
                                             'native_files',
                                             'extension_files',
                                             'readonly_resources',
                                             'required_mapped_images'],
                             'role_runtime_delivery': 'Selected immutable rolemanifest '
                                                      'mountedsealedat '
                                                      '/run/engagement-runtime.json (0444), '
                                                      'max131072; child reads/validatesbeforeseal '
                                                      'and closesreadFD. Globalruntimefilehash '
                                                      'isnot placedas large ordinarypacket; '
                                                      'bootstrap bindsruntime_sha256 '
                                                      'plusselectedmanifestsha.',
                             'source_inventory': 'allexactnewproduction secure_agent modulepaths '
                                                 'plus explicitacceptedroleunion below '
                                                 'and2packagefiles; no tests/scripts in '
                                                 'productionclosure; eachrole onlyitsclosedsubset',
                             'source_row_fields': ['module', 'destination', 'size', 'sha256'],
                             'stdlib_fields': ['path', 'device', 'inode', 'mode'],
                             'stdlib_rules': 'fixedreadonlydistributionPythonstdlib; lib-dynload '
                                             'hidden/replaced then exactroleextensions mounted. '
                                             'Explicitly not fullstdlib-byte-sealing or '
                                             'everyopen-syscallattestation.'},
 'source_partitions': {'admission_extra': ['engagement_live_admission_worker'],
                       'audit_exact': ['planner_worker',
                                       'audit_worker',
                                       'audit_protocol',
                                       'audit_witness'],
                       'broker_extra': ['engagement_dispatch_store',
                                        'engagement_live_broker_worker',
                                        'engagement_live_witness',
                                        'engagement_live_context',
                                        'configurable_parser',
                                        'http_headers_parser',
                                        'network_tools_nmap_parser',
                                        'network_tools_parser',
                                        'audit_witness',
                                        'audit_protocol'],
                       'common': ['engagement_live_runtime',
                                  'engagement_live_contract',
                                  'engagement_live_protocol',
                                  'engagement_dispatch_contract',
                                  'engagement_contract',
                                  'configurable_contract',
                                  'configurable_scope',
                                  'models',
                                  'tool_parameters',
                                  'tool_adapters',
                                  'session_limits',
                                  'worker',
                                  'tool_worker_common',
                                  'name_tls_worker_common',
                                  'planner_worker',
                                  'name_tls_topology_spec'],
                       'endpoint_extra': ['engagement_live_endpoint_worker'],
                       'headers_extra': ['engagement_live_client_worker'],
                       'launcher_extra': ['engagement_live_launcher_worker',
                                          'engagement_live_client',
                                          'engagement_live_client_worker',
                                          'engagement_live_parser',
                                          'engagement_live_endpoint',
                                          'engagement_live_admission_worker',
                                          'engagement_live_witness',
                                          'engagement_live_context',
                                          'execution',
                                          'isolation',
                                          'routed',
                                          'engagement_live_parser_worker',
                                          'configurable_parser',
                                          'http_headers_parser',
                                          'network_tools_nmap_parser',
                                          'network_tools_parser',
                                          'audit_witness',
                                          'audit_protocol'],
                       'nmap_extra': ['engagement_live_client_worker'],
                       'parser_extra': ['engagement_live_parser_worker',
                                        'configurable_parser',
                                        'http_headers_parser',
                                        'network_tools_nmap_parser',
                                        'network_tools_parser'],
                       'principle': 'Exact common+roleextra+2 inertpackagefiles; accepted audit '
                                    'ownlayout. No '
                                    'graphical_approval_isolation/approval_isolation/planner_isolation '
                                    'dependency for reused pureview/seal helpers. Launcher '
                                    'includes fixedchild sourceunion forstage. Host-onlyimports '
                                    'remainlazy andunmounted inleaves. Sourcecodepresence is '
                                    'notpermissionto mount binaries/data/authority.',
                       'terminal_and_graphical_extra': ['approval_worker',
                                                        'graphical_approval_worker',
                                                        'graphical_approval_view',
                                                        'graphical_approval_protocol',
                                                        'approval_protocol',
                                                        'approvals',
                                                        'name_tls_public',
                                                        'engagement_live_approval_worker',
                                                        'engagement_live_approval_view']},
 'status': 'runtime_contract_addendum_for_review',
 'supersedes_sha256': '7a2b4bc576a9726dbb3beadaafcb285d1426df725696901c3e1bcfa7427a6368'}

NEW_MODULES = ('engagement_live_admission_worker', 'engagement_live_approval', 'engagement_live_approval_view', 'engagement_live_approval_worker', 'engagement_live_audit', 'engagement_live_broker', 'engagement_live_broker_worker', 'engagement_live_client', 'engagement_live_client_worker', 'engagement_live_context', 'engagement_live_contract', 'engagement_live_endpoint', 'engagement_live_endpoint_worker', 'engagement_live_evidence', 'engagement_live_launcher', 'engagement_live_launcher_worker', 'engagement_live_parser', 'engagement_live_parser_worker', 'engagement_live_protocol', 'engagement_live_runtime', 'engagement_live_session', 'engagement_live_witness')

PROFILE = 'engagement-live-runtime-v1'
ROLES = ('broker', 'terminal', 'graphical', 'launcher', 'endpoint', 'nmap', 'headers', 'parser', 'admission')
READY_PREFIX = b'RECON_ENGAGEMENT_LIVE_READY_V1 '
MANIFEST_PATH = '/run/engagement-runtime.json'
PACKAGE_FILES = {'recon_cockpit.__init__': '/app/recon_cockpit/__init__.py',
                 'recon_cockpit.secure_agent.__init__': '/app/recon_cockpit/secure_agent/__init__.py'}
ENTRYPOINTS = {role: '/app/recon_cockpit/secure_agent/engagement_live_' +
              ('approval_worker' if role in ('terminal', 'graphical') else
               'client_worker' if role in ('nmap', 'headers') else role + '_worker') + '.py' for role in ROLES}
EXTENSIONS = ('_ctypes', '_hashlib', '_hmac', '_uuid', '_queue', 'resource')
RIGHTS = {role: tuple(SPEC['initial_rights_table'][role]['rights']) for role in ROLES}

_DIGEST = re.compile(r'[a-f0-9]{64}\Z')
_UUID = re.compile(r'[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}\Z')


def _fail(code='invalid_runtime'):
    from .engagement_live_contract import LiveError
    raise LiveError('engagement_live_' + code)


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def _decode(raw, maximum=32768):
    from .engagement_live_contract import decode
    return decode(raw, max_bytes=maximum)


def _hash(value):
    return hashlib.sha256(_json(value)).hexdigest()


def _fields(value, names):
    if type(value) is not dict or set(value) != set(names):
        _fail()
    return value


def _integer(value, minimum=0, maximum=2**63-1):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail()
    return value


def _digest(value):
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        _fail()
    return value


def _role(role):
    if type(role) is not str or role not in ROLES:
        _fail('invalid_role')
    return role


def _check(control=None, deadline_ns=None):
    if control is not None:
        control.check()
    if deadline_ns is not None and time.monotonic_ns() >= deadline_ns:
        _fail('timeout')


def _remaining(control, maximum=.05):
    _check(control)
    return max(0, min(maximum, control.deadline - time.monotonic()))


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_fd(fd, maximum, control=None):
    result = bytearray()
    while len(result) <= maximum:
        _check(control)
        part = os.read(fd, min(65536, maximum + 1 - len(result)))
        if not part:
            return bytes(result)
        result.extend(part)
    _fail('limit_exceeded')


def _read_file(path, maximum=16777216, control=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            _fail()
        raw = _read_fd(fd, maximum, control)
        if len(raw) != before.st_size or _stamp(before) != _stamp(os.fstat(fd)):
            _fail()
        return raw
    finally:
        os.close(fd)


def _source_path(module):
    if module in PACKAGE_FILES:
        return Path(__file__).with_name('__init__.py')
    if module not in source_modules():
        _fail()
    return Path(__file__).with_name(module + '.py')


def _destination(module):
    return PACKAGE_FILES.get(module, '/app/recon_cockpit/secure_agent/' + module + '.py')


def role_modules(role):
    _role(role)
    part = SPEC['source_partitions']
    extra = part['terminal_and_graphical_extra'] if role in ('terminal', 'graphical') else part[role + '_extra']
    modules = set(part['common']) | set(extra) | set(PACKAGE_FILES)
    if role == 'launcher':
        # The builder stages only its fixed child closures, not reviewer or DB roles.
        for child in ('nmap', 'headers', 'parser', 'admission'):
            modules.update(role_modules(child))
    return tuple(sorted(modules))


def source_modules():
    return tuple(sorted(set(NEW_MODULES) | set(PACKAGE_FILES) | set(SPEC['source_partitions']['audit_exact']) | set().union(*(set(role_modules(r)) for r in ROLES))))


def _file_row(source, destination, control=None):
    source = str(Path(source).resolve(strict=True))
    raw = _read_file(source, control=control)
    return {'source': source, 'destination': destination, 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def _elf(raw):
    """Parse ELF64 program/dynamic headers without executing a candidate image."""
    import struct
    if len(raw) < 64 or raw[:7] != b'\x7fELF\x02\x01\x01':
        _fail('unsupported_runtime')
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', raw)
    if header[2] != 62 or header[9] != 56 or not 1 <= header[10] <= 128:
        _fail('unsupported_runtime')
    segments, interp, dynamic = [], None, None
    try:
        for n in range(header[10]):
            kind, flags, offset, virtual, _, filesz, memsz, align = struct.unpack_from('<IIQQQQQQ', raw, header[5] + n * 56)
            if offset + filesz > len(raw):
                _fail()
            if kind == 1:
                segments.append((virtual, virtual + filesz, offset))
            elif kind == 3:
                interp = raw[offset:offset+filesz].rstrip(b'\x00').decode('ascii')
            elif kind == 2:
                dynamic = (offset, filesz)
        if dynamic is None:
            _fail('unsupported_runtime')
        tags = []
        for offset in range(dynamic[0], dynamic[0] + dynamic[1], 16):
            tag, value = struct.unpack_from('<qQ', raw, offset)
            if tag == 0:
                break
            tags.append((tag, value))
        address = next(value for tag, value in tags if tag == 5)
        size = next(value for tag, value in tags if tag == 10)
        start = next(offset + address - lo for lo, hi, offset in segments if lo <= address < hi)
        if size > 2**20 or start + size > len(raw):
            _fail()
        strings = raw[start:start+size]
        needed = []
        for tag, value in tags:
            if tag != 1:
                continue
            end = strings.index(b'\x00', value)
            name = strings[value:end].decode('ascii')
            if not re.fullmatch(r'[A-Za-z0-9_+.-]{1,128}', name):
                _fail()
            needed.append(name)
        return interp, tuple(needed)
    except (ValueError, StopIteration, IndexError, struct.error, UnicodeError):
        _fail('unsupported_runtime')


def _library(name):
    for root in ('/lib/x86_64-linux-gnu', '/usr/lib/x86_64-linux-gnu'):
        path = Path(root, name)
        if path.is_file():
            resolved = path.resolve(strict=True)
            if not str(resolved).startswith('/usr/lib/x86_64-linux-gnu/'):
                _fail()
            return str(resolved), '/lib/x86_64-linux-gnu/' + name
    _fail('unsupported_runtime')


def _closure(source, destination, control=None):
    pending = [(source, destination)]
    rows, interpreter = {}, None
    while pending:
        source, destination = pending.pop()
        if destination in rows:
            continue
        if len(rows) >= 64:
            _fail('limit_exceeded')
        row = _file_row(source, destination, control)
        raw = _read_file(row['source'], control=control)
        interp, needed = _elf(raw)
        rows[destination] = row
        if interp:
            if interp != '/lib64/ld-linux-x86-64.so.2':
                _fail('unsupported_runtime')
            interpreter = interp
            pending.append((str(Path(interp).resolve(strict=True)), interp))
        pending.extend(_library(name) for name in needed)
    return sorted(rows.values(), key=lambda row: row['destination']), interpreter


_COMPILED = {'graphical_fontconfig': ('/run/reviewer-fonts.conf',
                          b'<?xml version="1.0"?>\n<!DOCTYPE fontconfig SYSTEM "urn:fontconfig:fonts.dtd"'
                          b'>\n<fontconfig><dir>/usr/share/fonts/truetype/dejavu</dir>\n<cachedir>/var/cac'
                          b'he/fontconfig</cachedir></fontconfig>\n'),
 'nmap_nse_shim': ('/tool/data/nse_main.lua',
                   b"local engine, rules = ...\nassert(type(engine) == 'table' and engine.scriptversion =="
                   b' true)\nassert(engine.default == false and engine.scriptupdatedb == false and engine.'
                   b"scripthelp == false)\nassert(engine.scriptargs == '' and engine.scriptargsfile == nil"
                   b")\nassert(type(rules) == 'table' and next(rules) == nil)\nreturn function(hosts, phase"
                   b")\n  assert(type(hosts) == 'table' and #hosts <= 1 and phase == 'NSE_SCAN')\nend\n"),
 'nmap_protocols': ('/tool/data/nmap-protocols', b'tcp 6 TCP\n'),
 'nmap_service_probes': ('/tool/data/nmap-service-probes',
                         b'# Reviewed TCP NULL and one fixed metadata GET; no SSL, UDP or RPC probes.\nProbe'
                         b' TCP NULL q||\ntotalwaitms 400\ntcpwrappedms 100\nmatch ssh m%^SSH-2\\.0-OpenSSH'
                         b'_([0-9]{1,3}(?:\\.[0-9]{1,3}){0,2})\\r\\n$% p/OpenSSH/ v/$1/\nProbe TCP GetReque'
                         b'st q|GET / HTTP/1.0\\r\\n\\r\\n|\nports 8080\nrarity 1\ntotalwaitms 700\nmatch h'
                         b'ttp m%^HTTP/1\\.[01] [1-5][0-9]{2} [A-Za-z][A-Za-z ]{0,47}\\r\\nServer: nginx/('
                         b'[0-9]{1,3}(?:\\.[0-9]{1,3}){0,2})\\r\\n% p/nginx/ v/$1/\nmatch http m%^HTTP/1\\.['
                         b'01] [1-5][0-9]{2} [A-Za-z][A-Za-z ]{0,47}\\r\\nServer: Apache/([0-9]{1,3}(?:\\.'
                         b'[0-9]{1,3}){0,2})\\r\\n% p/Apache httpd/ v/$1/\nmatch http m%^HTTP/1\\.[01] [1-5'
                         b'][0-9]{2} [A-Za-z][A-Za-z ]{0,47}\\r\\n%\n'),
 'nmap_services': ('/tool/data/nmap-services', b'unknown 8080/tcp 1.0\n')}

def _compiled():
    return dict(_COMPILED)


def _resource(path, control=None):
    root = Path(path)
    info = root.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
        _fail('unsupported_runtime')
    rows, total = [], 0
    for current, dirs, files in os.walk(root, followlinks=False):
        _check(control)
        for name in dirs:
            if Path(current, name).is_symlink():
                _fail()
        for name in sorted(files):
            selected = Path(current, name)
            raw = _read_file(selected, 16777216, control)
            total += len(raw)
            if len(rows) >= 512 or total > 33554432:
                _fail('limit_exceeded')
            rows.append([str(selected.relative_to(root)), len(raw), hashlib.sha256(raw).hexdigest()])
    if _stamp(info) != _stamp(root.stat()):
        _fail()
    return {'kind': 'directory', 'source': path, 'destination': path, 'device': info.st_dev,
            'inode': info.st_ino, 'mode': info.st_mode, 'files_sha256': _hash(sorted(rows))}


def inspect_runtime(control):
    import platform
    import subprocess
    if platform.system() != 'Linux' or platform.machine() != 'x86_64' or os.getuid() == 0:
        _fail('unsupported_runtime')
    _check(control)
    started = time.monotonic()
    end = min(control.deadline, started + 15)
    # This is fixed interpreter metadata inspection, not a selected native tool.
    metadata = subprocess.run(['/usr/bin/python3', '-I', '-S', '-c',
        'import sys,json;print(json.dumps([sys.version.split()[0],list(sys.builtin_module_names)]))'],
        capture_output=True, timeout=max(.001, end-time.monotonic()), check=True)
    if metadata.stderr or len(metadata.stdout) > 16384:
        _fail()
    version, builtins = json.loads(metadata.stdout)
    if not version.startswith('3.14.'):
        _fail('unsupported_runtime')
    stdlib = '/usr/lib/python3.14'
    info = os.stat(stdlib)
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
        _fail()
    python = _file_row('/usr/bin/python3', '/usr/bin/python3', control)
    python.update(version=version, builtin_modules=sorted(builtins))
    common, interpreter = _closure('/usr/bin/python3', '/usr/bin/python3', control)
    seccomp, _ = _closure('/lib/x86_64-linux-gnu/libseccomp.so.2', '/lib/x86_64-linux-gnu/libseccomp.so.2', control)
    sources = []
    for module in source_modules():
        raw = _read_file(_source_path(module), 262144, control)
        sources.append({'module': module, 'destination': _destination(module), 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
    helpers = []
    for name, dest in SPEC['runtime_manifest_schema']['helpers_schema']['destinations'].items():
        files, interp = _closure(dest, dest, control)
        helpers.append({'name': name, 'executable': next(x for x in files if x['destination'] == dest), 'interpreter': interp, 'files': files})
    resources = [_resource(path, control) for path in ('/usr/share/tcltk/tcl8.6', '/usr/share/tcltk/tk8.6',
                   '/usr/share/fonts/truetype/dejavu', '/var/cache/fontconfig')]
    roles = []
    for role in ROLES:
        selected = list(EXTENSIONS) + (['_sqlite3'] if role == 'broker' else ['_tkinter'] if role == 'graphical' else ['termios'] if role == 'terminal' else [])
        files = {x['destination']: x for x in common + seccomp}
        extensions = []
        for name in selected:
            matches = list(Path(stdlib, 'lib-dynload').glob(name + '.*.so'))
            if len(matches) != 1:
                _fail('unsupported_runtime')
            rows, _ = _closure(str(matches[0]), str(matches[0]), control)
            extensions.extend(x for x in rows if x['destination'] == str(matches[0]))
            files.update((x['destination'], x) for x in rows if x['destination'] != str(matches[0]))
        native_required = []
        if role in ('nmap', 'launcher'):
            rows, _ = _closure('/usr/lib/nmap/nmap', '/tool/nmap', control)
            files.update((x['destination'], x) for x in rows)
            native_required = [x['destination'] for x in rows]
        if role in ('endpoint', 'launcher'):
            helper = next(x for x in helpers if x['name'] == ('nft' if role == 'endpoint' else 'bwrap'))
            files.update((x['destination'], x) for x in helper['files'])
        # Launcher stages fixed child extensions; no broker/GUI extension is included.
        rows = sorted(files.values(), key=lambda row: row['destination'])
        roles.append({'role': role, 'entrypoint': ENTRYPOINTS[role],
            'sources': [x for x in sources if x['module'] in role_modules(role)],
            'executable': '/tool/nmap' if role == 'nmap' else '/usr/bin/python3',
            'interpreter': interpreter, 'native_files': rows, 'extension_files': sorted(extensions, key=lambda x:x['destination']),
            'readonly_resources': resources if role == 'graphical' else [],
            'required_mapped_images': sorted(native_required if role == 'nmap' else [x['destination'] for x in common])})
    compiled = [{'name': name, 'destination': destination, 'size':len(raw), 'sha256':hashlib.sha256(raw).hexdigest()}
                for name,(destination,raw) in sorted(_compiled().items())]
    result = {'schema_version':'1','profile':PROFILE,'platform':'linux-x86_64','python':python,
        'stdlib':{'path':stdlib,'device':info.st_dev,'inode':info.st_ino,'mode':info.st_mode},
        'sources':sources,'roles':roles,'helpers':sorted(helpers,key=lambda x:x['name']),'compiled':compiled}
    _check(control, int(end*1e9))
    return validate_runtime(result)


def _validate_file(row):
    _fields(row, ('source','destination','size','sha256'))
    for key in ('source','destination'):
        if (type(row[key]) is not str or len(row[key]) > 4096 or not row[key].startswith('/')
                or '..' in Path(row[key]).parts or '\x00' in row[key]):
            _fail()
    if not row['source'].startswith(('/usr/bin/', '/usr/sbin/', '/usr/lib/', '/lib/')):
        _fail()
    _integer(row['size'], 1, 16777216)
    _digest(row['sha256'])


def _validate_source(row):
    _fields(row, ('module','destination','size','sha256'))
    if row['module'] not in source_modules() or row['destination'] != _destination(row['module']):
        _fail()
    _integer(row['size'],1,262144)
    _digest(row['sha256'])


def validate_role_manifest(value, role=None):
    _fields(value, SPEC['runtime_manifest_schema']['role_fields'])
    selected = _role(value['role'])
    if role is not None and selected != role or value['entrypoint'] != ENTRYPOINTS[selected]:
        _fail()
    if value['executable'] != ('/tool/nmap' if selected == 'nmap' else '/usr/bin/python3') or value['interpreter'] != '/lib64/ld-linux-x86-64.so.2':
        _fail()
    if type(value['sources']) is not list or len(value['sources']) != len(role_modules(selected)):
        _fail()
    for row in value['sources']:
        _validate_source(row)
    if [x['module'] for x in value['sources']] != list(role_modules(selected)):
        _fail()
    for key in ('native_files','extension_files'):
        rows=value[key]
        if type(rows) is not list or not 1 <= len(rows) <= 64:
            _fail()
        for row in rows:
            _validate_file(row)
        if [x['destination'] for x in rows] != sorted({x['destination'] for x in rows}):
            _fail()
    destinations = {x['destination'] for x in value['native_files']}
    if not {'/usr/bin/python3', value['interpreter']} <= destinations:
        _fail()
    executables = {p for p in destinations if p.startswith(('/usr/bin/','/usr/sbin/','/tool/'))}
    expected={'/usr/bin/python3'}
    if selected in ('nmap','launcher'): expected.add('/tool/nmap')
    if selected=='launcher':expected.add('/usr/bin/bwrap')
    if selected=='endpoint':expected.add('/usr/sbin/nft')
    if executables != expected:
        _fail()
    extensions=set(EXTENSIONS) | ({'_sqlite3'} if selected=='broker' else {'_tkinter'} if selected=='graphical' else {'termios'} if selected=='terminal' else set())
    actual={Path(x['destination']).name.split('.')[0] for x in value['extension_files']}
    if actual!=extensions or any(not x['destination'].startswith('/usr/lib/python3.14/lib-dynload/') for x in value['extension_files']):
        _fail()
    required=value['required_mapped_images']
    if type(required)is not list or required!=sorted(set(required)) or not set(required)<=destinations or value['interpreter'] not in required or value['executable'] not in required:
        _fail()
    resources=value['readonly_resources']
    paths=['/usr/share/tcltk/tcl8.6','/usr/share/tcltk/tk8.6','/usr/share/fonts/truetype/dejavu','/var/cache/fontconfig'] if selected=='graphical' else []
    if type(resources)is not list or len(resources)!=len(paths):_fail()
    for row,path in zip(resources,paths,strict=True):
        _fields(row,SPEC['runtime_manifest_schema']['resource_fields'])
        if row['kind']!='directory' or row['source']!=path or row['destination']!=path:_fail()
        for key in ('device','inode','mode'):_integer(row[key],0,2**64-1)
        _digest(row['files_sha256'])
    if len(_json(value))>131072:_fail('limit_exceeded')
    return json.loads(_json(value))


def validate_runtime(value):
    _fields(value, SPEC['runtime_manifest_schema']['bundle_fields'])
    if value['schema_version']!='1' or value['profile']!=PROFILE or value['platform']!='linux-x86_64':_fail()
    py=value['python'];_fields(py,SPEC['runtime_manifest_schema']['python_fields'])
    _validate_file({k:py[k] for k in ('source','destination','size','sha256')})
    if py['destination']!='/usr/bin/python3' or not re.fullmatch(r'3\.14\.\d+',py['version']):_fail()
    builtins=py['builtin_modules']
    if type(builtins)is not list or not 1<=len(builtins)<=128 or builtins!=sorted(set(builtins)) or any(type(x)is not str or not re.fullmatch(r'[_a-zA-Z][_a-zA-Z0-9]*',x) for x in builtins):_fail()
    _fields(value['stdlib'],('path','device','inode','mode'))
    if value['stdlib']['path']!='/usr/lib/python3.14':_fail()
    for key in ('device','inode','mode'):_integer(value['stdlib'][key],0,2**64-1)
    rows=value['sources']
    if type(rows)is not list or len(rows)!=len(source_modules()):_fail()
    for row in rows:_validate_source(row)
    if [x['module'] for x in rows]!=list(source_modules()) or sum(x['size'] for x in rows)>8388608 or len(_json(rows))>65536:_fail()
    if type(value['roles'])is not list or [x.get('role') for x in value['roles']]!=list(ROLES):_fail()
    for role in value['roles']:
        validate_role_manifest(role)
        if role['sources']!=[x for x in rows if x['module'] in role_modules(role['role'])]:_fail()
        if next(x for x in role['native_files'] if x['destination']=='/usr/bin/python3')!={k:py[k] for k in ('source','destination','size','sha256')}:_fail()
    helpers=value['helpers']
    if type(helpers)is not list or [x.get('name') for x in helpers]!=['bwrap','nft','nsenter','readelf']:_fail()
    for helper in helpers:
        _fields(helper,('name','executable','interpreter','files'))
        _validate_file(helper['executable'])
        if helper['executable']['destination']!=SPEC['runtime_manifest_schema']['helpers_schema']['destinations'][helper['name']] or helper['interpreter']!='/lib64/ld-linux-x86-64.so.2':_fail()
        if type(helper['files'])is not list or not 1<=len(helper['files'])<=32:_fail()
        for row in helper['files']:_validate_file(row)
        if helper['executable'] not in helper['files']:_fail()
    compiled=[{'name':name,'destination':dest,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()} for name,(dest,raw) in sorted(_compiled().items())]
    if value['compiled']!=compiled:_fail()
    if len(_json(value))>2097152:_fail('limit_exceeded')
    return json.loads(_json(value))


def runtime_digest(value):
    return _hash(validate_runtime(value))


def _seals():
    import fcntl
    return fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL


def _sealed(raw, *, name='engagement-live', control=None):
    import fcntl
    if not hasattr(os,'memfd_create'):_fail('unavailable')
    fd=os.memfd_create(name,os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    try:
        offset=0
        while offset<len(raw):
            _check(control)
            n=os.write(fd,raw[offset:])
            if n<=0:_fail()
            offset+=n
        os.lseek(fd,0,os.SEEK_SET)
        fcntl.fcntl(fd,fcntl.F_ADD_SEALS,_seals())
        if fcntl.fcntl(fd,fcntl.F_GET_SEALS)!=_seals():_fail()
        return fd
    except BaseException:
        os.close(fd)
        raise


class RoleSnapshot:
    def __init__(self,bundle,role,control):
        bundle=validate_runtime(bundle);_role(role)
        self.role=role;self.runtime_sha256=_hash(bundle)
        self.manifest=next(x for x in bundle['roles'] if x['role']==role)
        self.stdlib=bundle['stdlib']['path'];self.sources={};self.native={};self.extensions={};self.compiled={};self.manifest_fd=None
        self._fds=[];self.closed=False;self.bundle_fd=None
        try:
            for row in self.manifest['sources']:
                raw=_read_file(_source_path(row['module']),262144,control)
                self._stage(row,raw,self.sources,control)
            for key,target in (('native_files',self.native),('extension_files',self.extensions)):
                for row in self.manifest[key]:
                    # Inside an isolated launcher the reviewed source is already at
                    # its sealed destination. Verify those exact bytes again.
                    path=row['source'] if Path(row['source']).is_file() else row['destination']
                    raw=_read_file(path,16777216,control)
                    self._stage(row,raw,target,control)
            for name,(destination,raw) in _compiled().items():
                if (role in ('nmap','launcher') and name.startswith('nmap_')) or role=='graphical' and name=='graphical_fontconfig':
                    row=next(x for x in bundle['compiled'] if x['name']==name)
                    self._stage(row,raw,self.compiled,control)
            self.manifest_fd=_sealed(_json(self.manifest),control=control);self._fds.append(self.manifest_fd)
            if role=='launcher':
                self.bundle_fd=_sealed(_json(bundle),control=control);self._fds.append(self.bundle_fd)
            if len(self._fds)>128 or sum(os.fstat(fd).st_size for fd in self._fds)>134217728:_fail('limit_exceeded')
            _check(control)
        except BaseException:
            self.close();raise
    def _stage(self,row,raw,target,control):
        if len(raw)!=row['size'] or hashlib.sha256(raw).hexdigest()!=row['sha256']:_fail()
        fd=_sealed(raw,control=control);self._fds.append(fd);target[row['destination']]=fd
    @property
    def pass_fds(self):return tuple(self._fds)
    def mounts(self,argv):
        import fcntl
        if self.closed:_fail()
        mounts={**self.sources,**self.native,**self.extensions,**self.compiled,MANIFEST_PATH:self.manifest_fd}
        if self.bundle_fd is not None:mounts['/run/engagement-runtime-bundle.json']=self.bundle_fd
        for destination,fd in sorted(mounts.items()):
            if fcntl.fcntl(fd,fcntl.F_GET_SEALS)!=_seals():_fail()
            mode='0555' if destination in ('/usr/bin/python3','/tool/nmap','/usr/bin/bwrap','/usr/sbin/nft',self.manifest['interpreter']) else '0444'
            argv.extend(('--perms',mode,'--ro-bind-data',str(fd),destination))
        return argv
    def close(self):
        if self.closed:return
        self.closed=True
        errors=[]
        for fd in self._fds:
            try:os.close(fd)
            except OSError as error:errors.append(error)
        self._fds.clear()
        if errors:raise errors[0]
    def __enter__(self):return self
    def __exit__(self,*unused):self.close()


def snapshot_role(bundle,role,control):
    return RoleSnapshot(bundle,role,control)


class _AuditSnapshot(RoleSnapshot):
    """Accepted legacy audit layout, sealed from the same pinned bundle."""
    def __init__(self,bundle,control):
        bundle=validate_runtime(bundle)
        self.role='audit';self.runtime_sha256=runtime_digest(bundle)
        selected=next(x for x in bundle['roles'] if x['role']=='parser')
        self.manifest=json.loads(_json(selected))
        self.manifest.update(role='audit',entrypoint='/app/audit_worker.py',sources=[])
        self.stdlib=bundle['stdlib']['path'];self.sources={};self.native={};self.extensions={};self.compiled={};self.manifest_fd=None
        self._fds=[];self.closed=False
        try:
            for module in SPEC['source_partitions']['audit_exact']:
                row=dict(next(x for x in bundle['sources'] if x['module']==module))
                row['destination']='/app/'+module+'.py'
                self.manifest['sources'].append(row)
                self._stage(row,_read_file(_source_path(module),262144,control),self.sources,control)
            for key,target in (('native_files',self.native),('extension_files',self.extensions)):
                for row in self.manifest[key]:self._stage(row,_read_file(row['source'],16777216,control),target,control)
            if len(self._fds)>128 or sum(os.fstat(fd).st_size for fd in self._fds)>134217728:_fail('limit_exceeded')
            _check(control)
        except BaseException:self.close();raise
    def mounts(self,argv):
        import fcntl
        if self.closed:_fail()
        for destination,fd in sorted({**self.sources,**self.native,**self.extensions}.items()):
            if fcntl.fcntl(fd,fcntl.F_GET_SEALS)!=_seals():_fail()
            argv.extend(('--perms','0555' if destination in ('/usr/bin/python3',self.manifest['interpreter']) else '0444','--ro-bind-data',str(fd),destination))
        return argv


def _snapshot_audit(bundle,control):return _AuditSnapshot(bundle,control)


def _observer():
    return {'pid':os.getpid(),'uid':os.getuid(),'gid':os.getgid(),
            'namespaces':{name:os.readlink('/proc/self/ns/'+name) for name in ('user','net','mnt','pid')}}


def _base_command(snapshot,*,role,info_fd,worker_id,bootstrap_sha256,unshare_net=True):
    _role(role)
    if snapshot.role!=role or _UUID.fullmatch(worker_id) is None:_fail()
    _digest(bootstrap_sha256);_integer(info_fd,3,255)
    argv=['/usr/bin/bwrap','--unshare-user','--unshare-pid','--unshare-ipc','--unshare-uts','--unshare-cgroup',
        '--uid','65534','--gid','65534','--cap-drop','ALL','--cap-add','CAP_SETPCAP',
        '--die-with-parent','--new-session','--as-pid-1','--info-fd',str(info_fd),'--clearenv',
        '--setenv','LC_ALL','C','--setenv','MALLOC_ARENA_MAX','1','--chdir','/','--proc','/proc','--dev','/dev']
    if unshare_net:argv.append('--unshare-net')
    if role=='endpoint':argv.extend(('--cap-add','CAP_NET_ADMIN','--cap-add','CAP_SYS_ADMIN'))
    argv.extend(('--ro-bind',snapshot.stdlib,snapshot.stdlib,'--tmpfs',snapshot.stdlib+'/lib-dynload'))
    snapshot.mounts(argv)
    for row in snapshot.manifest['readonly_resources']:
        argv.extend(('--ro-bind',row['source'],row['destination']))
    return argv


def _finish_command(argv,*,role,worker_id,bootstrap_sha256):
    _role(role)
    if _UUID.fullmatch(worker_id) is None:_fail()
    _digest(bootstrap_sha256)
    if role!='endpoint':argv.extend(('--remount-ro','/proc'))
    argv.extend(('--remount-ro','/dev','--remount-ro','/','/usr/bin/python3','-I','-S',ENTRYPOINTS[role],worker_id,bootstrap_sha256))
    return argv


def _descriptor(fd,purpose):
    import fcntl
    info=os.fstat(fd)
    return {'fd':fd,'purpose':purpose,'device':info.st_dev,'inode':info.st_ino,
            'mode':info.st_mode,'flags':fcntl.fcntl(fd,fcntl.F_GETFL)}


def _make_bootstrap(*,snapshot,worker_id,rights,payload,control,observer=None,expected_net=None):
    if type(rights)is not dict or tuple(rights)!=RIGHTS[snapshot.role]:_fail('invalid_role')
    observer=_observer() if observer is None else observer
    expected=dict(observer['namespaces'])
    if expected_net is not None:expected['net']=expected_net
    value={'schema_version':'1','role':snapshot.role,'worker_id':worker_id,'observer':observer,
        'expected_namespaces':expected,'deadline_ns':int(control.deadline*1e9),
        'runtime_sha256':snapshot.runtime_sha256,'role_manifest_sha256':_hash(snapshot.manifest),
        'source_sha256':_hash(snapshot.manifest['sources']),
        'descriptors':[{**_descriptor(fd,name), 'fd':index+3} for index,(name,fd) in enumerate(rights.items())], 'payload':payload}
    if len(_json(value))>32768:_fail('limit_exceeded')
    return value


def _receive_initial(role,worker_id,commitment,*,entry_verified):
    import array
    import fcntl
    import socket
    import ctypes
    import resource
    from .name_tls_worker_common import close_import_descriptor
    close_import_descriptor(entry_verified=entry_verified)
    channel=socket.socket(fileno=0)
    import select
    channel.setblocking(False)
    initial_end=time.monotonic()+2
    while not select.select([channel],[],[],max(0,min(.05,initial_end-time.monotonic())))[0]:
        if time.monotonic()>=initial_end:_fail('timeout')
    raw,ancillary,flags,_=channel.recvmsg(32769,socket.CMSG_SPACE(32*array.array('i').itemsize),socket.MSG_CMSG_CLOEXEC)
    rights=[]
    try:
        invalid_ancillary=False
        for level,kind,data in ancillary:
            if level!=socket.SOL_SOCKET or kind!=socket.SCM_RIGHTS:
                invalid_ancillary=True;continue
            values=array.array('i');values.frombytes(data[:len(data)-len(data)%values.itemsize]);rights.extend(values)
            if len(data)%values.itemsize:invalid_ancillary=True
        if invalid_ancillary:_fail('invalid_frame')
        if flags & (socket.MSG_TRUNC|socket.MSG_CTRUNC) or len(raw)>32768 or len(ancillary)>1:_fail('invalid_frame')
        if hashlib.sha256(raw).hexdigest()!=commitment:_fail('invalid_runtime')
        value=_decode(raw)
        _fields(value,SPEC['closed_objects']['initial_bootstrap']['fields'])
        if value['schema_version']!='1' or value['role']!=role or value['worker_id']!=worker_id:_fail()
        rows=value['descriptors']
        if type(rows)is not list or len(rows)!=len(RIGHTS[role]) or len(rights)!=len(rows):_fail('invalid_role')
        actual={}
        for row,fd,purpose in zip(rows,rights,RIGHTS[role],strict=True):
            _fields(row,SPEC['closed_objects']['bootstrap_descriptor']['fields'])
            observed=_descriptor(fd,purpose)
            if row['purpose']!=purpose or fd!=row['fd'] or any(observed[k]!=row[k] for k in ('device','inode','mode','flags')):_fail('invalid_role')
            actual[purpose]=fd
        manifest=_decode(_read_file(MANIFEST_PATH,131072),131072)
        validate_role_manifest(manifest,role)
        if _hash(manifest)!=value['role_manifest_sha256'] or _hash(manifest['sources'])!=value['source_sha256']:_fail()
        payload=value['payload']
        if role!='broker':_fields(payload,SPEC['closed_objects']['bootstrap_payloads'][role])
        if role in ('endpoint','launcher','terminal','graphical'):
            from .engagement_live_contract import validate_role_context
            validate_role_context(binding=payload['session_binding'],roe=payload['roe'],scope=payload['scope'],policy=payload['policy'])
        _check(deadline_ns=_integer(value['deadline_ns'],1))
        channel.setblocking(False)
        return value,manifest,actual,channel
    except BaseException:
        for fd in rights:
            try:os.close(fd)
            except OSError:pass
        channel.detach()
        raise


def _fd_inventory(directory='/proc/self', purposes=None, *, role=None, steady=False):
    import fcntl
    result=[];purposes={0:'stdin',1:'stdout',2:'stderr'} if purposes is None else dict(purposes)
    if role=='broker' and steady:
        # The bootstrap input is closed before SQLite opens. Its descriptor
        # number can then be reused; the old purpose must not follow that number.
        purposes={fd:name for fd,name in purposes.items() if name!='runtime_input'}
    for name in sorted(os.listdir(str(directory)+'/fd'),key=int):
        fd=int(name)
        try:
            info=os.stat(str(directory)+'/fd/'+name)
            target=os.readlink(str(directory)+'/fd/'+name)
            raw=Path(str(directory)+'/fdinfo/'+name).read_text(encoding='ascii')
        except FileNotFoundError:
            continue
        if len(raw)>4096:_fail()
        flags=int(next(x.split()[1] for x in raw.splitlines() if x.startswith('flags:')),8) & ~os.O_CLOEXEC
        mode=info.st_mode
        if target.startswith('anon_inode:[pidfd]'):kind='pidfd'
        elif target=='anon_inode:[eventpoll]':kind='eventpoll'
        elif target=='anon_inode:[eventfd]':kind='eventfd'
        elif stat.S_ISFIFO(mode):kind='pipe'
        elif stat.S_ISREG(mode):kind='regular'
        elif stat.S_ISDIR(mode):kind='proc_directory' if target.startswith('/proc/') else 'directory'
        elif stat.S_ISCHR(mode):kind='character'
        elif stat.S_ISSOCK(mode):kind='seqpacket' if purposes.get(fd,'') in ('stdin',*RIGHTS['broker'],*RIGHTS['endpoint'],*RIGHTS['launcher'],'review_witness') else 'stream_socket'
        else:_fail('invalid_role')
        purpose=purposes.get(fd,'stdio' if fd<=2 else 'observed')
        if role=='broker' and steady and fd not in purposes:
            purpose={'/store':'held_parent_directory','/store/engagement':'held_store_directory',
                     '/store/engagement/records.sqlite3':'sqlite_main',
                     '/store/engagement/records.sqlite3-journal':'transient_rollback_journal',
                     'anon_inode:[eventpoll]':'selector'}.get(target,'observed')
        result.append({'fd':fd,'purpose':purpose,
                       'kind':kind,'device':info.st_dev,'inode':info.st_ino,'mode':mode,'flags':flags})
    return result


def check_role_entry(*,role,bootstrap,expected_fds,observer):
    _role(role)
    if bootstrap['role']!=role or bootstrap['observer']!=observer or type(expected_fds)is not dict or tuple(expected_fds)!=RIGHTS[role]:_fail('invalid_role')
    if os.getuid()!=65534 or os.getgid()!=65534 or len(os.getgroups())>64 or any(x!=65534 for x in os.getgroups()):_fail('invalid_role')
    namespaces={name:os.readlink('/proc/self/ns/'+name) for name in ('user','net','mnt','pid')}
    for name in ('user','mnt','pid'):
        if namespaces[name]==observer['namespaces'][name]:_fail('invalid_role')
    if role in ('nmap','headers','launcher'):
        if namespaces['net']!=bootstrap['expected_namespaces']['net']:_fail('invalid_role')
    elif namespaces['net']==observer['namespaces']['net']:_fail('invalid_role')
    from .name_tls_worker_common import namespace_identity
    identity=namespace_identity()
    purposes={0:'stdin',1:'stdout',2:'stderr',**{fd:name for name,fd in expected_fds.items()}}
    actual=_fd_inventory(purposes=purposes)
    if {x['fd'] for x in actual}!={0,1,2,*expected_fds.values()}:_fail('invalid_role')
    for row in bootstrap['descriptors']:
        selected=next(x for x in actual if x['fd']==expected_fds[row['purpose']])
        if any(selected[k]!=row[k] for k in ('device','inode','mode','flags')):_fail('invalid_role')
    _check(deadline_ns=bootstrap['deadline_ns'])
    return {'role':role,'bootstrap':bootstrap,'namespaces':namespaces,'identity':identity,
            'descriptors':actual,'purposes':purposes}


def _install_filter(role):
    import ctypes
    import socket
    from . import planner_worker
    if role not in ('nmap','headers','endpoint','launcher'):
        planner_worker._install_syscall_filter()
        return
    if role=='launcher':
        # Child namespaces/execution are allowed only by the fixed trusted builder;
        # no arbitrary worker source or executable is mounted. Network syscalls
        # and host-observation attacks remain denied.
        denied=('socket','connect','bind','listen','accept','accept4','ptrace','process_vm_readv',
                'process_vm_writev','pidfd_getfd','bpf','keyctl','add_key','request_key','perf_event_open','userfaultfd','io_uring_setup','open_by_handle_at')
    else:
        from .tool_worker_common import syscall_filter
        syscall_filter(allow_threads=False)
        denied=('execve',) if role in ('headers','endpoint') else ()
        if role=='endpoint':denied+=('connect',)
    class Arg(ctypes.Structure):
        _fields_=[('arg',ctypes.c_uint),('op',ctypes.c_int),('a',ctypes.c_uint64),('b',ctypes.c_uint64)]
    lib=ctypes.CDLL('libseccomp.so.2',use_errno=True)
    lib.seccomp_init.argtypes=[ctypes.c_uint32];lib.seccomp_init.restype=ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes=[ctypes.c_char_p];lib.seccomp_syscall_resolve_name.restype=ctypes.c_int
    lib.seccomp_rule_add_array.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.c_int,ctypes.c_uint,ctypes.POINTER(Arg)]
    lib.seccomp_attr_set.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_uint32]
    lib.seccomp_load.argtypes=[ctypes.c_void_p];lib.seccomp_release.argtypes=[ctypes.c_void_p]
    ctx=lib.seccomp_init(0x7fff0000)
    if not ctx:_fail('unavailable')
    try:
        if lib.seccomp_attr_set(ctx,4,1):_fail('unavailable')
        def deny(name,args=()):
            number=lib.seccomp_syscall_resolve_name(name.encode('ascii'))
            if number==-1 or lib.seccomp_rule_add_array(ctx,0x50000|errno.EPERM,number,len(args),(Arg*len(args))(*args)):_fail('unavailable')
        for name in denied:deny(name)
        if role=='endpoint':
            for name,index in (('send',3),('sendto',3),('sendmsg',2),('sendmmsg',3)):
                deny(name,(Arg(index,7,0x20000000,0x20000000),))
        if lib.seccomp_load(ctx):_fail('unavailable')
    finally:lib.seccomp_release(ctx)


def _steady_fd_max(role,stage='sealed'):
    if stage not in ('sealed','native'):return 32
    if role=='nmap' and stage=='native':return 16
    if role in ('nmap','headers'):return SPEC['fd_inventory']['waiting_client_max']
    if role=='launcher':return SPEC['fd_inventory']['launcher_non_snapshot_max']
    return SPEC['fd_inventory'][role+'_max']


def bootstrap_role(*,role,entry,runtime_manifest,expected_fds,deadline_ns):
    import resource
    import socket
    from . import worker,planner_worker
    from .name_tls_worker_common import seal_group_identity
    validate_role_manifest(runtime_manifest,role)
    if entry['role']!=role or entry['bootstrap']['deadline_ns']!=deadline_ns:_fail('invalid_role')
    _check(deadline_ns=deadline_ns)
    tasks=sorted(int(x) for x in os.listdir('/proc/self/task'))
    steady=_fd_inventory(purposes=entry['purposes'],role=role,steady=True)
    if len(steady)>_steady_fd_max(role):_fail('invalid_role')
    if role=='broker':
        required=set(RIGHTS['broker'])-{'runtime_input'}|{'stdin','stdout','stderr',
            'held_parent_directory','held_store_directory','sqlite_main'}
        names=[row['purpose'] for row in steady]
        if not required<=set(names) or set(names)-required-{'transient_rollback_journal','selector'} or len(names)!=len(set(names)) or len(names)>SPEC['fd_inventory']['broker_max']:_fail('invalid_role')
        for row in entry['descriptors']:
            if row['purpose']=='runtime_input':continue
            current=next((item for item in steady if item['purpose']==row['purpose']),None)
            if current is None or current!=row:_fail('invalid_role')
    extra={x['fd'] for x in steady}-{0,1,2,*expected_fds.values()}
    if role in ('terminal','graphical') and (len(steady)>(5 if role=='terminal' else 7) or (extra and role=='terminal')):_fail('invalid_role')
    if role=='graphical' and any(x['kind'] not in ('stream_socket','pipe','eventfd') for x in steady if x['fd'] in extra):_fail('invalid_role')
    if not 1<=len(tasks)<=SPEC['resources'][role].get('tasks_max',1):_fail('invalid_role')
    bounds=SPEC['resources'][role]
    for kind,maximum in ((resource.RLIMIT_AS,bounds['as_mib']*1048576),(resource.RLIMIT_CPU,bounds['cpu_seconds']),
            (resource.RLIMIT_NOFILE,bounds['nofile']),(resource.RLIMIT_NPROC,bounds['nproc']),
            (resource.RLIMIT_FSIZE,bounds['fsize_bytes']),(resource.RLIMIT_CORE,0)):
        current=resource.getrlimit(kind)[1];bound=maximum if current==resource.RLIM_INFINITY else min(current,maximum)
        resource.setrlimit(kind,(bound,bound))
    worker.drop_privileges()
    seal_group_identity(entry['identity'])
    _install_filter(role)
    if not os.statvfs('/').f_flag & os.ST_RDONLY:_fail('invalid_role')
    planner_worker._zero_capabilities();planner_worker._no_new_privileges()
    if role!='launcher':
        planner_worker._process_creation_blocked();planner_worker._namespace_creation_blocked()
    if role not in ('nmap','headers','endpoint'):
        planner_worker._sockets_blocked()
    # Filesystem leaf rules are installed after all parsers/data were preloaded.
    if role in ('nmap','headers','parser','endpoint'):
        from .tool_worker_common import apply_landlock
        permissions={'/dev/null':2|4,'/proc/self/status':4}
        if role=='nmap':
            for row in runtime_manifest['native_files']:
                if row['destination']!='/usr/bin/python3':permissions[row['destination']]=1|4
            for destination,_ in _compiled().values():
                if destination.startswith('/tool/'):permissions[destination]=4
        apply_landlock(permissions)
    checks={name:True for name in SPEC['closed_objects']['boundary_checks']['common']}
    if role=='launcher':
        checks.pop('process_creation_blocked');checks.pop('namespace_creation_blocked')
        checks.update(bounded_child_creation=True,fixed_namespace_builder=True)
    # Role-specific effect witnesses are supplied by their fixed worker after
    # setup; they are not inferred from a common seccomp installation.
    ready={'schema_version':'1','role':role,'worker_id':entry['bootstrap']['worker_id'],
        'bootstrap_sha256':_hash(entry['bootstrap']),'runtime_sha256':entry['bootstrap']['runtime_sha256'],
        'source_sha256':entry['bootstrap']['source_sha256'],
        'stage':'sealed_reviewer' if role in ('terminal','graphical') else 'sealed_waiting' if role in ('nmap','headers') else 'sealed_'+role,
        'namespaces':entry['namespaces'],'uid':os.getuid(),'gid':os.getgid(),'groups':os.getgroups(),
        'task_ids':tasks,'descriptor_sha256':_hash(steady),'boundary_checks':checks}
    return ready


def _emit_ready(ready):
    validate_worker_ready(ready)
    raw=READY_PREFIX+_json(ready)+b'\n'
    if len(raw)>8192:_fail('limit_exceeded')
    offset=0
    while offset<len(raw):
        count=os.write(1,raw[offset:])
        if count<=0:_fail('unavailable')
        offset+=count


def validate_worker_ready(value):
    _fields(value,SPEC['closed_objects']['worker_ready']['fields']);role=_role(value['role'])
    if value['schema_version']!='1' or _UUID.fullmatch(value['worker_id']) is None:_fail()
    for key in ('bootstrap_sha256','runtime_sha256','source_sha256','descriptor_sha256'):_digest(value[key])
    expected=set(SPEC['closed_objects']['boundary_checks']['common'])|set(SPEC['closed_objects']['boundary_checks']['role_specific'][role])
    if role=='launcher':expected-={'process_creation_blocked','namespace_creation_blocked'};expected|={'bounded_child_creation','fixed_namespace_builder'}
    if type(value['boundary_checks'])is not dict or set(value['boundary_checks'])!=expected or any(x is not True for x in value['boundary_checks'].values()):_fail('invalid_role')
    if value['uid']!=65534 or type(value['uid'])is not int or value['gid']!=65534 or type(value['gid'])is not int:_fail()
    if type(value['groups'])is not list or len(value['groups'])>64 or any(type(x)is not int or x!=65534 for x in value['groups']):_fail()
    _fields(value['namespaces'],('user','net','mnt','pid'))
    for key,text in value['namespaces'].items():
        if type(text)is not str or not re.fullmatch(key+r':\[\d+\]',text):_fail()
    tasks=value['task_ids']
    if type(tasks)is not list or not 1<=len(tasks)<=SPEC['resources'][role].get('tasks_max',1) or tasks!=sorted(set(tasks)):_fail()
    for pid in tasks:_integer(pid,1,2**31-1)
    expected_stage='sealed_reviewer' if role in ('terminal','graphical') else 'sealed_waiting' if role in ('nmap','headers') else 'sealed_'+role
    if value['stage']!=expected_stage or len(_json(value))>8192:_fail()
    return json.loads(_json(value))


def _proc_read(directory,path,maximum):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
    try:return _read_fd(fd,maximum)
    finally:os.close(fd)


def _process_identity(pid):
    raw=Path('/proc',str(pid),'stat').read_text(encoding='ascii')
    if len(raw)>8192:_fail()
    fields=raw[raw.rfind(')')+2:].split()
    return {'pid':pid,'parent_pid':int(fields[1]),'start_time_ticks':int(fields[19])}


def _payload_state(fd):
    import select
    poll=select.poll();poll.register(fd,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)
    rows=poll.poll(0)
    if not rows:return 'alive'
    flags=rows[0][1]
    if flags & (select.POLLNVAL|select.POLLERR) or flags==0:_fail('cleanup_incomplete')
    if flags & select.POLLHUP:return 'reaped'
    if flags & select.POLLIN:return 'exited'
    _fail('cleanup_incomplete')


class PinnedProcess:
    def __init__(self,process,pid,role):
        import signal
        if not callable(getattr(os,'pidfd_open',None)) or not callable(getattr(signal,'pidfd_send_signal',None)):_fail('unavailable')
        _integer(pid,1,2**31-1)
        if role!='audit':_role(role)
        self.process=process;self.role=role;self.pid=pid;self.fd=None;self.directory=None;self.receipt=None;self.verified=False
        try:
            self.fd=os.pidfd_open(pid,0)
            self.directory=os.open('/proc/'+str(pid),os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
            self.identity=_process_identity(pid)
            self.check_alive()
        except BaseException:
            self.close();raise
    def check_alive(self):
        if self.fd is None or _payload_state(self.fd)!='alive' or _process_identity(self.pid)!=self.identity:_fail('unavailable')
    def close(self):
        for name in ('directory','fd'):
            fd=getattr(self,name,None)
            if fd is not None:
                setattr(self,name,None);os.close(fd)


def _image(directory,path,destination):
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC,dir_fd=directory)
    try:
        before=os.fstat(fd);raw=_read_fd(fd,16777216)
        if _stamp(before)!=_stamp(os.fstat(fd)):_fail()
        return {'destination':destination,'device':before.st_dev,'inode':before.st_ino,'mode':before.st_mode,
                'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    finally:os.close(fd)


def _process_observation(pin,manifest,observer,expected_net,*,stage='sealed'):
    pin.check_alive();directory=pin.directory
    ancestry=[];pid=pin.pid
    while len(ancestry)<16:
        item=_process_identity(pid);ancestry.append(item)
        if pid==pin.process.pid:break
        pid=item['parent_pid']
        if pid<=0:_fail('invalid_role')
    if ancestry[-1]['pid']!=pin.process.pid:_fail('invalid_role')
    for child,parent in zip(ancestry,ancestry[1:]):
        if child['start_time_ticks']<parent['start_time_ticks']:_fail('invalid_role')
    namespaces={name:os.readlink('ns/'+name,dir_fd=directory) for name in ('user','net','mnt','pid')}
    for name in ('user','mnt','pid'):
        if namespaces[name]==observer['namespaces'][name]:_fail('invalid_role')
    if expected_net is None:
        if namespaces['net']==observer['namespaces']['net']:_fail('invalid_role')
    elif namespaces['net']!=expected_net:_fail('invalid_role')
    maps={name:[list(map(int,line.split())) for line in _proc_read(directory,name+'_map',1024).decode('ascii').splitlines()] for name in ('uid','gid')}
    inside=0 if pin.role=='audit' else 65534
    if maps['uid']!=[[inside,observer['uid'],1]] or maps['gid']!=[[inside,observer['gid'],1]]:_fail('invalid_role')
    status={k:v.strip() for line in _proc_read(directory,'status',65536).decode('ascii').splitlines() if ':' in line for k,v in [line.split(':',1)]}
    if status.get('Uid','').split()!=[str(observer['uid'])]*4 or status.get('Gid','').split()!=[str(observer['gid'])]*4:_fail('invalid_role')
    fields={'cap_inheritable':'CapInh','cap_permitted':'CapPrm','cap_effective':'CapEff','cap_bounding':'CapBnd','cap_ambient':'CapAmb'}
    actual_status={k:int(status[v],16) for k,v in fields.items()}
    actual_status.update(no_new_privs=int(status['NoNewPrivs']),seccomp_mode=int(status['Seccomp']))
    if stage in ('sealed','native') and (any(actual_status[k] for k in fields) or actual_status['no_new_privs']!=1 or actual_status['seccomp_mode']!=2):_fail('invalid_role')
    task_ids=sorted(int(x) for x in os.listdir('/proc/'+str(pin.pid)+'/task'))
    if len(task_ids)>SPEC['resources'][pin.role].get('tasks_max',1):_fail('invalid_role')
    purposes=('audit_append','audit_witness') if pin.role=='audit' else RIGHTS.get(pin.role,())
    descriptors=_fd_inventory('/proc/'+str(pin.pid),purposes={0:'stdin',1:'stdout',2:'stderr',**{i+3:name for i,name in enumerate(purposes)}},role=pin.role,steady=stage in ('sealed','native'))
    if len(descriptors)>_steady_fd_max(pin.role,stage):_fail('invalid_role')
    executable=_image(directory,'exe',manifest['executable'] if stage=='native' else '/usr/bin/python3')
    expected=next(x for x in manifest['native_files'] if x['destination']==executable['destination'])
    if executable['sha256']!=expected['sha256'] or executable['size']!=expected['size']:_fail('invalid_runtime')
    allowed={}
    for row in manifest['native_files']+manifest['extension_files']:
        image=_image(directory,'root'+row['destination'],row['destination'])
        if image['sha256']!=row['sha256'] or image['size']!=row['size']:_fail('invalid_runtime')
        allowed.setdefault((image['device'],image['inode']),[]).append(row['destination'])
    # Inspect actual source bytes inside the payload's read-only mount namespace.
    if stage!='native':
        for row in manifest['sources']:
            image=_image(directory,'root'+row['destination'],row['destination'])
            if image['sha256']!=row['sha256'] or image['size']!=row['size']:_fail('invalid_runtime')
    mapped=[]
    for line in _proc_read(directory,'maps',262144).decode('utf-8').splitlines():
        bits=line.split(maxsplit=5)
        if len(bits)<6 or bits[5].startswith('['):continue
        device=os.makedev(*(int(x,16) for x in bits[3].split(':')));inode=int(bits[4])
        if 'x' not in bits[1]:continue
        if (device,inode) not in allowed:_fail('invalid_runtime')
        mapped.extend({'destination':dest,'device':device,'inode':inode} for dest in allowed[(device,inode)])
    unique={x['destination']:x for x in mapped}
    if not set(manifest['required_mapped_images'] if stage=='native' else ('/usr/bin/python3',manifest['interpreter']))<=set(unique):_fail('invalid_runtime')
    receipt={'schema_version':'1','role':pin.role,'observer':observer,'wrapper':ancestry[-1],'payload':pin.identity,
        'ancestry':ancestry,'namespaces':namespaces,'uid_map':maps['uid'],'gid_map':maps['gid'],
        'uids':[int(x) for x in status['Uid'].split()],'gids':[int(x) for x in status['Gid'].split()],
        'groups':[int(x) for x in status['Groups'].split()],'task_ids':task_ids,'descriptors':descriptors,
        'executable':executable,'mapped_images':sorted(unique.values(),key=lambda x:x['destination']),
        'status':actual_status,'sampled_at_ns':time.monotonic_ns(),'stage':stage}
    pin.check_alive();return receipt


def observe_process(*,info_raw,process,role,bundle,observer,expected_net,control):
    if type(info_raw)is not bytes or len(info_raw)>4096:_fail()
    info=json.loads(info_raw)
    if type(info)is not dict or type(info.get('child-pid'))is not int:_fail()
    pid=_integer(info['child-pid'],1,2**31-1)
    pin=PinnedProcess(process,pid,role)
    try:
        _check(control)
        manifest=next(x for x in validate_runtime(bundle)['roles'] if x['role']==role)
        pin.receipt=_process_observation(pin,manifest,observer,expected_net)
        pin.verified=True;_check(control);return pin
    except BaseException:
        # The caller always terminates the wrapper. Preserve the opened pin for
        # bounded non-signalling HUP synchronization even if observation failed.
        process._engagement_unverified_pin=pin
        raise


def observe_native(pin,manifest,*,waiting_image,control):
    manifest=validate_role_manifest(manifest,'nmap')
    while True:
        _check(control);pin.check_alive()
        actual=_image(pin.directory,'exe','/tool/nmap')
        if (actual['device'],actual['inode'])==(waiting_image['device'],waiting_image['inode']):
            time.sleep(min(.01,_remaining(control)));continue
        observation=_process_observation(pin,manifest,pin.receipt['observer'],pin.receipt['namespaces']['net'],stage='native')
        return {'schema_version':'1','role':'nmap','waiting_image':waiting_image,'parent_observation':observation,'observed_at_ns':time.monotonic_ns()}


def _observe_legacy_audit(*,info_raw,process,bundle,observer,control):
    if type(info_raw)is not bytes or len(info_raw)>4096:_fail()
    info=json.loads(info_raw)
    if type(info)is not dict or type(info.get('child-pid'))is not int:_fail()
    pin=PinnedProcess(process,_integer(info['child-pid'],1,2**31-1),'audit')
    try:
        validated=validate_runtime(bundle)
        manifest=json.loads(_json(next(x for x in validated['roles'] if x['role']=='parser')))
        manifest.update(role='audit',sources=[{**next(x for x in validated['sources'] if x['module']==module),'destination':'/app/'+module+'.py'} for module in SPEC['source_partitions']['audit_exact']])
        _check(control)
        pin.receipt=_process_observation(pin,manifest,observer,None)
        validate_audit_observation(pin.receipt)
        pin.verified=True;_check(control);return pin
    except BaseException:
        process._engagement_unverified_pin=pin
        raise


def cleanup_owned(processes,pins,*,deadline=None):
    import signal
    import subprocess
    started=time.monotonic_ns();end=min(started+2000000000, int(deadline*1e9) if deadline is not None else started+2000000000)
    if len(processes)>26 or len(pins)>26:_fail('cleanup_incomplete')
    records=[];failed=False;unobserved=[];closed=True
    allpins=list(pins)
    for process in processes:
        extra=getattr(process,'_engagement_unverified_pin',None)
        if extra is not None and extra not in allpins:allpins.append(extra)
    for process in processes:
        if not any(pin.process is process for pin in allpins):
            # Wrapper cleanup is observed; an unobserved payload is explicitly
            # unknown, never an empty successful no-start receipt.
            unobserved.append((process,{'role':getattr(process,'_engagement_role','launcher'),
                'pid':None,'start_time_ticks':None,'pin_verified':False,
                'signal_attempted':False,'exit_observed':False,'reaped_observed':False,
                'wrapper_pid':process.pid,'wrapper_returncode':None}))
    try:
        for pin in allpins:
            record={'role':pin.role,'pid':pin.pid,'start_time_ticks':pin.identity['start_time_ticks'],
                'pin_verified':pin.verified,'signal_attempted':False,'exit_observed':False,'reaped_observed':False,
                'wrapper_pid':pin.process.pid,'wrapper_returncode':None}
            records.append(record)
            try:
                state=_payload_state(pin.fd)
                if pin.verified and state=='alive':
                    record['signal_attempted']=True
                    sender=getattr(signal,'pidfd_send_signal',None)
                    if not callable(sender):raise OSError(errno.ENOSYS,'pidfd signal unavailable')
                    sender(pin.fd,signal.SIGKILL,None,0)
            except ProcessLookupError:pass
            except (OSError,ValueError):failed=True
        # Verified payloads die first so their bwrap parent can reap naturally.
        grace=min(end,time.monotonic_ns()+100000000)
        while time.monotonic_ns()<grace and any(p.poll() is None for p in processes):time.sleep(.005)
        for process in processes:
            if process.poll() is None:
                try:os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                except OSError:failed=True
        for process in processes:
            remaining=max(0,(end-time.monotonic_ns())/1e9)
            try:process.wait(timeout=remaining)
            except (subprocess.TimeoutExpired,OSError):failed=True
        while time.monotonic_ns()<end:
            complete=True
            for pin,record in zip(allpins,records,strict=True):
                try:
                    state=_payload_state(pin.fd)
                    record['exit_observed']=state in ('exited','reaped')
                    record['reaped_observed']=state=='reaped'
                except (OSError,ValueError):failed=True
                record['wrapper_returncode']=pin.process.returncode
                complete &= record['reaped_observed'] and pin.process.returncode is not None
            if complete:break
            time.sleep(min(.005,max(0,(end-time.monotonic_ns())/1e9)))
        if any(not r['reaped_observed'] or r['wrapper_returncode'] is None for r in records):failed=True
    finally:
        for pin in allpins:
            try:pin.close()
            except OSError:failed=True;closed=False
        for process in processes:
            for name in ('stdin','stdout','stderr'):
                pipe=getattr(process,name,None)
                if pipe is not None:
                    try:pipe.close()
                    except OSError:failed=True;closed=False
    for process,record in unobserved:
        record['wrapper_returncode']=process.returncode
        records.append(record)
    finished=time.monotonic_ns()
    if finished>end:failed=True
    result={'schema_version':'1','started_at_ns':started,'finished_at_ns':finished,'deadline_ns':end,
            'status':'failed' if failed else 'unknown' if unobserved else 'complete','processes':records,'descriptors_closed':closed}
    if failed:
        from .engagement_live_contract import LiveError
        error=LiveError('engagement_live_cleanup_incomplete');error.cleanup=result;raise error
    return result


def _read_info(process,info_read,control):
    import select
    raw=bytearray();os.set_blocking(info_read,False)
    while True:
        _check(control)
        if process.poll()is not None:_fail('unavailable')
        if not select.select([info_read],[],[],_remaining(control,.01))[0]:continue
        part=os.read(info_read,4097-len(raw))
        if not part:_fail('unavailable')
        raw.extend(part)
        if len(raw)>4096:_fail('limit_exceeded')
        try:value=json.loads(raw)
        except (ValueError,UnicodeError):continue
        if type(value)is not dict or type(value.get('child-pid'))is not int:_fail('invalid_role')
        _integer(value['child-pid'],1,2**31-1)
        return bytes(raw),value['child-pid']


def _read_startup(process,info_read,control,*,initial_info=b''):
    import selectors
    buffers={'stdout':bytearray(),'stderr':bytearray(),'info':bytearray(initial_info)};selector=selectors.DefaultSelector()
    try:
        for fd,key in ((process.stdout.fileno(),'stdout'),(process.stderr.fileno(),'stderr'),(info_read,'info')):
            os.set_blocking(fd,False);selector.register(fd,selectors.EVENT_READ,key)
        while True:
            _check(control)
            if process.poll() is not None:_fail('unavailable')
            if b'\n' in buffers['stdout'] and buffers['info']:
                line,rest=bytes(buffers['stdout']).split(b'\n',1)
                if rest or not line.startswith(READY_PREFIX) or buffers['stderr']:_fail('invalid_role')
                try:json.loads(buffers['info'])
                except (ValueError,UnicodeError):pass
                else:return _decode(line[len(READY_PREFIX):],8192),bytes(buffers['info'])
            for key,_ in selector.select(_remaining(control,.01)):
                part=os.read(key.fd,4096)
                if not part:
                    selector.unregister(key.fd)
                    if key.data!='info':_fail('unavailable')
                    continue
                buffers[key.data].extend(part)
                if len(buffers[key.data])>(8192 if key.data=='stdout' else 4096):_fail('limit_exceeded')
    except BaseException as error:
        error.startup_info=bytes(buffers['info'])
        error.startup_diagnostics=bytes(buffers['stderr'])
        raise
    finally:selector.close()


class RoleProcess:
    def __init__(self,process,channel,pin,bootstrap,ready):
        self.process=process;self.channel=channel;self.pin=pin;self.bootstrap=bootstrap;self.ready=ready;self.cleanup=None
    def close(self,*,deadline=None):
        if self.cleanup is not None:return self.cleanup
        try:self.channel.close()
        finally:self.cleanup=cleanup_owned([self.process],[self.pin],deadline=deadline)
        return self.cleanup


def _finish_start(*,process,channel,info_read,bootstrap,bundle,role,control,expected_net=None,pin=None,initial_info=b''):
    ready,info=_read_startup(process,info_read,control,initial_info=initial_info)
    validate_worker_ready(ready)
    if ready['worker_id']!=bootstrap['worker_id'] or ready['bootstrap_sha256']!=_hash(bootstrap) or ready['runtime_sha256']!=bootstrap['runtime_sha256'] or ready['source_sha256']!=bootstrap['source_sha256']:_fail('invalid_role')
    if pin is None:pin=observe_process(info_raw=info,process=process,role=role,bundle=bundle,observer=bootstrap['observer'],expected_net=expected_net,control=control)
    else:
        pin.check_alive()
        manifest=next(x for x in bundle['roles'] if x['role']==role)
        pin.receipt=_process_observation(pin,manifest,bootstrap['observer'],expected_net)
        pin.verified=True
    if role=='launcher':
        held=_image(pin.directory,'root/run/engagement-runtime-bundle.json','/run/engagement-runtime-bundle.json')
        expected=_json(bundle)
        if held['size']!=len(expected) or held['sha256']!=hashlib.sha256(expected).hexdigest():_fail('invalid_runtime')
    compound={'schema_version':'1','role':role,'worker_ready':ready,'parent_observation':pin.receipt}
    validate_readiness(role,compound,bundle)
    return RoleProcess(process,channel,pin,bootstrap,compound)


def _start_role_owned(*,runtime,role,payload,rights,control,stdin_pair=None,extra_mounts=(),environment=None,namespace_fds=None,expected_net=None,worker_id=None):
    import array
    import socket
    import subprocess
    import uuid
    _role(role);runtime=validate_runtime(runtime)
    if getattr(control,'clock',time.monotonic) is not time.monotonic:_fail('invalid_input')
    startup=_ClippedControl(control,min(control.deadline,time.monotonic()+10))
    worker_id=str(uuid.uuid4()) if worker_id is None else worker_id
    if _UUID.fullmatch(worker_id) is None:_fail('invalid_input')
    environment={} if environment is None else environment
    if role!='graphical' and environment or set(environment)-{'DISPLAY','XAUTHORITY','FONTCONFIG_FILE','TCL_LIBRARY','TK_LIBRARY'}:_fail('invalid_role')
    if stdin_pair is None:parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    else:parent,child=stdin_pair
    process=None;pin=None;info_read=info_write=None
    snapshot=None;owner=None;successful=False;failure=None
    try:
        info_read,info_write=os.pipe2(os.O_CLOEXEC)
        snapshot=snapshot_role(runtime,role,startup)
        bootstrap=_make_bootstrap(snapshot=snapshot,worker_id=worker_id,rights=rights,payload=payload,control=control,expected_net=expected_net)
        raw=_json(bootstrap);commitment=hashlib.sha256(raw).hexdigest()
        argv=_base_command(snapshot,role=role,info_fd=info_write,worker_id=worker_id,bootstrap_sha256=commitment,unshare_net=role not in ('launcher','nmap','headers'))
        for source,destination in extra_mounts:
            allowed=(role=='broker' and destination=='/store/engagement') or (role=='graphical' and (destination.startswith('/tmp/.X11-unix/X') or destination=='/run/reviewer.Xauthority'))
            if not allowed:_fail('invalid_role')
            if role=='broker':
                if type(source)is not int:_fail('invalid_role')
                info=os.fstat(source)
                if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o700 or info.st_uid!=os.getuid():_fail('invalid_role')
                argv.extend(('--perms','0700','--dir','/store','--bind-fd',str(source),destination))
            elif type(source)is int:argv.extend(('--perms','0400','--ro-bind-data',str(source),destination))
            else:argv.extend(('--bind' if role=='broker' else '--ro-bind',str(source),destination))
        for key,value in sorted(environment.items()):argv.extend(('--setenv',key,value))
        _finish_command(argv,role=role,worker_id=worker_id,bootstrap_sha256=commitment)
        extra_fds=tuple(source for source,_ in extra_mounts if type(source)is int)
        pass_fds=(*snapshot.pass_fds,info_write,*extra_fds)
        if namespace_fds is not None:
            if role!='launcher' or len(namespace_fds)!=2:_fail('invalid_role')
            # Fixed trusted startup shim drops namespace descriptors before bwrap;
            # these host setup capabilities never reach the new payload.
            close_code='import os,sys;keep={0,1,2,*map(int,sys.argv[1].split(","))};[(os.close(int(n))) for n in os.listdir("/proc/self/fd") if int(n) not in keep and os.path.exists("/proc/self/fd/"+n)];os.execv(sys.argv[2],sys.argv[2:])'
            argv=['/usr/bin/nsenter','--user=/proc/self/fd/'+str(namespace_fds[0]),'--net=/proc/self/fd/'+str(namespace_fds[1]),'--preserve-credentials','--','/usr/bin/python3','-I','-S','-c',close_code,','.join(map(str,pass_fds)),*argv]
            pass_fds=(*pass_fds,*namespace_fds)
        _check(startup)
        process=subprocess.Popen(argv,stdin=child,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=pass_fds,start_new_session=True,close_fds=True)
        process._engagement_role=role
        child.close();os.close(info_write);info_write=None
        snapshot.close();snapshot=None
        initial_info,payload_pid=_read_info(process,info_read,startup)
        pin=PinnedProcess(process,payload_pid,role)
        process._engagement_unverified_pin=pin
        manifest=next(x for x in runtime['roles'] if x['role']==role)
        expected_image=next(x for x in manifest['native_files'] if x['destination']=='/usr/bin/python3')
        while True:
            pin.check_alive();_check(startup)
            actual_image=_image(pin.directory,'exe','/usr/bin/python3')
            if actual_image['sha256']==expected_image['sha256'] and actual_image['size']==expected_image['size']:break
            time.sleep(min(.005,_remaining(startup)))
        # This observation binds the waiting image before bootstrap. It does not
        # claim the later syscall/FD/resource seal has already happened.
        pin.receipt=_process_observation(pin,manifest,bootstrap['observer'],expected_net,stage='entry')
        pin.entry_receipt=pin.receipt
        pin.verified=True
        parent.setblocking(False)
        import select
        while not select.select([], [parent], [], _remaining(startup,.01))[1]:_check(startup)
        ancillary=[] if not rights else [(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',tuple(rights.values())))]
        count=parent.sendmsg([raw],ancillary)
        if count!=len(raw):_fail('unavailable')
        while rights:
            _,fd=rights.popitem()
            os.close(fd)
        owner=_finish_start(process=process,channel=parent,info_read=info_read,bootstrap=bootstrap,bundle=runtime,role=role,control=startup,expected_net=expected_net,pin=pin,initial_info=initial_info)
        _check(control)
        successful=True
        return owner
    except BaseException as error:
        failure=error
        if process is not None and owner is None and not hasattr(process,'_engagement_unverified_pin'):
            raw=getattr(error,'startup_info',b'')
            try:
                info=json.loads(raw)
                if type(info)is dict and type(info.get('child-pid'))is int:
                    process._engagement_unverified_pin=PinnedProcess(process,info['child-pid'],role)
            except (ValueError,OSError):pass
        raise
    finally:
        _release_startup_resources(snapshot=snapshot,info_read=info_read,info_write=info_write,
            child=child,rights=rights,parent=parent,process=process,owner=owner,
            successful=successful,failure=failure)


def _release_startup_resources(*,snapshot,info_read,info_write,child,rights,parent,process,owner,successful,failure):
    """Every owned close and process reap is attempted despite earlier errors."""
    errors=[]
    def close(call):
        try:call()
        except BaseException as error:errors.append(error)
    if snapshot is not None:close(snapshot.close)
    for fd in (info_write,info_read):
        if fd is not None:close(lambda fd=fd:os.close(fd))
    close(child.close)
    while rights:
        _,fd=rights.popitem()
        close(lambda fd=fd:os.close(fd))
    if successful and not errors:return
    close(parent.close)
    observation=getattr(getattr(process,'_engagement_unverified_pin',None),'entry_receipt',None)
    receipt=None
    if process is not None:
        try:receipt=owner.close() if owner is not None else cleanup_owned([process],[])
        except BaseException as error:
            if hasattr(error,'cleanup'):error.startup_cleanup=error.cleanup
            error.startup_observation=observation
            if failure is not None:error.startup_failure=failure
            raise
    if failure is not None:
        failure.startup_cleanup=receipt
        failure.startup_observation=observation
        if errors:failure.resource_cleanup_error=errors[0]
    elif errors:
        from .engagement_live_contract import LiveError
        error=LiveError('engagement_live_unavailable')
        error.startup_cleanup=receipt;error.startup_observation=observation
        error.resource_cleanup_error=errors[0]
        raise error




_RETAINED_FIXTURE_DESCRIPTORS=ContextVar('engagement_live_retained_fixture_descriptors',default=None)


def _validate_parent_observation(value,role=None,*,audit=False):
    _fields(value,SPEC['closed_objects']['parent_observation']['fields'])
    selected=value['role']
    if audit:
        if selected!='audit':_fail()
    else:_role(selected)
    if role is not None and selected!=role:_fail()
    if value['schema_version']!='1' or value['stage'] not in ('entry','prepared','sealed','native'):_fail()
    _fields(value['observer'],('pid','uid','gid','namespaces'))
    for key in ('pid','uid','gid'):_integer(value['observer'][key],1 if key=='pid' else 0,2**32-1)
    for key in ('payload','wrapper'):
        _fields(value[key],('pid','parent_pid','start_time_ticks'))
        for n in ('pid','parent_pid'):_integer(value[key][n],1,2**31-1)
        _integer(value[key]['start_time_ticks'],1)
    ancestry=value['ancestry']
    if type(ancestry)is not list or not 1<=len(ancestry)<=16 or ancestry[0]!=value['payload'] or ancestry[-1]!=value['wrapper']:_fail()
    for child,parent in zip(ancestry,ancestry[1:]):
        _fields(child,('pid','parent_pid','start_time_ticks'))
        if child['parent_pid']!=parent['pid'] or child['start_time_ticks']<parent['start_time_ticks']:_fail()
    for field in ('namespaces',):
        _fields(value[field],('user','net','mnt','pid'))
        for name,text in value[field].items():
            if type(text)is not str or not re.fullmatch(name+r':\[\d+\]',text):_fail()
    for name in ('user','mnt','pid'):
        if value['namespaces'][name]==value['observer']['namespaces'][name]:_fail()
    for k,identity in (('uid',value['observer']['uid']),('gid',value['observer']['gid'])):
        if value[k+'_map']!=[[0 if audit else 65534,identity,1]] or value[k+'s']!=[identity]*4:_fail()
        if any(type(x)is not int for x in value[k+'s']):_fail()
    if type(value['groups'])is not list or len(value['groups'])>64 or any(type(x)is not int or not 0<=x<2**32 for x in value['groups']):_fail()
    tasks=value['task_ids']
    if type(tasks)is not list or not 1<=len(tasks)<=SPEC['resources'][selected].get('tasks_max',1) or tasks!=sorted(set(tasks)):_fail()
    for t in tasks:_integer(t,1,2**31-1)
    _fields(value['status'],SPEC['closed_objects']['process_status']['fields'])
    if any(type(x)is not int for x in value['status'].values()):_fail()
    if value['stage'] in ('sealed','native') and (any(value['status'][x] for x in value['status'] if x.startswith('cap_')) or value['status']['no_new_privs']!=1 or value['status']['seccomp_mode']!=2):_fail()
    descriptors=value['descriptors']
    limit=_steady_fd_max(selected,value['stage'])
    retained=_RETAINED_FIXTURE_DESCRIPTORS.get()
    if retained is not None and selected=='endpoint' and value['stage']=='sealed':
        identity=(value['payload']['pid'],value['payload']['start_time_ticks'])
        if identity==retained['payload']:
            if descriptors!=retained['descriptors']:_fail()
            limit=len(retained['descriptors'])
    if type(descriptors)is not list or len(descriptors)>limit or len({x.get('fd') for x in descriptors})!=len(descriptors):_fail()
    for row in descriptors:
        _fields(row,SPEC['closed_objects']['descriptor']['fields'])
        _integer(row['fd'],0,255)
        if row['kind'] not in SPEC['closed_objects']['descriptor']['kind'] or type(row['purpose'])is not str or len(row['purpose'])>64:_fail()
        for key in ('device','inode','mode','flags'):_integer(row[key],0,2**64-1)
    _fields(value['executable'],SPEC['closed_objects']['file_identity']['fields'])
    _digest(value['executable']['sha256']);_integer(value['executable']['size'],1,16777216)
    images=value['mapped_images']
    if type(images)is not list or len(images)>64 or len({x.get('destination') for x in images})!=len(images):_fail()
    for row in images:
        _fields(row,('destination','device','inode'))
        for key in ('device','inode'):_integer(row[key],0,2**64-1)
    _integer(value['sampled_at_ns'],1)
    return json.loads(_json(value))


def validate_parent_observation(value,role=None):return _validate_parent_observation(value,role)


def validate_audit_observation(value):return _validate_parent_observation(value,'audit',audit=True)


def validate_readiness(role,value,bundle,*,expected_binding=None):
    _fields(value,('schema_version','role','worker_ready','parent_observation'))
    _role(role)
    if value['schema_version']!='1' or value['role']!=role:_fail()
    ready=validate_worker_ready(value['worker_ready']);parent=validate_parent_observation(value['parent_observation'],role)
    manifest=next(x for x in validate_runtime(bundle)['roles'] if x['role']==role)
    if ready['role']!=role or ready['runtime_sha256']!=runtime_digest(bundle) or ready['source_sha256']!=_hash(manifest['sources']):_fail()
    if ready['namespaces']!=parent['namespaces'] or len(ready['task_ids'])!=len(parent['task_ids']) or ready['descriptor_sha256']!=_hash(parent['descriptors']):_fail()
    expected=next(x for x in manifest['native_files'] if x['destination']=='/usr/bin/python3')
    if parent['executable']['sha256']!=expected['sha256'] or parent['executable']['size']!=expected['size'] or parent['stage']!='sealed':_fail()
    if expected_binding is not None:
        if ready['worker_id']!=expected_binding.get('worker_id',ready['worker_id']):_fail()
    if len(_json(value))>16384:_fail('limit_exceeded')
    return json.loads(_json(value))


def validate_cleanup(value):
    _fields(value,SPEC['closed_objects']['cleanup']['fields'])
    if value['schema_version']!='1' or value['status'] not in ('complete','failed','unknown') or type(value['descriptors_closed'])is not bool:_fail()
    for key in ('started_at_ns','finished_at_ns','deadline_ns'):_integer(value[key],1)
    if value['finished_at_ns']<value['started_at_ns'] or value['deadline_ns']>value['started_at_ns']+2000000000:_fail()
    if type(value['processes'])is not list or len(value['processes'])>26:_fail()
    for row in value['processes']:
        _fields(row,SPEC['closed_objects']['cleanup_process']['fields'])
        if row['role'] not in (*ROLES,'audit'):_fail()
        for key in ('pin_verified','signal_attempted','exit_observed','reaped_observed'):
            if type(row[key])is not bool:_fail()
        if row['signal_attempted'] and not row['pin_verified'] or row['reaped_observed'] and not row['exit_observed']:_fail()
        for key in ('pid','wrapper_pid'):
            if row[key] is not None:_integer(row[key],1,2**31-1)
        if row['start_time_ticks'] is not None:_integer(row['start_time_ticks'],1)
        if row['wrapper_returncode'] is not None:_integer(row['wrapper_returncode'],-255,255)
    if value['status']=='complete' and (not value['descriptors_closed'] or value['finished_at_ns']>value['deadline_ns'] or any(not x['reaped_observed'] or x['wrapper_returncode'] is None for x in value['processes'])):_fail()
    return json.loads(_json(value))


def validate_protocol_value(kind,value):
    if kind=='worker_ready':return validate_worker_ready(value)
    if kind=='cleanup':return validate_cleanup(value)
    if kind=='native_readiness':
        _fields(value,SPEC['closed_objects']['native_readiness']['fields'])
        if value['schema_version']!='1' or value['role']!='nmap':_fail()
        parent=validate_parent_observation(value['parent_observation'],'nmap')
        _fields(value['waiting_image'],SPEC['closed_objects']['file_identity']['fields'])
        if parent['stage']!='native' or parent['executable']['destination']!='/tool/nmap' or parent['executable']['sha256']==value['waiting_image']['sha256']:_fail()
        _integer(value['observed_at_ns'],1)
    elif kind=='role_readiness':
        _fields(value,('schema_version','role','worker_ready','parent_observation'))
        if value['schema_version']!='1':_fail()
        validate_worker_ready(value['worker_ready']);validate_parent_observation(value['parent_observation'],value['role'])
        if value['worker_ready']['role']!=value['role'] or value['worker_ready']['namespaces']!=value['parent_observation']['namespaces']:_fail()
    elif kind=='meter':
        return validate_meter(value)
    elif kind=='client_result':
        from .engagement_live_context import validate_client_result
        return validate_client_result(value)
    else:_fail('invalid_frame')
    return json.loads(_json(value))


def _start_role(*, runtime, role, payload, rights, control, **options):
    # Ownership transfers at entry, including validation failures.
    owned = dict(rights)
    try:
        return _start_role_owned(runtime=runtime, role=role, payload=payload,
                                 rights=owned, control=control, **options)
    except BaseException:
        while owned:
            _, fd = owned.popitem()
            try: os.close(fd)
            except OSError: pass
        for peer in options.get('stdin_pair') or ():
            try: peer.close()
            except OSError: pass
        raise


class _ClippedControl:
    """Clip time while delegating every cancellation check to the original owner."""
    def __init__(self,parent,deadline):
        self.parent=parent
        self.deadline=min(parent.deadline,deadline)
        self.cancelled=getattr(parent,'cancelled',None)
        self.clock=getattr(parent,'clock',time.monotonic)
    def remaining(self):
        self.parent.check()
        remaining=min(self.parent.remaining(),self.deadline-self.clock())
        if remaining<=0:_fail('timeout')
        return remaining
    def check(self):self.remaining()


class _WorkerControl:
    def __init__(self,deadline_ns):
        self.deadline=deadline_ns/1e9;self.clock=time.monotonic;self.cancelled=None
    def remaining(self):
        remaining=self.deadline-time.monotonic()
        if remaining<=0:_fail('timeout')
        return remaining
    def check(self):self.remaining()


def _meter_bytes(encoded,maximum):
    import base64
    if type(encoded)is not str or len(encoded)>((maximum+2)//3)*4:_fail('evidence_invalid')
    try:raw=base64.b64decode(encoded,validate=True)
    except (ValueError,TypeError):_fail('evidence_invalid')
    if len(raw)>maximum or base64.b64encode(raw).decode('ascii')!=encoded:_fail('evidence_invalid')
    return raw


def validate_meter_event(value):
    s=SPEC['output_and_evidence']
    _fields(value,s['meter_event_exact_fields'])
    _integer(value['sequence'],1,64);_integer(value['monotonic_ns'],1)
    if value['kind'] not in s['meter_event_kind']:_fail('evidence_invalid')
    _integer(value['connection'],0,3)
    for key in ('requested_bytes','actual_bytes','remaining_before','remaining_after'):_integer(value[key],0,4096)
    if value['reason']is not None and value['reason'] not in s['reason_enum']:_fail('evidence_invalid')
    if value['actual_bytes']>value['requested_bytes'] or value['requested_bytes']>value['remaining_before'] or value['remaining_after']!=value['remaining_before']-value['actual_bytes']:_fail('evidence_invalid')
    return json.loads(_json(value))


def validate_meter(value):
    s=SPEC['output_and_evidence']
    _fields(value,s['meter_exact_fields'])
    if value['schema_version']!='1' or value['slot'] not in ('http_identify','http_headers'):_fail('evidence_invalid')
    for key in ('endpoint_id','session_id','dispatch_id'):
        if type(value[key])is not str or _UUID.fullmatch(value[key])is None:_fail('evidence_invalid')
    for key in ('envelope_sha256','go_sha256','request_sha256','response_sha256'):_digest(value[key])
    if type(value['arm_sequence'])is not int or value['arm_sequence']!=1:_fail('evidence_invalid')
    caps=s['meter_raw_payload_caps'][value['slot']]
    request=_meter_bytes(value['request_base64'],caps['request']);response=_meter_bytes(value['response_base64'],caps['response'])
    if hashlib.sha256(request).hexdigest()!=value['request_sha256'] or hashlib.sha256(response).hexdigest()!=value['response_sha256']:_fail('evidence_invalid')
    if value['reason'] not in s['reason_enum'] or type(value['delivery_known'])is not bool:_fail('evidence_invalid')
    for key in ('armed_at_ns','finished_at_ns'):
        if value[key]is not None:_integer(value[key],1)
    if value['delivery_known']:
        _integer(value['accepted_connections'],0,3 if value['slot']=='http_identify' else 1)
        if type(value['received_request_bytes'])is not int or value['received_request_bytes']!=len(request):_fail('evidence_invalid')
        if type(value['sent_response_bytes'])is not int or value['sent_response_bytes']!=len(response):_fail('evidence_invalid')
        if value['finished_at_ns']is None or value['armed_at_ns']is None or value['finished_at_ns']<value['armed_at_ns']:_fail('evidence_invalid')
    elif any(value[k]is not None for k in ('accepted_connections','received_request_bytes','sent_response_bytes','finished_at_ns')):_fail('evidence_invalid')
    events=value['events']
    if type(events)is not list or not 1<=len(events)<=64 or len(_json(value))>32768:_fail('evidence_invalid')
    previous=0;received=sent=accepted=0;closed=False
    for sequence,row in enumerate(events,1):
        validate_meter_event(row)
        if row['sequence']!=sequence or closed or row['monotonic_ns']<previous:_fail('evidence_invalid')
        previous=row['monotonic_ns']
        _integer(row['connection'],0,3 if value['slot']=='http_identify' else 1)
        kind=row['kind']
        if (kind=='arm')!=(sequence==1) or sequence==1 and row['monotonic_ns']!=value['armed_at_ns']:_fail('evidence_invalid')
        if kind=='accept':accepted+=1
        if row['connection']!=accepted:_fail('evidence_invalid')
        if kind in ('recv','send'):
            before=caps['request']-received if kind=='recv' else caps['response']-sent
            if not accepted or row['remaining_before']!=before or not 1<=row['actual_bytes']<=row['requested_bytes']:_fail('evidence_invalid')
            if kind=='recv':received+=row['actual_bytes']
            else:sent+=row['actual_bytes']
        elif any(row[key] for key in ('requested_bytes','actual_bytes','remaining_before','remaining_after')):_fail('evidence_invalid')
        if kind in ('close','cancel'):
            if row['reason']is None:_fail('evidence_invalid')
        elif row['reason']is not None:_fail('evidence_invalid')
        if kind=='close':
            closed=True
            if row['reason']!=value['reason'] or value['delivery_known'] and row['monotonic_ns']!=value['finished_at_ns']:_fail('evidence_invalid')
    if received!=len(request) or sent!=len(response):_fail('evidence_invalid')
    if value['delivery_known'] and (not closed or accepted!=value['accepted_connections']):_fail('evidence_invalid')
    if value['reason']=='complete' and not value['delivery_known']:_fail('evidence_invalid')
    return json.loads(_json(value))



def _send_bytes(channel,raw,control):
    import select
    import socket
    while not select.select([],[channel],[],_remaining(control,.01))[1]:_check(control)
    if channel.send(raw,socket.MSG_DONTWAIT|getattr(socket,'MSG_NOSIGNAL',0))!=len(raw):_fail('unavailable')
    _check(control)


def _receive_bytes(channel,maximum,control):
    import array
    import select
    import socket
    while not select.select([channel],[],[],_remaining(control,.01))[0]:_check(control)
    raw,ancillary,flags,_=channel.recvmsg(maximum+1,socket.CMSG_SPACE(32*array.array('i').itemsize),socket.MSG_DONTWAIT|socket.MSG_CMSG_CLOEXEC)
    for level,kind,data in ancillary:
        if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
            fds=array.array('i');fds.frombytes(data[:len(data)-len(data)%fds.itemsize])
            for fd in fds:os.close(fd)
    if ancillary or flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC) or not raw or len(raw)>maximum:_fail('invalid_frame')
    _check(control);return raw
