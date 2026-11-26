"""Intrinsic public-result grammar; no authority or runtime proof."""

RESULT_MAX_BYTES = 1024
RESULT_MAX_DEPTH = 12
RESULT_FIELDS = (
    'schema_version', 'operation_id', 'outcome',
    'service_identifier', 'service_status', 'http_status',
)
UUID4_PATTERN = r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}'
# outcome, service identifier, service status, HTTP status
RESULT_RELATIONS = (
    ('ready', 'recon-owned-status-v1', 'ready', 200),
    ('degraded', 'recon-owned-status-v1', 'degraded', 200),
    ('authentication_refused', None, None, 401),
    ('authorization_refused', None, None, 403),
    ('authority_refused', None, None, None),
    ('tls_refused', None, None, None),
    ('invalid_response', None, None, None),
    ('unsupported_response', None, None, None),
    ('limit_exceeded', None, None, None),
    ('cancelled', None, None, None),
    ('interrupted_unknown', None, None, None),
    ('cleanup_failed', None, None, None),
)

# Intrinsic ROE declarations only; these do not represent available authority.
ROE_MAX_BYTES = 4096
ROE_MAX_DEPTH = 2
ROE_FIELDS = (
    'active_operation_limit', 'allowed_fixture_ids', 'budgets', 'engagement_id',
    'excluded_operations', 'expires_utc', 'included_operations', 'not_before_utc',
    'operation_profile_sha256', 'previous_revision_sha256', 'revision',
    'runtime_lock_sha256', 'schema_version', 'trust_sha256',
)
ROE_BUDGET_MAXIMA = (
    ('actions', 64), ('connections', 64), ('inbound_tls_bytes', 1048576),
    ('outbound_tls_bytes', 524288), ('runtime_ms', 320000),
)
ROE_FIXTURES = ('allowed', 'invalid', 'restricted')
ROE_OPERATION = 'synthetic-service-status-v1'
ROE_PROFILE_SHA256 = 'b0e32be82eb77085db8fed7a165cab5c13ca2219247958f69dfe0ed8fc47d5e2'
SHA256_PATTERN = r'[0-9a-f]{64}'
ROE_UTC_PATTERN = r'([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{6})Z'

# Single lease snapshots only; external authority and transitions stay gated.
LEASE_MAX_BYTES = 4096
LEASE_MAX_DEPTH = 1
LEASE_FIELDS = (
    'action_sha256', 'approval_id', 'broker_id', 'cancel_requested',
    'cleanup_deadline_ns', 'clock_epoch_id', 'close_kind', 'closure_event_id',
    'completion_event_id', 'credential_reference', 'engagement_id', 'expires_utc',
    'fixture_id', 'generation', 'lease_id', 'operation_id',
    'operation_profile_sha256', 'operation_started_ns', 'prepared_utc',
    'release_event_id', 'request_template_sha256', 'reservation_id', 'review_view',
    'reviewer_id', 'revision', 'roe_sha256', 'runtime_lock_sha256', 'schema_version',
    'session_id', 'state', 'store_owner_id', 'trust_sha256', 'work_deadline_ns',
)
LEASE_UUID_FIELDS = (
    'approval_id', 'broker_id', 'clock_epoch_id', 'credential_reference',
    'engagement_id', 'lease_id', 'operation_id', 'reviewer_id', 'session_id',
    'store_owner_id',
)
LEASE_LINK_FIELDS = (
    'closure_event_id', 'completion_event_id', 'release_event_id', 'reservation_id',
)
LEASE_HASH_FIELDS = (
    'action_sha256', 'operation_profile_sha256', 'request_template_sha256',
    'roe_sha256', 'runtime_lock_sha256', 'trust_sha256',
)
LEASE_TIME_FIELDS = ('operation_started_ns', 'work_deadline_ns', 'cleanup_deadline_ns')

# Intrinsic event records only; no ledger, transaction or observation authority.
EVENT_MAX_BYTES = 4096
EVENT_MAX_DEPTH = 3
EVENT_FIELDS = (
    'actor_owner_id', 'actor_session_id', 'details', 'engagement_id', 'event_id',
    'generation', 'kind', 'lease_id', 'operation_id', 'previous_event_sha256',
    'recorded_utc', 'revision', 'schema_version', 'sequence', 'transaction_id',
)
EVENT_SCALARS = (
    ('actor_owner_id', 'uuid4'), ('actor_session_id', 'uuid4'),
    ('engagement_id', 'uuid4'), ('event_id', 'uuid4'), ('generation', 'generation'),
    ('kind', 'event_kind'), ('lease_id', 'uuid4?'), ('operation_id', 'uuid4?'),
    ('previous_event_sha256', 'sha256?'), ('recorded_utc', 'utc'),
    ('revision', 'revision'), ('schema_version', 's43-event-v1'),
    ('sequence', 'event_sequence'), ('transaction_id', 'uuid4'),
)
EVENT_BUDGET_VECTOR = (
    ('actions', 1), ('connections', 1), ('inbound_tls_bytes', 16384),
    ('outbound_tls_bytes', 8192), ('runtime_ms', 5000),
)
EVENT_VARIANTS = {
    'allowance_reserved': ('lease', (
        ('cleanup_deadline_ns', 'monotonic_ns'), ('operation_started_ns', 'monotonic_ns'),
        ('reservation_id', 'uuid4'), ('reserved', 'budget_vector'),
        ('usage_after', 'budget_totals'), ('work_deadline_ns', 'monotonic_ns'),
    )),
    'cancellation_requested': ('lease', (('reason', 'cancel_reason'),)),
    'credential_released': ('lease', (('reservation_id', 'uuid4'), ('tls_observation_id', 'uuid4'))),
    'engagement_revoked': ('engagement', (('previous_generation', 'generation'),)),
    'exchange_observed': ('lease', (
        ('phase', 'pre_write'), ('progress_observation_id', 'uuid4'), ('release_event_id', 'uuid4'),
    )),
    'lease_closed': ('lease', (
        ('cleanup_observation_id', 'uuid4'), ('close_kind', 'close_kind'), ('completion_event_id', 'uuid4?'),
    )),
    'lease_prepared': ('lease', (('lease_binding_sha256', 'sha256'),)),
    'owner_recovered': ('engagement', (('cleanup_observation_id', 'uuid4'), ('previous_owner_id', 'uuid4'))),
    'result_observed': ('lease', (('result', 'public_result'),)),
    'result_recorded': ('lease', (('observation_event_id', 'uuid4'), ('result_sha256', 'sha256'))),
    'roe_adopted': ('engagement', (('previous_revision_sha256', 'sha256?'), ('roe_sha256', 'sha256'))),
}

# Intrinsic observation records only; no producer authentication or registry.
OBSERVATION_MAX_BYTES = 4096
OBSERVATION_MAX_DEPTH = 3
OBSERVATION_FIELDS = (
    'action_sha256', 'clock_epoch_id', 'engagement_id', 'issuer_instance_id',
    'issuer_role', 'kind', 'lease_id', 'observed_monotonic_ns', 'observer_owner_id',
    'observer_session_id', 'operation_id', 'payload', 'reference_id',
    'runtime_lock_sha256', 'schema_version', 'subject_generation', 'subject_owner_id',
)
OBSERVATION_SCALARS = (
    ('action_sha256', 'sha256?'), ('clock_epoch_id', 'uuid4'),
    ('engagement_id', 'uuid4'), ('issuer_instance_id', 'uuid4'),
    ('issuer_role', 'producer_role'), ('kind', 'observation_kind'),
    ('lease_id', 'uuid4?'), ('observed_monotonic_ns', 'monotonic_ns'),
    ('observer_owner_id', 'uuid4'), ('observer_session_id', 'uuid4'),
    ('operation_id', 'uuid4?'), ('reference_id', 'uuid4'),
    ('runtime_lock_sha256', 'sha256'), ('schema_version', 's43-observation-v1'),
    ('subject_generation', 'generation?'), ('subject_owner_id', 'uuid4'),
)
OBSERVATION_ENUMS = {
    'producer_role': ('broker', 'reviewer', 'lifecycle_monitor', 'operation_worker', 'release_guard'),
    'cleanup_scope': ('operation_graph', 'owner_graph'),
    'fixture_id': ('allowed', 'invalid', 'restricted'),
    'review_view': ('terminal', 'graphical'),
}
OBSERVATION_LITERALS = (
    's43-observation-v1', 'TLSv1.2', 'ECDHE-RSA-AES128-GCM-SHA256',
    'http/1.1', 'approved',
)
OBSERVATION_SUBJECT_FIELDS = ('operation_id', 'lease_id', 'action_sha256', 'subject_generation')
OBSERVATION_VARIANTS = {
    'action_prepared': ('broker', 'operation_before_lease', (
        ('credential_reference', 'uuid4'), ('fixture_id', 'fixture_id'),
        ('operation_profile_sha256', 'sha256'), ('request_template_sha256', 'sha256'),
        ('revision', 'revision'), ('roe_sha256', 'sha256'), ('trust_sha256', 'sha256'),
    )),
    'approval_recorded': ('reviewer', 'operation_before_lease', (
        ('action_reference_id', 'uuid4'), ('approval_id', 'uuid4'), ('decision', 'approved'),
        ('review_view', 'review_view'), ('reviewed_action_sha256', 'sha256'),
    )),
    'graph_closed': ('lifecycle_monitor', 'operation_or_owner_graph', (
        ('descriptors_closed', 'true'), ('graph_id', 'uuid4'),
        ('physical_receipt_id', 'uuid4'), ('processes_reaped', 'true'), ('scope', 'cleanup_scope'),
    )),
    'pre_write_reached': ('operation_worker', 'operation_lease', (
        ('phase', 'pre_write'), ('release_event_id', 'uuid4'), ('socket_observation_id', 'uuid4'),
    )),
    'result_released': ('release_guard', 'operation_lease', (('result', 'public_result'),)),
    'tls_verified': ('operation_worker', 'operation_lease', (
        ('negotiated_alpn', 'http/1.1'), ('negotiated_cipher', 'ECDHE-RSA-AES128-GCM-SHA256'),
        ('negotiated_version', 'TLSv1.2'), ('peer_certificate_sha256', 'sha256'),
        ('session_reused', 'false'), ('socket_observation_id', 'uuid4'), ('trust_sha256', 'sha256'),
    )),
}

# Partial intrinsic receipt coverage; no physical custody or authority proof.
CUSTODY_RECEIPT_MAX_BYTES = 4096
CUSTODY_RECEIPT_MAX_DEPTH = 3
CUSTODY_RECEIPT_FIELDS = (
    'clock_epoch_id', 'graph_id', 'issuer_instance_id', 'issuer_role', 'kind',
    'observed_monotonic_ns', 'observer_session_id', 'operation_id', 'payload',
    'phase', 'receipt_id', 'runtime_lock_sha256', 'schema_version', 'subject_owner_id',
)
CUSTODY_RECEIPT_SCALARS = (
    ('clock_epoch_id', 'uuid4'), ('graph_id', 'uuid4'), ('issuer_instance_id', 'uuid4'),
    ('issuer_role', 'role'), ('kind', 'custody_receipt_kind'),
    ('observed_monotonic_ns', 'monotonic_ns'), ('observer_session_id', 'uuid4'),
    ('operation_id', 'uuid4?'), ('phase', 'phase'), ('receipt_id', 'uuid4'),
    ('runtime_lock_sha256', 'sha256'), ('schema_version', 's43-physical-receipt-v1'),
    ('subject_owner_id', 'uuid4'),
)
CUSTODY_RECEIPT_ENUMS = {
    'role': ('driver', 'supervisor', 'broker', 'reviewer', 'fixture_source', 'connector',
             'operation_worker', 'release_guard', 'owned_service', 'graphical_display', 'fixture_probe'),
    'phase': ('ready', 'socket_transferred', 'credential_transferred', 'result_released', 'closed'),
    'fixture_id': ('allowed', 'invalid', 'restricted'),
}
CUSTODY_RECEIPT_LITERALS = (
    's43-physical-receipt-v1', 'tcp', '127.0.0.1', 'read_only', 'write_grow_shrink_seal',
)
CUSTODY_RECEIPT_INTEGER_BOUNDS = {
    'u64': (0, 18446744073709551615), 'port': (1, 65535),
    'service_port': (9443, 9443), 'credential_size': (1, 64),
}
CUSTODY_RECEIPT_VARIANTS = {
    'socket_custody': (
        ('local_address', '127.0.0.1'), ('local_port', 'port'), ('network_namespace_inode', 'u64'),
        ('peer_address', '127.0.0.1'), ('peer_port', 'service_port'), ('protocol', 'tcp'),
        ('receiver_descriptor_receipt_id', 'uuid4'), ('receiver_instance_id', 'uuid4'),
        ('sender_aliases_closed', 'true'), ('sender_descriptor_receipt_id', 'uuid4'),
        ('sender_instance_id', 'uuid4'), ('socket_observation_id', 'uuid4'), ('transfer_id', 'uuid4'),
    ),
    'source_custody': (
        ('access_mode', 'read_only'), ('fixture_id', 'fixture_id'),
        ('receiver_descriptor_receipt_id', 'uuid4'), ('receiver_instance_id', 'uuid4'),
        ('release_event_id', 'uuid4'), ('seals', 'write_grow_shrink_seal'), ('size_bytes', 'credential_size'),
        ('source_aliases_closed', 'true'), ('source_descriptor_receipt_id', 'uuid4'),
        ('source_instance_id', 'uuid4'), ('transfer_id', 'uuid4'), ('writable_aliases_closed', 'true'),
    ),
}

# Intrinsic descriptor syntax only; declared nullability eligibility stays external.
DESCRIPTOR_RECEIPT_MAX_BYTES = 4096
DESCRIPTOR_RECEIPT_MAX_DEPTH = 3
DESCRIPTOR_RECEIPT_FIELDS = (
    'clock_epoch_id', 'graph_id', 'issuer_instance_id', 'issuer_role', 'kind',
    'observed_monotonic_ns', 'observer_session_id', 'operation_id', 'payload',
    'phase', 'receipt_id', 'runtime_lock_sha256', 'schema_version', 'subject_owner_id',
)
DESCRIPTOR_RECEIPT_SCALARS = (
    ('clock_epoch_id', 'uuid4'), ('graph_id', 'uuid4'), ('issuer_instance_id', 'uuid4'),
    ('issuer_role', 'role'), ('kind', 'descriptor_identity'),
    ('observed_monotonic_ns', 'monotonic_ns'), ('observer_session_id', 'uuid4'),
    ('operation_id', 'uuid4?'), ('phase', 'phase'), ('receipt_id', 'uuid4'),
    ('runtime_lock_sha256', 'sha256'), ('schema_version', 's43-physical-receipt-v1'),
    ('subject_owner_id', 'uuid4'),
)
DESCRIPTOR_RECEIPT_PAYLOAD = (
    ('access_mode', 'access_mode'), ('close_on_exec', 'true'), ('device', 'u64'), ('fd_number', 'fd'),
    ('holder_instance_id', 'uuid4'), ('inode', 'u64'), ('object_kind', 'object_kind'),
    ('peer_instance_id', 'uuid4?'), ('process_receipt_id', 'uuid4'), ('seals', 'seals'),
    ('transfer_id', 'uuid4?'),
)
DESCRIPTOR_RECEIPT_ENUMS = {
    'access_mode': ('read_only', 'write_only', 'read_write'),
    'object_kind': ('credential_memfd', 'connected_socket', 'seqpacket', 'pipe', 'null_sink',
                    'authority_file', 'display_socket', 'other_pinned_bootstrap_object'),
    'seals': ('none', 'write_grow_shrink_seal'),
}
DESCRIPTOR_RECEIPT_ISSUER_ROLES = ('supervisor', 'driver', 'fixture_source', 'connector', 'operation_worker')
DESCRIPTOR_RECEIPT_FD_BOUNDS = (0, 2147483647)

# Intrinsic process claims only; live identity and runtime eligibility stay external.
PROCESS_RECEIPT_MAX_BYTES = 4096
PROCESS_RECEIPT_MAX_DEPTH = 3
PROCESS_RECEIPT_FIELDS = (
    'clock_epoch_id', 'graph_id', 'issuer_instance_id', 'issuer_role', 'kind',
    'observed_monotonic_ns', 'observer_session_id', 'operation_id', 'payload',
    'phase', 'receipt_id', 'runtime_lock_sha256', 'schema_version', 'subject_owner_id',
)
PROCESS_RECEIPT_SCALARS = (
    ('clock_epoch_id', 'uuid4'), ('graph_id', 'uuid4'), ('issuer_instance_id', 'uuid4'),
    ('issuer_role', 'role'), ('kind', 'process_identity'),
    ('observed_monotonic_ns', 'monotonic_ns'), ('observer_session_id', 'uuid4'),
    ('operation_id', 'uuid4?'), ('phase', 'phase'), ('receipt_id', 'uuid4'),
    ('runtime_lock_sha256', 'sha256'), ('schema_version', 's43-physical-receipt-v1'),
    ('subject_owner_id', 'uuid4'),
)
PROCESS_RECEIPT_PAYLOAD = (
    ('boot_id', 'uuid4'), ('effective_capabilities', 'cap_mask'), ('gid', 'uid_gid'),
    ('instance_id', 'uuid4'), ('no_new_privileges', 'true'),
    ('observer_pid_namespace_inode', 'u64'), ('parent_instance_id', 'uuid4?'),
    ('pid_in_observer_namespace', 'pid'), ('pid_in_subject_namespace', 'pid'),
    ('pidfd_reference', 'uuid4'), ('role', 'role'), ('runtime_image_sha256', 'sha256'),
    ('start_ticks', 'u64'), ('subject_pid_namespace_inode', 'u64'),
    ('task_count', 'task_count'), ('uid', 'uid_gid'),
)
PROCESS_RECEIPT_INTEGER_BOUNDS = {
    'pid': (1, 2147483647), 'uid_gid': (0, 4294967294), 'task_count': (1, 8),
}
PROCESS_RECEIPT_CAP_MASK_PATTERN = r'[0-9a-f]{16}'
# Subject role -> claimed issuer and static task ceiling; profile gates remain.
PROCESS_RECEIPT_ROLE_RULES = {
    'supervisor': ('driver', 1), 'broker': ('supervisor', 2),
    'reviewer': ('supervisor', 2), 'fixture_source': ('supervisor', 1),
    'connector': ('supervisor', 1), 'operation_worker': ('supervisor', 1),
    'release_guard': ('supervisor', 1), 'owned_service': ('supervisor', 1),
    'graphical_display': ('supervisor', 8), 'fixture_probe': ('supervisor', 1),
}

# Intrinsic termination claims only; actual reaping and closure remain external.
TERMINATION_RECEIPT_MAX_BYTES = 2048
TERMINATION_RECEIPT_MAX_DEPTH = 3
TERMINATION_RECEIPT_FIELDS = (
    'clock_epoch_id', 'graph_id', 'issuer_instance_id', 'issuer_role', 'kind',
    'observed_monotonic_ns', 'observer_session_id', 'operation_id', 'payload',
    'phase', 'receipt_id', 'runtime_lock_sha256', 'schema_version', 'subject_owner_id',
)
TERMINATION_RECEIPT_SCALARS = (
    ('clock_epoch_id', 'uuid4'), ('graph_id', 'uuid4'), ('issuer_instance_id', 'uuid4'),
    ('issuer_role', 'role'), ('kind', 'monitor_termination'),
    ('observed_monotonic_ns', 'monotonic_ns'), ('observer_session_id', 'uuid4'),
    ('operation_id', 'uuid4?'), ('phase', 'phase'), ('receipt_id', 'uuid4'),
    ('runtime_lock_sha256', 'sha256'), ('schema_version', 's43-physical-receipt-v1'),
    ('subject_owner_id', 'uuid4'),
)
TERMINATION_RECEIPT_PAYLOAD = (
    ('birth_process_receipt_id', 'uuid4'), ('exit_code', 'exit_code'),
    ('exit_status', 'exit_status'), ('instance_id', 'uuid4'), ('monitor_session_id', 'uuid4'),
    ('pidfd_reference', 'uuid4'), ('reaped_monotonic_ns', 'monotonic_ns'),
    ('si_pid', 'pid'), ('si_signo', 'sigchld'), ('si_uid', 'uid_gid'),
)
TERMINATION_RECEIPT_INTEGER_BOUNDS = {
    'exit_status': (0, 255), 'pid': (1, 2147483647), 'uid_gid': (0, 4294967294),
}
TERMINATION_RECEIPT_ENUMS = {'exit_code': ('CLD_EXITED', 'CLD_KILLED', 'CLD_DUMPED')}
TERMINATION_RECEIPT_LITERALS = {'monitor_termination': 'monitor_termination', 'sigchld': 'SIGCHLD'}
TERMINATION_RECEIPT_ISSUER_ROLES = ('supervisor', 'driver')

# Intrinsic closure claims only; registry membership and live cleanup are external.
GRAPH_CLOSURE_RECEIPT_MAX_BYTES = 4096
GRAPH_CLOSURE_RECEIPT_MAX_DEPTH = 3
GRAPH_CLOSURE_RECEIPT_MAX_MEMBERS = 11
GRAPH_CLOSURE_RECEIPT_FIELDS = (
    'clock_epoch_id', 'graph_id', 'issuer_instance_id', 'issuer_role', 'kind',
    'observed_monotonic_ns', 'observer_session_id', 'operation_id', 'payload',
    'phase', 'receipt_id', 'runtime_lock_sha256', 'schema_version', 'subject_owner_id',
)
GRAPH_CLOSURE_RECEIPT_SCALARS = (
    ('clock_epoch_id', 'uuid4'), ('graph_id', 'uuid4'), ('issuer_instance_id', 'uuid4'),
    ('issuer_role', 'role'), ('kind', 'graph_closure'),
    ('observed_monotonic_ns', 'monotonic_ns'), ('observer_session_id', 'uuid4'),
    ('operation_id', 'uuid4?'), ('phase', 'phase'), ('receipt_id', 'uuid4'),
    ('runtime_lock_sha256', 'sha256'), ('schema_version', 's43-physical-receipt-v1'),
    ('subject_owner_id', 'uuid4'),
)
GRAPH_CLOSURE_RECEIPT_PAYLOAD = (
    ('expected_processes', 'process_count'), ('graph_id', 'uuid4'),
    ('graph_manifest_sha256', 'sha256'), ('member_process_receipt_ids', 'receipt_id_set'),
    ('outstanding_transfers', 'zero'), ('reaped_processes', 'process_count'),
    ('reason', 'closure_reason'), ('remaining_descriptors', 'zero'),
    ('scope', 'graph_scope'), ('validated_receipt_set_sha256', 'sha256'),
)
GRAPH_CLOSURE_RECEIPT_INTEGER_BOUNDS = {'process_count': (0, 11), 'zero': (0, 0)}
GRAPH_CLOSURE_RECEIPT_ENUMS = {
    'closure_reason': ('operation_terminal', 'owner_recovery'),
    'graph_scope': ('operation_graph', 'owner_graph'),
}
GRAPH_CLOSURE_RECEIPT_ISSUER_ROLES = ('supervisor',)

# Intrinsic recovery binding claims only; continuous live custody is external.
RECOVERY_BINDING_MAX_BYTES = 2048
RECOVERY_BINDING_MAX_DEPTH = 3
RECOVERY_BINDING_LIST_BOUNDS = (1, 10)
RECOVERY_BINDING_FIELDS = (
    'clock_epoch_id', 'graph_id', 'issuer_instance_id', 'issuer_role', 'kind',
    'observed_monotonic_ns', 'observer_session_id', 'operation_id', 'payload',
    'phase', 'receipt_id', 'runtime_lock_sha256', 'schema_version', 'subject_owner_id',
)
RECOVERY_BINDING_SCALARS = (
    ('clock_epoch_id', 'uuid4'), ('graph_id', 'uuid4'), ('issuer_instance_id', 'uuid4'),
    ('issuer_role', 'role'), ('kind', 'recovery_closure_binding'),
    ('observed_monotonic_ns', 'monotonic_ns'), ('observer_session_id', 'uuid4'),
    ('operation_id', 'uuid4?'), ('phase', 'phase'), ('receipt_id', 'uuid4'),
    ('runtime_lock_sha256', 'sha256'), ('schema_version', 's43-physical-receipt-v1'),
    ('subject_owner_id', 'uuid4'),
)
RECOVERY_BINDING_PAYLOAD = (
    ('activation_id', 'uuid4'), ('challenge_id', 'uuid4'), ('consumer_owner_id', 'uuid4'),
    ('consumer_session_id', 'uuid4'), ('evaluated_monotonic_ns', 'monotonic_ns'),
    ('graph_closure_receipt_id', 'uuid4'), ('monitor_session_id', 'uuid4'),
    ('root_aliases_closed', 'true'), ('subject_graph_id', 'uuid4'),
    ('terminal_pidfds_verified', 'true'), ('termination_receipt_ids', 'uuid_list10'),
    ('transfers_empty', 'true'),
)
RECOVERY_BINDING_ISSUER_ROLES = ('supervisor',)
RECOVERY_BINDING_PHASE = 'closed'


# Intrinsic lifecycle claims only; actual waits, signals and live custody are external.
RECOVERY_LIFECYCLE_MAX_BYTES = 2048
RECOVERY_LIFECYCLE_MAX_DEPTH = 3
RECOVERY_LIFECYCLE_FIELDS = (
    'clock_epoch_id', 'graph_id', 'issuer_instance_id', 'issuer_role', 'kind',
    'observed_monotonic_ns', 'observer_session_id', 'operation_id', 'payload',
    'phase', 'receipt_id', 'runtime_lock_sha256', 'schema_version', 'subject_owner_id',
)
RECOVERY_LIFECYCLE_SCALARS = (
    ('clock_epoch_id', 'uuid4'), ('graph_id', 'uuid4'), ('issuer_instance_id', 'uuid4'),
    ('issuer_role', 'role'), ('kind', 'recovery_lifecycle'),
    ('observed_monotonic_ns', 'monotonic_ns'), ('observer_session_id', 'uuid4'),
    ('operation_id', 'uuid4?'), ('phase', 'phase'), ('receipt_id', 'uuid4'),
    ('runtime_lock_sha256', 'sha256'), ('schema_version', 's43-physical-receipt-v1'),
    ('subject_owner_id', 'uuid4'),
)
RECOVERY_LIFECYCLE_PAYLOAD = (
    ('bootstrap_manifest_sha256', 'sha256'), ('fd_layout_sha256', 'sha256'),
    ('filter_sha256', 'sha256'), ('monitor_session_id', 'uuid4'),
    ('observed_monotonic_ns', 'monotonic_ns'), ('pidfd_reference', 'uuid4'),
    ('recovery_instance_id', 'uuid4'), ('si_pid', 'pid'), ('si_signo', 'sigchld'),
    ('si_uid', 'uid_gid'), ('signal', 'signal'), ('state', 'lifecycle_state'),
    ('wait_code', 'wait_code'),
)
RECOVERY_LIFECYCLE_INTEGER_BOUNDS = {'pid': (1, 2147483647), 'uid_gid': (0, 4294967294)}
RECOVERY_LIFECYCLE_ENUMS = {
    'lifecycle_state': ('stopped', 'precontinue', 'continued'),
    'wait_code': ('CLD_STOPPED', 'CLD_CONTINUED'), 'signal': ('SIGSTOP', 'SIGCONT'),
}
RECOVERY_LIFECYCLE_LITERALS = {'recovery_lifecycle': 'recovery_lifecycle', 'sigchld': 'SIGCHLD'}
RECOVERY_LIFECYCLE_ISSUER_ROLES = ('supervisor',)
RECOVERY_LIFECYCLE_VALID_TUPLES = (
    ('stopped', 'CLD_STOPPED', 'SIGSTOP'), ('precontinue', 'CLD_STOPPED', 'SIGSTOP'),
    ('continued', 'CLD_CONTINUED', 'SIGCONT'),
)
