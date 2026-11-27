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


# Intrinsic prepared projection only; actual receives/bootstrap proof are external.
RECOVERY_PREPARED_MAX_BYTES = 2048
RECOVERY_PREPARED_MAX_DEPTH = 3
RECOVERY_PREPARED_FIELDS = (
    'clock_epoch_id', 'graph_id', 'issuer_instance_id', 'issuer_role', 'kind',
    'observed_monotonic_ns', 'observer_session_id', 'operation_id', 'payload',
    'phase', 'receipt_id', 'runtime_lock_sha256', 'schema_version', 'subject_owner_id',
)
RECOVERY_PREPARED_SCALARS = (
    ('clock_epoch_id', 'uuid4'), ('graph_id', 'uuid4'), ('issuer_instance_id', 'uuid4'),
    ('issuer_role', 'role'), ('kind', 'recovery_control_prepared'),
    ('observed_monotonic_ns', 'monotonic_ns'), ('observer_session_id', 'uuid4'),
    ('operation_id', 'uuid4?'), ('phase', 'phase'), ('receipt_id', 'uuid4'),
    ('runtime_lock_sha256', 'sha256'), ('schema_version', 's43-physical-receipt-v1'),
    ('subject_owner_id', 'uuid4'),
)
RECOVERY_PREPARED_PAYLOAD = (
    ('bootstrap_manifest_sha256', 'sha256'), ('case_id', 'uuid4'),
    ('channel_sequence', 'u64'), ('clock_epoch_id', 'uuid4'), ('database_open', 'false'),
    ('engagement_id', 'uuid4'), ('fd_layout_sha256', 'sha256'), ('filter_sha256', 'sha256'),
    ('image_sha256', 'sha256'), ('message_kind', 'control_kind_prepared'),
    ('monitor_session_id', 'uuid4'), ('old_owner_graph_id', 'uuid4'), ('old_owner_id', 'uuid4'),
    ('original_deadline_ns', 'monotonic_ns'), ('recovery_instance_id', 'uuid4'),
    ('recovery_owner_id', 'uuid4'), ('recovery_session_id', 'uuid4'), ('runtime_lock_sha256', 'sha256'),
)
RECOVERY_PREPARED_INTEGER_BOUNDS = {'u64': (0, 18446744073709551615)}
RECOVERY_PREPARED_LITERALS = {
    'recovery_control_prepared': 'recovery_control_prepared', 'control_kind_prepared': 'recovery_prepared',
}
RECOVERY_PREPARED_ISSUER_ROLES = ('supervisor', 'broker')


# Intrinsic activation projection only; receive/continuation/witness proof is external.
RECOVERY_ACTIVATE_MAX_BYTES = 2048
RECOVERY_ACTIVATE_MAX_DEPTH = 3
RECOVERY_ACTIVATE_FIELDS = (
    'clock_epoch_id', 'graph_id', 'issuer_instance_id', 'issuer_role', 'kind',
    'observed_monotonic_ns', 'observer_session_id', 'operation_id', 'payload',
    'phase', 'receipt_id', 'runtime_lock_sha256', 'schema_version', 'subject_owner_id',
)
RECOVERY_ACTIVATE_SCALARS = (
    ('clock_epoch_id', 'uuid4'), ('graph_id', 'uuid4'), ('issuer_instance_id', 'uuid4'),
    ('issuer_role', 'role'), ('kind', 'recovery_control_activate'),
    ('observed_monotonic_ns', 'monotonic_ns'), ('observer_session_id', 'uuid4'),
    ('operation_id', 'uuid4?'), ('phase', 'phase'), ('receipt_id', 'uuid4'),
    ('runtime_lock_sha256', 'sha256'), ('schema_version', 's43-physical-receipt-v1'),
    ('subject_owner_id', 'uuid4'),
)
RECOVERY_ACTIVATE_PAYLOAD = (
    ('activation_id', 'uuid4'), ('case_id', 'uuid4'), ('channel_sequence', 'u64'),
    ('clock_epoch_id', 'uuid4'), ('continued_receipt_id', 'uuid4'), ('cut_transaction_id', 'uuid4'),
    ('engagement_id', 'uuid4'), ('message_kind', 'control_kind_activate'),
    ('monitor_session_id', 'uuid4'), ('old_owner_graph_id', 'uuid4'), ('old_owner_id', 'uuid4'),
    ('original_deadline_ns', 'monotonic_ns'), ('owner_closure_receipt_id', 'uuid4'),
    ('recovery_instance_id', 'uuid4'), ('recovery_owner_id', 'uuid4'),
    ('recovery_session_id', 'uuid4'), ('runtime_lock_sha256', 'sha256'),
)
RECOVERY_ACTIVATE_INTEGER_BOUNDS = {'u64': (0, 18446744073709551615)}
RECOVERY_ACTIVATE_LITERALS = {
    'recovery_control_activate': 'recovery_control_activate', 'control_kind_activate': 'recovery_activate',
}
RECOVERY_ACTIVATE_ISSUER_ROLES = ('supervisor', 'broker')


# Intrinsic challenge projection only; receive/freshness/consumption proof is external.
RECOVERY_CHALLENGE_MAX_BYTES = 2048
RECOVERY_CHALLENGE_MAX_DEPTH = 3
RECOVERY_CHALLENGE_FIELDS = (
    'clock_epoch_id', 'graph_id', 'issuer_instance_id', 'issuer_role', 'kind',
    'observed_monotonic_ns', 'observer_session_id', 'operation_id', 'payload',
    'phase', 'receipt_id', 'runtime_lock_sha256', 'schema_version', 'subject_owner_id',
)
RECOVERY_CHALLENGE_SCALARS = (
    ('clock_epoch_id', 'uuid4'), ('graph_id', 'uuid4'), ('issuer_instance_id', 'uuid4'),
    ('issuer_role', 'role'), ('kind', 'recovery_control_challenge'),
    ('observed_monotonic_ns', 'monotonic_ns'), ('observer_session_id', 'uuid4'),
    ('operation_id', 'uuid4?'), ('phase', 'phase'), ('receipt_id', 'uuid4'),
    ('runtime_lock_sha256', 'sha256'), ('schema_version', 's43-physical-receipt-v1'),
    ('subject_owner_id', 'uuid4'),
)
RECOVERY_CHALLENGE_PAYLOAD = (
    ('activation_id', 'uuid4'), ('case_id', 'uuid4'), ('challenge_id', 'uuid4'),
    ('channel_sequence', 'u64'), ('clock_epoch_id', 'uuid4'),
    ('engagement_id', 'uuid4'), ('message_kind', 'control_kind_challenge'),
    ('monitor_session_id', 'uuid4'), ('old_owner_graph_id', 'uuid4'), ('old_owner_id', 'uuid4'),
    ('original_deadline_ns', 'monotonic_ns'), ('owner_closure_receipt_id', 'uuid4'),
    ('recovery_instance_id', 'uuid4'), ('recovery_owner_id', 'uuid4'),
    ('recovery_session_id', 'uuid4'), ('runtime_lock_sha256', 'sha256'),
)
RECOVERY_CHALLENGE_INTEGER_BOUNDS = {'u64': (0, 18446744073709551615)}
RECOVERY_CHALLENGE_LITERALS = {
    'recovery_control_challenge': 'recovery_control_challenge', 'control_kind_challenge': 'recovery_challenge',
}
RECOVERY_CHALLENGE_ISSUER_ROLES = ('supervisor', 'broker')


# Intrinsic response projection only; live binding completeness and authority are external.
RECOVERY_RESPONSE_MAX_BYTES = 2048
RECOVERY_RESPONSE_MAX_DEPTH = 3
RECOVERY_RESPONSE_FIELDS = (
    'clock_epoch_id', 'graph_id', 'issuer_instance_id', 'issuer_role', 'kind',
    'observed_monotonic_ns', 'observer_session_id', 'operation_id', 'payload',
    'phase', 'receipt_id', 'runtime_lock_sha256', 'schema_version', 'subject_owner_id',
)
RECOVERY_RESPONSE_SCALARS = (
    ('clock_epoch_id', 'uuid4'), ('graph_id', 'uuid4'), ('issuer_instance_id', 'uuid4'),
    ('issuer_role', 'role'), ('kind', 'recovery_control_response'),
    ('observed_monotonic_ns', 'monotonic_ns'), ('observer_session_id', 'uuid4'),
    ('operation_id', 'uuid4?'), ('phase', 'phase'), ('receipt_id', 'uuid4'),
    ('runtime_lock_sha256', 'sha256'), ('schema_version', 's43-physical-receipt-v1'),
    ('subject_owner_id', 'uuid4'),
)
RECOVERY_RESPONSE_PAYLOAD = (
    ('activation_id', 'uuid4'), ('binding_receipt_ids', 'uuid_list3'), ('case_id', 'uuid4'), ('challenge_id', 'uuid4'),
    ('channel_sequence', 'u64'), ('clock_epoch_id', 'uuid4'),
    ('engagement_id', 'uuid4'), ('message_kind', 'control_kind_response'),
    ('monitor_session_id', 'uuid4'), ('old_owner_graph_id', 'uuid4'), ('old_owner_id', 'uuid4'),
    ('original_deadline_ns', 'monotonic_ns'),
    ('recovery_instance_id', 'uuid4'), ('recovery_owner_id', 'uuid4'),
    ('recovery_session_id', 'uuid4'), ('runtime_lock_sha256', 'sha256'),
)
RECOVERY_RESPONSE_INTEGER_BOUNDS = {'u64': (0, 18446744073709551615)}
RECOVERY_RESPONSE_LITERALS = {
    'recovery_control_response': 'recovery_control_response', 'control_kind_response': 'recovery_response',
}
RECOVERY_RESPONSE_ISSUER_ROLES = ('supervisor', 'broker')
RECOVERY_RESPONSE_LIST_BOUNDS = (0, 3)


# Intrinsic refusal projection only; receive, cause and failed-witness checks are external.
RECOVERY_REFUSED_MAX_BYTES = 2048
RECOVERY_REFUSED_MAX_DEPTH = 3
RECOVERY_REFUSED_FIELDS = (
    'clock_epoch_id', 'graph_id', 'issuer_instance_id', 'issuer_role', 'kind',
    'observed_monotonic_ns', 'observer_session_id', 'operation_id', 'payload',
    'phase', 'receipt_id', 'runtime_lock_sha256', 'schema_version', 'subject_owner_id',
)
RECOVERY_REFUSED_SCALARS = (
    ('clock_epoch_id', 'uuid4'), ('graph_id', 'uuid4'), ('issuer_instance_id', 'uuid4'),
    ('issuer_role', 'role'), ('kind', 'recovery_control_refused'),
    ('observed_monotonic_ns', 'monotonic_ns'), ('observer_session_id', 'uuid4'),
    ('operation_id', 'uuid4?'), ('phase', 'phase'), ('receipt_id', 'uuid4'),
    ('runtime_lock_sha256', 'sha256'), ('schema_version', 's43-physical-receipt-v1'),
    ('subject_owner_id', 'uuid4'),
)
RECOVERY_REFUSED_PAYLOAD = (
    ('activation_id', 'uuid4'), ('case_id', 'uuid4'), ('challenge_id', 'uuid4'),
    ('channel_sequence', 'u64'), ('clock_epoch_id', 'uuid4'),
    ('engagement_id', 'uuid4'), ('message_kind', 'control_kind_refused'),
    ('monitor_session_id', 'uuid4'), ('old_owner_graph_id', 'uuid4'), ('old_owner_id', 'uuid4'),
    ('original_deadline_ns', 'monotonic_ns'), ('reason', 'recovery_reason'),
    ('recovery_instance_id', 'uuid4'), ('recovery_owner_id', 'uuid4'),
    ('recovery_session_id', 'uuid4'), ('runtime_lock_sha256', 'sha256'),
)
RECOVERY_REFUSED_INTEGER_BOUNDS = {'u64': (0, 18446744073709551615)}
RECOVERY_REFUSED_LITERALS = {
    'recovery_control_refused': 'recovery_control_refused', 'control_kind_refused': 'recovery_refused',
}
RECOVERY_REFUSED_ISSUER_ROLES = ('supervisor', 'broker')
RECOVERY_REFUSED_ENUMS = {
    'recovery_reason': ('binding_refused', 'bootstrap_refused', 'closure_unproved',
                        'deadline', 'resource_limit', 'unexpected_transition', 'authority_unavailable'),
}


# Intrinsic fixed-failure projection only; receive, cause and failed-witness checks are external.
RECOVERY_FIXED_FAILURE_MAX_BYTES = 2048
RECOVERY_FIXED_FAILURE_MAX_DEPTH = 3
RECOVERY_FIXED_FAILURE_FIELDS = (
    'clock_epoch_id', 'graph_id', 'issuer_instance_id', 'issuer_role', 'kind',
    'observed_monotonic_ns', 'observer_session_id', 'operation_id', 'payload',
    'phase', 'receipt_id', 'runtime_lock_sha256', 'schema_version', 'subject_owner_id',
)
RECOVERY_FIXED_FAILURE_SCALARS = (
    ('clock_epoch_id', 'uuid4'), ('graph_id', 'uuid4'), ('issuer_instance_id', 'uuid4'),
    ('issuer_role', 'role'), ('kind', 'recovery_control_fixed_failure'),
    ('observed_monotonic_ns', 'monotonic_ns'), ('observer_session_id', 'uuid4'),
    ('operation_id', 'uuid4?'), ('phase', 'phase'), ('receipt_id', 'uuid4'),
    ('runtime_lock_sha256', 'sha256'), ('schema_version', 's43-physical-receipt-v1'),
    ('subject_owner_id', 'uuid4'),
)
RECOVERY_FIXED_FAILURE_PAYLOAD = (
    ('bootstrap_manifest_sha256', 'sha256'), ('case_id', 'uuid4'), ('channel_sequence', 'u64'),
    ('clock_epoch_id', 'uuid4'), ('graph_id', 'uuid4'), ('message_kind', 'control_kind_fixed_failure'),
    ('owner_id', 'uuid4'), ('reason', 'failure_reason'), ('role', 'role'),
    ('role_instance_id', 'uuid4'), ('runtime_lock_sha256', 'sha256'),
    ('session_deadline_ns', 'monotonic_ns'), ('session_id', 'uuid4'), ('stage', 'stage'),
)
RECOVERY_FIXED_FAILURE_INTEGER_BOUNDS = {'u64': (0, 18446744073709551615)}
RECOVERY_FIXED_FAILURE_LITERALS = {
    'recovery_control_fixed_failure': 'recovery_control_fixed_failure', 'control_kind_fixed_failure': 'fixed_failure',
}
RECOVERY_FIXED_FAILURE_ISSUER_ROLES = ('supervisor', 'broker')
RECOVERY_FIXED_FAILURE_ENUMS = {
    'failure_reason': ('bootstrap_refused', 'binding_refused', 'protocol_refused',
                       'deadline', 'resource_limit', 'unexpected_exit', 'authority_unavailable'),
    'stage': ('bootstrap', 'ready', 'reserved', 'tls', 'released', 'exchange', 'cleanup'),
}


# Intrinsic progress claims only; live observations and interval proofs are external.
PROGRESS_MAX_BYTES = 3072
PROGRESS_MAX_DEPTH = 1
PROGRESS_FIELDS = (
    'clock_epoch_id', 'connection_attempts', 'credential_reads', 'graph_id',
    'http_requests', 'issuer_instance_id', 'issuer_role', 'observed_monotonic_ns',
    'operation_id', 'owner_id', 'perspective', 'plaintext_request_bytes',
    'plaintext_response_bytes', 'reason', 'record_id', 'runtime_lock_sha256',
    'sample_sequence', 'schema_version', 'server_received_requests', 'session_id',
    'stage', 'tls_handshakes', 'tls_inbound_bytes', 'tls_outbound_bytes',
)
PROGRESS_SCALARS = (
    ('clock_epoch_id', 'uuid4'), ('connection_attempts', 'count_or_unknown'),
    ('credential_reads', 'count_or_unknown'), ('graph_id', 'uuid4'),
    ('http_requests', 'count_or_unknown'), ('issuer_instance_id', 'uuid4'),
    ('issuer_role', 'progress_role'), ('observed_monotonic_ns', 'monotonic_ns'),
    ('operation_id', 'uuid4'), ('owner_id', 'uuid4'), ('perspective', 'progress_perspective'),
    ('plaintext_request_bytes', 'bytes_or_unknown'), ('plaintext_response_bytes', 'bytes_or_unknown'),
    ('reason', 'stop_reason_or_none'), ('record_id', 'uuid4'), ('runtime_lock_sha256', 'sha256'),
    ('sample_sequence', 'sample_sequence'), ('schema_version', 's43-progress-v1'),
    ('server_received_requests', 'count_or_unknown'), ('session_id', 'uuid4'),
    ('stage', 'progress_stage'), ('tls_handshakes', 'count_or_unknown'),
    ('tls_inbound_bytes', 'bytes_or_unknown'), ('tls_outbound_bytes', 'bytes_or_unknown'),
)
PROGRESS_INTEGER_BOUNDS = {
    'count_or_unknown': (0, 1), 'bytes_or_unknown': (0, 16384), 'sample_sequence': (1, 16),
}
PROGRESS_NULLABLE_TYPES = ('count_or_unknown', 'bytes_or_unknown', 'stop_reason_or_none')
PROGRESS_ENUMS = {
    'progress_role': ('connector', 'operation_worker', 'owned_service'),
    'progress_perspective': ('connector_local', 'client_local', 'server_local'),
    'progress_stage': ('prepared', 'reserved', 'socket_transferred', 'tls_verified',
                       'released', 'pre_write', 'exchange', 'closed'),
    'stop_reason_or_none': ('operator_cancel', 'deadline', 'authority_lost', 'revoked',
                            'protocol_failure', 'resource_limit', 'case_complete'),
}
PROGRESS_ROLE_PERSPECTIVES = {
    'connector': 'connector_local', 'operation_worker': 'client_local', 'owned_service': 'server_local',
}
PROGRESS_COUNTER_FIELDS = (
    'connection_attempts', 'credential_reads', 'http_requests', 'server_received_requests',
    'tls_handshakes', 'plaintext_request_bytes', 'plaintext_response_bytes',
    'tls_inbound_bytes', 'tls_outbound_bytes',
)
PROGRESS_KNOWN_FIELDS = {
    'connector_local': ('connection_attempts',),
    'client_local': ('credential_reads', 'http_requests', 'tls_handshakes',
                     'plaintext_request_bytes', 'plaintext_response_bytes', 'tls_inbound_bytes', 'tls_outbound_bytes'),
    'server_local': ('server_received_requests', 'tls_handshakes',
                     'plaintext_request_bytes', 'plaintext_response_bytes', 'tls_inbound_bytes', 'tls_outbound_bytes'),
}
PROGRESS_BYTE_CAPS = {
    'connector_local': (),
    'client_local': (('tls_outbound_bytes', 8192), ('tls_inbound_bytes', 16384),
                     ('plaintext_request_bytes', 512), ('plaintext_response_bytes', 2048)),
    'server_local': (('tls_outbound_bytes', 16384), ('tls_inbound_bytes', 8192),
                     ('plaintext_request_bytes', 512), ('plaintext_response_bytes', 2048)),
}


# Intrinsic public-manifest claims only; context and digest resolution are external.
PUBLIC_BINDING_MAX_BYTES = 3072
PUBLIC_BINDING_MAX_DEPTH = 2
PUBLIC_BINDING_MAX_RELATED_IDS = 11
PUBLIC_BINDING_FIELDS = (
    'kind', 'public_manifest_sha256', 'record_id', 'related_ids', 'schema_version', 'subject_id',
)
PUBLIC_BINDING_SCALARS = (
    ('kind', 'binding_kind'), ('public_manifest_sha256', 'sha256'), ('record_id', 'uuid4'),
    ('schema_version', 's43-public-binding-v1'), ('subject_id', 'uuid4'),
)
PUBLIC_BINDING_KINDS = ('runtime', 'graph', 'role', 'input', 'source_manifest')


# Intrinsic lookup claims only; live lookup and persisted crosslinks are external.
LOOKUP_OBSERVED_MAX_BYTES = 3072
LOOKUP_OBSERVED_MAX_DEPTH = 1
LOOKUP_OBSERVED_FIELDS = (
    'clock_epoch_id', 'closure_event_id', 'completion_event_id', 'issuer_instance_id',
    'lease_id', 'observed_monotonic_ns', 'operation_id', 'owner_id', 'record_id',
    'result_operation_id', 'runtime_lock_sha256', 'schema_version', 'session_id', 'status',
)
LOOKUP_OBSERVED_SCALARS = (
    ('clock_epoch_id', 'uuid4'), ('closure_event_id', 'uuid4?'),
    ('completion_event_id', 'uuid4?'), ('issuer_instance_id', 'uuid4'), ('lease_id', 'uuid4?'),
    ('observed_monotonic_ns', 'monotonic_ns'), ('operation_id', 'uuid4'), ('owner_id', 'uuid4'),
    ('record_id', 'uuid4'), ('result_operation_id', 'uuid4?'), ('runtime_lock_sha256', 'sha256'),
    ('schema_version', 's43-lookup-observed-v1'), ('session_id', 'uuid4'), ('status', 'lookup_status'),
)
LOOKUP_OBSERVED_STATUSES = ('closed', 'not_closed', 'absent', 'unavailable')
LOOKUP_OBSERVED_REFERENCES = ('lease_id', 'closure_event_id', 'completion_event_id', 'result_operation_id')


# Intrinsic transaction-result claims only; commit and live authority are external.
TRANSACTION_RESULT_MAX_BYTES = 1024
TRANSACTION_RESULT_MAX_DEPTH = 1
TRANSACTION_RESULT_FIELDS = (
    'call_id', 'last_event_sequence', 'lease_id', 'operation_id', 'reason',
    'schema_version', 'status', 'transaction_id',
)
TRANSACTION_RESULT_SCALARS = (
    ('call_id', 'uuid4'), ('last_event_sequence', 'event_sequence?'),
    ('lease_id', 'uuid4?'), ('operation_id', 'uuid4?'), ('reason', 'transaction_reason?'),
    ('schema_version', 's43-txn-result-v1'), ('status', 'transaction_status'),
    ('transaction_id', 'uuid4?'),
)
TRANSACTION_RESULT_STATUSES = ('committed', 'refused', 'unavailable', 'uncertain')
TRANSACTION_RESULT_REASONS = (
    'invalid_input', 'stale_authority', 'wrong_state', 'expired', 'budget_exhausted',
    'scope_refused', 'audit_unavailable', 'store_unavailable', 'commit_unknown', 'cleanup_unconfirmed',
)
TRANSACTION_RESULT_STATUS_REASONS = {
    'committed': (None,),
    'refused': ('invalid_input', 'stale_authority', 'wrong_state', 'expired',
                'budget_exhausted', 'scope_refused'),
    'unavailable': ('audit_unavailable', 'store_unavailable', 'cleanup_unconfirmed'),
    'uncertain': ('commit_unknown',),
}
TRANSACTION_RESULT_COMMIT_FIELDS = ('transaction_id', 'last_event_sequence', 'operation_id', 'lease_id')


# Intrinsic witness claims only; actual SQL boundaries and event validity are external.
TRANSACTION_WITNESS_MAX_BYTES = 3072
TRANSACTION_WITNESS_MAX_DEPTH = 2
TRANSACTION_WITNESS_MAX_EVENT_IDS = 2
TRANSACTION_WITNESS_FIELDS = (
    'barrier', 'call_id', 'event_ids', 'method', 'ordinal', 'record_id',
    'schema_version', 'transaction_result', 'writer_id',
)
TRANSACTION_WITNESS_SCALARS = (
    ('barrier', 'transaction_barrier'), ('call_id', 'uuid4'), ('method', 'transaction_method'),
    ('ordinal', 'positive_int'), ('record_id', 'uuid4'),
    ('schema_version', 's43-transaction-witness-v1'), ('writer_id', 'uuid4'),
)
TRANSACTION_WITNESS_METHODS = (
    'adopt_roe', 'cancel_lease', 'close_lease', 'observe_exchange', 'observe_result',
    'prepare_lease', 'recover_owner', 'release', 'reserve', 'revoke_engagement',
)
TRANSACTION_WITNESS_BARRIERS = (
    'call_entered', 'before_begin', 'after_begin', 'before_event_insert', 'before_commit',
    'after_commit_before_ack', 'refused', 'unknown_commit',
)


# Intrinsic planned-case claims only; actual execution and provenance are external.
CASE_CONTEXT_MAX_BYTES = 3072
CASE_CONTEXT_MAX_DEPTH = 1
CASE_CONTEXT_FIELDS = ('bundle_id',
 'case_id',
 'case_status',
 'code_manifest_sha256',
 'fixture_id',
 'graph_manifest_sha256',
 'node_id',
 'parent_id',
 'review_view',
 'runtime_lock_sha256',
 'schema_version',
 'variant_id')
CASE_CONTEXT_SCALARS = (('bundle_id', 'uuid4'),
 ('case_id', 'uuid4'),
 ('case_status', 'case_status'),
 ('code_manifest_sha256', 'sha256'),
 ('fixture_id', 'fixture_id'),
 ('graph_manifest_sha256', 'sha256'),
 ('node_id', 'planned_node_id'),
 ('parent_id', 'parent_id'),
 ('review_view', 'review_view'),
 ('runtime_lock_sha256', 'sha256'),
 ('schema_version', 's43-case-context-v1'),
 ('variant_id', 'variant_id'))
CASE_CONTEXT_VALUES = {'case_status': ('observed', 'refused', 'failed', 'interrupted_unknown'),
 'fixture_id': ('allowed', 'invalid', 'restricted'),
 'planned_node_id': ('tests/test_secure_synthetic_custody_linux.py::test_s43_a02[degraded]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a03[invalid_credential_401]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a04[restricted_credential_403]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a05[cookie]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a05[redirect]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a05[referral_header]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a05[second_request]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a05[token_refresh]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a06[certificate_name]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a06[cipher_suite]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a06[expired_certificate]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a06[host]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a06[numeric_endpoint]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a06[sni]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a06[tls_version]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a06[untrusted_ca]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a07[body_over_cap]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a07[chunked]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a07[compressed]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a07[duplicate_field]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a07[header_over_cap]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a07[invalid_utf8]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a07[malformed_json]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a07[partial_body]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a07[partial_headers]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a07[trailing_data]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a07[unexpected_http_status]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a07[unknown_schema]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a08[connection_cap]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a08[operator_cancel]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a08[plaintext_request_cap]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a08[plaintext_response_cap]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a08[process_cap]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a08[public_output_cap]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a08[revoke_after_release]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a08[tls_receive_cap]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a08[tls_send_cap]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_a08[work_deadline]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_authority[audit_failure_after_release]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_authority[audit_failure_before_release]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_authority[broker_restart_after_completion_before_ack]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_authority[broker_restart_after_release]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_authority[broker_restart_after_reservation]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_authority[completion_commit_failure]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_authority[concurrent_generation_writers]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_authority[distinct_actions_final_allowance]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_authority[release_commit_failure]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_authority[reservation_commit_failure]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k01[graphical]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k01[terminal]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k02[copied_handle]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k02[duplicate_consume]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k02[environment_source]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k02[file_source]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k02[foreign_action]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k02[foreign_engagement]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k02[foreign_service]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k02[legacy_source]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k03[clock_forward]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k03[clock_rollback]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k03[engagement_revocation]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k03[lease_expiry]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k03[lease_revocation]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k03[revoke_before_release]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k03[window_expiry]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k04[argv_environment]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k04[both_review_views]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k04[diagnostic_failure]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k04[fds_mounts]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k04[keylog_disabled]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k05[base64_body]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k05[error_body]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k05[json_escaped_body]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k05[literal_body]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k05[unknown_field]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k05[unknown_header]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k06[after_release_before_write]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k06[before_release]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k06[during_read]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k06[during_write]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k06[lost_completion_ack]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k07[arbitrary_path]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k07[environment_name]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k07[legacy_case_path]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k07[mode_switch]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_k07[unlisted_value]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_p02[ambient_credentials]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_p02[legacy_json]',
                     'tests/test_secure_synthetic_custody_linux.py::test_s43_p02[legacy_markdown]'),
 'parent_id': ('S4-A01',
               'S4-A02',
               'S4-A03',
               'S4-A04',
               'S4-A05',
               'S4-A06',
               'S4-A07',
               'S4-A08',
               'S4-K01',
               'S4-K02',
               'S4-K03',
               'S4-K04',
               'S4-K05',
               'S4-K06',
               'S4-K07',
               'S4-P02',
               'S43-AUTH01',
               'S43-AUTH02',
               'S43-AUTH03',
               'S43-AUTH04',
               'S43-AUTH05',
               'S43-AUTH06',
               'S43-AUTH07',
               'S43-AUTH08',
               'S43-AUTH09',
               'S43-AUTH10'),
 'review_view': ('terminal', 'graphical'),
 's43-case-context-v1': ('s43-case-context-v1',),
 'variant_id': ('after_release_before_write',
                'ambient_credentials',
                'arbitrary_path',
                'argv_environment',
                'audit_failure_after_release',
                'audit_failure_before_release',
                'base64_body',
                'before_release',
                'body_over_cap',
                'both_review_views',
                'broker_restart_after_completion_before_ack',
                'broker_restart_after_release',
                'broker_restart_after_reservation',
                'certificate_name',
                'chunked',
                'cipher_suite',
                'clock_forward',
                'clock_rollback',
                'completion_commit_failure',
                'compressed',
                'concurrent_generation_writers',
                'connection_cap',
                'cookie',
                'copied_handle',
                'degraded',
                'diagnostic_failure',
                'distinct_actions_final_allowance',
                'duplicate_consume',
                'duplicate_field',
                'during_read',
                'during_write',
                'engagement_revocation',
                'environment_name',
                'environment_source',
                'error_body',
                'expired_certificate',
                'fds_mounts',
                'file_source',
                'foreign_action',
                'foreign_engagement',
                'foreign_service',
                'graphical',
                'header_over_cap',
                'host',
                'invalid_credential_401',
                'invalid_utf8',
                'json_escaped_body',
                'keylog_disabled',
                'lease_expiry',
                'lease_revocation',
                'legacy_case_path',
                'legacy_json',
                'legacy_markdown',
                'legacy_source',
                'literal_body',
                'lost_completion_ack',
                'malformed_json',
                'mode_switch',
                'numeric_endpoint',
                'operator_cancel',
                'partial_body',
                'partial_headers',
                'plaintext_request_cap',
                'plaintext_response_cap',
                'process_cap',
                'public_output_cap',
                'redirect',
                'referral_header',
                'release_commit_failure',
                'reservation_commit_failure',
                'restricted_credential_403',
                'revoke_after_release',
                'revoke_before_release',
                'second_request',
                'sni',
                'terminal',
                'tls_receive_cap',
                'tls_send_cap',
                'tls_version',
                'token_refresh',
                'trailing_data',
                'unexpected_http_status',
                'unknown_field',
                'unknown_header',
                'unknown_schema',
                'unlisted_value',
                'untrusted_ca',
                'window_expiry',
                'work_deadline')}
CASE_CONTEXT_NATIVE_MAPPINGS = (('S4-A01', 'terminal', 'tests/test_secure_synthetic_custody_linux.py::test_s43_k01[terminal]'),
 ('S4-A02', 'degraded', 'tests/test_secure_synthetic_custody_linux.py::test_s43_a02[degraded]'),
 ('S4-A03',
  'invalid_credential_401',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_a03[invalid_credential_401]'),
 ('S4-A04',
  'restricted_credential_403',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_a04[restricted_credential_403]'),
 ('S4-A05', 'cookie', 'tests/test_secure_synthetic_custody_linux.py::test_s43_a05[cookie]'),
 ('S4-A05', 'redirect', 'tests/test_secure_synthetic_custody_linux.py::test_s43_a05[redirect]'),
 ('S4-A05', 'referral_header', 'tests/test_secure_synthetic_custody_linux.py::test_s43_a05[referral_header]'),
 ('S4-A05', 'second_request', 'tests/test_secure_synthetic_custody_linux.py::test_s43_a05[second_request]'),
 ('S4-A05', 'token_refresh', 'tests/test_secure_synthetic_custody_linux.py::test_s43_a05[token_refresh]'),
 ('S4-A06',
  'certificate_name',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_a06[certificate_name]'),
 ('S4-A06', 'cipher_suite', 'tests/test_secure_synthetic_custody_linux.py::test_s43_a06[cipher_suite]'),
 ('S4-A06',
  'expired_certificate',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_a06[expired_certificate]'),
 ('S4-A06', 'host', 'tests/test_secure_synthetic_custody_linux.py::test_s43_a06[host]'),
 ('S4-A06',
  'numeric_endpoint',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_a06[numeric_endpoint]'),
 ('S4-A06', 'sni', 'tests/test_secure_synthetic_custody_linux.py::test_s43_a06[sni]'),
 ('S4-A06', 'tls_version', 'tests/test_secure_synthetic_custody_linux.py::test_s43_a06[tls_version]'),
 ('S4-A06', 'untrusted_ca', 'tests/test_secure_synthetic_custody_linux.py::test_s43_a06[untrusted_ca]'),
 ('S4-A07', 'body_over_cap', 'tests/test_secure_synthetic_custody_linux.py::test_s43_a07[body_over_cap]'),
 ('S4-A07', 'chunked', 'tests/test_secure_synthetic_custody_linux.py::test_s43_a07[chunked]'),
 ('S4-A07', 'compressed', 'tests/test_secure_synthetic_custody_linux.py::test_s43_a07[compressed]'),
 ('S4-A07', 'duplicate_field', 'tests/test_secure_synthetic_custody_linux.py::test_s43_a07[duplicate_field]'),
 ('S4-A07', 'header_over_cap', 'tests/test_secure_synthetic_custody_linux.py::test_s43_a07[header_over_cap]'),
 ('S4-A07', 'invalid_utf8', 'tests/test_secure_synthetic_custody_linux.py::test_s43_a07[invalid_utf8]'),
 ('S4-A07', 'malformed_json', 'tests/test_secure_synthetic_custody_linux.py::test_s43_a07[malformed_json]'),
 ('S4-A07', 'partial_body', 'tests/test_secure_synthetic_custody_linux.py::test_s43_a07[partial_body]'),
 ('S4-A07', 'partial_headers', 'tests/test_secure_synthetic_custody_linux.py::test_s43_a07[partial_headers]'),
 ('S4-A07', 'trailing_data', 'tests/test_secure_synthetic_custody_linux.py::test_s43_a07[trailing_data]'),
 ('S4-A07',
  'unexpected_http_status',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_a07[unexpected_http_status]'),
 ('S4-A07', 'unknown_schema', 'tests/test_secure_synthetic_custody_linux.py::test_s43_a07[unknown_schema]'),
 ('S4-A08', 'connection_cap', 'tests/test_secure_synthetic_custody_linux.py::test_s43_a08[connection_cap]'),
 ('S4-A08', 'operator_cancel', 'tests/test_secure_synthetic_custody_linux.py::test_s43_a08[operator_cancel]'),
 ('S4-A08',
  'plaintext_request_cap',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_a08[plaintext_request_cap]'),
 ('S4-A08',
  'plaintext_response_cap',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_a08[plaintext_response_cap]'),
 ('S4-A08', 'process_cap', 'tests/test_secure_synthetic_custody_linux.py::test_s43_a08[process_cap]'),
 ('S4-A08',
  'public_output_cap',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_a08[public_output_cap]'),
 ('S4-A08',
  'revoke_after_release',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_a08[revoke_after_release]'),
 ('S4-A08', 'tls_receive_cap', 'tests/test_secure_synthetic_custody_linux.py::test_s43_a08[tls_receive_cap]'),
 ('S4-A08', 'tls_send_cap', 'tests/test_secure_synthetic_custody_linux.py::test_s43_a08[tls_send_cap]'),
 ('S4-A08', 'work_deadline', 'tests/test_secure_synthetic_custody_linux.py::test_s43_a08[work_deadline]'),
 ('S4-K01', 'graphical', 'tests/test_secure_synthetic_custody_linux.py::test_s43_k01[graphical]'),
 ('S4-K01', 'terminal', 'tests/test_secure_synthetic_custody_linux.py::test_s43_k01[terminal]'),
 ('S4-K02', 'copied_handle', 'tests/test_secure_synthetic_custody_linux.py::test_s43_k02[copied_handle]'),
 ('S4-K02',
  'duplicate_consume',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_k02[duplicate_consume]'),
 ('S4-K02',
  'environment_source',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_k02[environment_source]'),
 ('S4-K02', 'file_source', 'tests/test_secure_synthetic_custody_linux.py::test_s43_k02[file_source]'),
 ('S4-K02', 'foreign_action', 'tests/test_secure_synthetic_custody_linux.py::test_s43_k02[foreign_action]'),
 ('S4-K02',
  'foreign_engagement',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_k02[foreign_engagement]'),
 ('S4-K02', 'foreign_service', 'tests/test_secure_synthetic_custody_linux.py::test_s43_k02[foreign_service]'),
 ('S4-K02', 'legacy_source', 'tests/test_secure_synthetic_custody_linux.py::test_s43_k02[legacy_source]'),
 ('S4-K03', 'clock_forward', 'tests/test_secure_synthetic_custody_linux.py::test_s43_k03[clock_forward]'),
 ('S4-K03', 'clock_rollback', 'tests/test_secure_synthetic_custody_linux.py::test_s43_k03[clock_rollback]'),
 ('S4-K03',
  'engagement_revocation',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_k03[engagement_revocation]'),
 ('S4-K03', 'lease_expiry', 'tests/test_secure_synthetic_custody_linux.py::test_s43_k03[lease_expiry]'),
 ('S4-K03',
  'lease_revocation',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_k03[lease_revocation]'),
 ('S4-K03',
  'revoke_before_release',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_k03[revoke_before_release]'),
 ('S4-K03', 'window_expiry', 'tests/test_secure_synthetic_custody_linux.py::test_s43_k03[window_expiry]'),
 ('S4-K04',
  'argv_environment',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_k04[argv_environment]'),
 ('S4-K04',
  'both_review_views',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_k04[both_review_views]'),
 ('S4-K04',
  'diagnostic_failure',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_k04[diagnostic_failure]'),
 ('S4-K04', 'fds_mounts', 'tests/test_secure_synthetic_custody_linux.py::test_s43_k04[fds_mounts]'),
 ('S4-K04', 'keylog_disabled', 'tests/test_secure_synthetic_custody_linux.py::test_s43_k04[keylog_disabled]'),
 ('S4-K05', 'base64_body', 'tests/test_secure_synthetic_custody_linux.py::test_s43_k05[base64_body]'),
 ('S4-K05', 'error_body', 'tests/test_secure_synthetic_custody_linux.py::test_s43_k05[error_body]'),
 ('S4-K05',
  'json_escaped_body',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_k05[json_escaped_body]'),
 ('S4-K05', 'literal_body', 'tests/test_secure_synthetic_custody_linux.py::test_s43_k05[literal_body]'),
 ('S4-K05', 'unknown_field', 'tests/test_secure_synthetic_custody_linux.py::test_s43_k05[unknown_field]'),
 ('S4-K05', 'unknown_header', 'tests/test_secure_synthetic_custody_linux.py::test_s43_k05[unknown_header]'),
 ('S4-K06',
  'after_release_before_write',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_k06[after_release_before_write]'),
 ('S4-K06', 'before_release', 'tests/test_secure_synthetic_custody_linux.py::test_s43_k06[before_release]'),
 ('S4-K06', 'during_read', 'tests/test_secure_synthetic_custody_linux.py::test_s43_k06[during_read]'),
 ('S4-K06', 'during_write', 'tests/test_secure_synthetic_custody_linux.py::test_s43_k06[during_write]'),
 ('S4-K06',
  'lost_completion_ack',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_k06[lost_completion_ack]'),
 ('S4-K07', 'arbitrary_path', 'tests/test_secure_synthetic_custody_linux.py::test_s43_k07[arbitrary_path]'),
 ('S4-K07',
  'environment_name',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_k07[environment_name]'),
 ('S4-K07',
  'legacy_case_path',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_k07[legacy_case_path]'),
 ('S4-K07', 'mode_switch', 'tests/test_secure_synthetic_custody_linux.py::test_s43_k07[mode_switch]'),
 ('S4-K07', 'unlisted_value', 'tests/test_secure_synthetic_custody_linux.py::test_s43_k07[unlisted_value]'),
 ('S4-P02',
  'ambient_credentials',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_p02[ambient_credentials]'),
 ('S4-P02', 'legacy_json', 'tests/test_secure_synthetic_custody_linux.py::test_s43_p02[legacy_json]'),
 ('S4-P02', 'legacy_markdown', 'tests/test_secure_synthetic_custody_linux.py::test_s43_p02[legacy_markdown]'),
 ('S43-AUTH01',
  'distinct_actions_final_allowance',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_authority[distinct_actions_final_allowance]'),
 ('S43-AUTH02',
  'broker_restart_after_reservation',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_authority[broker_restart_after_reservation]'),
 ('S43-AUTH03',
  'broker_restart_after_release',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_authority[broker_restart_after_release]'),
 ('S43-AUTH04',
  'broker_restart_after_completion_before_ack',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_authority[broker_restart_after_completion_before_ack]'),
 ('S43-AUTH05',
  'reservation_commit_failure',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_authority[reservation_commit_failure]'),
 ('S43-AUTH06',
  'release_commit_failure',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_authority[release_commit_failure]'),
 ('S43-AUTH07',
  'completion_commit_failure',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_authority[completion_commit_failure]'),
 ('S43-AUTH08',
  'audit_failure_before_release',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_authority[audit_failure_before_release]'),
 ('S43-AUTH09',
  'audit_failure_after_release',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_authority[audit_failure_after_release]'),
 ('S43-AUTH10',
  'concurrent_generation_writers',
  'tests/test_secure_synthetic_custody_linux.py::test_s43_authority[concurrent_generation_writers]'))


# Intrinsic inspection claims only; actual reading and validated counts are external.
READER_RECEIPT_MAX_BYTES = 3072
READER_RECEIPT_MAX_DEPTH = 1
READER_RECEIPT_FIELDS = (
    'bundle_id', 'manifest_sha256', 'member_count', 'reader_code_sha256',
    'reader_kind', 'reason', 'record_count', 'schema_version', 'status',
)
READER_RECEIPT_SCALARS = (
    ('bundle_id', 'uuid4?'), ('manifest_sha256', 'sha256?'), ('member_count', 'member_count'),
    ('reader_code_sha256', 'sha256'), ('reader_kind', 'reader_kind'),
    ('reason', 'inspection_reason'), ('record_count', 'record_count'),
    ('schema_version', 's43-inspection-v1'), ('status', 'inspection_status'),
)
READER_RECEIPT_COUNT_MAXIMA = {'member_count': 9, 'record_count': 1530}
READER_RECEIPT_KINDS = ('python', 'cli')
READER_RECEIPT_STATUSES = ('valid', 'invalid', 'unavailable')
READER_RECEIPT_REASONS = (
    'none', 'schema', 'identity', 'ordering', 'custody', 'budget', 'unsafe_path',
    'changed_member', 'oversize', 'missing_member', 'unknown_member', 'unavailable_context',
)
