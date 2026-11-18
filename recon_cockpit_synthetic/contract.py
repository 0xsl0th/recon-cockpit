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
