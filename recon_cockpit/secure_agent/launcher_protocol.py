"""Fixed fixture-launcher messages; requests cannot select executables or permits."""

import json
import re

from . import launch_admission as admission
from .models import _object_pairs, parse_action

MAX_REPLY = 6 * 65536 + 32768
CHECKS = frozenset({'namespaces_private', 'nonroot_identity', 'capabilities_dropped',
    'no_new_privs', 'root_read_only', 'descriptors_private', 'network_private'})
PROFILES = {'fixture': 'linux-authorized-fixture-executor-v1',
            'discovery_fixture': 'linux-authorized-discovery-fixture-executor-v1',
            'owned_lab': 'linux-authorized-owned-lab-executor-v1',
            'owned_nmap_lab': 'linux-authorized-owned-nmap-lab-executor-v1',
            'owned_web_lab': 'linux-authorized-owned-web-lab-executor-v1',
            'owned_http_headers_lab': 'linux-authorized-owned-http-headers-executor-v1',
            'owned_web_tools_lab': 'linux-authorized-owned-web-tools-executor-v1',
            'owned_network_tools_lab': 'linux-authorized-owned-network-tools-executor-v1',
            'owned_service_web_lab': 'linux-authorized-owned-service-web-executor-v1',
            'configurable_owned_lab': 'linux-authorized-configurable-owned-executor-v1'}
RUNTIME_TAGS = {'owned_nmap_lab': 'nmap-launch-preconditions', 'owned_web_lab': 'web-launch-preconditions',
    'owned_http_headers_lab': 'http-headers-launch-preconditions',
    'owned_web_tools_lab': 'web-tools-launch-preconditions',
    'owned_network_tools_lab': 'network-tools-launch-preconditions',
    'owned_service_web_lab': 'service-web-launch-preconditions',
    'configurable_owned_lab': 'configurable-launch-preconditions'}


def runtime_tag(config, closure):
    if (config['profile'] == 'owned_network_tools_lab'
            and closure.get('network_tools_runtime', {}).get('tool_id') == 'whatweb_http_fingerprint_v1'):
        return 'whatweb-tools-launch-preconditions'
    if (config['profile'] == 'owned_network_tools_lab'
            and closure.get('network_tools_runtime', {}).get('tool_id') == 'kerbrute_userenum_v1'):
        return 'kerberos-tools-launch-preconditions'
    if (config['profile'] == 'owned_network_tools_lab'
            and closure.get('network_tools_runtime', {}).get('tool_id') == 'smb_share_list_v1'):
        return 'smb-tools-launch-preconditions'
    return RUNTIME_TAGS.get(config['profile'])


def validate_runtime_tag(tag, config, closure):
    expected = runtime_tag(config, closure)
    special = tag in {*RUNTIME_TAGS.values(), 'smb-tools-launch-preconditions', 'kerberos-tools-launch-preconditions', 'whatweb-tools-launch-preconditions'}
    if (expected is not None) != special or (expected is not None and tag != expected):
        raise ValueError('launcher_runtime_profile_changed')


def encode(value):
    raw = json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                     separators=(',', ':')).encode('ascii')
    if len(raw) > MAX_REPLY:
        raise ValueError('launcher_reply_limit')
    return raw


def decode(raw):
    if type(raw) is not bytes or len(raw) > MAX_REPLY:
        raise ValueError('launcher_reply_limit')
    def constant(_):
        raise ValueError('invalid_launcher_constant')
    value = json.loads(raw.decode('ascii'), object_pairs_hook=_object_pairs, parse_constant=constant)
    if type(value) is not dict:
        raise ValueError('invalid_launcher_object')
    return value


def configuration(value):
    if type(value) is dict and value.get('profile') in {'owned_lab', 'owned_nmap_lab', 'owned_web_lab', 'owned_http_headers_lab', 'owned_web_tools_lab', 'owned_network_tools_lab', 'owned_service_web_lab', 'configurable_owned_lab'}:
        from .owned_lab_contract import validate_identity
        if value['profile'] == 'owned_web_lab':
            from .web_lab_contract import validate_identity
        elif value['profile'] == 'owned_http_headers_lab':
            from .http_headers_lab_contract import validate_identity
        elif value['profile'] == 'owned_web_tools_lab':
            from .web_tools_lab_contract import validate_identity
        elif value['profile'] == 'owned_network_tools_lab':
            from .network_tools_lab_contract import validate_identity
        elif value['profile'] == 'owned_service_web_lab':
            from .service_web_lab_contract import validate_identity
        base = admission.configuration({key: item for key, item in value.items() if key != 'owned_lab'})
        if value['profile'] == 'configurable_owned_lab':
            from .configurable_lab_contract import validate_assessment_identity
            return {**base, 'owned_lab': validate_assessment_identity(value.get('owned_lab'), scope=base['case'])}
        return {**base, 'owned_lab': validate_identity(value.get('owned_lab'), case=base['case'])}
    value = admission.configuration(value)
    if value['profile'] not in PROFILES:
        raise ValueError('unsupported_launcher_profile')
    return value


def runtime(value, *, owned_lab=False, nmap=False, web_tools=False, network_tools=False, service_web=False,
            configurable=False):
    fields = ({'stdlib', 'files'} | ({'nmap_runtime'} if nmap else set()) |
              ({'web_tools_runtime'} if web_tools else set()) | ({'network_tools_runtime'} if network_tools else set()) |
              ({'service_web_runtime'} if service_web else set()) |
              ({'configurable_runtime'} if configurable else set()))
    if type(value) is not dict or set(value) != fields or (sum((nmap, web_tools, network_tools, service_web, configurable)) > 1):
        raise ValueError('invalid_launcher_runtime')
    if nmap:
        from .nmap_runtime import validate_manifest
        validate_manifest(value['nmap_runtime'])
    if web_tools:
        from .web_tools_runtime import validate_manifest
        validate_manifest(value['web_tools_runtime'])
    if network_tools:
        from .network_tools_runtime import validate_manifest
        validate_manifest(value['network_tools_runtime'])
    if service_web:
        from .service_web_runtime import validate_manifests
        validate_manifests(value['service_web_runtime'])
    if configurable:
        from .configurable_runtime import validate_manifests
        validate_manifests(value['configurable_runtime'])
    if type(value['stdlib']) is not str or not re.fullmatch(r'/usr/lib/python3\.\d+', value['stdlib']):
        raise ValueError('invalid_launcher_stdlib')
    paths = value['files']
    programs = {'/usr/bin/python3', '/usr/sbin/nft', '/usr/bin/bwrap'}
    if owned_lab:
        programs.add('/usr/bin/nsenter')
    if (type(paths) is not list or not 3 <= len(paths) <= 128
            or any(type(p) is not str or '..' in p or '//' in p or not (
                p in programs or re.fullmatch(r'/(?:usr/)?lib(?:64)?/[A-Za-z0-9_./+-]+\.so(?:\.[0-9]+)*', p)) for p in paths)
            or len(set(paths)) != len(paths) or not programs <= set(paths)):
        raise ValueError('invalid_launcher_files')
    return value


def initial(value, now):
    if type(value) is not dict or set(value) not in ({'configuration', 'deadline', 'runtime'},
            {'configuration', 'deadline', 'runtime', 'audit_witness'},
            {'configuration', 'deadline', 'runtime', 'audit_witness', 'approval_witness'}):
        raise ValueError('invalid_launcher_init')
    if 'audit_witness' in value:
        from .audit_witness import manifest
        manifest(value['audit_witness'])
    if 'approval_witness' in value:
        from .approval_witness import manifest
        manifest(value['approval_witness'])
    config = configuration(value['configuration'])
    admission.initial({'configuration': {k: v for k, v in config.items() if k != 'owned_lab'}, 'deadline': value['deadline']}, now)
    runtime(value['runtime'], owned_lab=config['profile'] in {'owned_lab', 'owned_nmap_lab', 'owned_web_lab', 'owned_http_headers_lab', 'owned_web_tools_lab', 'owned_network_tools_lab', 'owned_service_web_lab', 'configurable_owned_lab'},
            nmap=config['profile'] in {'owned_nmap_lab', 'owned_web_lab', 'owned_http_headers_lab'},
            web_tools=config['profile'] == 'owned_web_tools_lab', network_tools=config['profile'] == 'owned_network_tools_lab',
            service_web=config['profile'] == 'owned_service_web_lab',
            configurable=config['profile'] == 'configurable_owned_lab')
    if config['profile'] == 'owned_web_tools_lab':
        from .web_tools_contract import action
        if value['runtime']['web_tools_runtime']['tool_id'] != action(config['case'], 1)['tool_id']:
            raise ValueError('launcher_web_tool_runtime_changed')
    if config['profile'] == 'owned_network_tools_lab':
        from .network_tools_contract import action
        if value['runtime']['network_tools_runtime']['tool_id'] != action(config['case'], 1)['tool_id']:
            raise ValueError('launcher_network_tool_runtime_changed')
    return config


def request(value, config, sequence):
    fields = {'version', 'service_id', 'session_id', 'sequence', 'operation', 'action', 'policy_digest'}
    if (type(value) is not dict or set(value) != fields or value['version'] != '1'
            or value['service_id'] != config['service_id'] or value['session_id'] != config['session_id']
            or type(value['sequence']) is not int or value['sequence'] != sequence
            or not 1 <= sequence <= config['limits']['max_steps'] or value['operation'] != 'execute'
            or value['policy_digest'] != admission.digest(config['policy'])):
        raise ValueError('invalid_launcher_request')
    action = parse_action(value['action'])
    if (config['profile'] == 'owned_service_web_lab' and
            action.tool_id != ('nmap_service_identify_v1', 'ffuf_content_discovery_v1', 'http_headers_v1')[sequence - 1]):
        raise ValueError('invalid_launcher_service_web_step')
    if config['profile'] == 'configurable_owned_lab':
        from .configurable_contract import step_for_action
        if step_for_action(config['case'], action) != sequence:
            raise ValueError('invalid_launcher_configurable_step')
    if not admission.profile_allows(action, config):
        raise ValueError('invalid_launcher_action')
    return action


def receipt(value, result, snapshot):
    return {'version': '1', 'service_id': value['service_id'], 'session_id': value['session_id'],
            'sequence': value['sequence'], 'request_digest': admission.digest(value),
            'result': result, 'snapshot': dict(snapshot)}


def result(value, config):
    if (type(value) is not dict or type(value.get('status')) is not str
            or value['status'] not in {'succeeded', 'failed', 'timeout', 'output_limit'}
            or value.get('backend') != PROFILES[config['profile']]
            or type(value.get('results')) is not list):
        raise ValueError('invalid_launcher_result')
    return value
