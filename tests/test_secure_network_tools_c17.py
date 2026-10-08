"""C17 adds a fixed Git marker while preserving every accepted operation."""
import hashlib
import json
from pathlib import Path
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_contract as contract
from recon_cockpit.secure_agent import network_tools_workflow as workflow
from recon_cockpit.secure_agent import network_tools_lab_contract as lab
from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent import tool_adapters
from recon_cockpit.secure_agent.models import ValidationError, parse_action, parse_policy
from recon_cockpit.secure_agent.network_tools_backend import AuthorizedNetworkToolsBackend


def policy(**changes):
    value = json.loads(Path('examples/secure-agent-nuclei-git-policy.json').read_text())
    return parse_policy({**value, **changes})


@pytest.mark.parametrize('case', contract.C17_CASES)
def test_fixed_git_head_action_requires_exact_scope_method_and_fresh_authority(case):
    action = parse_action(contract.action(case))
    assert action.tool_id == contract.NUCLEI_GIT_TOOL_ID
    assert action.tool_id in AuthorizedNetworkToolsBackend.supported_tools
    assert action.parameters.to_dict() == {'port': 8080, 'timeout_seconds': 5, 'max_output_bytes': 8192}
    assert contract.profile_allows(action, case)
    assert policy().evaluate(action).decision == 'approval_required'
    assert policy(allowed_methods=[]).evaluate(action).reasons == ('method_not_allowed',)
    assert policy(allowed_ports=[]).evaluate(action).reasons == ('port_not_allowed',)
    assert workflow.card_identity(case)['version'] == '25'
    assert set(workflow.card(case)['action_digests']) == set(contract.C17_CASES)
    spec = lab.spec(case)
    assert spec['tool_id'] == action.tool_id and spec['method'] == 'GET' and spec['path'] == '/.git/HEAD'
    assert spec['max_connections'] == spec['max_requests'] == 1 and spec['followup'] is False
    with pytest.raises(ValueError):
        contract.action(case, 2)


@pytest.mark.parametrize('field', ['argv', 'executable', 'command', 'template', 'template_id', 'path',
    'url', 'method', 'ref', 'object', 'repository', 'config', 'script', 'workflow', 'followup',
    'username', 'password', 'headers', 'environment', 'credentials', 'authentication', 'redirects'])
def test_proposal_cannot_select_repository_content_templates_or_authentication(field):
    value = contract.action('nuclei-git-main')
    value['parameters'][field] = 'untrusted'
    with pytest.raises(ValidationError):
        parse_action(value)


@pytest.mark.parametrize('change', [{'target': '127.0.0.2'}, {'port': 8081},
    {'timeout_seconds': 10}, {'max_output_bytes': 16384}])
def test_valid_parameter_syntax_does_not_expand_fixed_execution_scope(change):
    value = contract.action('nuclei-git-main')
    (value if 'target' in change else value['parameters']).update(change)
    assert not contract.profile_allows(parse_action(value), 'nuclei-git-main')


def test_profiles_cannot_substitute_for_each_other_at_authority_gate():
    action = parse_action(contract.action('nuclei-git-main'))
    assert not contract.profile_allows(action, 'nuclei-index')
    assert policy(allowed_tools=[contract.NUCLEI_TOOL_ID]).evaluate(action).reasons == ('tool_not_allowed',)
    assert lab.identity('nuclei-git-main', str(uuid4()))['spec_sha256'] != lab.identity('nuclei-index', str(uuid4()))['spec_sha256']


def test_all_accepted_case_adapter_and_runtime_bytes_remain_identical():
    # Captured on accepted main 1cfbf8b before C17 edits; never regenerate from C17.
    old_cases = [case for case in contract.CASES if case not in contract.C17_CASES + contract.C18_CASES]
    old_tools = set(tool_adapters.ADAPTERS) - {contract.NUCLEI_GIT_TOOL_ID, contract.DIG_MX_TOOL_ID}
    old_runtime = set(runtime.EXECUTABLES) - {contract.NUCLEI_GIT_TOOL_ID, contract.DIG_MX_TOOL_ID}
    assert (len(old_cases), len(old_tools), len(old_runtime)) == (290, 41, 32)
    value = {
        'adapters': {key: tool_adapters.ADAPTERS[key].to_dict() for key in old_tools},
        'cases': {case: {'action': contract.action(case), 'card': workflow.card(case),
            'descriptor': contract.capability_descriptor(case), 'spec': lab.spec(case)} for case in old_cases},
        'argv': {key: runtime.FIXED_ARGV[key] for key in old_runtime},
        'environment': {key: runtime.execution_environment(key) for key in old_runtime},
        'runtime': {key: [runtime.EXECUTABLES[key], runtime.FIXED_ARGV[key], runtime.execution_environment(key),
            [(source, dest, raw.hex()) for source, dest, raw in runtime.compiled_files(key)]] for key in old_runtime},
        'c16_manifest': runtime.nuclei_runtime.manifest(),
    }
    raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    assert hashlib.sha256(raw).hexdigest() == 'dd5900c5d75230fd09580f7f8ecdfad046f4c7db4f8f69eee59c314c49ceedfc'
