"""The exact 54 owned live engagement gates and their immutable evidence."""

import json
import os
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATES = json.loads((ROOT/'docs/stage4-engagement-live-gates.json').read_text())
CASES = tuple(row for row in GATES['cases'] if row['group']=='native_core')
assert len(CASES) == 54
pytestmark = pytest.mark.integration


@pytest.mark.parametrize('variant',[row['variant'] for row in CASES])
def test_live_case(variant,tmp_path,record_property):
    if os.environ.get('RECON_LINUX_INTEGRATION') != '1':
        pytest.skip('enable RECON_LINUX_INTEGRATION for the owned isolated live gates')
    assert sys.platform == 'linux' and os.geteuid() != 0
    case = next(row for row in CASES if row['variant']==variant)
    if case.get('frontend') == 'graphical':
        if os.environ.get('RECON_GRAPHICAL_APPROVAL_INTEGRATION') != '1':
            pytest.skip('enable RECON_GRAPHICAL_APPROVAL_INTEGRATION with an owned display')
        assert os.environ.get('DISPLAY') and os.environ.get('XAUTHORITY')
    from engagement_live_native import run_core_case, inspect_saved_case
    directory = run_core_case(variant,tmp_path)
    report, receipt = inspect_saved_case(directory,case_id=case['id'])
    assert report['status']=='complete' and report['case_passed'] is True
    record_property('engagement_live_case_id',case['id'])
    record_property('engagement_live_bundle',str(directory))
    record_property('engagement_live_inspection_receipt',json.dumps(receipt,sort_keys=True))
