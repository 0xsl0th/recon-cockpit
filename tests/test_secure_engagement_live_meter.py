"""S42C-M01..M16: actual syscall return models, no native gate claims."""
from copy import deepcopy
import errno
import hashlib
from types import SimpleNamespace

import pytest
from recon_cockpit.secure_agent import engagement_live_endpoint_worker as e
from recon_cockpit.secure_agent import engagement_live_runtime as r
from recon_cockpit.secure_agent import engagement_live_contract as c
from test_secure_engagement_live_contract import prepared, opened, release, clock, uid, M


class Stream:
    def __init__(self,chunks=(),sends=()):self.chunks=list(chunks);self.sends=list(sends);self.read_calls=[];self.write_calls=[];self.delivered=bytearray()
    def recv(self,n):
        self.read_calls.append(n)
        item=self.chunks.pop(0)
        if isinstance(item,BaseException):raise item
        head,tail=item[:n],item[n:]
        if tail:self.chunks.insert(0,tail)
        return head
    def send(self,data):
        self.write_calls.append(bytes(data));count=self.sends.pop(0) if self.sends else len(data)
        if isinstance(count,BaseException):raise count
        self.delivered.extend(data[:count]);return count


@pytest.fixture
def meter(monkeypatch):
    monkeypatch.setattr(c,'sample_clock',lambda:clock())
    monkeypatch.setattr(e.time,'monotonic_ns',lambda:M+1000)
    def build(slot='http_headers'):
        value=prepared(slot);obj=e.Meter(value,uid(40),opened()['scope']);obj.arm(release(value));return obj
    return build


def refused(function,*args):
    with pytest.raises(c.LiveError):function(*args)


def test_exact_identify_and_headers_grammar(meter):
    h=meter();h.admit();s=Stream([h.expected]);assert h.receive(s)==e.HEADER_RESPONSE;assert h.send(s)
    assert bytes(s.delivered)==e.HEADER_RESPONSE and r.validate_meter(h.snapshot())['reason']=='complete'
    n=meter('http_identify');n.admit();assert n.receive(Stream([b'']))==b'';n.admit();s=Stream([e.IDENTIFY_REQUEST]);assert n.receive(s)==e.IDENTIFY_RESPONSE;assert n.send(s)
    assert bytes(s.delivered)==e.IDENTIFY_RESPONSE


def test_bounded_empty_native_probe_connections(meter):
    for endings in (('eof',),('reset',),('eof','eof'),('eof','reset'),('reset','eof'),('reset','reset')):
        m=meter('http_identify')
        for connection,kind in enumerate(endings,1):
            m.admit();before=deepcopy(m.events)
            s=Stream([b'' if kind=='eof' else ConnectionResetError(errno.ECONNRESET,'actual reset')])
            assert m.receive(s)==b'' and s.read_calls==[4096] and not s.write_calls
            assert m.events[:-1]==before and m.events[-1]['kind']==kind
            assert m.events[-1]['connection']==m.connections==connection
            assert all(m.events[-1][key]==0 for key in ('requested_bytes','actual_bytes','remaining_before','remaining_after'))
            assert m.events[-1]['reason']is None and m.reason is None
            assert not m.requests and not m.responses and not m.current
        m.admit();s=Stream([m.expected]);assert m.receive(s)==m.reply;assert m.send(s)
        settled=r.validate_meter(m.snapshot())
        assert settled['accepted_connections']==len(endings)+1
        assert settled['received_request_bytes']==len(m.expected) and settled['sent_response_bytes']==len(m.reply)
        assert bytes(m.requests)==m.expected and bytes(m.responses)==bytes(s.delivered)==m.reply
        assert [row['kind'] for row in m.events if row['kind'] in ('eof','reset')]==list(endings)
    for slot in ('http_headers','http_identify'):
        for kind in ('eof','reset'):
            m=meter(slot)
            if slot=='http_identify':
                for _ in range(2):m.admit();assert m.receive(Stream([b'']))==b''
            m.admit();before=deepcopy(m.events)
            s=Stream([b'' if kind=='eof' else ConnectionResetError(errno.ECONNRESET,'actual reset')])
            with pytest.raises(c.LiveError) as caught:m.receive(s)
            assert caught.value.code=='engagement_live_meter_refused' and m.reason=='peer_eof'
            assert m.events[:-2]==before and [row['kind'] for row in m.events[-2:]]==[kind,'close']
            assert len(s.read_calls)==1 and not s.write_calls and not m.requests and not m.responses
            assert r.validate_meter(m.snapshot())['accepted_connections']==(3 if slot=='http_identify' else 1)
    other=OSError('not a ConnectionResetError');other.errno=errno.ECONNRESET
    for error in (ConnectionResetError(),ConnectionResetError(errno.EPIPE,'wrong errno'),OSError(errno.EIO,'other error'),other):
        m=meter('http_identify');m.admit();before=deepcopy(m.events);s=Stream([error])
        with pytest.raises(type(error)) as caught:m.receive(s)
        assert caught.value is error and s.read_calls==[4096] and not s.write_calls
        assert m.events==before and m.connections==1 and m.reason is None and not m.requests and not m.responses
    m=meter('http_identify');m.admit();refused(m.receive,Stream([m.expected]));assert not m.responses


def test_extra_or_unsupported_request_refused(meter):
    for content in (b'POST / HTTP/1.0\r\n\r\n',b'CONNECT x:443 HTTP/1.0\r\n\r\n',b'GET /x HTTP/1.0\r\n\r\n'):
        m=meter();m.admit();s=Stream([content]);refused(m.receive,s);assert not s.write_calls and m.reason=='malformed_request'


def test_segmented_request_not_responded_early(meter):
    m=meter();m.admit();s=Stream([m.expected[:8],m.expected[8:]])
    assert m.receive(s)is None and not s.write_calls
    assert m.receive(s)==m.reply and len(s.read_calls)==2


def test_one_request_no_pipeline_or_extra_data(meter):
    m=meter();m.admit();s=Stream([m.expected+m.expected]);refused(m.receive,s)
    assert m.reason=='malformed_request' and not s.write_calls
    m=meter();m.admit();s=Stream([m.expected]);m.receive(s);m.send(s)
    refused(m.admit);refused(m.send,s)
    assert len(s.write_calls)==1 # No second response can be generated after terminal settlement.


def test_connection_capacity_before_admission(meter):
    for slot,cap in (('http_identify',3),('http_headers',1)):
        m=meter(slot)
        for _ in range(cap):m.admit()
        refused(m.admit);assert m.connections==cap and m.reason=='connection_limit'


def test_read_never_exceeds_remaining(meter):
    m=meter();m.admit();m.requests.extend(b'x'*255);s=Stream([b'GZ'])
    assert m.receive(s)is None and s.read_calls==[1] and s.chunks==[b'Z']
    refused(m.receive,s);assert s.read_calls==[1] and m.reason=='request_limit'


def test_partial_read_counts_irreversible(meter):
    m=meter();m.admit();s=Stream([b'GE',BlockingIOError(),b'wrong'])
    assert m.receive(s)is None;assert m.receive(s)is None;refused(m.receive,s)
    assert bytes(m.requests)==b'GEwrong' and sum(x['actual_bytes'] for x in m.events if x['kind']=='recv')==7
    assert m.snapshot()['received_request_bytes']==7
    for slot,connection in (('http_headers',1),('http_identify',1),('http_identify',2),('http_identify',3)):
        m=meter(slot)
        for _ in range(connection-1):m.admit();assert m.receive(Stream([b'']))==b''
        m.admit();s=Stream([b'GE',ConnectionResetError(errno.ECONNRESET,'actual reset')])
        assert m.receive(s)is None;before=deepcopy(m.events)
        with pytest.raises(c.LiveError) as caught:m.receive(s)
        assert caught.value.code=='engagement_live_meter_refused' and m.reason=='peer_eof'
        assert s.read_calls==[m.request_limit,m.request_limit-2] and not s.write_calls
        assert m.events[:-2]==before and [row['kind'] for row in m.events[-2:]]==['reset','close']
        assert bytes(m.requests)==bytes(m.current)==b'GE' and not m.responses
        assert sum(row['actual_bytes'] for row in m.events if row['kind']=='recv')==2
        settled=r.validate_meter(m.snapshot())
        assert settled['received_request_bytes']==2 and settled['accepted_connections']==connection
        refused(m.receive,s);refused(m.admit)
        assert len(s.read_calls)==2 and m.connections==connection and bytes(m.requests)==b'GE'


def test_write_never_exceeds_remaining(meter):
    m=meter();m.admit();m.receive(Stream([m.expected]));m.responses.extend(b'x'*2047);s=Stream(sends=[1])
    assert not m.send(s) and s.write_calls==[m.reply[:1]]
    refused(m.send,s);assert len(s.write_calls)==1 and m.reason=='response_limit'


def test_partial_write_counts_irreversible(meter):
    m=meter();m.admit();m.receive(Stream([m.expected]));s=Stream(sends=[7,BlockingIOError(),5])
    assert not m.send(s);assert not m.send(s);assert not m.send(s)
    m.cancel();assert bytes(m.responses)==m.reply[:12] and bytes(s.delivered)==m.reply[:12]
    assert m.snapshot()['sent_response_bytes']==12


def test_eagain_no_refund_or_spin(meter):
    m=meter();m.admit();s=Stream([BlockingIOError()]);count=len(m.events)
    assert m.receive(s)is None and len(s.read_calls)==1 and len(m.events)==count
    m.receive(Stream([m.expected]));s=Stream(sends=[BlockingIOError()]);count=len(m.events)
    assert not m.send(s) and len(s.write_calls)==1 and len(m.events)==count
    assert not m.responses


def test_cancel_eof_priority_over_io(meter):
    m=meter();m.admit();s=Stream([m.expected]);m.cancel('channel_eof')
    refused(m.receive,s);refused(m.send,s);assert not s.read_calls and not s.write_calls
    assert m.reason=='channel_eof'


def test_late_arm_cannot_resurrect(meter):
    m=meter();m.cancel();before=deepcopy(m.snapshot())
    refused(m.arm,release(m.prepared));assert m.snapshot()==before
    m=meter();refused(m.arm,release(m.prepared));assert len([x for x in m.events if x['kind']=='arm'])==1


def test_current_clock_before_accept_read_write(meter,monkeypatch):
    for operation in ('admit','receive','send'):
        m=meter();s=Stream([m.expected]);
        if operation!='admit':m.admit()
        if operation=='send':m.receive(s);s.read_calls.clear()
        monkeypatch.setattr(c,'sample_clock',lambda:clock(100*c.SECOND))
        refused(getattr(m,operation),*(() if operation=='admit' else (s,)))
        assert not s.read_calls and not s.write_calls
        monkeypatch.setattr(c,'sample_clock',lambda:clock())


def test_deadline_after_partial_before_next_send(meter,monkeypatch):
    m=meter();m.admit();m.receive(Stream([m.expected]));s=Stream(sends=[9])
    assert not m.send(s);monkeypatch.setattr(c,'sample_clock',lambda:clock(10*c.SECOND))
    refused(m.send,s);assert len(s.write_calls)==1 and len(m.responses)==9
    m.cancel('timeout');assert m.snapshot()['sent_response_bytes']==9


def test_settlement_digest_and_unknown_delivery(meter):
    m=meter();m.admit();m.receive(Stream([m.expected]));unknown=r.validate_meter(m.snapshot())
    assert unknown['delivery_known'] is False and unknown['sent_response_bytes']is None
    m.send(Stream());known=r.validate_meter(m.snapshot());assert known['delivery_known'] and known['response_sha256']==hashlib.sha256(m.reply).hexdigest()
    bad=deepcopy(known);bad['sent_response_bytes']+=1;refused(r.validate_meter,bad)
    bad=deepcopy(known);bad['events'][2]['actual_bytes']+=1;refused(r.validate_meter,bad)
    n=meter('http_identify');n.admit()
    assert n.receive(Stream([ConnectionResetError(errno.ECONNRESET,'actual reset')]))==b''
    empty_unknown=r.validate_meter(n.snapshot());termination=deepcopy(empty_unknown['events'][-1])
    assert termination['kind']=='reset' and r.validate_meter_event(termination)==termination
    assert empty_unknown['delivery_known'] is False
    assert all(empty_unknown[key]is None for key in ('accepted_connections','received_request_bytes','sent_response_bytes','finished_at_ns'))
    n.admit();s=Stream([n.expected]);assert n.receive(s)==n.reply
    payload_unknown=r.validate_meter(n.snapshot())
    assert payload_unknown['request_sha256']==hashlib.sha256(n.expected).hexdigest()
    assert all(payload_unknown[key]is None for key in ('accepted_connections','received_request_bytes','sent_response_bytes','finished_at_ns'))
    assert n.send(s);settled=r.validate_meter(n.snapshot())
    assert settled['delivery_known'] and settled['accepted_connections']==2
    assert settled['received_request_bytes']==len(n.expected) and settled['sent_response_bytes']==len(n.reply)
    assert settled['response_sha256']==hashlib.sha256(n.reply).hexdigest()
    for kind in ('eof','reset'):
        event=deepcopy(termination);event['kind']=kind
        assert r.validate_meter_event(event)==event
        invalid=[]
        for key in ('requested_bytes','actual_bytes','remaining_before','remaining_after'):
            bad=deepcopy(event);bad[key]=1;invalid.append(bad)
        # These mutations satisfy the generic arithmetic but still cannot be a
        # non-payload termination event, including in a direct witness row.
        bad=deepcopy(event);bad.update(requested_bytes=1,actual_bytes=1,remaining_before=1,remaining_after=0);invalid.append(bad)
        bad=deepcopy(event);bad.update(remaining_before=1,remaining_after=1);invalid.append(bad)
        bad=deepcopy(event);bad['reason']='peer_eof';invalid.append(bad)
        bad=deepcopy(event);bad['kind']='rst';invalid.append(bad)
        for bad_event in invalid:
            refused(r.validate_meter_event,bad_event)
            for snapshot in (empty_unknown,payload_unknown,settled):
                bad=deepcopy(snapshot);bad['events'][termination['sequence']-1]=bad_event
                refused(r.validate_meter,bad)
    for key in ('accepted_connections','received_request_bytes','sent_response_bytes','finished_at_ns'):
        bad=deepcopy(payload_unknown);bad[key]=0;refused(r.validate_meter,bad)
