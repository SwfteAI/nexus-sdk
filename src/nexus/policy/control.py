"""Explicit authenticated prevention adapter; network I/O stays on its worker thread.

This adapter owns an isolated signed snapshot. It never substitutes governance rules or a
wrapper client-access policy, and never swaps another tenant's process-global policy engine.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import threading
import time
import uuid
from pathlib import Path

from . import engine, envelope, rules


class ControlClient:
    def __init__(self, *, url, token, workspace_id, consumer_id, pubkey_hex, session_id=None,
                 timeout_s=5, allow_loopback=False, state_path=None):
        from urllib.parse import urlsplit
        parsed = urlsplit(url)
        loopback = parsed.hostname in ('127.0.0.1', '::1')
        if (parsed.scheme != 'https' and not (allow_loopback is True and loopback and parsed.scheme == 'http')) \
                or parsed.username or parsed.password or parsed.query or parsed.fragment \
                or parsed.path != '/api/sdk-control/poll':
            raise ValueError('SDK control endpoint requires HTTPS or explicit literal loopback')
        if not isinstance(workspace_id, str) or not workspace_id or not isinstance(consumer_id, str) or not consumer_id or not envelope.key_is_configured(pubkey_hex) \
                or not isinstance(token, str) or not token or '\r' in token or '\n' in token:
            raise ValueError('SDK control requires workspace, pinned key and dedicated bearer')
        pubkey_hex = pubkey_hex.strip().lower()
        self.url, self.token, self.workspace_id, self.pubkey_hex = url, token, workspace_id, pubkey_hex
        self.consumer_id = consumer_id
        self.session_id = session_id or uuid.uuid4().hex
        if (session_id is not None and (not isinstance(session_id, str) or not session_id)) \
                or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', self.session_id):
            raise ValueError('SDK control session ID must use 1..100 letters, digits, underscore or hyphen')
        self.timeout_s = min(30, max(.1, timeout_s))
        binding = hashlib.sha256((pubkey_hex + ':' + workspace_id).encode()).hexdigest()
        self.state_path = Path(state_path) if state_path else Path.home() / '.nexus/sdk-policy' / (binding + '.json')
        if not self.state_path.is_absolute():
            raise ValueError('SDK policy state path must be absolute')
        self.snapshot = engine.Snapshot()
        self.receipt = None
        self.approvals = {}
        self.used = set()
        self.revision = None
        self._lock = threading.RLock()
        self.pending = {}
        self.approval_receipts = {}

    def refresh(self):
        from nexus import enabled
        if not enabled():
            return False
        # The host explicitly opted into prevention and bounded waiting. All network and state
        # file I/O runs on the worker; the caller only waits and atomically adopts a result.
        with self._lock:
            result, finished = {}, threading.Event()
            def pull():
                try:
                    result['value'] = self._pull()
                except Exception as exc:
                    result['error'] = exc
                finally:
                    finished.set()
            worker = threading.Thread(target=pull, name='nexus-sdk-control', daemon=True)
            worker.start()
            if not finished.wait(self.timeout_s + 1):
                raise RuntimeError('SDK control refresh timed out')
            if 'error' in result:
                raise RuntimeError('SDK control refresh rejected') from result['error']
            snap, signed, approvals = result['value']
            self.snapshot, self.revision = snap, signed['signature']
            self.pending = {key: value for key, value in self.pending.items() if value['policy_signature'] == self.revision}
            self.receipt = {'issued_at': signed['policy']['issued_at'], 'signature': self.revision, 'installed': True}
            self.approvals = approvals
            return True

    def _pull(self):
        from nexus import transport
        body = {'schema': 'nexus.sdk-control.v1'}
        if self.receipt:
            body['receipt'] = self.receipt
        outgoing_receipts = list(self.approval_receipts.values())[:20]
        if self.pending or outgoing_receipts:
            body.update(session_id=self.session_id, approval_requests=list(self.pending.values()),
                        approval_receipts=outgoing_receipts)
        data = transport.pull_control(self.url, self.token, body, self.timeout_s)
        if not isinstance(data, dict) or data.get('schema') != 'nexus.sdk-control.v1' \
                or data.get('workspace_id') != self.workspace_id or data.get('consumer_id') != self.consumer_id or not isinstance(data.get('approvals'), list) \
                or len(data['approvals']) > 100:
            raise ValueError('SDK control response binding mismatch')
        signed = data.get('policy')
        payload, problem = envelope.verify(signed, pubkey_hex=self.pubkey_hex)
        now = time.time()
        if not payload or not self._canonical_numbers(payload) or payload.get('workspace_id') != self.workspace_id or payload.get('version') != 1 \
                or type(payload.get('issued_at')) is not int or payload['issued_at'] <= 0 or payload['issued_at'] > now + 300 \
                or type(payload.get('expires_at')) is not int or payload['expires_at'] <= now \
                or payload['expires_at'] <= payload['issued_at'] or not isinstance(payload.get('rules'), list) \
                or len(payload['rules']) > 1000:
            raise ValueError(problem or 'no current workspace-bound SDK bundle')
        ruleset = rules.parse(payload['rules'])
        if ruleset.quarantined:
            raise ValueError('SDK control contains invalid enforcement rules')
        self._ratchet(payload)
        env = envelope.Envelope(payload=payload, verified=True, issued_at=payload['issued_at'])
        snapshot = engine.Snapshot(env=env, ruleset=ruleset, installed_at=now)
        # Delivery is one-use at the broker; an empty later poll must preserve unused authority.
        approvals = {aid: value for aid, value in self.approvals.items()
                     if value['policy_signature'] == signed['signature'] and value['expires_at'] > now and aid not in self.used}
        for signed_approval in data['approvals']:
            a, _ = envelope.verify({'policy': signed_approval.get('approval'), 'signature': signed_approval.get('signature')}, pubkey_hex=self.pubkey_hex)
            if not a or a.get('schema') != 'nexus.sdk-approval.v1' or a.get('workspace_id') != self.workspace_id or a.get('consumer_id') != self.consumer_id \
                    or a.get('session_id') != self.session_id or a.get('policy_signature') != signed['signature'] \
                    or not isinstance(a.get('request_id'), str) or not 0 < len(a['request_id']) <= 128 \
                    or a['request_id'] in self.used or a.get('allow') is not True \
                    or not self._canonical_numbers(a) or type(a.get('issued_at')) is not int or a['issued_at'] <= 0 or a['issued_at'] > now + 300 \
                    or type(a.get('expires_at')) is not int or a['expires_at'] <= now \
                    or a['expires_at'] <= a['issued_at'] or a['expires_at'] - a['issued_at'] > 300:
                continue
            if a['request_id'] not in approvals and len(approvals) >= 100:
                raise ValueError('SDK control approval cache capacity exhausted')
            approvals[a['request_id']] = {**a, 'signature': signed_approval['signature']}
        for receipt in outgoing_receipts:
            if self.approval_receipts.get(receipt['request_id']) is receipt:
                self.approval_receipts.pop(receipt['request_id'], None)
        return snapshot, signed, approvals

    def _ratchet(self, payload):
        mark = {'schema': 1, 'pubkey': self.pubkey_hex.lower(), 'workspace_id': self.workspace_id,
                'issued_at': payload['issued_at'], 'payload_hash': hashlib.sha256(envelope.canonical(payload)).hexdigest()}
        path = self.state_path
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        lock_path = str(path) + '.lock'
        fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        temp = str(path) + '.' + uuid.uuid4().hex + '.tmp'
        try:
            prev = None
            if path.exists() or path.is_symlink():
                if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
                    raise ValueError('SDK control ratchet is not a bounded regular file')
                prev = json.loads(path.read_text())
            if prev is not None:
                if not isinstance(prev, dict) or prev.get('schema') != 1 or prev.get('pubkey') != mark['pubkey'] \
                        or prev.get('workspace_id') != self.workspace_id or type(prev.get('issued_at')) is not int \
                        or not isinstance(prev.get('payload_hash'), str):
                    raise ValueError('SDK control ratchet binding mismatch')
                if payload['issued_at'] < prev['issued_at'] or (payload['issued_at'] == prev['issued_at'] \
                        and mark['payload_hash'] != prev['payload_hash']):
                    raise ValueError('SDK control policy rollback')
                if payload['issued_at'] == prev['issued_at']:
                    return
                used = prev.get('used_approvals', [])
                if not isinstance(used, list):
                    raise ValueError('invalid persisted approval state')
                mark['used_approvals'] = [a for a in used if a.get('expires_at', 0) > time.time()]
            out = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(out, 'w') as stream:
                json.dump(mark, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, path)
            self._sync_directory()
        finally:
            os.close(fd)
            os.unlink(lock_path)
            try:
                os.unlink(temp)
            except FileNotFoundError:
                pass

    def gate(self, kind, subject, effect):
        from nexus import enabled
        if not callable(effect):
            raise TypeError('SDK control gate requires an effect callback')
        if not enabled():
            return effect(engine.Decision(source='disabled'))
        with self._lock:
            self.refresh()
            if self.snapshot.env.payload['expires_at'] <= time.time():
                raise RuntimeError('SDK control authority expired')
            # Reuse the tested engine with this client's snapshot; remote approvals must never
            # fall through to the unrelated process-local approver channel.
            d = engine._decide(kind, subject, None, None, 0, None, engine._perf(),
                               snapshot_override=self.snapshot, external_approval=True)
            if d.source in ('error', 'budget-exceeded', 'no-policy'):
                raise RuntimeError('SDK control could not decide safely')
            approval_id = None
            approval_signature = None
            approval_deadline = None
            if d.denied and d.source == 'approval-unavailable':
                fingerprint = hashlib.sha256(envelope.canonical({'kind': kind, 'subject': subject})).hexdigest()
                request_key = self.revision + ':' + d.rule_id + ':' + fingerprint
                if request_key not in self.pending:
                    if len(self.pending) >= 20:
                        raise RuntimeError('SDK control pending approval capacity exhausted')
                    self.pending[request_key] = {'request_id': str(uuid.uuid4()), 'session_id': self.session_id,
                        'policy_signature': self.revision, 'rule_id': d.rule_id, 'subject_fingerprint': fingerprint,
                        'action_kind': 'tool' if kind == 'tool_action' else kind if kind in ('command', 'http') else 'other'}
                pending_id = self.pending[request_key]['request_id']
                if pending_id not in self.approvals:
                    self.refresh()
                d = engine._decide(kind, subject, None, None, 0, None, engine._perf(),
                                   snapshot_override=self.snapshot, external_approval=True)
                if d.source in ('error', 'budget-exceeded', 'no-policy'):
                    raise RuntimeError('SDK control could not decide safely')
                for aid, a in self.approvals.items():
                    if d.denied and d.source == 'approval-unavailable' and aid == pending_id \
                            and a.get('rule_id') == d.rule_id and a.get('subject_fingerprint') == fingerprint \
                            and a['expires_at'] > time.time() and aid not in self.used:
                        approval_id = aid
                        approval_signature = a['signature']
                        approval_deadline = a['expires_at']
                        break
            if d.denied and not approval_id:
                self._evidence(kind, subject, d, 'denied')
                raise engine.Denied(d)
            if approval_id:
                try:
                    self._consume_approval(approval_id, self.approvals[approval_id]['expires_at'])
                except Exception:
                    self.approval_receipts[approval_id] = {'request_id': approval_id, 'signature': approval_signature, 'status': 'rejected'}
                    self._evidence(kind, subject, d, 'denied')
                    raise RuntimeError('SDK control approval consumed or unavailable') from None
                self.used.add(approval_id)
                self.pending.pop(request_key, None)
                self.approvals.pop(approval_id, None)
                if len(self.used) > 10000:
                    raise RuntimeError('SDK control approval capacity exhausted')
                d = dataclasses.replace(d, action='allow', enforced=True, source='signed-approval')
            self._evidence(kind, subject, d, 'approved' if approval_id else 'advisory' if d.action == 'deny' else 'allowed')
            if self.snapshot.env.payload['expires_at'] <= time.time() or (approval_deadline and approval_deadline <= time.time()):
                if approval_id:
                    self.approval_receipts[approval_id] = {'request_id': approval_id, 'signature': approval_signature, 'status': 'rejected'}
                raise RuntimeError('SDK control authority expired before effect')
            try:
                result = effect(d)
                if approval_id:
                    self.approval_receipts[approval_id] = {'request_id': approval_id, 'signature': approval_signature, 'status': 'applied'}
                return result
            except Exception:
                if approval_id:
                    self.approval_receipts[approval_id] = {'request_id': approval_id, 'signature': approval_signature, 'status': 'uncertain'}
                raise

    def _evidence(self, kind, subject, decision, disposition):
        try:
            from nexus import client, contract
            c = client.get_client()
            if c is None:
                return
            event = contract.tool_action(c.session_id, c.cfg, tool_name=subject.get('tool') or kind,
                                        action='invoke', target=subject.get('target'), blocked=decision.denied,
                                        reason=decision.reason)
            if decision.rule_id:
                event['rule_id'] = decision.rule_id
            event['disposition'] = disposition
            c.emit(event)
        except Exception:
            pass  # evidence availability never grants permission

    def _sync_directory(self):
        try:
            fd = os.open(self.state_path.parent, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            if os.name != 'nt':
                raise

    @staticmethod
    def _canonical_numbers(value):
        if isinstance(value, dict):
            return all(ControlClient._canonical_numbers(v) for v in value.values())
        if isinstance(value, list):
            return all(ControlClient._canonical_numbers(v) for v in value)
        return type(value) is not float and (type(value) is not int or abs(value) <= 9007199254740991)

    def _consume_approval(self, aid, expires_at):
        result, done = {}, threading.Event()
        def persist():
            try:
                self._persist_approval(aid, expires_at)
            except Exception as exc:
                result['error'] = exc
            finally:
                done.set()
        threading.Thread(target=persist, name='nexus-sdk-control', daemon=True).start()
        if not done.wait(self.timeout_s + 1) or 'error' in result:
            raise RuntimeError('approval consumption unavailable')

    def _persist_approval(self, aid, expires_at):
        path = self.state_path
        lock_path = str(path) + '.lock'
        fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        temp = str(path) + '.' + uuid.uuid4().hex + '.tmp'
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
                raise ValueError('invalid approval state')
            data = json.loads(path.read_text())
            if data.get('workspace_id') != self.workspace_id or data.get('pubkey') != self.pubkey_hex.lower():
                raise ValueError('approval binding mismatch')
            used = data.get('used_approvals', [])
            if not isinstance(used, list):
                raise ValueError('invalid approval state')
            used = [a for a in used if a.get('expires_at', 0) > time.time()]
            if len(used) >= 10000 or any(a.get('id') == aid for a in used):
                raise ValueError('approval already consumed')
            data['used_approvals'] = used + [{'id': aid, 'expires_at': expires_at}]
            out = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(out, 'w') as stream:
                json.dump(data, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, path)
            self._sync_directory()
        finally:
            os.close(fd)
            os.unlink(lock_path)
            try:
                os.unlink(temp)
            except FileNotFoundError:
                pass
