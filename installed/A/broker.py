# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Owned Root UNIX metadata rendezvous; image/layer bytes never traverse it."""
import json
import os
import queue
import re
import socket
import stat
import struct
import threading
import time
import uuid
from plan import SOCKET, OPERATION, Refused, need
CAP = 2 * 1024 ** 2
KINDS = frozenset(('pulse', 'dns', 'anonymous-token'))

def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()

def frame(conn):
    raw = bytearray()
    while len(raw) <= CAP:
        data = conn.recv(min(65536, CAP + 1 - len(raw)))
        need(data, 'metadata_EOF')
        raw.extend(data)
        if b'\n' in raw:
            break
    need(len(raw) <= CAP and raw.count(b'\n') == 1 and raw.endswith(b'\n'), 'one_bounded_metadata_frame')
    from json import loads

    def pairs(items):
        result = {}
        for k, v in items:
            need(k not in result, 'duplicate_metadata_key')
            result[k] = v
        return result
    try:
        return loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(Refused('nonfinite_metadata')))
    except Exception:
        raise Refused('metadata_frame_refused') from None

def peer(conn):
    pid, uid, gid = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    need(uid == 0, 'metadata_Root_peer_only')
    return pid

class Broker:

    def __init__(self, end, path=SOCKET):
        self.end, self.path = (end, path)
        self.listener, self.thread = (None, None)
        self.lock = threading.Lock()
        self.pending = None
        self.failure = None
        self.done = threading.Event()
        self.answers = queue.Queue(maxsize=1)
        self.worker_pid = None
        self.worker_thread = None

    def start(self):
        need(not os.path.lexists(self.path), 'new_owned_metadata_socket_only')
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.listener.bind(self.path)
            os.chmod(self.path, 384)
            self.listener.listen(2)
            self.listener.settimeout(0.25)
        except BaseException:
            self.listener.close()
            self.failure = 'owned_metadata_bind_failed'
            raise Refused('owned_metadata_bind_failed') from None
        self.socket_identity = os.lstat(self.path)
        self.thread = threading.Thread(target=self.serve, name='owned-registry-metadata', daemon=False)
        self.thread.start()

    def serve(self):
        try:
            while not self.done.is_set():
                need(time.monotonic() < self.end, 'metadata_whole_deadline')
                try:
                    conn, _ = self.listener.accept()
                except socket.timeout:
                    continue
                handed = False
                try:
                    conn.settimeout(min(30, self.end - time.monotonic()))
                    pid = peer(conn)
                    request = frame(conn)
                    need(request.get('operation') == OPERATION, 'metadata_fixed_operation')
                    action = request.get('action')
                    if action == 'worker-request':
                        need(pid == self.worker_pid and set(request) == {'action', 'operation', 'kind', 'nonce', 'payload'} and (request['kind'] in KINDS) and re.fullmatch('[0-9a-f]{32}', request['nonce']), 'owned_worker_metadata_request')
                        with self.lock:
                            need(self.pending is None and self.answers.empty(), 'one_metadata_request_inflight')
                            self.pending = request
                        need(self.worker_thread is None or not self.worker_thread.is_alive(), 'one_worker_wait_thread')
                        self.worker_thread = threading.Thread(target=self.worker_answer, args=(conn, request), daemon=False)
                        self.worker_thread.start()
                        handed = True
                    elif action == 'parent-next':
                        need(set(request) == {'action', 'operation'}, 'parent_next_fixed_shape')
                        with self.lock:
                            conn.sendall(encode({'ok': True, 'pending': self.pending, 'failure': self.failure}))
                    else:
                        need(action == 'parent-answer' and set(request) == {'action', 'operation', 'nonce', 'answer'}, 'fixed_parent_metadata_answer')
                        with self.lock:
                            need(self.pending is not None and request['nonce'] == self.pending['nonce'] and self.answers.empty(), 'late_unknown_duplicate_metadata_answer')
                            self.answers.put_nowait({'ok': True, 'nonce': request['nonce'], 'answer': request['answer']})
                        conn.sendall(encode({'ok': True, 'accepted_nonce': request['nonce']}))
                finally:
                    if not handed:
                        conn.close()
        except BaseException:
            self.failure = 'owned_metadata_failed'
            self.done.set()
        finally:
            if self.listener is not None:
                self.listener.close()

    def worker_answer(self, conn, request):
        try:
            answer = self.answers.get(timeout=min(30, self.end - time.monotonic()))
            need(answer['nonce'] == request['nonce'], 'same_metadata_answer_nonce')
            conn.sendall(encode(answer))
        except BaseException:
            self.failure = 'worker_metadata_timeout_or_send_failed'
            self.done.set()
        finally:
            conn.close()
            with self.lock:
                self.pending = None

    def close(self):
        self.done.set()
        if self.thread is not None:
            self.thread.join(timeout=max(0.001, min(31, self.end - time.monotonic())))
            need(not self.thread.is_alive(), 'metadata_thread_alive_preserve_owned_scope')
        if self.worker_thread is not None:
            self.worker_thread.join(timeout=max(0.001, min(31, self.end - time.monotonic())))
            need(not self.worker_thread.is_alive(), 'metadata_worker_thread_alive_preserve_owned_scope')
        if self.listener is not None:
            self.listener.close()

def exchange(value, end, path=SOCKET, server_pid=None):
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        st = os.lstat(path)
        need(stat.S_ISSOCK(st.st_mode) and st.st_uid == 0 and (stat.S_IMODE(st.st_mode) == 384), 'Root_owned_metadata_endpoint')
        conn.settimeout(min(30, end - time.monotonic()))
        conn.connect(path)
        pid = peer(conn)
        need(server_pid is not None and pid == server_pid, 'owned_exact_metadata_server_PID')
        conn.sendall(encode(value))
        return frame(conn)
    except Exception:
        raise Refused('metadata_exchange_failed') from None
    finally:
        conn.close()

def request(kind, payload, end, server_pid=None):
    need(kind in KINDS, 'fixed_metadata_kind')
    nonce = uuid.uuid4().hex
    r = exchange({'action': 'worker-request', 'operation': OPERATION, 'kind': kind, 'nonce': nonce, 'payload': payload}, end, server_pid=os.getppid() if server_pid is None else server_pid)
    need(r.get('ok') is True and r.get('nonce') == nonce and (set(r) == {'ok', 'nonce', 'answer'}), 'metadata_original_answer')
    if kind == 'dns':
        need(type(r['answer']) is dict and r['answer'].get('query_nonce') == nonce, 'DNS_supplier_actual_request_nonce_not_two_self_asserted_fields')
    return r['answer']
