#!/usr/bin/env python3

import argparse
import collections
import csv
import dataclasses
import datetime
import hashlib
import ipaddress
import json
import os
import pathlib
import platform
import re
import shutil
import signal
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any


VERSION = '1.0.0'
SCHEMA_VERSION = 1


class ObserverError(Exception):
    pass


@dataclasses.dataclass(frozen=True)
class CommandResult:
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False

    def as_dict(self):
        return dataclasses.asdict(self)


@dataclasses.dataclass
class Finding:
    severity: str
    code: str
    title: str
    detail: str
    evidence: dict = dataclasses.field(default_factory=dict)

    def as_dict(self):
        return dataclasses.asdict(self)


class Runner:
    def __init__(self, binary='pfctl', timeout=8.0, max_bytes=4_000_000):
        self.binary = shutil.which(binary) or (binary if os.path.isabs(binary) and os.access(binary, os.X_OK) else None)
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.calls = 0
        self.errors = 0
        self.elapsed = 0.0

    def execute(self, args):
        if not self.binary:
            return CommandResult(tuple(args), 127, '', 'pfctl executable not found', 0.0)
        argv = [self.binary, *args]
        start = time.monotonic()
        timed_out = False
        try:
            process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
            try:
                output, error = process.communicate(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                process.kill()
                output, error = process.communicate()
            rc = 124 if timed_out else process.returncode
            stdout = output[:self.max_bytes].decode('utf-8', errors='replace')
            stderr = error[:self.max_bytes].decode('utf-8', errors='replace')
        except OSError as exc:
            rc, stdout, stderr = 126, '', str(exc)
        elapsed = time.monotonic() - start
        self.calls += 1
        self.elapsed += elapsed
        if rc:
            self.errors += 1
        return CommandResult(tuple(args), rc, stdout, stderr, elapsed, timed_out)


class Parsing:
    NUMBER = re.compile(r'(?<!\w)(\d[\d,]*)(?!\w)')
    RULE = re.compile(r'^\s*(?:@(?P<index>\d+)\s+)?(?P<action>pass|block|match|anchor|antispoof|scrub|nat|rdr|binat|no\s+nat|no\s+rdr)\b(?P<body>.*)$', re.I)
    LABEL = re.compile(r'\blabel\s+"([^"]+)"')
    IFACE = re.compile(r'\bon\s+(?:\{\s*)?([a-zA-Z][\w.:-]*)')
    PORT = re.compile(r'\bport\s+(?:=\s*)?(\d+|[\w-]+)')
    PROTO = re.compile(r'\bproto\s+(tcp|udp|icmp6?|\{[^}]+\}|\w+)')
    COUNTERS = re.compile(r'\b(Packets|Bytes|States|Evaluations|In|Out|Pass|Block|Match)\s*:\s*([\d,]+)', re.I)
    STATE_LINE = re.compile(r'^\s*(?P<proto>tcp|udp|icmp|icmp6|gre|esp|\w+)\s+(?P<body>.+)$', re.I)
    INT = re.compile(r'^\s*([\w./:-]+)\s+(\d[\d,]*)\s+(\d[\d,]*)\s+(\d[\d,]*)\s+(\d[\d,]*)\s*$')

    @staticmethod
    def integer(value, default=0):
        try:
            return int(str(value).replace(',', ''))
        except (ValueError, TypeError):
            return default

    @staticmethod
    def digest(value):
        return hashlib.sha256(value.encode('utf-8', errors='replace')).hexdigest()

    @staticmethod
    def parse_status(text):
        data = {'enabled': None, 'since': None, 'debug': None, 'hostid': None, 'checksum': None, 'counters': {}, 'raw_sections': {}}
        section = 'general'
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            match = re.search(r'\bStatus:\s*(Enabled|Disabled)', stripped, re.I)
            if match:
                data['enabled'] = match.group(1).lower() == 'enabled'
                since = re.search(r'\bfor\s+(.+)$', stripped, re.I)
                if since:
                    data['since'] = since.group(1)
            for key, pattern in [('debug', r'^Debug:\s*(.+)$'), ('hostid', r'^Hostid:\s*(\S+)'), ('checksum', r'^Checksum:\s*(\S+)')]:
                match = re.search(pattern, stripped, re.I)
                if match:
                    data[key] = match.group(1).strip()
            if re.match(r'^[A-Za-z][A-Za-z /-]+:\s*$', stripped):
                section = stripped.rstrip(':').lower().replace(' ', '_')
                continue
            data['raw_sections'].setdefault(section, []).append(stripped)
            match = re.match(r'^([\w][\w /.-]*?)\s{2,}([\d,]+)(?:\s|$)', stripped)
            if match:
                key = section + '.' + match.group(1).strip().lower().replace(' ', '_')
                data['counters'][key] = Parsing.integer(match.group(2))
        return data

    @staticmethod
    def parse_rules(text, category):
        rules = []
        current = None
        for line in text.splitlines():
            match = Parsing.RULE.match(line)
            if match:
                body = match.group('body').strip()
                action = match.group('action').lower().replace(' ', '_')
                label = Parsing.LABEL.search(body)
                iface = Parsing.IFACE.search(body)
                proto = Parsing.PROTO.search(body)
                port = Parsing.PORT.search(body)
                current = {
                    'category': category,
                    'index': Parsing.integer(match.group('index'), len(rules)),
                    'action': action,
                    'direction': 'in' if re.search(r'\bin\b', body) else ('out' if re.search(r'\bout\b', body) else 'any'),
                    'quick': bool(re.search(r'\bquick\b', body)),
                    'interface': iface.group(1) if iface else None,
                    'protocol': proto.group(1) if proto else None,
                    'port': port.group(1) if port else None,
                    'label': label.group(1) if label else None,
                    'log': bool(re.search(r'\blog\b', body)),
                    'keep_state': bool(re.search(r'\bkeep\s+state\b', body)),
                    'text': line.strip(),
                    'fingerprint': Parsing.digest(line.strip()),
                    'counters': {},
                }
                rules.append(current)
            elif current:
                for name, value in Parsing.COUNTERS.findall(line):
                    current['counters'][name.lower()] = Parsing.integer(value)
        return rules

    @staticmethod
    def parse_states(text, limit):
        states = []
        for line in text.splitlines():
            if len(states) >= limit:
                break
            match = Parsing.STATE_LINE.match(line)
            if not match:
                continue
            body = match.group('body').strip()
            if not ('->' in body or '<-' in body):
                continue
            endpoints = re.split(r'\s+(?:->|<-)\s+', body, maxsplit=1)
            left = endpoints[0].strip()
            right = endpoints[1].strip() if len(endpoints) > 1 else ''
            state_match = re.search(r'\b(ESTABLISHED|SYN_SENT|SYN_RECEIVED|FIN_WAIT_?[12]|CLOSE_WAIT|CLOSING|LAST_ACK|TIME_WAIT|CLOSED|MULTIPLE|SINGLE|NO_TRAFFIC|UNREPLIED|ASSURED|PROXY_SRC|PROXY_DST)(?::[\w_]+)?\b', body, re.I)
            state = state_match.group(0) if state_match else 'UNKNOWN'
            states.append({'protocol': match.group('proto').lower(), 'source': left, 'destination': right, 'state': state, 'text': line.strip(), 'fingerprint': Parsing.digest(line.strip())})
        return states

    @staticmethod
    def parse_tables(text):
        tables = []
        for line in text.splitlines():
            name = line.strip().split()
            if name and not name[0].startswith('#'):
                tables.append(name[0])
        return sorted(set(tables))

    @staticmethod
    def parse_interfaces(text):
        items = []
        current = None
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            match = re.match(r'^([\w.:-]+)\s*$', stripped)
            if match:
                current = {'name': match.group(1), 'details': [], 'counters': {}}
                items.append(current)
            elif current:
                current['details'].append(stripped)
                for name, value in Parsing.COUNTERS.findall(stripped):
                    current['counters'][name.lower()] = Parsing.integer(value)
        return items

    @staticmethod
    def parse_limits(text):
        limits = {}
        for line in text.splitlines():
            match = re.match(r'^\s*([\w.-]+)\s+(\d[\d,]*)\s*$', line)
            if match:
                limits[match.group(1)] = Parsing.integer(match.group(2))
        return limits

    @staticmethod
    def parse_timeouts(text):
        values = {}
        for line in text.splitlines():
            match = re.match(r'^\s*([\w.:-]+)\s+(\d[\d,]*)\s*$', line)
            if match:
                values[match.group(1)] = Parsing.integer(match.group(2))
        return values


class Storage:
    def __init__(self, path):
        self.path = pathlib.Path(path).expanduser()
        self.lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), timeout=10, check_same_thread=False)
        self.conn.execute('PRAGMA journal_mode=WAL')
        self.conn.execute('PRAGMA busy_timeout=10000')
        self.conn.executescript('''
            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                epoch REAL NOT NULL,
                enabled INTEGER,
                rules INTEGER NOT NULL,
                states INTEGER NOT NULL,
                findings INTEGER NOT NULL,
                digest TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_snapshots_epoch ON snapshots(epoch);
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                epoch REAL NOT NULL,
                timestamp TEXT NOT NULL,
                kind TEXT NOT NULL,
                severity TEXT NOT NULL,
                detail TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_epoch ON events(epoch);
        ''')
        self.conn.commit()

    def save(self, snapshot):
        with self.lock:
            metrics = snapshot['metrics']
            self.conn.execute('INSERT INTO snapshots(timestamp,epoch,enabled,rules,states,findings,digest,payload) VALUES(?,?,?,?,?,?,?,?)', (
                snapshot['timestamp'], snapshot['epoch'], None if snapshot['status']['enabled'] is None else int(snapshot['status']['enabled']),
                metrics['rules'], metrics['states'], len(snapshot['findings']), snapshot['rule_digest'], json.dumps(snapshot, separators=(',', ':'))))
            self.conn.commit()

    def add_events(self, events):
        if not events:
            return
        with self.lock:
            self.conn.executemany('INSERT INTO events(epoch,timestamp,kind,severity,detail,payload) VALUES(?,?,?,?,?,?)', [
                (event['epoch'], event['timestamp'], event['kind'], event['severity'], event['detail'], json.dumps(event, separators=(',', ':'))) for event in events])
            self.conn.commit()

    def previous(self):
        with self.lock:
            row = self.conn.execute('SELECT payload FROM snapshots ORDER BY id DESC LIMIT 1').fetchone()
        if not row:
            return None
        try:
            return json.loads(row[0])
        except json.JSONDecodeError:
            return None

    def history(self, limit=20):
        with self.lock:
            rows = self.conn.execute('SELECT timestamp,enabled,rules,states,findings,digest FROM snapshots ORDER BY id DESC LIMIT ?', (limit,)).fetchall()
        return [{'timestamp': r[0], 'enabled': None if r[1] is None else bool(r[1]), 'rules': r[2], 'states': r[3], 'findings': r[4], 'digest': r[5]} for r in rows]

    def events(self, limit=20):
        with self.lock:
            rows = self.conn.execute('SELECT payload FROM events ORDER BY id DESC LIMIT ?', (limit,)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def prune(self, keep):
        with self.lock:
            self.conn.execute('DELETE FROM snapshots WHERE id NOT IN (SELECT id FROM snapshots ORDER BY id DESC LIMIT ?)', (keep,))
            self.conn.execute('DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?)', (keep * 10,))
            self.conn.commit()

    def close(self):
        with self.lock:
            self.conn.close()


class Collector:
    TASKS = {
        'status': ['-s', 'info'],
        'rules': ['-vvs', 'rules'],
        'nat': ['-vvs', 'nat'],
        'states': ['-s', 'states'],
        'interfaces': ['-s', 'Interfaces'],
        'tables': ['-s', 'Tables'],
        'limits': ['-s', 'memory'],
        'timeouts': ['-s', 'timeouts'],
    }

    def __init__(self, runner, max_states=10000, include_raw=False):
        self.runner = runner
        self.max_states = max_states
        self.include_raw = include_raw

    def collect(self):
        started = time.monotonic()
        results = {name: self.runner.execute(args) for name, args in self.TASKS.items()}
        status = Parsing.parse_status(results['status'].stdout)
        rules = Parsing.parse_rules(results['rules'].stdout, 'filter')
        nat = Parsing.parse_rules(results['nat'].stdout, 'translation')
        states = Parsing.parse_states(results['states'].stdout, self.max_states)
        interfaces = Parsing.parse_interfaces(results['interfaces'].stdout)
        tables = Parsing.parse_tables(results['tables'].stdout)
        limits = Parsing.parse_limits(results['limits'].stdout)
        timeouts = Parsing.parse_timeouts(results['timeouts'].stdout)
        by_action = dict(collections.Counter(rule['action'] for rule in rules))
        by_protocol = dict(collections.Counter(state['protocol'] for state in states))
        by_state = dict(collections.Counter(state['state'] for state in states))
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        epoch = time.time()
        digest = Parsing.digest('\n'.join(rule['text'] for rule in rules + nat))
        data = {
            'schema_version': SCHEMA_VERSION,
            'version': VERSION,
            'timestamp': timestamp,
            'epoch': epoch,
            'host': {'hostname': platform.node(), 'system': platform.system(), 'release': platform.release(), 'python': platform.python_version(), 'uid': os.geteuid() if hasattr(os, 'geteuid') else None},
            'status': status,
            'rules': rules,
            'nat': nat,
            'states': states,
            'interfaces': interfaces,
            'tables': tables,
            'limits': limits,
            'timeouts': timeouts,
            'rule_digest': digest,
            'metrics': {
                'rules': len(rules), 'translations': len(nat), 'states': len(states), 'interfaces': len(interfaces), 'tables': len(tables),
                'rules_by_action': by_action, 'states_by_protocol': by_protocol, 'states_by_state': by_state,
                'collection_seconds': round(time.monotonic() - started, 4), 'commands': len(results),
                'failed_commands': sum(bool(r.returncode) for r in results.values()),
            },
            'commands': {name: {'returncode': r.returncode, 'stderr': r.stderr.strip(), 'duration': round(r.duration, 4), 'timed_out': r.timed_out} for name, r in results.items()},
            'findings': [],
        }
        if self.include_raw:
            data['raw'] = {name: result.stdout for name, result in results.items()}
        return data


class Analyzer:
    SEVERITIES = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}

    def analyze(self, snapshot):
        findings = []
        status = snapshot['status']
        metrics = snapshot['metrics']
        commands = snapshot['commands']
        if snapshot['host']['system'] != 'FreeBSD':
            findings.append(Finding('low', 'NON_FREEBSD', 'Non-FreeBSD host', 'This collector is designed for FreeBSD.'))
        if status['enabled'] is False:
            findings.append(Finding('medium', 'PF_DISABLED', 'PF is disabled', 'The packet filter is not currently enabled. This may be intentional.'))
        if status['enabled'] is None:
            findings.append(Finding('high', 'PF_STATUS_UNKNOWN', 'Unable to determine PF status', 'Inspect pfctl availability, kernel support, and user permissions.'))
        for name, result in commands.items():
            if result['returncode'] != 0:
                findings.append(Finding('low', 'COLLECT_' + name.upper(), 'Collection unavailable: ' + name, result['stderr'] or 'pfctl returned a nonzero status', {'returncode': result['returncode']}))
        if status['enabled'] and not metrics['rules']:
            findings.append(Finding('medium', 'NO_FILTER_RULES', 'No filter rules collected', 'PF is enabled but no filter rules were visible. Verify permissions and configuration.'))
        for rule in snapshot['rules']:
            text = rule['text'].lower()
            if rule['action'] == 'pass' and re.search(r'\bfrom\s+any\s+to\s+any\b', text) and not rule['quick']:
                findings.append(Finding('low', 'BROAD_PASS', 'Broad pass rule', 'Review a pass rule matching any source and destination; later rules may affect its outcome.', {'rule': rule['text']}))
            if rule['action'] == 'pass' and re.search(r'\bfrom\s+any\s+to\s+any\b', text) and rule['quick']:
                findings.append(Finding('medium', 'BROAD_QUICK_PASS', 'Broad quick pass rule', 'A quick pass rule matches any source and destination. Verify its intended scope.', {'rule': rule['text']}))
            if rule['action'] == 'pass' and 'log' not in text and rule['direction'] == 'in':
                findings.append(Finding('info', 'PASS_WITHOUT_LOG', 'Inbound pass rule without logging', 'Logging is not configured for this inbound pass rule.', {'rule': rule['text']}))
        if metrics['states'] >= 10000:
            findings.append(Finding('low', 'HIGH_STATE_COUNT', 'Large state sample', 'State count reached 10,000 or more. Review configured limits.', {'states': metrics['states']}))
        if snapshot['host']['uid'] not in (0, None) and metrics['failed_commands']:
            findings.append(Finding('info', 'PERMISSION_CONTEXT', 'Unprivileged collection', 'Some PF observations may require root privileges.'))
        snapshot['findings'] = [f.as_dict() for f in sorted(findings, key=lambda f: -self.SEVERITIES.get(f.severity, 0))]
        snapshot['metrics']['finding_severities'] = dict(collections.Counter(f.severity for f in findings))
        snapshot['metrics']['risk_score'] = min(100, sum({'critical': 30, 'high': 18, 'medium': 7, 'low': 2, 'info': 0}[f.severity] for f in findings))
        return snapshot


class Differ:
    @staticmethod
    def compare(previous, current):
        if not previous:
            return []
        events = []
        stamp = current['timestamp']
        epoch = current['epoch']

        def add(kind, severity, detail, payload=None):
            events.append({'timestamp': stamp, 'epoch': epoch, 'kind': kind, 'severity': severity, 'detail': detail, 'payload': payload or {}})

        before = previous['status']['enabled']
        after = current['status']['enabled']
        if before != after:
            add('pf_status_changed', 'high' if after is False else 'medium', f'PF status changed from {before} to {after}')
        if previous['rule_digest'] != current['rule_digest']:
            add('rules_changed', 'medium', 'Filter or translation rule fingerprint changed', {'before': previous['rule_digest'], 'after': current['rule_digest']})
        for key in ('rules', 'translations', 'states', 'interfaces', 'tables'):
            a = previous['metrics'].get(key, 0)
            b = current['metrics'].get(key, 0)
            if a != b:
                add('metric_changed', 'info', f'{key}: {a} -> {b}', {'metric': key, 'before': a, 'after': b, 'delta': b - a})
        old_findings = {f['code'] + ':' + json.dumps(f.get('evidence', {}), sort_keys=True) for f in previous.get('findings', [])}
        for finding in current.get('findings', []):
            key = finding['code'] + ':' + json.dumps(finding.get('evidence', {}), sort_keys=True)
            if key not in old_findings:
                add('finding_new', finding['severity'], finding['title'], finding)
        return events


class Formatter:
    @staticmethod
    def terminal(snapshot, show_rules=False, show_states=False, show_findings=True, max_rows=30):
        m = snapshot['metrics']
        status = snapshot['status']['enabled']
        state = 'ENABLED' if status is True else ('DISABLED' if status is False else 'UNKNOWN')
        lines = [
            'PF OBSERVER | FreeBSD packet filter observability',
            '=' * 76,
            f"Host: {snapshot['host']['hostname']}  FreeBSD: {snapshot['host']['release']}  Time: {snapshot['timestamp']}",
            f"PF: {state}  Rules: {m['rules']}  NAT: {m['translations']}  States: {m['states']}",
            f"Interfaces: {m['interfaces']}  Tables: {m['tables']}  Risk score: {m['risk_score']}/100",
            f"Commands: {m['commands']}  Failed: {m['failed_commands']}  Collection: {m['collection_seconds']:.3f}s",
            f"Rule SHA256: {snapshot['rule_digest']}",
        ]
        if m['states_by_protocol']:
            lines.append('Protocols: ' + ', '.join(f'{k}={v}' for k, v in sorted(m['states_by_protocol'].items())))
        if m['states_by_state']:
            lines.append('TCP/state labels: ' + ', '.join(f'{k}={v}' for k, v in sorted(m['states_by_state'].items())))
        if show_rules:
            lines += ['', 'FILTER RULES', '-' * 76]
            lines.extend(f"[{r['index']:>4}] {r['text']}" for r in snapshot['rules'][:max_rows])
            if len(snapshot['rules']) > max_rows:
                lines.append(f"... {len(snapshot['rules']) - max_rows} more rules")
            lines += ['', 'TRANSLATION RULES', '-' * 76]
            lines.extend(r['text'] for r in snapshot['nat'][:max_rows])
        if show_states:
            lines += ['', 'STATES', '-' * 76]
            lines.extend(s['text'] for s in snapshot['states'][:max_rows])
            if len(snapshot['states']) > max_rows:
                lines.append(f"... {len(snapshot['states']) - max_rows} more states")
        if show_findings:
            lines += ['', 'FINDINGS', '-' * 76]
            if not snapshot['findings']:
                lines.append('No heuristic findings')
            for finding in snapshot['findings'][:max_rows]:
                lines.append(f"[{finding['severity'].upper()}] {finding['code']}: {finding['title']}")
                lines.append('  ' + finding['detail'])
        return '\n'.join(lines) + '\n'

    @staticmethod
    def csv(snapshot, section='states'):
        import io
        stream = io.StringIO()
        writer = csv.writer(stream)
        if section == 'states':
            fields = ['protocol', 'source', 'destination', 'state', 'fingerprint']
            rows = snapshot['states']
        elif section == 'rules':
            fields = ['category', 'index', 'action', 'direction', 'quick', 'interface', 'protocol', 'port', 'label', 'log', 'fingerprint', 'text']
            rows = snapshot['rules'] + snapshot['nat']
        else:
            fields = ['severity', 'code', 'title', 'detail']
            rows = snapshot['findings']
        writer.writerow(fields)
        for row in rows:
            writer.writerow([row.get(field, '') for field in fields])
        return stream.getvalue()

    @staticmethod
    def json(data, pretty=True):
        return json.dumps(data, indent=2 if pretty else None, ensure_ascii=False, default=str) + '\n'


class Reporter:
    @staticmethod
    def atomic_write(path, content):
        target = pathlib.Path(path).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix='.pf-observer-', dir=str(target.parent))
        try:
            with os.fdopen(descriptor, 'w', encoding='utf-8', newline='') as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


class Runtime:
    def __init__(self, args):
        self.args = args
        self.stop = threading.Event()
        self.runner = Runner(args.pfctl, args.timeout, args.max_output_bytes)
        self.collector = Collector(self.runner, args.max_states, args.raw)
        self.analyzer = Analyzer()
        self.store = Storage(args.database) if not args.no_database else None
        self.iterations = 0

    def shutdown(self, *_):
        self.stop.set()

    def once(self):
        previous = self.store.previous() if self.store else None
        snapshot = self.analyzer.analyze(self.collector.collect())
        events = Differ.compare(previous, snapshot)
        snapshot['events'] = events
        if self.store:
            self.store.save(snapshot)
            self.store.add_events(events)
            if self.iterations % 25 == 0:
                self.store.prune(self.args.retain)
        return snapshot

    def output(self, snapshot):
        if self.args.format == 'json':
            content = Formatter.json(snapshot)
        elif self.args.format == 'csv':
            content = Formatter.csv(snapshot, self.args.csv_section)
        else:
            content = Formatter.terminal(snapshot, self.args.rules, self.args.states, not self.args.no_findings, self.args.max_rows)
            if self.args.events and snapshot['events']:
                content += '\nEVENTS\n' + '\n'.join(f"[{e['severity']}] {e['detail']}" for e in snapshot['events']) + '\n'
        if self.args.output:
            Reporter.atomic_write(self.args.output, content)
        else:
            sys.stdout.write(content)
            sys.stdout.flush()

    def run(self):
        if self.args.history:
            if not self.store:
                raise ObserverError('History requires the database')
            records = self.store.history(self.args.history)
            sys.stdout.write(Formatter.json(records) if self.args.format == 'json' else '\n'.join(f"{r['timestamp']}  PF={r['enabled']}  rules={r['rules']}  states={r['states']}  findings={r['findings']}" for r in records) + '\n')
            return 0
        if self.args.event_history:
            if not self.store:
                raise ObserverError('Event history requires the database')
            events = self.store.events(self.args.event_history)
            sys.stdout.write(Formatter.json(events))
            return 0
        while not self.stop.is_set():
            self.iterations += 1
            snapshot = self.once()
            self.output(snapshot)
            if self.args.strict and snapshot['metrics']['failed_commands']:
                return 2
            if self.args.fail_on_risk is not None and snapshot['metrics']['risk_score'] >= self.args.fail_on_risk:
                return 3
            if not self.args.watch or (self.args.count and self.iterations >= self.args.count):
                break
            self.stop.wait(self.args.interval)
        return 0

    def close(self):
        if self.store:
            self.store.close()


def build_parser():
    parser = argparse.ArgumentParser(prog='pf-observer', description='Read-only FreeBSD PF monitoring, forensics, and history')
    parser.add_argument('--version', action='version', version='pf-observer ' + VERSION)
    parser.add_argument('--pfctl', default='/sbin/pfctl' if os.path.isfile('/sbin/pfctl') else 'pfctl')
    parser.add_argument('--timeout', type=float, default=8.0)
    parser.add_argument('--max-output-bytes', type=int, default=4_000_000)
    parser.add_argument('--max-states', type=int, default=10000)
    parser.add_argument('--max-rows', type=int, default=30)
    parser.add_argument('--database', default=str(pathlib.Path.home() / '.local' / 'state' / 'pf-observer' / 'history.sqlite3'))
    parser.add_argument('--no-database', action='store_true')
    parser.add_argument('--retain', type=int, default=1000)
    parser.add_argument('--format', choices=('table', 'json', 'csv'), default='table')
    parser.add_argument('--csv-section', choices=('states', 'rules', 'findings'), default='states')
    parser.add_argument('--output')
    parser.add_argument('--rules', action='store_true')
    parser.add_argument('--states', action='store_true')
    parser.add_argument('--raw', action='store_true')
    parser.add_argument('--events', action='store_true')
    parser.add_argument('--no-findings', action='store_true')
    parser.add_argument('--watch', action='store_true')
    parser.add_argument('--interval', type=float, default=3.0)
    parser.add_argument('--count', type=int, default=0)
    parser.add_argument('--history', type=int, default=0)
    parser.add_argument('--event-history', type=int, default=0)
    parser.add_argument('--strict', action='store_true')
    parser.add_argument('--fail-on-risk', type=int)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.timeout <= 0 or args.interval <= 0 or args.max_states < 1 or args.max_rows < 1 or args.retain < 1 or args.max_output_bytes < 1024 or args.count < 0:
        parser.error('Timeout, interval, limits, and retention must be positive')
    if args.fail_on_risk is not None and not 0 <= args.fail_on_risk <= 100:
        parser.error('--fail-on-risk must be between 0 and 100')
    runtime = None
    try:
        runtime = Runtime(args)
        signal.signal(signal.SIGINT, runtime.shutdown)
        signal.signal(signal.SIGTERM, runtime.shutdown)
        return runtime.run()
    except (ObserverError, OSError, sqlite3.Error) as exc:
        print('pf-observer: ' + str(exc), file=sys.stderr)
        return 1
    finally:
        if runtime:
            runtime.close()


if __name__ == '__main__':
    sys.exit(main())
