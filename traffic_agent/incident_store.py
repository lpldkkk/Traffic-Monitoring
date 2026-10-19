"""Transactional incident persistence and read interfaces shared by Agent/UI.

All connection references are (session_id, connection_id). Evidence snapshots
are immutable; a finding can become withdrawn without erasing its past trigger.
"""
import json
import math
import time

from .anomaly import RULE_VERSION
from .incidents import (CORRELATION_VERSION, CORRELATION_WINDOW, WINDOW_SELECTION,
                        correlate, detector_windows, encoded, identity, risk_level, subject_processes)


def create_schema(db):
    schema = """
    CREATE TABLE IF NOT EXISTS incident_evidence(
      evidence_id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES capture_sessions(id) ON DELETE CASCADE,
      detector_version INTEGER NOT NULL, payload TEXT NOT NULL, created_at REAL NOT NULL);
    CREATE TABLE IF NOT EXISTS incident_findings(
      finding_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, connection_id TEXT NOT NULL,
      rule_code TEXT NOT NULL, detector_version INTEGER NOT NULL,
      first_seen REAL NOT NULL, last_seen REAL NOT NULL,
      original_score INTEGER NOT NULL CHECK(original_score BETWEEN 0 AND 100), risk_level TEXT NOT NULL,
      state TEXT NOT NULL CHECK(state IN ('active','withdrawn')), eligible INTEGER NOT NULL CHECK(eligible IN (0,1)),
      payload TEXT NOT NULL, revision INTEGER NOT NULL, created_at REAL NOT NULL, updated_at REAL NOT NULL,
      UNIQUE(session_id,connection_id,rule_code,detector_version),
      FOREIGN KEY(session_id,connection_id) REFERENCES session_connection_metrics(session_id,connection_id) ON DELETE CASCADE);
    CREATE INDEX IF NOT EXISTS finding_session ON incident_findings(session_id,state,first_seen);
    CREATE TABLE IF NOT EXISTS incident_finding_evidence(
      finding_id TEXT NOT NULL REFERENCES incident_findings(finding_id) ON DELETE CASCADE,
      evidence_id TEXT NOT NULL REFERENCES incident_evidence(evidence_id) ON DELETE CASCADE,
      PRIMARY KEY(finding_id,evidence_id));
    CREATE TABLE IF NOT EXISTS incidents(
      event_id TEXT PRIMARY KEY, correlation_version INTEGER NOT NULL, anchor_time REAL NOT NULL,
      first_seen REAL NOT NULL,last_seen REAL NOT NULL,risk_score INTEGER NOT NULL,
      severity TEXT NOT NULL CHECK(severity IN ('none','watch','medium','high')),
      status TEXT NOT NULL CHECK(status IN ('open','acknowledged','closed')),
      correlation_confidence TEXT NOT NULL, uncertainty_flags TEXT NOT NULL,
      closed_observed_through REAL, revision INTEGER NOT NULL, created_at REAL NOT NULL, updated_at REAL NOT NULL);
    CREATE INDEX IF NOT EXISTS incident_filter ON incidents(status,severity,first_seen,last_seen);
    CREATE INDEX IF NOT EXISTS incident_window ON incidents(correlation_version,anchor_time);
    CREATE TABLE IF NOT EXISTS incident_members(
      event_id TEXT NOT NULL REFERENCES incidents(event_id) ON DELETE CASCADE,
      finding_id TEXT NOT NULL UNIQUE REFERENCES incident_findings(finding_id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
      anchor_finding_id TEXT REFERENCES incident_findings(finding_id) ON DELETE SET NULL,
      reason TEXT NOT NULL, created_at REAL NOT NULL, PRIMARY KEY(event_id,finding_id));
    CREATE TABLE IF NOT EXISTS incident_timeline(
      timeline_id TEXT PRIMARY KEY, event_id TEXT NOT NULL REFERENCES incidents(event_id) ON DELETE CASCADE,
      finding_id TEXT REFERENCES incident_findings(finding_id) ON DELETE CASCADE,
      evidence_id TEXT REFERENCES incident_evidence(evidence_id) ON DELETE CASCADE,
      action TEXT NOT NULL, observed_at REAL NOT NULL, recorded_at REAL NOT NULL, payload TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS incident_time ON incident_timeline(event_id,observed_at,timeline_id);
    """
    for statement in schema.split(';'):
        if statement.strip():
            db.execute(statement)


class IncidentStore:
    def __init__(self, store):
        self.store, self.db = store, store.db

    @staticmethod
    def _finding(row):
        result = dict(row)
        result['data'] = json.loads(result.pop('payload'))
        result['eligible'] = bool(result['eligible'])
        return result

    def _drafts(self, session, records):
        findings, evidence, connections, applications = {}, {}, {}, {}

        def connection(row):
            cid = row['connection_id']
            if cid not in connections:
                connections[cid] = self.store._reference_connection(row)
                connections[cid].update({k: row[k] for k in ('syn_seen','syn_ack_seen','fin_seen','rst_seen',
                    'a_to_b_packets','b_to_a_packets','a_to_b_bytes','b_to_a_bytes')})
            return connections[cid]

        def application(row):
            cid = row['connection_id']
            if cid not in applications:
                key = (row['a'], row['ap'], row['b'], row['bp'], row['protocol'], cid)
                value = self.store._application_identity(session['id'], key)
                for page in range(2, value['pages']+1):
                    value['observations'].extend(self.store._application_identity(session['id'], key, page)['observations'])
                applications[cid] = value
            return applications[cid]

        for scope, assessment, context, members in detector_windows(records):
            # Only aliases and existing allowlisted application metadata enter
            # incident JSON; tools must never leak raw addresses or payloads.
            assessment = json.loads(encoded(assessment))
            for endpoint in ('src', 'dst'):
                if endpoint in assessment:
                    assessment[endpoint] = self.store.alias(assessment[endpoint])
            snapshot = {'session_id': session['id'], 'source_kind': session['source_kind'],
                'detector_version': RULE_VERSION, 'score_scope': scope, 'assessment': assessment,
                'selection_policy': WINDOW_SELECTION if scope == 'group_window' else 'all_scored_connections',
                'context_connections': [{'session_id': session['id'], **connection(r),
                    'application_identity': application(r)} for r in context]}
            eid = identity('ie_', snapshot)
            evidence[eid] = snapshot
            for signal in assessment['signals']:
                for row in members[signal['code']]:
                    cid, rule = row['connection_id'], signal['code']
                    fid = identity('finding_', session['id'], cid, RULE_VERSION, rule)
                    metric, app = connection(row), application(row)
                    processes, proxies = subject_processes(metric, app)
                    uncertainties = set(metric['uncertainties']) | {'metadata_not_malicious_probability', 'driver_packet_loss_unknown'}
                    if scope == 'group_window':
                        uncertainties.update(('group_membership_not_individual_verdict', WINDOW_SELECTION))
                    if app['status'] in ('unknown', 'partial', 'multiple_identities'):
                        uncertainties.add('application_'+app['status'])
                    if session['filtered'] or session['legacy_incomplete']:
                        uncertainties.add('incomplete_capture_scope')
                    eligible = metric['instance_kind'] == 'tcp_observed'
                    if not eligible:
                        uncertainties.add('not_precise_instance_pending_correlation')
                    data = {'connection': metric, 'application': app, 'subject_processes': processes,
                        'verified_proxy_processes': proxies, 'source_kind': session['source_kind'],
                        'capture_scope': identity('scope_', session['source_kind'], session['interface']),
                        'score_scope': scope, 'rule_score': signal['score'], 'trigger': signal,
                        'evidence_references': [eid], 'uncertainty_flags': sorted(uncertainties),
                        'completeness': {'handshake_basis': metric['handshake_basis'],
                            'instance_kind': metric['instance_kind'], 'filtered_capture': bool(session['filtered']),
                            'legacy_incomplete': bool(session['legacy_incomplete']),
                            'process_identity_status': app['status']}}
                    draft = dict(finding_id=fid, session_id=session['id'], connection_id=cid,
                        rule_code=rule, detector_version=RULE_VERSION, first_seen=row['first_seen'],
                        last_seen=row['last_seen'], original_score=assessment['anomaly_score'],
                        risk_level=assessment['risk_level'], state='active', eligible=int(eligible), data=data)
                    if fid in findings:
                        previous = findings[fid]
                        refs = sorted(set(previous['data']['evidence_references']+[eid]))
                        if draft['original_score'] > previous['original_score']:
                            findings[fid] = draft
                        findings[fid]['data']['evidence_references'] = refs
                    else:
                        findings[fid] = draft
        return findings, evidence

    def _timeline(self, event_id, action, observed, payload, fid=None, eid=None, marker=None):
        key = identity('it_', event_id, action, fid, marker if marker is not None else payload)
        self.db.execute('INSERT OR IGNORE INTO incident_timeline VALUES(?,?,?,?,?,?,?,?)',
            (key, event_id, fid, eid, action, observed, time.time(), encoded(payload)))

    def _members(self, event_id):
        return [self._finding(r) for r in self.db.execute('''SELECT f.* FROM incident_findings f
            JOIN incident_members m USING(finding_id) WHERE m.event_id=? ORDER BY f.first_seen,f.finding_id''', (event_id,))]

    def _reconcile_processes(self, event_id):
        members = self._members(event_id)
        dominant = next((set(map(tuple, f['data']['subject_processes'])) for f in members
                         if f['state'] == 'active' and f['data']['subject_processes']), set())
        for finding in members:
            tokens = set(map(tuple, finding['data']['subject_processes']))
            if finding['state'] == 'active' and tokens and dominant and not tokens & dominant:
                self.db.execute('DELETE FROM incident_members WHERE event_id=? AND finding_id=?', (event_id, finding['finding_id']))
                self._timeline(event_id, 'member_detached', finding['last_seen'],
                    {'reason': 'new_saved_process_identity_conflicts_with_event'}, finding['finding_id'], marker=finding['revision'])

    def _assign(self, finding, member_cache=None):
        # Cache only within this transaction. Re-reading and decoding an entire
        # growing event for each new member otherwise makes ingestion quadratic
        # in large JSON snapshots. Never reuse this after identity reconciliation.
        if member_cache is None:
            member_cache = {}
        fid = finding['finding_id']
        if not finding['eligible'] or finding['state'] != 'active':
            return None
        old = self.db.execute('SELECT event_id FROM incident_members WHERE finding_id=?', (fid,)).fetchone()
        if old:
            return old[0]
        candidates = self.db.execute('''SELECT DISTINCT e.* FROM incidents e LEFT JOIN incident_members m USING(event_id)
            LEFT JOIN incident_findings f USING(finding_id) WHERE e.correlation_version=? AND
            ((e.anchor_time<=? AND e.anchor_time>=?) OR (f.session_id=? AND f.connection_id=?))
            ORDER BY e.anchor_time,e.event_id''', (CORRELATION_VERSION, finding['first_seen'],
                finding['first_seen']-CORRELATION_WINDOW, finding['session_id'], finding['connection_id'])).fetchall()
        selected, reason, anchor = None, None, None
        existing_refs = {r[0] for r in self.db.execute('''SELECT m.event_id FROM incident_members m
            JOIN incident_findings f USING(finding_id) WHERE f.session_id=? AND f.connection_id=?''',
            (finding['session_id'],finding['connection_id']))}
        candidates = sorted(candidates, key=lambda e: (e['event_id'] not in existing_refs,e['anchor_time'],e['event_id']))
        for event in candidates:
            if event['event_id'] not in member_cache:
                member_cache[event['event_id']] = self._members(event['event_id'])
            members = member_cache[event['event_id']]
            same_connection = any((f['session_id'], f['connection_id']) == (finding['session_id'], finding['connection_id']) for f in members)
            known = {tuple(p) for f in members if f['state'] == 'active' for p in f['data']['subject_processes']}
            current = set(map(tuple, finding['data']['subject_processes']))
            if not same_connection and known and current and not known & current:
                continue
            for other in members:
                if other['state'] != 'active':
                    continue
                if finding['session_id'] != other['session_id'] and finding['data']['source_kind'] != 'live':
                    continue
                match = correlate(finding, other, event)
                if match:
                    selected, reason, anchor = event['event_id'], match, other['finding_id']
                    break
            if selected:
                break
        now = time.time()
        if selected is None:
            selected = identity('event_', CORRELATION_VERSION, fid)
            if self.db.execute('SELECT 1 FROM incident_members WHERE event_id=?', (selected,)).fetchone():
                # A former seed may be detached after new identity evidence.
                # Its original event ID must not silently reattach it there.
                selected = identity('event_', CORRELATION_VERSION, fid, finding['revision'],
                                    finding['data']['subject_processes'])
            self.db.execute('''INSERT OR IGNORE INTO incidents VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                (selected, CORRELATION_VERSION, finding['first_seen'], finding['first_seen'], finding['last_seen'],
                 finding['original_score'], finding['risk_level'], 'open', 'not_applicable', '[]', None, 1, now, now))
            reason = {'rule': 'SINGLE_CONNECTION_SEED', 'version': CORRELATION_VERSION, 'confidence': 'not_applicable',
                'fields': {'session_id': finding['session_id'], 'connection_id': finding['connection_id']},
                'window': {'anchor': finding['first_seen'], 'seconds': CORRELATION_WINDOW, 'time_basis': 'connection_first_seen'},
                'evidence_references': finding['data']['evidence_references'], 'meaning': '独立调查候选，不代表恶意已确认'}
            self._timeline(selected, 'created', finding['first_seen'], {'correlation_version': CORRELATION_VERSION})
        self.db.execute('INSERT INTO incident_members VALUES(?,?,?,?,?)', (selected, fid, anchor, encoded(reason), now))
        member_cache.setdefault(selected, []).append(finding)
        self.db.execute('UPDATE incidents SET revision=revision+1,updated_at=? WHERE event_id=?',(now,selected))
        self._timeline(selected, 'member_added', finding['first_seen'], reason, fid, finding['data']['evidence_references'][0])
        return selected

    def _refresh(self, event_id, allow_reopen=True):
        event = self.db.execute('SELECT * FROM incidents WHERE event_id=?', (event_id,)).fetchone()
        if event is None:
            return
        members = self._members(event_id)
        if not members:
            self.db.execute('DELETE FROM incidents WHERE event_id=?', (event_id,))
            return
        active = [f for f in members if f['state'] == 'active']
        score = max((f['original_score'] for f in active), default=0)
        flags = set(json.loads(event['uncertainty_flags'])) & {'source_data_removed'}
        # Process reconciliation can move a former anchor to another event.
        # Preserve the historical reason, but do not claim its support is current.
        for row in self.db.execute('''SELECT m.finding_id,m.reason FROM incident_members m
            WHERE m.event_id=? AND m.anchor_finding_id IS NOT NULL AND NOT EXISTS(
              SELECT 1 FROM incident_members a WHERE a.event_id=m.event_id AND a.finding_id=m.anchor_finding_id)''', (event_id,)).fetchall():
            reason = json.loads(row['reason'])
            reason['support_status'] = 'anchor_moved_revalidation_required'
            self.db.execute('UPDATE incident_members SET anchor_finding_id=NULL,reason=? WHERE finding_id=?',
                            (encoded(reason),row['finding_id']))
        flags.update(v for f in members for v in f['data']['uncertainty_flags'])
        if not active:
            flags.add('no_current_trigger')
        reasons = [json.loads(r[0]) for r in self.db.execute('SELECT reason FROM incident_members WHERE event_id=?', (event_id,))]
        if any(r.get('support_status') == 'anchor_moved_revalidation_required' for r in reasons):
            flags.add('association_support_changed')
        confidence = 'not_applicable' if len({(f['session_id'],f['connection_id']) for f in members}) == 1 else (
            'unknown' if flags & {'source_data_removed','association_support_changed'} else 'medium' if any(r['confidence']=='medium' for r in reasons) else 'high')
        status = event['status']
        if allow_reopen and status == 'closed' and any(f['last_seen'] > event['closed_observed_through'] for f in active):
            status = 'open'
            self._timeline(event_id, 'reopened', max(f['last_seen'] for f in active),
                           {'reason': 'new_observed_activity_after_close', 'previous_status': 'closed'}, marker=event['revision']+1)
        values = (min(f['first_seen'] for f in members), max(f['last_seen'] for f in members), score,
                  risk_level(score), status, confidence, encoded(sorted(flags)))
        current = tuple(event[k] for k in ('first_seen','last_seen','risk_score','severity','status','correlation_confidence','uncertainty_flags'))
        if values != current:
            self.db.execute('''UPDATE incidents SET first_seen=?,last_seen=?,risk_score=?,severity=?,status=?,
                correlation_confidence=?,uncertainty_flags=?,revision=revision+1,updated_at=? WHERE event_id=?''', (*values, time.time(), event_id))

    def process_session(self, session_id):
        """One atomic assessment/update, safe to retry after failure or restart."""
        with self.store.lock:
            if self.db.in_transaction:
                raise RuntimeError('事件处理需要独立事务，请先提交调用方事务')
            return self._process_session(session_id)

    def _process_session(self, session_id):
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            session = self.store._session(session_id)
            records = [dict(r) for r in self.db.execute('''SELECT * FROM session_connection_metrics
                WHERE session_id=? ORDER BY first_seen,connection_id''', (session_id,))]
            drafts, evidence = self._drafts(session, records)
            # A newer representative window must not withdraw an older valid
            # trigger merely because it is no longer the largest window. Recheck
            # its saved context with the SAME detector; memoize shared contexts.
            by_id = {r['connection_id']: r for r in records}
            recovered = {}
            for previous in self.db.execute("SELECT * FROM incident_findings WHERE session_id=? AND detector_version=? AND state='active'", (session_id,RULE_VERSION)).fetchall():
                if previous['finding_id'] in drafts:
                    continue
                data = json.loads(previous['payload'])
                if data['score_scope'] != 'group_window':
                    continue
                for eid in data['evidence_references']:
                    snapshot = json.loads(self.db.execute('SELECT payload FROM incident_evidence WHERE evidence_id=?',(eid,)).fetchone()[0])
                    ids = tuple(sorted(c['connection_id'] for c in snapshot['context_connections']))
                    if ids not in recovered:
                        recovered[ids] = self._drafts(session,[by_id[cid] for cid in ids if cid in by_id])
                    old_drafts, old_evidence = recovered[ids]
                    if previous['finding_id'] in old_drafts:
                        drafts[previous['finding_id']] = old_drafts[previous['finding_id']]
                        refs = drafts[previous['finding_id']]['data']['evidence_references']
                        evidence.update({ref:old_evidence[ref] for ref in refs})
                        break
            now, changed = time.time(), []
            for eid, snapshot in evidence.items():
                self.db.execute('INSERT OR IGNORE INTO incident_evidence VALUES(?,?,?,?,?)',
                                (eid, session_id, RULE_VERSION, encoded(snapshot), now))
            for fid, f in drafts.items():
                previous = self.db.execute('SELECT * FROM incident_findings WHERE finding_id=?', (fid,)).fetchone()
                payload = encoded(f['data'])
                if previous and previous['payload'] == payload and previous['state'] == 'active':
                    continue
                revision = previous['revision']+1 if previous else 1
                self.db.execute('''INSERT INTO incident_findings VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(finding_id) DO UPDATE SET first_seen=excluded.first_seen,last_seen=excluded.last_seen,original_score=excluded.original_score,
                    risk_level=excluded.risk_level,state='active',eligible=excluded.eligible,payload=excluded.payload,
                    revision=excluded.revision,updated_at=excluded.updated_at''',
                    (fid, session_id, f['connection_id'], f['rule_code'], RULE_VERSION, f['first_seen'], f['last_seen'],
                     f['original_score'], f['risk_level'], 'active', f['eligible'], payload, revision,
                     previous['created_at'] if previous else now, now))
                self.db.executemany('INSERT OR IGNORE INTO incident_finding_evidence VALUES(?,?)',
                                    [(fid, eid) for eid in f['data']['evidence_references']])
                changed.append(fid)
            old_active = self.db.execute("SELECT finding_id FROM incident_findings WHERE session_id=? AND detector_version=? AND state='active'", (session_id, RULE_VERSION)).fetchall()
            for old in old_active:
                if old[0] not in drafts:
                    self.db.execute("UPDATE incident_findings SET state='withdrawn',revision=revision+1,updated_at=? WHERE finding_id=?", (now, old[0]))
                    changed.append(old[0])
            touched = {r[0] for r in self.db.execute('''SELECT DISTINCT m.event_id FROM incident_members m
                JOIN incident_findings f USING(finding_id) WHERE f.session_id=?''', (session_id,))}
            for event_id in sorted(touched):
                self._reconcile_processes(event_id)
            # Detached findings from other captures also need a new home.
            pending = self.db.execute('''SELECT f.* FROM incident_findings f LEFT JOIN incident_members m USING(finding_id)
                WHERE m.finding_id IS NULL AND f.eligible=1 AND f.state='active' ORDER BY first_seen,
                CASE rule_code WHEN 'PORT_SWEEP' THEN 0 WHEN 'SYN_ONLY_BURST' THEN 1 ELSE 2 END,finding_id''').fetchall()
            member_cache = {}
            for row in pending:
                assigned = self._assign(self._finding(row), member_cache)
                if assigned:
                    touched.add(assigned)
            for fid in changed:
                row = self.db.execute('''SELECT f.*,m.event_id FROM incident_findings f JOIN incident_members m USING(finding_id)
                    WHERE finding_id=?''', (fid,)).fetchone()
                if row:
                    f = self._finding(row)
                    self._timeline(row['event_id'], 'finding_'+f['state'], f['last_seen'],
                        {'state': f['state'], 'original_score': f['original_score'], 'revision': f['revision']}, fid,
                        f['data']['evidence_references'][0], f['revision'])
                    touched.add(row['event_id'])
                    self.db.execute('UPDATE incidents SET revision=revision+1,updated_at=? WHERE event_id=?',(now,row['event_id']))
            for event_id in sorted(touched):
                self._refresh(event_id)
            return {'session_id': session_id, 'findings': len(drafts), 'changed_findings': len(changed),
                    'event_ids': sorted(e for e in touched if self.db.execute('SELECT 1 FROM incidents WHERE event_id=?', (e,)).fetchone()),
                    'correlation_version': CORRELATION_VERSION, 'window_selection': WINDOW_SELECTION,
                    'llm_called': False}

    def invalidate_session(self, session_id):
        """Called INSIDE Store's delete/filter transaction; remove saved snapshots too."""
        self.store.jobs.invalidate_source(session_id)
        touched = [r[0] for r in self.db.execute('''SELECT DISTINCT m.event_id FROM incident_members m
            JOIN incident_findings f USING(finding_id) WHERE f.session_id=?''', (session_id,))]
        self.db.execute('DELETE FROM incident_findings WHERE session_id=?', (session_id,))
        self.db.execute('DELETE FROM incident_evidence WHERE session_id=?', (session_id,))
        def surviving_refs(reason):
            reason['evidence_references'] = [eid for eid in reason.get('evidence_references', [])
                if self.db.execute('SELECT 1 FROM incident_evidence WHERE evidence_id=?', (eid,)).fetchone()]
            reason['support_status'] = 'source_data_removed_revalidation_required'
            return encoded(reason)
        for event_id in touched:
            for member in self.db.execute('SELECT finding_id,reason FROM incident_members WHERE event_id=?', (event_id,)).fetchall():
                reason = json.loads(member['reason'])
                self.db.execute('UPDATE incident_members SET reason=? WHERE finding_id=?', (surviving_refs(reason), member['finding_id']))
            for entry in self.db.execute('SELECT timeline_id,payload FROM incident_timeline WHERE event_id=?', (event_id,)).fetchall():
                payload = json.loads(entry['payload'])
                if 'evidence_references' in payload:
                    self.db.execute('UPDATE incident_timeline SET payload=? WHERE timeline_id=?',
                                    (surviving_refs(payload),entry['timeline_id']))
            self.db.execute("UPDATE incidents SET uncertainty_flags=? WHERE event_id=?", (encoded(['source_data_removed']), event_id))
            self._timeline(event_id, 'source_data_removed', time.time(), {'reason': 'capture_deleted_or_filtered'})
            self._refresh(event_id, allow_reopen=False)

    def _authorize(self, event_id, session_id):
        row = self.db.execute('SELECT * FROM incidents WHERE event_id=?', (event_id,)).fetchone()
        if row is None or session_id is not None and not self.db.execute('''SELECT 1 FROM incident_members m
            JOIN incident_findings f USING(finding_id) WHERE m.event_id=? AND f.session_id=? LIMIT 1''', (event_id, session_id)).fetchone():
            raise ValueError('事件不存在或不属于绑定采集')
        return dict(row)

    @staticmethod
    def _page(page, page_size):
        if type(page) is not int or page < 1 or type(page_size) is not int or not 1 <= page_size <= 50:
            raise ValueError('page必须>=1，page_size为1到50')
        return page_size, (page-1)*page_size

    def list_events(self, session_id=None, status=None, severity=None, since=None, until=None, page=1, page_size=20):
        paging = self._page(page, page_size)
        where, args = ['1=1'], []
        for name, value, options in [('status', status, ('open','acknowledged','closed')), ('severity',severity,('none','watch','medium','high'))]:
            if value is not None:
                if value not in options:
                    raise ValueError('无效事件筛选值')
                where.append('e.'+name+'=?'); args.append(value)
        for value, condition in ((since,'e.last_seen>=?'),(until,'e.first_seen<=?')):
            if value is not None:
                if type(value) not in (int,float) or not math.isfinite(value) or value < 0:
                    raise ValueError('时间必须为非负Unix秒数')
                where.append(condition); args.append(value)
        if since is not None and until is not None and since > until:
            raise ValueError('开始时间不能晚于结束时间')
        if session_id is not None:
            self.store._session(session_id)
            where.append('EXISTS(SELECT 1 FROM incident_members m JOIN incident_findings f USING(finding_id) WHERE m.event_id=e.event_id AND f.session_id=?)')
            args.append(session_id)
        query = ' FROM incidents e WHERE '+' AND '.join(where)
        with self.store.lock:
            total = self.db.execute('SELECT count(*)'+query, args).fetchone()[0]
            rows = [dict(r) for r in self.db.execute('SELECT e.*'+query+' ORDER BY e.first_seen,e.event_id LIMIT ? OFFSET ?', (*args,*paging))]
        for row in rows:
            row['uncertainty_flags'] = json.loads(row['uncertainty_flags'])
        return {'items':rows,'total':total,'page':page,'pages':max(1,math.ceil(total/page_size)), 'page_size':page_size}

    def members(self, event_id, session_id=None, page=1, page_size=20):
        paging = self._page(page,page_size)
        with self.store.lock:
            self._authorize(event_id,session_id)
            total = self.db.execute('SELECT count(*) FROM incident_members WHERE event_id=?',(event_id,)).fetchone()[0]
            rows = self.db.execute('''SELECT f.*,m.anchor_finding_id,m.reason FROM incident_members m
                JOIN incident_findings f USING(finding_id) WHERE event_id=? ORDER BY first_seen,finding_id LIMIT ? OFFSET ?''',(event_id,*paging)).fetchall()
            items = []
            for row in rows:
                finding = self._finding(row)
                finding['correlation_reason'] = json.loads(finding.pop('reason'))
                items.append(finding)
        return {'event_id':event_id,'items':items,'total':total,'page':page,'page_size':page_size,'pages':max(1,math.ceil(total/page_size))}

    def get_event(self,event_id,session_id=None):
        with self.store.lock:
            result = self._authorize(event_id,session_id)
            result['uncertainty_flags'] = json.loads(result['uncertainty_flags'])
            page = self.members(event_id,session_id,page_size=20)
            findings = page['items']
            result.update(related_findings=[f['finding_id'] for f in findings],
                related_connections=[dict(session_id=sid,connection_id=cid) for sid,cid in sorted({(f['session_id'],f['connection_id']) for f in findings})],
                related_processes=[{'session_id':f['session_id'],'connection_id':f['connection_id'],
                    'observations':f['data']['application']['observations']} for f in findings],
                correlation_reasons=[f['correlation_reason'] for f in findings],
                evidence_references=sorted({e for f in findings for e in f['data']['evidence_references']}),
                members_total=page['total'],members_pages=page['pages'],members_page_size=20,
                risk_policy='max_current_original_assessment_score; never sum connections; not a malicious probability',
                scope='本页为前20条线索；用query_incident_members遍历全部关联。跨采集内容只限当前事件的持久化证据。')
            return result

    def timeline(self,event_id,session_id=None,page=1,page_size=20):
        paging = self._page(page,page_size)
        with self.store.lock:
            self._authorize(event_id,session_id)
            total = self.db.execute('SELECT count(*) FROM incident_timeline WHERE event_id=?',(event_id,)).fetchone()[0]
            items = [dict(r) for r in self.db.execute('SELECT * FROM incident_timeline WHERE event_id=? ORDER BY observed_at,timeline_id LIMIT ? OFFSET ?',(event_id,*paging))]
        for item in items:
            item['data'] = json.loads(item.pop('payload'))
        return {'event_id':event_id,'items':items,'total':total,'page':page,'page_size':page_size,'pages':max(1,math.ceil(total/page_size))}

    def evidence(self,event_id,evidence_id,session_id=None,page=1,page_size=20):
        paging = self._page(page,page_size)
        with self.store.lock:
            self._authorize(event_id,session_id)
            row = self.db.execute('''SELECT e.payload FROM incident_evidence e JOIN incident_finding_evidence x USING(evidence_id)
                JOIN incident_members m USING(finding_id) WHERE m.event_id=? AND e.evidence_id=? LIMIT 1''',(event_id,evidence_id)).fetchone()
            if row is None:
                # A historical association may cite an anchor subsequently moved
                # to another event. Authorize that specific saved reference only.
                references = set()
                for saved in self.db.execute('SELECT reason FROM incident_members WHERE event_id=? UNION ALL SELECT payload FROM incident_timeline WHERE event_id=?', (event_id,event_id)):
                    references.update(json.loads(saved[0]).get('evidence_references', []))
                if evidence_id in references:
                    row = self.db.execute('SELECT payload FROM incident_evidence WHERE evidence_id=?',(evidence_id,)).fetchone()
            if row is None:
                raise ValueError('证据不属于该事件')
            result = json.loads(row[0])
            context = result['context_connections']
            result.update(evidence_id=evidence_id,event_id=event_id,context_connections=context[paging[1]:paging[1]+paging[0]],
                total=len(context),page=page,page_size=page_size,pages=max(1,math.ceil(len(context)/page_size)))
            return result

    def unassociated(self,session_id=None,page=1,page_size=20):
        paging = self._page(page,page_size)
        where, args = 'm.finding_id IS NULL AND f.state=\'active\'', []
        if session_id is not None:
            self.store._session(session_id)
            where += ' AND f.session_id=?'; args.append(session_id)
        query = ' FROM incident_findings f LEFT JOIN incident_members m USING(finding_id) WHERE '+where
        with self.store.lock:
            total = self.db.execute('SELECT count(*)'+query,args).fetchone()[0]
            rows = [self._finding(r) for r in self.db.execute('SELECT f.*'+query+' ORDER BY first_seen,finding_id LIMIT ? OFFSET ?',(*args,*paging))]
        return {'items':rows,'total':total,'page':page,'page_size':page_size,'pages':max(1,math.ceil(total/page_size))}

    def set_status(self,event_id,status):
        """Local user action only; intentionally not exposed as an Agent tool."""
        if status not in ('open','acknowledged','closed'):
            raise ValueError('无效事件状态')
        with self.store.lock,self.db:
            event = self._authorize(event_id,None)
            if event['status'] == status:
                return self.get_event(event_id)
            self.db.execute('''UPDATE incidents SET status=?,closed_observed_through=?,revision=revision+1,
                updated_at=? WHERE event_id=?''',(status,event['last_seen'] if status=='closed' else None,time.time(),event_id))
            self._timeline(event_id,'status_changed',event['last_seen'],{'from':event['status'],'to':status},marker=event['revision']+1)
        return self.get_event(event_id)
