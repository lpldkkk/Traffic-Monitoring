import json
import time
import uuid
from jsonschema import Draft202012Validator


WINDOW = {"type": "integer", "minimum": 60, "maximum": 604800, "description": "回看秒数，默认300；时间分辨率60秒"}
HOST = {"type": "string", "pattern": "^host_[0-9a-f]{16}$", "description": "查询结果里的稳定主机化名"}


def definition(name, description, properties=None, required=None):
    return {"type": "function", "function": {"name": name, "description": description,
            "parameters": {"type": "object", "properties": properties or {},
                           "required": required or [], "additionalProperties": False}}}


DEFINITIONS = [
    definition("top_connections", "分页查询全部连接与应用，按用量排序每页10条，page默认1，可按local_port筛选。代理可用时返回代理活动连接累计，否则本次网卡近5分钟。按scope解释，不能合并计量；域名不上传，应用名不可信。仅live，IP脱敏",
               {'page': {'type': 'integer', 'minimum': 1, 'maximum': 2000},
                'local_port': {'type': 'integer', 'minimum': 0, 'maximum': 65535}}),
    definition("capture_status", "获取真实采集状态、可见范围、丢包计数及当前会话数据源"),
    definition("capture_traffic", "在用户已选网卡上真实抓包若干秒；不会切换网卡。live会话可用；已持续采集时等待观察窗口，不停止采集。",
               {"seconds": {"type": "integer", "minimum": 1, "maximum": 30}}, ["seconds"]),
    definition("protocol_stats", "统计当前数据源的协议/包数/字节数、流量排行、HTTPS和单向流量比例", {"seconds": WINDOW}),
    definition("query_flows", "按化名、协议或端口查询有向流量分钟桶，返回流ID与时间、SYN/RST等证据",
               {"seconds": WINDOW, "host": HOST, "protocol": {"type": "string", "enum": ["TCP", "UDP", "ICMP", "ICMPv6", "OTHER"]},
                "port": {"type": "integer", "minimum": 0, "maximum": 65535}, "limit": {"type": "integer", "minimum": 1, "maximum": 50}}),
    definition("analyze_ip", "查询单个主机的双向字节、对端和端口分散程度、标志位及候选线索；线索不是攻击结论",
               {"host": HOST, "seconds": WINDOW}, ["host"]),
    definition("query_history", "查询同一数据源历史分钟汇总；CSV时间是导入时间，不能当成当时真实流量",
               {"seconds": WINDOW, "host": HOST}),
    definition("communication_graph", "复用课程通信图：星型邻接、连通子图与有向最短路径；不是物理网络路由",
               {"seconds": WINDOW, "host": HOST, "target": HOST}),
]

CONNECTION_ID = {'type': 'string', 'pattern': '^conn_[0-9a-f]{32}$', 'description': '连接实例ID；同五元组有多个实例时必须指定，来自连接查询结果'}

SESSION_DEFINITIONS = [
    definition("session_summary", "汇总本次采集保留数据：协议、流排行、候选连接对和基于连接行为的anomaly_assessment。评分只排序调查优先级，非恶意概率；优先调查高分候选并说明评估覆盖率。先调用此工具，再选择需要查证的连接"),
    definition("session_connection_history", "查询指定主机对或双向五元组的全程分钟时间线、连接指标与主机对评估。UNKNOWN不能推断成功或失败。sport和dport须同时填写或都省略。默认每页10行；分别检查pages和connection_metrics_pages，翻页保持相同page_size。参数来自session_summary。",
               {"connection_id": CONNECTION_ID, "src": HOST, "dst": HOST, "sport": {"type": "integer", "minimum": 0, "maximum": 65535},
                "dport": {"type": "integer", "minimum": 0, "maximum": 65535},
                "protocol": {"type": "string", "enum": ["TCP", "UDP", "ICMP", "ICMPv6", "OTHER"]},
                "page": {"type": "integer", "minimum": 1, "maximum": 200000},
                "page_size": {"type": "integer", "minimum": 1, "maximum": 50}},
               ["src", "dst", "protocol"]),
]

CONNECTION_PARAMETERS = {
    'connection_id': CONNECTION_ID,
    'src': HOST, 'dst': HOST,
    'protocol': {'type': 'string', 'enum': ['TCP', 'UDP', 'ICMP', 'ICMPv6', 'OTHER']},
    'sport': {'type': 'integer', 'minimum': 0, 'maximum': 65535},
    'dport': {'type': 'integer', 'minimum': 0, 'maximum': 65535},
}
SESSION_DEFINITIONS += [
    definition('query_application_identity', '查询采集时保存的应用身份：两端进程名/PID/进程创建时间、匹配时间与范围。snapshot_match是连接表快照唯一匹配；inferred是推测；unknown不能用当前进程补全。proxy_original仅限精确代理入站关联，代理出口不能反推原始应用。每页20条身份，page默认1。',
               {**CONNECTION_PARAMETERS, 'page': {'type': 'integer', 'minimum': 1, 'maximum': 200000}}, [k for k in CONNECTION_PARAMETERS if k != 'connection_id']),
    definition('query_connection', '查询本次采集的一个双向五元组：握手、标志位、双向计数、时间与单连接评估。高风险调查第一步，参数取自本次汇总。同五元组多实例须指定connection_id；CONFIRMED仅为握手观察证据，不保证连接成功。',
               CONNECTION_PARAMETERS, [k for k in CONNECTION_PARAMETERS if k != 'connection_id']),
    definition('query_connection_baseline', '查询当前双向五元组的历史正常范围、偏离与样本数量。仅用同网卡更早的人工正常完整采集；样本不足必须说明。字段baseline_kind=rule_threshold表示规则阈值，不能冒充历史基线。参数来自本次连接查询。',
               CONNECTION_PARAMETERS, [k for k in CONNECTION_PARAMETERS if k != 'connection_id']),
    definition('query_anomaly_evidence', '查询评分明细、指标值、阈值、解释与可靠性限制；单连接与主机对聚集评分分开。sport/dport同时填写或都省略；省略返回前50条，可用session_connection_history翻页。',
               CONNECTION_PARAMETERS, ['src', 'dst', 'protocol']),
    definition('query_similar_sessions', '查询同网卡更早完整采集中的相似连接，返回特征距离和历史人工正常标签。相似度非恶意概率，未标记记录不能证明安全。只读脱敏历史；最多10条。',
               {**CONNECTION_PARAMETERS, 'limit': {'type': 'integer', 'minimum': 1, 'maximum': 10}},
               [k for k in CONNECTION_PARAMETERS if k != 'connection_id']),
]


EVENT_ID = {'type': 'string', 'pattern': '^event_[0-9a-f]{32}$'}
INCIDENT_PAGING = {'page': {'type': 'integer', 'minimum': 1, 'maximum': 200000},
                   'page_size': {'type': 'integer', 'minimum': 1, 'maximum': 50}}
INCIDENT_DEFINITIONS = [
    definition('list_incidents', '只读查询与本次采集有关的已持久化事件。severity为调查优先级，correlation_confidence仅为关联可信度，均非恶意概率；时间过滤使用观测时间区间相交。',
        {**INCIDENT_PAGING, 'status': {'type':'string','enum':['open','acknowledged','closed']},
         'severity': {'type':'string','enum':['none','watch','medium','high']},
         'since': {'type':'number','minimum':0}, 'until': {'type':'number','minimum':0}}),
    definition('get_incident', '读取事件详情及前20条关联索引；members_pages>1时须翻页，不能称已查看全部。可读取同一事件的跨采集证据，不能切换到无关事件。', {'event_id':EVENT_ID}, ['event_id']),
    definition('query_incident_members', '分页读取事件全部线索、session_id+connection_id引用、采集时进程身份及关联理由。组评分不是每个成员的恶意结论；withdrawn是当前已不满足触发条件的历史线索。',
        {'event_id':EVENT_ID, **INCIDENT_PAGING}, ['event_id']),
    definition('query_incident_timeline', '分页读取持久化事件时间线；observed_at是流量观测时间，recorded_at是处理时间。没有自动调查任务。',
        {'event_id':EVENT_ID, **INCIDENT_PAGING}, ['event_id']),
    definition('query_incident_evidence', '读取ie_证据快照中的评分、规则阈值及分页上下文连接。不可把代表性窗口称为所有异常窗口或实时攻击证明。',
        {'event_id':EVENT_ID,'evidence_id':{'type':'string','pattern':'^ie_[0-9a-f]{32}$'}, **INCIDENT_PAGING}, ['event_id','evidence_id']),
    definition('query_unassociated_findings', '分页查询本次采集尚未关联的活动线索，例如旧聚合或缺少精确实例；不强行创建事件。', INCIDENT_PAGING),
]
SESSION_DEFINITIONS += INCIDENT_DEFINITIONS


class EventToolset:
    """Function Calling adapter to a job's immutable, allowlisted evidence.

    The old live/session Toolset is unchanged. These similarly named tools have
    a deliberately smaller job-bound schema; no arbitrary session or SQL reads.
    """
    def __init__(self, snapshot):
        self.snapshot = snapshot
        self.entries = {e['key']:e for e in snapshot['entries']}
        self.definitions=[]
        for name in sorted({e['name'] for e in snapshot['entries']}):
            params = ({'session_id':{'type':'string'},'connection_id':CONNECTION_ID}
                      if name in {'query_connection','query_application_identity','query_anomaly_evidence',
                                  'query_connection_baseline','query_similar_sessions'} else
                      {'evidence_id':{'type':'string','pattern':'^ie_[0-9a-f]{32}$'}} if name=='query_incident_evidence' else {})
            required=list(params)
            if name in {'query_incident_members','query_incident_timeline','query_incident_evidence'}:
                params={**params,**INCIDENT_PAGING}
            self.definitions.append(definition(name,
                '只读本任务固定event_id/revision的冻结证据；参数必须来自待查询清单。不读取新增流量。分页或其他范围未冻结时须报告未调查。',params,required))
        self.validators={d['function']['name']:Draft202012Validator(d['function']['parameters']) for d in self.definitions}

    def resolve(self,name,arguments):
        from .incidents import identity
        if name not in self.validators or not isinstance(arguments,str) or len(arguments)>4000:
            raise ValueError('不允许的事件工具')
        args=json.loads(arguments)
        if list(self.validators[name].iter_errors(args)): raise ValueError('事件工具参数错误')
        entry=self.entries.get(identity('query_',name,args))
        if entry is None: raise ValueError('查询超出冻结事件、采集或连接范围')
        return entry

    def call(self,entry):
        value=json.loads(json.dumps(entry['result']))
        if not value['ok']: return value
        data=value['data']
        if entry['name']=='query_incident_members':
            for item in data['items']:
                item['data']={k:item['data'][k] for k in ('score_scope','evidence_references','uncertainty_flags')}
            data['scope']='成员索引；具体连接和应用身份用对应工具查询；未调查成员需明确披露'
        if entry['name']=='get_incident':
            data.pop('related_processes',None)
            data['process_detail_tool']='query_application_identity'
        if entry['name']=='query_incident_evidence':
            for connection in data['context_connections']: connection.pop('application_identity',None)
            data['process_detail_tool']='query_application_identity'
        return value


class Toolset:
    def __init__(self, store, collector, source="live", session_id=None):
        if source not in {"live", "csv", "simulation"}:
            raise ValueError("无效数据源")
        if session_id is not None and source != 'live':
            raise ValueError('采集会话只支持实时来源')
        self.store, self.collector, self.source, self.session_id = store, collector, source, session_id
        if session_id and store._session(session_id)['source_kind'] == 'replay':
            self.source = 'replay'
        self.definitions = SESSION_DEFINITIONS if session_id else DEFINITIONS
        self.validators = {d["function"]["name"]: Draft202012Validator(d["function"]["parameters"]) for d in self.definitions}

    def call(self, name, arguments):
        evidence = "ev_" + uuid.uuid4().hex[:12]
        result = {"evidence_id": evidence, "observed_at": time.time(), "source": self.source}
        try:
            if name not in self.validators:
                raise ValueError("工具不在白名单")
            if not isinstance(arguments, str) or len(arguments) > 4000:
                raise ValueError("工具参数过长或类型错误")
            args = json.loads(arguments)
            if list(self.validators[name].iter_errors(args)):
                raise ValueError("参数不符合 JSON Schema：检查参数名、类型和范围")
            if name in {'list_incidents','get_incident','query_incident_members','query_incident_timeline','query_incident_evidence','query_unassociated_findings'}:
                method = {'list_incidents':'list_events','get_incident':'get_event','query_incident_members':'members',
                          'query_incident_timeline':'timeline','query_incident_evidence':'evidence',
                          'query_unassociated_findings':'unassociated'}[name]
                data = getattr(self.store.incidents, method)(session_id=self.session_id, **args)
            elif name == "session_summary":
                data = self.store.session_summary(self.session_id)
            elif name == "session_connection_history":
                args.setdefault('page_size', 10)
                data = self.store.session_connection_history(self.session_id, **args)
            elif name == 'query_connection':
                data = self.store._queried_connection(self.session_id, **args)
            elif name in {'query_connection_baseline', 'query_anomaly_evidence', 'query_similar_sessions', 'query_application_identity'}:
                data = getattr(self.store, name)(self.session_id, **args)
            elif name == "top_connections":
                tracker = getattr(self.collector, 'connections', None)
                if self.source != 'live' or tracker is None:
                    raise ValueError('当前会话没有实时连接应用视图；请使用流查询工具')
                data = tracker.for_agent(self.store, **args)
            elif name == "capture_status":
                data = self.collector.status()
            elif name == "capture_traffic":
                if self.source != "live":
                    raise ValueError("当前会话为离线/模拟数据；实时抓包只能在 live 会话调用")
                data = self.collector.observe(args["seconds"])
            else:
                method = {"protocol_stats": self.store.summary, "query_flows": self.store.flow_query,
                          "analyze_ip": self.store.behavior, "query_history": self.store.history,
                          "communication_graph": self.store.graph}[name]
                data = method(source=self.source, **args)
            result.update(ok=True, data=data)
        except (ValueError, RuntimeError) as exc:
            result.update(ok=False, error=str(exc)[:250])
        except Exception as exc:
            result.update(ok=False, error="工具内部错误：" + type(exc).__name__)
        return result
