"""Private/synthetic PCAPs and a scripted model; not a real LLM quality test."""
from dataclasses import replace
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / '.runtime'))
from traffic_agent.agent import Agent
from traffic_agent.config import Config
from traffic_agent.investigation import STEPS, REQUIRED_REPORT_FIELDS, high_risk_target
from traffic_agent.replay import Replay, replay_to_directory
from traffic_agent.store import Store
from traffic_agent.tools import Toolset
from test_evaluation import small_pcap
from sample_data import port_scan_pcap


class FunctionCallingFixture:
    def __init__(self, bypass=False, wrong_target=False, wrong_order=False):
        self.bodies = []
        self.bypass, self.wrong_target, self.wrong_order = bypass, wrong_target, wrong_order

    def complete(self, config, key, body):
        self.bodies.append(json.loads(json.dumps(body)))
        results = [json.loads(m['content']) for m in body['messages'] if m['role'] == 'tool']
        choice = body['tool_choice']
        if self.bypass and results or results and choice == 'auto':
            return {'choices': [{'message': {'role': 'assistant', 'content': '[脚本模型] 需核实业务与历史样本不足。' + results[-1]['evidence_id']}, 'finish_reason': 'stop'}]}
        name = choice['function']['name'] if isinstance(choice, dict) else 'session_summary'
        args = {}
        if name != 'session_summary':
            instruction = next(m['content'] for m in reversed(body['messages']) if m['role'] == 'system' and '绑定五元组：' in m['content'])
            args, _ = json.JSONDecoder().raw_decode(instruction.split('绑定五元组：', 1)[1])
            if self.wrong_target:
                args['sport'] = 1 if args['sport'] != 1 else 2
            if self.wrong_order:
                name = 'query_similar_sessions'
        return {'choices': [{'message': {'role': 'assistant', 'content': None, 'tool_calls': [
            {'id': 'call_' + str(len(results)), 'type': 'function', 'function': {'name': name, 'arguments': json.dumps(args)}}]}, 'finish_reason': 'tool_calls'}]}


class InvestigationTests(unittest.TestCase):
    def pcap(self):
        return port_scan_pcap(self)

    def test_high_risk_automatically_completes_five_steps_and_structured_report(self):
        with Replay(self.pcap()) as replay:
            model = FunctionCallingFixture()
            result = Agent(replay.store, None, Config(), 'scripted-key', model).run('分析', session_id=replay.session_id)
            self.assertTrue(result['ok'], result)
            self.assertEqual([r['name'] for r in result['trace']], ['session_summary', *STEPS])
            report = result['investigation_report']
            self.assertTrue(set(REQUIRED_REPORT_FIELDS) <= report.keys())
            self.assertTrue(report['investigation_complete'])
            self.assertEqual(report['应用身份']['status'], 'unknown')
            self.assertEqual(report['风险']['level'], 'high')
            self.assertEqual(len(report['evidence_ids']), 5)
            self.assertEqual(report['历史比较']['baseline']['baseline']['status'], 'insufficient_evidence')
            self.assertNotIn('127.0.0.1', json.dumps(model.bodies))
            self.assertTrue(all(r['result']['source'] == 'replay' for r in result['trace']))

    def test_incomplete_wrong_target_or_wrong_order_cannot_claim_completion(self):
        for options in ({'bypass': True}, {'wrong_target': True}, {'wrong_order': True}):
            with self.subTest(options=options), Replay(self.pcap()) as replay:
                result = Agent(replay.store, None, Config(), 'scripted-key', FunctionCallingFixture(**options)).run('分析', session_id=replay.session_id)
                self.assertFalse(result['ok'])
                self.assertFalse(result.get('investigation_report'))

    def test_api_failure_leaves_replay_detection_available(self):
        class Unavailable:
            def complete(self, *args):
                raise RuntimeError('测试API故障')
        with Replay(self.pcap()) as replay:
            result = Agent(replay.store, None, Config(), 'scripted-key', Unavailable()).run('分析', session_id=replay.session_id)
            self.assertFalse(result['ok'])
            self.assertEqual(replay.detection['prediction'], 1)
            self.assertGreater(replay.store.session_summary(replay.session_id)['packets'], 0)

    def test_connection_tool_is_bound_and_replay_cannot_capture(self):
        with Replay(self.pcap()) as replay:
            toolset = Toolset(replay.store, None, session_id=replay.session_id)
            args = high_risk_target(replay.store, replay.session_id)
            result = toolset.call('query_connection', json.dumps(args))
            self.assertTrue(result['ok'])
            self.assertEqual(result['source'], 'replay')
            self.assertFalse(toolset.call('capture_traffic', '{"seconds":1}')['ok'])
            self.assertFalse(toolset.call('query_connection', json.dumps({**args, 'session_id': 'foreign'}))['ok'])

    def test_shared_budget_is_persistent_and_does_not_interrupt_capture(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'live.db'
            live = Store(path)
            sid = live.start_session('live-test')
            budget = Store(path, recover_running=False)
            try:
                self.assertEqual(live._session(sid)['state'], 'running')
                with Replay(self.pcap()) as replay:
                    budget.db.execute('UPDATE budget SET calls=10000 WHERE id=1')
                    budget.db.commit()
                    config = Config()
                    result = Agent(replay.store, None, config, 'scripted-key', FunctionCallingFixture(), budget_store=budget).run('分析', session_id=replay.session_id)
                    self.assertTrue(result['ok'], result)
                    self.assertEqual(live.usage()['calls'], 10007)
                    self.assertEqual(replay.store.usage()['calls'], 0)
                    self.assertEqual(live._session(sid)['state'], 'running')
            finally:
                budget.close()
                live.close()

    def test_completed_report_cache_prevents_repeated_api_call(self):
        with tempfile.TemporaryDirectory() as folder:
            pcap = Path(folder) / 'fixture.pcap'
            output = Path(folder) / 'report'
            small_pcap(pcap)
            model = FunctionCallingFixture()
            with patch('traffic_agent.credentials.active_key', return_value='scripted-key'), patch('traffic_agent.agent.HTTPTransport', return_value=model):
                first = replay_to_directory(pcap, output, True, settings_home=folder)
                self.assertEqual(first['agent_status'], 'completed')
                calls = len(model.bodies)
                report_bytes = (output / 'agent_report.json').read_bytes()
                second = replay_to_directory(pcap, output, True, settings_home=folder)
                self.assertEqual(second['agent_status'], 'cached_completed_report')
                self.assertEqual(len(model.bodies), calls)
                self.assertEqual((output / 'agent_report.json').read_bytes(), report_bytes)

    def test_structured_report_is_not_silently_truncated(self):
        store = Store(':memory:')
        try:
            sid = store.start_session('test')
            value = {'事件': 'test', '异常证据': ['evidence'] * 2000}
            answer = json.dumps(value)
            self.assertGreater(len(answer), 16000)
            self.assertTrue(store.save_session_report(sid, answer, True))
            self.assertEqual(json.loads(store.session_report(sid)['answer']), value)
            self.assertFalse(store.save_session_report(sid, 'x' * 200001, True))
            self.assertEqual(json.loads(store.session_report(sid)['answer']), value)
        finally:
            store.close()


if __name__ == '__main__':
    unittest.main()
