"""python app.py --help"""
from pathlib import Path
import sys

HOME = Path(__file__).resolve().parent
if (HOME / ".runtime").exists():
    sys.path.insert(0, str(HOME / ".runtime"))


def main():
    import argparse
    import json
    parser = argparse.ArgumentParser(description="流量监测（Traffic Monitoring）· 阶段 1C 桌面版")
    parser.add_argument("--interfaces", action="store_true", help="列出可抓包网卡")
    parser.add_argument("--capture-test", metavar="INTERFACE", help="在指定网卡执行真实限时抓包测试")
    parser.add_argument("--seconds", type=int, default=5)
    parser.add_argument("--simulate", action="store_true", help="显式模拟数据测试，不调用模型")
    parser.add_argument('--evaluate', metavar='DATASET', help='评估JSON/JSONL或包含PCAP/session.json/label.json的数据集目录')
    parser.add_argument('--replay', metavar='PCAP', help='离线回放PCAP，不发包；导出会话、评分与本地报告')
    parser.add_argument('--agent', action='store_true', help='回放时使用现有模型配置执行四步调查；成功报告按内容缓存')
    parser.add_argument('--collect-dataset', metavar='DIRECTORY', help='运行有界本机回环实验并保存PCAP、会话和待人工复核标签')
    parser.add_argument('--repeats', type=int, default=3, help='每个实验重复次数1–5，默认3')
    parser.add_argument('--output', help='评估报告JSON文件路径，或回放输出目录')
    args = parser.parse_args()
    if sum(bool(v) for v in (args.interfaces, args.capture_test, args.simulate, args.evaluate, args.replay, args.collect_dataset)) > 1:
        parser.error('一次只选择一种运行模式')
    if args.agent and not args.replay:
        parser.error('--agent需要同时指定--replay')
    if args.evaluate or args.replay or args.collect_dataset:
        try:
            if args.evaluate:
                from traffic_agent.evaluation import load_dataset, evaluate
                result = evaluate(load_dataset(args.evaluate))
                if args.output:
                    Path(args.output).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
            elif args.replay:
                from traffic_agent.replay import replay_to_directory
                result = replay_to_directory(args.replay, args.output, args.agent)
            else:
                from traffic_agent.lab import collect_dataset
                result = collect_dataset(args.collect_dataset, args.repeats)
            print(json.dumps(result, ensure_ascii=False, indent=2))
        except (ValueError, OSError, RuntimeError, ImportError) as exc:
            parser.exit(1, str(exc) + '\n')
        return
    from traffic_agent.capture import Collector, seed_simulation
    from traffic_agent.store import Store
    if args.interfaces:
        print(json.dumps(Collector.interfaces(), ensure_ascii=False, indent=2))
    elif args.capture_test or args.simulate:
        if not 1 <= args.seconds <= 30:
            parser.error("--seconds 应在1–30之间")
        store = Store(":memory:")
        collector = Collector(store)
        try:
            if args.simulate:
                seed_simulation(store)
                result = store.summary("simulation")
            else:
                collector.select(args.capture_test)
                result = collector.observe(args.seconds)
            print(json.dumps(result, ensure_ascii=False, indent=2))
        finally:
            collector.close()
            store.close()
    else:
        import tkinter as tk
        from traffic_agent.ui import App
        from traffic_agent.local_lock import LocalAppLock
        with LocalAppLock(HOME):
            root = tk.Tk()
            App(root, HOME)
            root.mainloop()


if __name__ == "__main__":
    main()
