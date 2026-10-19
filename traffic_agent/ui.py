"""Connection-first desktop UI. All Tk operations stay on the main thread."""
from collections import deque
from dataclasses import replace
import json
from pathlib import Path
import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from .agent import Agent, Monitor
from .capture import Collector, seed_simulation
from .config import Config, MODEL_PRESETS, choose_model, provider_for
from .credentials import Credentials, active_key
from .connections import ConnectionTracker, connection_page, endpoint_text, format_bytes, rank_connections
from .store import Store
from .applications import identity_label
from .runtime import InvestigationRuntime
from .jobs import STATUSES

BG = '#191c26'
PANEL = '#222633'
CARD = '#252a39'
LINE = '#343b4e'
TEXT = '#ecf0fa'
MUTED = '#929db5'
BLUE = '#5c96ff'
TEAL = '#48d3bc'
RED = '#ff647c'


def capture_times(session, now=None):
    started = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(session['started']))
    stopped = session['stopped']
    end = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stopped)) if stopped is not None else '进行中'
    seconds = max(0, int((stopped if stopped is not None else now if now is not None else time.time()) - session['started']))
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return started, end, f'{hours:02}:{minutes:02}:{seconds:02}'


def label(parent, text='', size=10, color=TEXT, bg=BG, **kwargs):
    return tk.Label(parent, text=text, bg=bg, fg=color, font=('Microsoft YaHei UI', size), **kwargs)


def button(parent, text, command, primary=False, **kwargs):
    return tk.Button(parent, text=text, command=command, bg=BLUE if primary else CARD, fg='#ffffff' if primary else TEXT,
                     activebackground='#437bdf' if primary else LINE, activeforeground=TEXT,
                     relief='flat', bd=0, padx=16, pady=9, cursor='hand2', font=('Microsoft YaHei UI', 10), **kwargs)


def scroll_frame(parent, bg=BG):
    outer = tk.Frame(parent, bg=bg)
    outer.rowconfigure(0, weight=1)
    outer.columnconfigure(0, weight=1)
    canvas = tk.Canvas(outer, bg=bg, highlightthickness=0)
    bar = ttk.Scrollbar(outer, orient='vertical', command=canvas.yview)
    canvas.configure(yscrollcommand=bar.set)
    canvas.grid(row=0, column=0, sticky='nsew')
    bar.grid(row=0, column=1, sticky='ns')
    content = tk.Frame(canvas, bg=bg)
    window = canvas.create_window(0, 0, window=content, anchor='nw')
    content.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox('all')))
    canvas.bind('<Configure>', lambda e: canvas.itemconfigure(window, width=e.width))
    # Bind to this widget's descendants only; do not steal scrolling from the chat.
    def wheel(event):
        canvas.yview_scroll(-int(event.delta/120) if event.delta else 0, 'units')
        return 'break'
    def bind_scroll(widget):
        widget.bind('<MouseWheel>', wheel)
        for child in widget.winfo_children():
            bind_scroll(child)
    content.bind('<Map>', lambda e: bind_scroll(content), add='+')
    return outer, content


class App:
    def __init__(self, root, home):
        self.root, self.home = root, Path(home)
        self.events, self.threads = queue.Queue(), []
        self.closing = self.refresh_pending = self.capture_pending = False
        self.store = Store(self.home / 'data/traffic.db')
        last_session = self.store.latest_session()
        self.latest_session_id = last_session['id'] if last_session else None
        self.selected_session_id = self.latest_session_id
        last_report = self.store.session_report(self.latest_session_id) if self.latest_session_id else None
        self.report_answer = last_report['answer'] if last_report else ''
        self.tracker = ConnectionTracker()
        self.collector = Collector(self.store, self.tracker)
        try:
            self.config = Config.load(self.home / 'config.local.json')
        except Exception:
            self.config = Config()
        self.credentials = Credentials(self.home / 'credentials.local.json')
        try:
            key = active_key(self.credentials, provider_for(self.config))
        except Exception:
            key = ''
        self.agent = Agent(self.store, self.collector, self.config, key)
        self.investigator = InvestigationRuntime(self.store, self.agent)
        self.monitor = Monitor(self.store, self.collector, self.agent, self.events.put)
        self.source = tk.StringVar(value='live')
        self.auto = tk.BooleanVar(value=False)
        self.interfaces, self.current_connections = [], []
        self.manual_interface = None
        self.interface_name = '自动识别当前网络'
        self.network_status = '准备就绪 · 点击右上角即可检测当前网络'
        self.snapshot = {}
        self.page = 'connections'
        self.last_refresh = 0
        self.source_revision = 0
        self.wire_view = False
        self.connection_page_index = 0
        self.connection_scope = None
        self.connection_search = tk.StringVar(value='')
        self.history_points = deque(maxlen=60)
        root.title('流量监测 · 网络安全 Agent')
        root.configure(bg=BG)
        width, height = min(1380, root.winfo_screenwidth()-80), min(900, root.winfo_screenheight()-90)
        root.geometry(f'{width}x{height}')
        root.minsize(min(980, width), min(620, height))
        self._styles()
        root.rowconfigure(0, weight=1)
        root.columnconfigure(1, weight=1)
        self._sidebar()
        body = tk.Frame(root, bg=BG)
        body.grid(row=0, column=1, sticky='nsew')
        body.rowconfigure(1, weight=1)
        body.columnconfigure(0, weight=1)
        self._header(body)
        self.pages = {}
        for name in ('connections', 'captures', 'agent', 'jobs', 'offline', 'settings'):
            frame = tk.Frame(body, bg=BG)
            frame.grid(row=1, column=0, sticky='nsew', padx=24, pady=(0, 12))
            self.pages[name] = frame
        self._connections_page()
        self._captures_page()
        self._agent_page()
        self._jobs_page()
        self._offline_page()
        self._settings_page()
        self.status_var = tk.StringVar(value=self.network_status)
        label(body, textvariable=self.status_var, size=9, color=MUTED, anchor='w').grid(row=2, column=0, sticky='ew', padx=24, pady=(0, 12))
        self.append(self.chat, '系统', '点击“检测当前网络”即可查看连接和应用，无需配置API。需要AI调查时，再到设置填写模型和预算。红色感叹号表示待核实的异常迹象。')
        self.show_page('connections')
        root.protocol('WM_DELETE_WINDOW', self.close)
        root.after(100, self.poll)

    def _styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TScrollbar', background=LINE, troughcolor=BG, bordercolor=BG, arrowcolor=MUTED)
        style.configure('TCombobox', fieldbackground=CARD, foreground=TEXT, background=LINE, arrowcolor=TEXT)
        style.map('TCombobox', fieldbackground=[('readonly', CARD)], foreground=[('readonly', TEXT)])
        style.configure('TNotebook', background=BG, borderwidth=0)
        style.configure('TNotebook.Tab', background=CARD, foreground=MUTED, padding=(18, 9), font=('Microsoft YaHei UI', 10))
        style.map('TNotebook.Tab', background=[('selected', LINE)], foreground=[('selected', TEXT)])
        style.configure('Archive.Treeview', background=CARD, foreground=TEXT, fieldbackground=CARD,
                        rowheight=28, borderwidth=0, font=('Microsoft YaHei UI', 9))
        style.map('Archive.Treeview', background=[('selected', '#345083')], foreground=[('selected', TEXT)])
        style.configure('Archive.Treeview.Heading', background=PANEL, foreground=TEXT,
                        font=('Microsoft YaHei UI', 9, 'bold'))

    def _sidebar(self):
        side = tk.Frame(self.root, bg=PANEL, width=176)
        side.grid(row=0, column=0, sticky='ns')
        side.grid_propagate(False)
        side.columnconfigure(0, weight=1)
        side.rowconfigure(8, weight=1)
        label(side, '◈  流量 Agent', size=14, bg=PANEL, anchor='w').grid(row=0, column=0, padx=16, pady=(30, 6), sticky='w')
        label(side, '本地网络 · 实时洞察', size=9, color=MUTED, bg=PANEL).grid(row=1, column=0, padx=20, pady=(0, 28), sticky='w')
        self.nav = {}
        for row, (key, text) in enumerate([('connections', '◉   连接'), ('captures', '▣   采集记录'),
                                           ('agent', '✦   AI 研判'), ('jobs','▥   事件调查'), ('offline', '▤   离线分析'), ('settings', '⚙   设置')], 2):
            b = button(side, text, lambda k=key: self.show_page(k), anchor='w')
            b.grid(row=row, column=0, sticky='ew', padx=12, pady=5)
            self.nav[key] = b
        bottom = tk.Frame(side, bg=PANEL)
        bottom.grid(row=9, column=0, sticky='ew', padx=18, pady=14)
        self.spark = tk.Canvas(bottom, bg=PANEL, height=56, width=135, highlightthickness=0)
        self.spark.pack(fill='x')
        self.side_up = label(bottom, '↑  0 B', color=TEAL, bg=PANEL, anchor='w')
        self.side_up.pack(fill='x', pady=(8, 3))
        self.side_down = label(bottom, '↓  0 B', color=BLUE, bg=PANEL, anchor='w')
        self.side_down.pack(fill='x')
        self.side_scope = label(bottom, '近5分钟 · 当前采集窗口', size=8, color=MUTED, bg=PANEL)
        self.side_scope.pack(anchor='w', pady=(10, 0))

    def _header(self, body):
        header = tk.Frame(body, bg=BG)
        header.grid(row=0, column=0, sticky='ew', padx=24, pady=(25, 20))
        header.columnconfigure(0, weight=1)
        self.page_title = label(header, '连接', size=23, anchor='w')
        self.page_title.grid(row=0, column=0, sticky='w')
        self.page_subtitle = label(header, '找到正在占用流量的连接与应用', size=10, color=MUTED, anchor='w')
        self.page_subtitle.grid(row=1, column=0, sticky='w', pady=(5, 0))
        self.start_button = button(header, '检测当前网络', self.start_capture, primary=True)
        self.start_button.grid(row=0, column=1, rowspan=2, padx=(10, 8))
        self.stop_button = button(header, '停止', self.stop_capture)
        self.stop_button.grid(row=0, column=2, rowspan=2)

    def _connections_page(self):
        page = self.pages['connections']
        page.rowconfigure(2, weight=1)
        page.columnconfigure(0, weight=1)
        metrics = tk.Frame(page, bg=BG)
        metrics.grid(row=0, column=0, sticky='ew', pady=(0, 22))
        self.metrics = {}
        for i, (key, title, color) in enumerate([('bytes', '总用量', TEXT), ('download', '下载', BLUE), ('upload', '上传', TEAL), ('alerts', '异常提示', RED)]):
            metrics.columnconfigure(i, weight=1, uniform='metric')
            card = tk.Frame(metrics, bg=CARD, padx=16, pady=11)
            card.grid(row=0, column=i, sticky='ew', padx=(0, 10 if i < 3 else 0))
            label(card, title, size=10, color=MUTED, bg=CARD).pack(anchor='w')
            self.metrics[key] = label(card, '0' if key == 'alerts' else '0 B', size=18, color=color, bg=CARD)
            self.metrics[key].pack(anchor='w', pady=(6, 0))
        line = tk.Frame(page, bg=BG)
        line.grid(row=1, column=0, sticky='ew', pady=(0, 12))
        line.columnconfigure(0, weight=1)
        self.list_title = label(line, '全部连接', size=14)
        self.list_title.grid(row=0, column=0, sticky='w')
        self.list_hint = label(line, '按用量排序 · 每页10条 · 点击查看属性', size=9, color=MUTED)
        self.list_hint.grid(row=1, column=0, columnspan=3, sticky='w', pady=(4, 0))
        self.alert_filter = button(line, '查看异常', self.show_alerts)
        self.alert_filter.grid(row=0, column=2)
        self.view_button = button(line, '查看网卡出口', self.toggle_connection_view)
        self.view_button.grid(row=0, column=1, padx=8)
        search_row = tk.Frame(line, bg=BG)
        search_row.grid(row=2, column=0, columnspan=3, sticky='ew', pady=(10, 0))
        search_row.columnconfigure(1, weight=1)
        label(search_row, '搜索全部连接', size=9, color=MUTED).grid(row=0, column=0, padx=(0, 10))
        self.search_entry = tk.Entry(search_row, textvariable=self.connection_search, bg=CARD, fg=TEXT,
            insertbackground=TEXT, relief='flat', font=('Microsoft YaHei UI', 10))
        self.search_entry.grid(row=0, column=1, sticky='ew', ipady=6)
        button(search_row, '清除', lambda: self.connection_search.set('')).grid(row=0, column=2, padx=(8, 0))
        self.connection_search.trace_add('write', self.search_connections)
        outer, self.connection_list = scroll_frame(page)
        outer.grid(row=2, column=0, sticky='nsew')
        self.empty = label(self.connection_list, '还没有采集到连接\n\n点击右上角“检测当前网络”，然后正常浏览网页或使用应用。', size=12, color=MUTED, justify='center', pady=80)
        self.empty.pack(fill='x')
        self.cards = []
        for i in range(10):
            card = tk.Frame(self.connection_list, bg=CARD, padx=16, pady=8, cursor='hand2')
            card.columnconfigure(1, weight=1)
            number = label(card, f'{i+1:02}', size=14, color=MUTED, bg=CARD)
            number.grid(row=0, column=0, rowspan=2, padx=(0, 16))
            app = label(card, '', size=11, bg=CARD, anchor='w')
            app.grid(row=0, column=1, sticky='ew')
            endpoint = label(card, '', size=9, color=MUTED, bg=CARD, anchor='w')
            endpoint.grid(row=1, column=1, sticky='ew', pady=(4, 0))
            amount = label(card, '', size=13, bg=CARD, anchor='e')
            amount.grid(row=0, column=2, padx=(12, 10), sticky='e')
            direction = label(card, '', size=9, color=MUTED, bg=CARD, anchor='e')
            direction.grid(row=1, column=2, padx=(12, 10), sticky='e')
            badge = label(card, '›', size=19, color=MUTED, bg=CARD, width=2)
            badge.grid(row=0, column=3, rowspan=2)
            progress = tk.Canvas(card, height=3, bg=LINE, highlightthickness=0)
            progress.grid(row=2, column=1, columnspan=2, sticky='ew', pady=(6, 0))
            for widget in (card, number, app, endpoint, amount, direction, badge, progress):
                widget.bind('<Button-1>', lambda e, index=i: self.open_index(index))
            self.cards.append((card, app, endpoint, amount, direction, badge, progress, number))
        pager = tk.Frame(page, bg=BG)
        pager.grid(row=3, column=0, sticky='ew', pady=(10, 0))
        pager.columnconfigure(0, weight=1)
        self.page_indicator = label(pager, '第 1 / 1 页', size=10, color=MUTED, anchor='w')
        self.page_indicator.grid(row=0, column=0, sticky='w')
        self.previous_page = button(pager, '上一页', lambda: self.change_connection_page(-1))
        self.previous_page.grid(row=0, column=1, padx=8)
        self.next_page = button(pager, '下一页', lambda: self.change_connection_page(1))
        self.next_page.grid(row=0, column=2)
        self.scope_label = label(page, '红色 ! = 待核实的异常迹象。自动关联本机代理中的原始应用；无法匹配时不猜测。', size=9, color=MUTED, anchor='w', wraplength=1050, justify='left')
        self.scope_label.grid(row=4, column=0, sticky='ew', pady=(8, 0))
        analysis = tk.Frame(page, bg=CARD, padx=14, pady=9)
        self.analysis_panel = analysis
        analysis.grid(row=5, column=0, sticky='ew', pady=(8, 0))
        analysis.columnconfigure(0, weight=1)
        label(analysis, '本次采集 · AI 研判', size=11, bg=CARD).grid(row=0, column=0, sticky='w')
        self.analysis_var = tk.StringVar(value=self.report_answer[:180].replace('\n', ' ') if self.report_answer else
            '采集结束后保存编号记录；可在采集记录中选择是否分析。')
        label(analysis, textvariable=self.analysis_var, size=9, color=MUTED, bg=CARD,
              wraplength=720, justify='left', anchor='w').grid(row=1, column=0, columnspan=3, sticky='ew', pady=(4, 0))
        button(analysis, '分析本次采集', self.analyze_session).grid(row=0, column=1, padx=6)
        button(analysis, '完整报告', self.show_session_report).grid(row=0, column=2)
        self.analyze_after_stop = tk.BooleanVar(value=False)
        tk.Checkbutton(analysis, text='停止后自动分析本次采集', variable=self.analyze_after_stop,
                      bg=CARD, fg=MUTED, selectcolor=PANEL, activebackground=CARD,
                      activeforeground=TEXT, font=('Microsoft YaHei UI', 9)).grid(row=2, column=0, sticky='w', pady=(5, 0))

    def _captures_page(self):
        page = self.pages['captures']
        page.columnconfigure(0, weight=1)
        page.rowconfigure(3, weight=1)
        label(page, '最多保存 10 次编号采集；达到上限时请手动删除旧记录。筛选保存会删除同次采集的其他连接和旧 AI 报告。',
              color=MUTED, anchor='w', wraplength=1000, justify='left').grid(row=0, column=0, sticky='ew', pady=(0, 12))
        columns = ('number', 'started', 'stopped', 'duration', 'state', 'bytes', 'packets', 'scope', 'report')
        self.capture_table = ttk.Treeview(page, columns=columns, show='headings', height=7,
                                          selectmode='browse', style='Archive.Treeview')
        headings = {'number': '编号', 'started': '开始时间', 'stopped': '结束时间', 'duration': '持续时长', 'state': '状态', 'bytes': '用量',
                    'packets': '包数', 'scope': '保存范围', 'report': 'AI 报告'}
        widths = {'number': 55, 'started': 165, 'stopped': 165, 'duration': 85, 'state': 65, 'bytes': 85,
                  'packets': 75, 'scope': 135, 'report': 70}
        for column in columns:
            self.capture_table.heading(column, text=headings[column])
            self.capture_table.column(column, width=widths[column], anchor='center' if column != 'started' else 'w')
        self.capture_table.grid(row=1, column=0, sticky='ew')
        self.capture_table.bind('<<TreeviewSelect>>', self.select_capture_record)
        self.archive_info = tk.StringVar(value='请选择采集记录')
        label(page, textvariable=self.archive_info, color=MUTED, anchor='w', wraplength=1000,
              justify='left').grid(row=2, column=0, sticky='ew', pady=(12, 8))
        block = tk.Frame(page, bg=BG)
        block.grid(row=3, column=0, sticky='nsew')
        block.columnconfigure(0, weight=1)
        block.rowconfigure(2, weight=1)
        label(block, '本次采集的全部连接 · 双击勾选要保留的连接，可跨页选择', size=13).grid(row=0, column=0, sticky='w', pady=(4, 8))
        search = tk.Frame(block, bg=BG)
        search.grid(row=1, column=0, sticky='ew', pady=(0, 8))
        search.columnconfigure(1, weight=1)
        label(search, '查找 IP / 端口 / 协议', color=MUTED).grid(row=0, column=0, padx=(0, 10))
        self.archive_search = tk.StringVar()
        tk.Entry(search, textvariable=self.archive_search, bg=CARD, fg=TEXT, insertbackground=TEXT,
                 relief='flat', font=('Microsoft YaHei UI', 10)).grid(row=0, column=1, sticky='ew', ipady=6)
        self.archive_search.trace_add('write', self.search_archive_connections)
        connection_columns = ('keep', 'instance', 'application', 'a', 'b', 'protocol', 'risk', 'bytes', 'packets')
        self.archive_table = ttk.Treeview(block, columns=connection_columns, show='headings',
                                          selectmode='browse', style='Archive.Treeview')
        connection_headings = {'keep': '保留', 'instance': '实例 / 记录类型', 'application': '应用（采集时匹配）', 'a': '端点 A', 'b': '端点 B', 'protocol': '协议', 'risk': '行为线索',
                               'bytes': '用量', 'packets': '包数'}
        connection_widths = {'keep': 45, 'instance': 130, 'application': 200, 'a': 175, 'b': 175, 'protocol': 60, 'risk': 85, 'bytes': 85, 'packets': 65}
        for column in connection_columns:
            self.archive_table.heading(column, text=connection_headings[column])
            self.archive_table.column(column, width=connection_widths[column], anchor='center')
        self.archive_table.grid(row=2, column=0, sticky='nsew')
        self.archive_table.tag_configure('candidate', foreground=RED)
        self.archive_table.bind('<Double-1>', self.toggle_archive_connection)
        self.archive_keys = {}
        self.archive_keep = set()
        self.archive_bound_session_id = None
        self.archive_assessment = None
        self.archive_page = 1
        controls = tk.Frame(block, bg=BG)
        controls.grid(row=3, column=0, sticky='ew', pady=(10, 0))
        controls.columnconfigure(0, weight=1)
        self.archive_pager = tk.StringVar(value='0 条连接')
        label(controls, textvariable=self.archive_pager, color=MUTED, anchor='w').grid(row=0, column=0, sticky='ew')
        button(controls, '上一页', lambda: self.change_archive_page(-1)).grid(row=0, column=1, padx=4)
        button(controls, '下一页', lambda: self.change_archive_page(1)).grid(row=0, column=2, padx=4)
        button(controls, '保留当前页全部', self.keep_archive_page).grid(row=0, column=3, padx=4)
        actions = tk.Frame(page, bg=BG)
        actions.grid(row=4, column=0, sticky='ew', pady=(14, 0))
        button(actions, '仅保留勾选连接', self.retain_capture_connections, primary=True).pack(side='left')
        button(actions, '分析选中采集', self.analyze_session).pack(side='left', padx=8)
        button(actions, '查看连接评估', self.show_archive_assessment).pack(side='left', padx=(0, 8))
        button(actions, '查看 AI 报告', self.show_session_report).pack(side='left')
        button(actions, '删除整次采集', self.delete_capture_record).pack(side='right')
        baseline_actions = tk.Frame(page, bg=BG)
        baseline_actions.grid(row=5, column=0, sticky='ew', pady=(8, 0))
        button(baseline_actions, '标为正常基线', lambda: self.label_capture_normal(True)).pack(side='left')
        button(baseline_actions, '取消正常标记', lambda: self.label_capture_normal(False)).pack(side='left', padx=8)
        label(baseline_actions, '请在核实业务后标记；至少 3 次完整采集用于历史参考。', color=MUTED).pack(side='left')

    def label_capture_normal(self, normal):
        if not self.selected_session_id:
            return
        try:
            self.store.set_session_normal(self.selected_session_id, normal)
            self.refresh_capture_records()
        except ValueError as exc:
            messagebox.showinfo('正常基线', str(exc))

    def refresh_capture_records(self):
        records = self.store.list_sessions()
        self.capture_table.delete(*self.capture_table.get_children())
        for session in records:
            state = {'running': '采集中', 'stopped': '已停止', 'interrupted': '已中断', 'failed': '启动失败'}.get(session['state'], session['state'])
            started, stopped, duration = capture_times(session)
            self.capture_table.insert('', 'end', iid=session['id'], values=(f"#{session['number']:03}",
                started, stopped, duration, state,
                format_bytes(session['bytes']), f"{session['packets']:,}",
                '仅保留所选连接' if session['filtered'] else '旧版可能不完整' if session['legacy_incomplete'] else '全部已采集汇总',
                '已分析' if session['reports'] else '未分析'))
        ids = [record['id'] for record in records]
        self.selected_session_id = self.selected_session_id if self.selected_session_id in ids else (ids[0] if ids else None)
        if self.selected_session_id:
            self.capture_table.selection_set(self.selected_session_id)
            self.select_capture_record()
        else:
            self.archive_keep.clear()
            self.archive_bound_session_id = None
            self.archive_table.delete(*self.archive_table.get_children())
            self.archive_assessment = None
            self.archive_info.set('暂无已保存的采集')
            self.archive_pager.set('0 条连接')

    def select_capture_record(self, _event=None):
        chosen = self.capture_table.selection()
        if not chosen:
            return
        self.selected_session_id = chosen[0]
        session = self.store._session(self.selected_session_id)
        if self.archive_bound_session_id != self.selected_session_id:
            self.archive_keep.clear()
            self.archive_bound_session_id = self.selected_session_id
            self.archive_page = 1
            if self.archive_search.get():
                self.archive_search.set('')
        self.report_answer = (self.store.session_report(self.selected_session_id) or {}).get('answer', '')
        self.archive_assessment = self.store.session_anomaly_assessment(self.selected_session_id, include_all=True)
        candidates = self.archive_assessment['candidate_pairs_total']
        risk_note = f' · {candidates} 组连接行为待核实' if candidates else ' · 当前无成组行为线索'
        if self.archive_assessment['status'] in ('partial', 'insufficient_evidence'):
            risk_note += '（部分数据无法评估）'
        elif self.archive_assessment['status'] == 'not_applicable':
            risk_note = ' · 当前协议不适用TCP行为规则'
        watches = self.archive_assessment['watch_connections_total']
        if watches:
            risk_note += f' · {watches} 条流量特征需结合业务观察'
        if session['normal_label'] == 'user_confirmed_normal':
            risk_note += ' · 已人工标记为正常基线'
        started, stopped, duration = capture_times(session)
        self.archive_info.set(f"采集 #{session['number']:03} · {session['interface']} · {started} → {stopped} · 持续 {duration}（本机时间）\n" +
            ('已筛选；AI 分析只会看到保留的连接。' if session['filtered'] else
             '旧版记录可能已被裁剪，无法保证覆盖原采集全程。' if session['legacy_incomplete'] else
             '未筛选；连接列表覆盖此次采集的已保存分钟汇总。') + risk_note)
        self.analysis_var.set(self.report_answer[:180].replace('\n', ' ') if self.report_answer else
                              f"采集 #{session['number']:03} 尚未分析；可点击“分析选中采集”。")
        self.render_archive_connections()

    def search_archive_connections(self, *_):
        if not hasattr(self, 'archive_table'):
            return
        self.archive_page = 1
        self.render_archive_connections()

    def render_archive_connections(self):
        self.archive_table.delete(*self.archive_table.get_children())
        self.archive_keys = {}
        self.archive_rows = {}
        if not self.selected_session_id:
            return
        result = self.store.session_connections(self.selected_session_id, self.archive_search.get(), self.archive_page)
        self.archive_page = min(self.archive_page, result['pages'])
        if self.archive_page != result['page']:
            result = self.store.session_connections(self.selected_session_id, self.archive_search.get(), self.archive_page)
        pair_levels = {(item['src'], item['dst']): item['level'] for item in
                       (self.archive_assessment or {}).get('candidate_pairs_all', [])}
        for index, row in enumerate(result['connections']):
            iid = str(index)
            key = row['key']
            self.archive_keys[iid] = key
            self.archive_rows[iid] = row
            metric = row['metrics']
            pair_level = pair_levels.get((metric['source_ip'], metric['destination_ip'])) if metric['direction_basis'] == 'observed_syn_initiator' else None
            risk = ('! 高优先' if pair_level == 'high' else '! 待核实' if pair_level == 'medium' else
                    '! 待核实' if metric['assessment']['review_required'] else
                    '观察' if metric['assessment']['score'] else
                    '不适用' if metric['assessment']['status'] == 'not_applicable' else
                    '证据不足' if metric['assessment']['status'] == 'insufficient_evidence' else '—')
            self.archive_table.insert('', 'end', iid=iid, values=(
                '✓' if key in self.archive_keep else '□',
                ('旧聚合 ' if metric['instance_kind'] == 'legacy_aggregate' else '未跟踪聚合 ' if metric['instance_kind'] == 'untracked_aggregate' else '不确定片段 ' if metric['instance_kind'] == 'ambiguous_fragment' else '协议聚合 ' if metric['instance_kind'] == 'transport_aggregate' else '') + row['connection_id'][5:13], identity_label(row['application_identity']), endpoint_text(row['a'], row['ap']),
                endpoint_text(row['b'], row['bp']), row['protocol'], risk, format_bytes(row['bytes']), f"{row['packets']:,}"),
                tags=('candidate',) if risk.startswith('!') else ())
        self.archive_pager.set(f"全部 {result['total']} 条 · 第 {self.archive_page}/{result['pages']} 页 · 待保留 {len(self.archive_keep)} 条")

    def show_archive_assessment(self):
        selected = self.archive_table.selection()
        row = self.archive_rows.get(selected[0]) if selected else None
        if row is None:
            messagebox.showinfo('连接评估', '请先单击选择一条已保存的连接。')
            return
        metric = row['metrics']
        pair = next((item for item in (self.archive_assessment or {}).get('candidate_pairs_all', [])
                     if (item['src'], item['dst']) == (metric['source_ip'], metric['destination_ip'])), None)
        window = tk.Toplevel(self.root, bg=BG)
        window.title('连接行为评估 · 本地证据')
        window.geometry('820x650')
        label(window, identity_label(row['application_identity']) + '\n应用信息来自采集当时；快照匹配并非逐包证明，推测关联需核实。', color=MUTED,
              wraplength=760).pack(anchor='w', padx=16, pady=(16, 8))
        box = self._textbox(window, state='normal', width=60, height=20)
        box.pack(fill='both', expand=True, padx=16, pady=(0, 16))
        args = dict(src=metric['source_ip'], dst=metric['destination_ip'], protocol=metric['protocol'],
                    sport=metric['source_port'], dport=metric['destination_port'], connection_id=metric['connection_id'])
        box.insert('1.0', json.dumps({'application_identity': row['application_identity'], 'connection_metrics': metric, 'pair_context': pair,
            'historical_baseline': self.store.query_connection_baseline(self.selected_session_id, **args),
            'similar_history': self.store.query_similar_sessions(self.selected_session_id, **args),
            'scope': '连接指标覆盖该次采集保留的双向五元组；主机对上下文包含其全部端口，组线索不代表其中每条连接都有攻击行为'},
            ensure_ascii=False, indent=2))
        box.configure(state='disabled')

    def toggle_archive_connection(self, event):
        iid = self.archive_table.identify_row(event.y)
        if iid not in self.archive_keys:
            return
        key = self.archive_keys[iid]
        if key in self.archive_keep:
            self.archive_keep.remove(key)
        else:
            self.archive_keep.add(key)
        self.archive_table.set(iid, 'keep', '✓' if key in self.archive_keep else '□')
        self.archive_pager.set(self.archive_pager.get().split(' · 待保留 ')[0] + f' · 待保留 {len(self.archive_keep)} 条')

    def keep_archive_page(self):
        self.archive_keep.update(self.archive_keys.values())
        self.render_archive_connections()

    def change_archive_page(self, delta):
        self.archive_page = max(1, self.archive_page + delta)
        self.render_archive_connections()

    def _archive_edit_allowed(self):
        if not self.selected_session_id:
            return False
        if self.capture_pending or self.collector.status()['running'] or self.agent.lock.locked():
            messagebox.showinfo('采集记录', '请先停止采集并等待当前 AI 分析结束。')
            return False
        return True

    def retain_capture_connections(self):
        if not self._archive_edit_allowed():
            return
        if not self.archive_keep:
            messagebox.showinfo('保留连接', '请先双击勾选至少一条连接；可跨页选择。')
            return
        session_id = self.selected_session_id
        total = self.store.session_connections(session_id, page_size=1)['total']
        if len(self.archive_keep) == total:
            self.archive_info.set('已勾选本次采集的全部连接，没有其他数据需要删除。')
            return
        if not messagebox.askyesno('确认筛选保存',
            f'本次采集共 {total} 条连接，将仅保留已勾选的 {len(self.archive_keep)} 条。\n\n'
            '其余连接的会话数据将永久删除，旧 AI 报告也会删除。确定继续吗?'):
            return
        try:
            result = self.store.retain_session_connections(session_id, self.archive_keep)
            if result['changed']:
                self.report_answer = ''
                self.archive_bound_session_id = None
            self.refresh_capture_records()
            if result['changed']:
                self.archive_info.set(f"采集 #{self.store._session(session_id)['number']:03} 已筛选：保留 {result['kept']} 条，删除 {result['deleted']} 条；旧报告已清除，可重新分析。")
        except Exception as exc:
            messagebox.showerror('筛选保存失败', str(exc))

    def delete_capture_record(self):
        if not self._archive_edit_allowed():
            return
        session_id = self.selected_session_id
        selected = self.store._session(session_id)
        number = selected['number']
        if not messagebox.askyesno('确认删除采集',
            f'将永久删除采集 #{number:03} 的全部连接汇总和 AI 报告，且无法恢复。确定删除吗?'):
            return
        try:
            self.store.delete_session(session_id)
            self.selected_session_id = None
            self.archive_bound_session_id = None
            self.latest_session_id = (self.store.latest_session() or {}).get('id')
            self.report_answer = ''
            self.analysis_var.set(f'采集 #{number:03} 已删除。')
            self.refresh_capture_records()
        except Exception as exc:
            messagebox.showerror('删除失败', str(exc))

    def _textbox(self, parent, **kwargs):
        return scrolledtext.ScrolledText(parent, bg=PANEL, fg=TEXT, insertbackground=TEXT, relief='flat', bd=0,
            selectbackground='#345083', font=('Microsoft YaHei UI', 10), wrap='word', padx=16, pady=14, **kwargs)

    def _agent_page(self):
        page = self.pages['agent']
        page.rowconfigure(0, weight=1)
        page.columnconfigure(0, weight=1)
        notebook = ttk.Notebook(page)
        notebook.grid(row=0, column=0, sticky='nsew')
        self.chat = self._textbox(notebook, state='disabled', height=8, width=40)
        self.trace = self._textbox(notebook, state='disabled', height=8, width=40)
        notebook.add(self.chat, text='对话与结论')
        notebook.add(self.trace, text='工具调用与证据')
        self.prompt = self._textbox(page, height=3, width=40)
        self.prompt.insert('1.0', '分析当前数据源的网络流量，先检查数据来源和覆盖范围，再调用工具调查异常迹象并引用证据。')
        self.prompt.grid(row=1, column=0, sticky='ew', pady=(12, 10))
        self.prompt.bind('<Control-Return>', lambda e: self.ask())
        commands = tk.Frame(page, bg=BG)
        commands.grid(row=2, column=0, sticky='ew')
        self.ask_button = button(commands, '发送给 Agent', self.ask, primary=True)
        self.ask_button.pack(side='left')
        button(commands, '取消分析', self.agent.cancel.set).pack(side='left', padx=8)
        button(commands, '新会话', self.new_chat).pack(side='left')
        self.budget_var = tk.StringVar()
        label(page, textvariable=self.budget_var, size=9, color=MUTED, anchor='w').grid(row=3, column=0, sticky='ew', pady=(10, 0))

    def _offline_page(self):
        page = self.pages['offline']
        page.rowconfigure(2, weight=1)
        page.columnconfigure(0, weight=1)
        commands = tk.Frame(page, bg=BG)
        commands.grid(row=0, column=0, sticky='ew', pady=(0, 12))
        button(commands, '导入 CSV', self.import_csv, primary=True).pack(side='left')
        button(commands, '加载模拟数据', self.simulate).pack(side='left', padx=8)
        button(commands, '返回实时连接', self.return_live).pack(side='left')
        label(page, 'CSV 只有端点、协议、端口、字节数和时长；无包数、SYN/RST或恶意标签，不能按实时规则判定安全。导入时间不是采集时间，重复导入会累加。', color=MUTED, anchor='w', wraplength=900, justify='left').grid(row=1, column=0, sticky='ew', pady=(0, 15))
        self.local = self._textbox(page, state='disabled', width=40, height=8)
        self.local.grid(row=2, column=0, sticky='nsew')

    def _settings_page(self):
        outer, page = scroll_frame(self.pages['settings'])
        outer.pack(fill='both', expand=True)
        label(page, '网络采集', size=16).pack(anchor='w', pady=(0, 10))
        label(page, '默认使用当前路由网卡。一键检测无需手动选择；仅在多网卡、回环测试等情况下覆盖。', color=MUTED, wraplength=760, justify='left').pack(anchor='w')
        row = tk.Frame(page, bg=BG)
        row.pack(fill='x', pady=16)
        self.interface_var = tk.StringVar(value='自动识别当前网络')
        self.interface_box = ttk.Combobox(row, textvariable=self.interface_var, width=43, state='readonly', values=['自动识别当前网络'])
        self.interface_box.pack(side='left')
        self.interface_box.current(0)
        button(row, '刷新网卡', self.refresh_interfaces).pack(side='left', padx=8)
        button(row, '应用', self.select_interface).pack(side='left')
        label(page, 'AI 模型', size=16).pack(anchor='w', pady=(25, 10))
        label(page, '选择服务商和模型，保存对应的 API Key 后即可使用 AI 研判。抓包和本地统计无需 API。', color=MUTED).pack(anchor='w')
        self.model_status_var = tk.StringVar(value=f"当前：{provider_for(self.config)} / {self.config.model}")
        label(page, textvariable=self.model_status_var, color=TEAL).pack(anchor='w', pady=(10, 0))
        button(page, '选择模型 / 保存 API Key', self.settings, primary=True).pack(anchor='w', pady=16)
        budget_row=tk.Frame(page,bg=BG); budget_row.pack(anchor='w',pady=(0,12))
        label(budget_row,'累计费用预算 USD').pack(side='left')
        self.total_budget=tk.StringVar(value=str(self.agent.config.max_cost))
        tk.Entry(budget_row,textvariable=self.total_budget,width=10,bg=CARD,fg=TEXT).pack(side='left',padx=8)
        button(budget_row,'保存预算',self.save_total_budget).pack(side='left')
        tk.Checkbutton(page, text='自动研判（仅实时数据）', variable=self.auto, command=self.toggle_monitor, bg=BG, fg=TEXT,
            selectcolor=CARD, activebackground=BG, activeforeground=TEXT, font=('Microsoft YaHei UI', 10)).pack(anchor='w')
        label(page, '隐私与识别范围', size=16).pack(anchor='w', pady=(30, 10))
        label(page, '仅采集头部元数据，不保存原始报文。应用归属通过系统连接表快照匹配，短连接、共享UDP端口或权限不足可能无法识别。\n\n自动只读连接本机 Clash Verge 控制接口（含 Windows 命名管道），通过代理连接元数据或原始端点关联应用。域名仅在本地显示；代理返回的路径只取文件名，不保留完整路径。\n\n代理应用视图显示活动连接自建立以来累计；网卡出口显示近5分钟抓包，二者不相加。代理视图不提供逐包异常检测，请切换网卡出口查看红色提示。', color=MUTED, wraplength=780, justify='left').pack(anchor='w')

    def save_total_budget(self):
        try:
            config=replace(self.agent.config,max_cost=float(self.total_budget.get())); config.validate()
        except ValueError as exc:
            messagebox.showerror('预算未保存',str(exc),parent=self.root); return
        def save():
            config.save(self.home/'config.local.json')
            self.config=self.agent.config=config
            return {'budget_limit':config.max_cost}
        self.background(save,'job_action')

    def _jobs_page(self):
        page=self.pages['jobs']
        page.columnconfigure(0,weight=1); page.rowconfigure(3,weight=1)
        top=tk.Frame(page,bg=BG); top.grid(row=0,column=0,sticky='ew',pady=(0,8))
        self.jobs_auto=tk.BooleanVar(value=False)
        tk.Checkbutton(top,text='自动调查新高风险事件（使用API预算）',variable=self.jobs_auto,
            command=lambda:setattr(self.investigator,'automatic',self.jobs_auto.get()),bg=BG,fg=TEXT,
            selectcolor=CARD,activebackground=BG,activeforeground=TEXT).pack(side='left')
        label(top,'任务预算 USD',color=MUTED).pack(side='left',padx=(16,5))
        self.job_cost=tk.StringVar(value='0.25')
        tk.Entry(top,textvariable=self.job_cost,width=8,bg=CARD,fg=TEXT).pack(side='left')
        self.job_event=tk.StringVar()
        events=tk.Frame(page,bg=BG); events.grid(row=1,column=0,sticky='ew',pady=(0,8))
        self.job_event_box=ttk.Combobox(events,textvariable=self.job_event,state='readonly',width=55)
        self.job_event_box.pack(side='left',fill='x',expand=True)
        button(events,'调查所选事件',self.enqueue_event).pack(side='left',padx=6)
        bar=tk.Frame(page,bg=BG); bar.grid(row=2,column=0,sticky='ew',pady=(0,8))
        self.job_filter=tk.StringVar(value='全部')
        filters=ttk.Combobox(bar,textvariable=self.job_filter,values=['全部',*STATUSES],state='readonly',width=16)
        filters.pack(side='left'); filters.bind('<<ComboboxSelected>>',lambda e:self.refresh_jobs(reset=True))
        for title,action in [('刷新',self.refresh_jobs),('报告/步骤',lambda:self.job_action('view')),
                             ('重试/恢复预算',lambda:self.job_action('retry')),('取消任务',lambda:self.job_action('cancel'))]:
            button(bar,title,action).pack(side='left',padx=3)
        columns=('event','revision','status','attempt','progress')
        self.job_tree=ttk.Treeview(page,columns=columns,show='headings',style='Archive.Treeview')
        for col,title,width in zip(columns,('事件','revision','任务状态','尝试次数','当前步骤 / 工具次数'),(225,70,125,80,230)):
            self.job_tree.heading(col,text=title); self.job_tree.column(col,width=width)
        self.job_tree.grid(row=3,column=0,sticky='nsew')
        self.job_tree.bind('<Double-1>',lambda e:self.job_action('view'))
        bottom=tk.Frame(page,bg=BG); bottom.grid(row=4,column=0,sticky='ew',pady=8)
        button(bottom,'上一页',lambda:self.change_job_page(-1)).pack(side='left')
        button(bottom,'下一页',lambda:self.change_job_page(1)).pack(side='left',padx=5)
        self.job_page_label=label(bottom,'',color=MUTED); self.job_page_label.pack(side='left',padx=12)
        label(page,'事件选择器显示前50项；任务可分页。完成调查 ≠ 事件已解决。模型结果未知时重试可能重复计费。',
              color=MUTED,size=9,anchor='w').grid(row=5,column=0,sticky='ew')
        self.job_page=1; self.job_pages=1; self.job_rows={}; self.job_event_ids={}
        self.jobs_refresh_pending=False; self.jobs_last_refresh=0

    def change_job_page(self,delta):
        self.job_page=max(1,min(self.job_pages,self.job_page+delta)); self.refresh_jobs()

    def refresh_jobs(self,reset=False):
        if self.jobs_refresh_pending or self.closing: return
        if reset: self.job_page=1
        self.jobs_refresh_pending=True; self.jobs_last_refresh=time.monotonic()
        status=None if self.job_filter.get()=='全部' else self.job_filter.get()
        page=self.job_page
        self.background(lambda:dict(tasks=self.store.jobs.list(status,page),
            events=self.store.incidents.list_events(page_size=50),runtime_error=self.investigator.last_error),'jobs_snapshot')

    def enqueue_event(self):
        event_id=self.job_event_ids.get(self.job_event.get())
        if not event_id: return
        try: cost=float(self.job_cost.get())
        except ValueError:
            messagebox.showerror('任务预算','请输入有效金额',parent=self.root); return
        self.background(lambda:self.store.jobs.enqueue(event_id,self.agent.config,cost_limit=cost),'job_action')

    def job_action(self,action):
        selected=self.job_tree.selection()
        if not selected: return
        job_id=selected[0]
        if action=='view':
            self.background(lambda:json.dumps(dict(task=self.store.jobs.get(job_id,False),
                reports=self.store.jobs.reports(job_id),steps=self.store.jobs.steps(job_id)),ensure_ascii=False,indent=2),'job_detail')
        elif action=='cancel':
            self.background(lambda:self.store.jobs.cancel(job_id),'job_action')
        else:
            row=self.job_rows[job_id]; confirmed=False
            if row['budget_state']['unknown_requests']:
                confirmed=messagebox.askyesno('可能重复计费',
                    '服务商可能已经处理了此前请求。确认重试并接受可能的重复计费？',parent=self.root)
                if not confirmed: return
            try: cost=float(self.job_cost.get())
            except ValueError:
                messagebox.showerror('任务预算','请输入有效金额',parent=self.root); return
            self.background(lambda:self.store.jobs.retry(job_id,confirm_unknown=confirmed,cost_limit=cost),'job_action')

    def show_page(self, name):
        self.page = name
        self.pages[name].tkraise()
        titles = {'connections': ('连接', '全部连接按用量排序 · 每页10条'),
                  'captures': ('采集记录', '最多保存10次编号采集 · 包头按分钟汇总'),
                  'agent': ('AI 研判', '让 Agent 自主调用工具，用证据回答问题'),
                  'jobs': ('事件调查','固定事件 revision · 持久化步骤 · 人工核验报告'),
                  'offline': ('离线分析', '保留课程 CSV 与明确标注的模拟数据'), 'settings': ('设置', '网络接口与 AI 模型')}
        self.page_title.configure(text=titles[name][0])
        self.page_subtitle.configure(text=titles[name][1])
        for key, widget in self.nav.items():
            widget.configure(bg='#2d4770' if key == name else PANEL, fg=TEXT if key == name else MUTED)
        if name == 'captures':
            self.refresh_capture_records()
        if name == 'jobs':
            self.refresh_jobs()

    def append(self, box, title, content):
        box.configure(state='normal')
        box.insert('end', f"[{time.strftime('%H:%M:%S')}] {title}\n{content}\n\n")
        if int(box.index('end-1c').split('.')[0]) > 5000:
            box.delete('1.0', '1000.0')
        box.see('end')
        box.configure(state='disabled')

    def background(self, fn, kind='local'):
        def work():
            try:
                self.events.put({'type': kind, 'result': fn()})
            except Exception as exc:
                self.events.put({'type': 'error', 'task': kind, 'error': str(exc)[:300]})
        self.threads = [t for t in self.threads if t.is_alive()]
        worker = threading.Thread(target=work, daemon=True)
        self.threads.append(worker)
        worker.start()

    def start_capture(self):
        if self.capture_pending:
            return
        if not self.collector.status()['running'] and len(self.store.list_sessions()) >= 10:
            messagebox.showinfo('采集记录已满', '最多保存 10 次采集。请到“采集记录”手动删除不需要的旧记录后再开始。')
            self.show_page('captures')
            return
        self.set_source('live')
        self.capture_pending = True
        self.network_status = '正在识别当前网络并启动采集…'
        self.analysis_var.set('正在采集；停止后保存编号记录，是否自动分析由下方选项决定。')
        self.start_button.configure(state='disabled')
        self.show_page('connections')
        manual = self.manual_interface
        def start():
            if self.collector.status()['running']:
                return {'name': self.interface_name}
            if manual:
                self.collector.select(manual['id'])
                selected = manual
            else:
                selected = self.collector.auto_select()
            self.collector.start()
            return selected
        self.background(start, 'capture_started')

    def stop_capture(self):
        if self.capture_pending:
            return
        status = self.collector.status()
        if not status['running'] and not status.get('session_id'):
            self.network_status = '当前没有运行中的采集；已保存的会话仍可手动分析'
            return
        self.capture_pending = True
        self.start_button.configure(state='disabled')
        self.background(self.collector.stop, 'capture_stopped')

    def analyze_session(self, auto=False):
        status = self.collector.status()
        session_id = self.selected_session_id or status.get('session_id') or status.get('last_session_id') or self.latest_session_id
        if not session_id:
            self.analysis_var.set('还没有真实抓包会话。请先点击“检测当前网络”。')
            return
        self.selected_session_id = session_id
        if not self.agent.api_key:
            self.analysis_var.set('会话已保存。配置模型 API Key 和预算后，点击“分析本次采集”。')
            return
        if self.agent.lock.locked():
            self.analysis_var.set('Agent 正在分析其他任务；结束后可再点击分析本次会话。')
            return
        selected = self.store._session(session_id)
        number = selected['number']
        self.analysis_var.set(f'正在分析采集 #{number:03}；先汇总，再调查候选连接的双向行为…')
        question = '分析所选真实采集已保存的全部连接流量。先调用session_summary；若该会话经过用户筛选，必须明确只代表保留连接。按证据调查可疑连接的双向分钟时间线，给出事实、可能解释、置信度与待验证事项。'
        def run():
            summary = self.store.session_summary(session_id)
            if not summary['packets']:
                result = {'ok': False, 'answer': '本次会话没有保存到数据包，未调用模型；请检查网卡和抓包状态。'}
            else:
                result = self.agent.run(question, 'live', self.events.put, remember=False, session_id=session_id)
            result['session_revision'] = selected['revision']
            return {'session_id': session_id, 'result': result}
        self.background(run, 'session_analysis')

    def show_session_report(self):
        session_id = self.selected_session_id or self.latest_session_id
        report = self.store.session_report(session_id) if session_id else None
        window = tk.Toplevel(self.root, bg=BG)
        number = self.store._session(session_id)['number'] if session_id else None
        window.title(f'采集 #{number:03} · AI 分析报告' if number else 'AI 分析报告')
        window.geometry('850x650')
        box = self._textbox(window, state='normal', width=60, height=15)
        box.pack(fill='both', expand=True, padx=16, pady=16)
        box.insert('1.0', report['answer'] if report else '此采集尚未生成 AI 报告。')
        box.configure(state='disabled')

    def refresh_interfaces(self):
        self.background(self.collector.interfaces, 'interfaces')

    def select_interface(self):
        if self.collector.status()['running'] or self.capture_pending or self.agent.lock.locked():
            messagebox.showinfo('网络接口', '请先停止采集并等待当前分析结束，再更换接口。')
            return
        index = self.interface_box.current()
        self.manual_interface = self.interfaces[index-1] if 0 < index <= len(self.interfaces) else None
        self.interface_name = self.manual_interface['name'] if self.manual_interface else '自动识别当前网络'
        self.network_status = '接口设置已应用：' + self.interface_name

    def set_source(self, source):
        self.source.set(source)
        self.source_revision += 1
        self.connection_page_index = 0
        self.current_connections = []
        self.last_refresh = 0

    def return_live(self):
        self.set_source('live')
        self.show_page('connections')

    def import_csv(self):
        path = filedialog.askopenfilename(title='导入会累加；每个数据集建议仅导入一次', filetypes=[('CSV', '*.csv')])
        if path:
            self.set_source('csv')
            self.background(lambda: self.store.import_csv(path), 'offline_loaded')

    def simulate(self):
        self.set_source('simulation')
        self.background(lambda: seed_simulation(self.store), 'offline_loaded')

    def local_summary(self):
        source = self.source.get()
        self.background(lambda: self.store.summary(source))

    def refresh_snapshot(self):
        source, revision = self.source.get(), self.source_revision
        wire = self.wire_view
        self.refresh_pending = True
        def read():
            if source == 'live':
                data = self.tracker.dashboard(wire=wire)
            else:
                data = rank_connections(self.store.read(source, 300), set())
                data['source'] = source
            return {'revision': revision, 'data': data, 'capture': self.collector.status(),
                    'capture_session': self.store.latest_session(), 'budget': self.store.usage()}
        self.background(read, 'snapshot')

    def toggle_connection_view(self):
        self.wire_view = not self.wire_view
        self.source_revision += 1
        self.connection_page_index = 0
        self.history_points.clear()
        self.last_refresh = 0

    def render_snapshot(self, result):
        if result['revision'] != self.source_revision:
            return
        data, capture = result['data'], result['capture']
        self.snapshot = data
        scope = (data.get('source'), bool(data.get('proxy')))
        if scope != self.connection_scope:
            self.connection_page_index = 0
            self.connection_scope = scope
        for key, widget in self.metrics.items():
            unknown_direction = key in ('upload', 'download') and data['unknown_direction_bytes'] == data['bytes'] and data['bytes'] > 0
            widget.configure(text='—' if unknown_direction or key == 'alerts' and (data.get('proxy') or data.get('source') == 'csv') else str(data[key]) if key == 'alerts' else format_bytes(data[key]))
        source_text = {'live': '实时', 'csv': 'CSV / 导入时间', 'simulation': '模拟数据'}[self.source.get()]
        if data.get('proxy'):
            source_text = '代理内应用'
        self.list_title.configure(text=f"全部连接  ·  {source_text}")
        self.view_button.configure(text='查看应用连接' if self.wire_view else '查看网卡出口', state='normal' if self.source.get() == 'live' else 'disabled')
        self.alert_filter.configure(state='disabled' if data.get('proxy') or data.get('source') == 'csv' else 'normal')
        if data.get('source') == 'csv':
            scope_note = 'CSV 为导入时间，缺少包数和 SYN/RST 标志；红色异常规则无法评估，显示“—”不代表安全。可在 AI 研判中分析端口、字节和通信关系。'
        else:
            scope_note = data.get('proxy_notice') or data.get('scope', '红色 ! = 待核实的异常迹象；未命中不代表安全。')
        self.scope_label.configure(text=scope_note)
        if self.page == 'connections':
            self.page_subtitle.configure(text='活动代理连接累计 · 全部连接分页显示' if data.get('proxy') else
                'CSV 导入记录 · 无 TCP 标志位，无法按实时规则评估' if data.get('source') == 'csv' else
                '近5分钟网卡连接 · 全部连接分页显示' if data.get('source') == 'live' else
                '明确标注的模拟流量 · 全部连接分页显示')
        self.render_connection_page()
        self.side_up.configure(text='↑  ' + format_bytes(data['upload']))
        self.side_down.configure(text='↓  ' + format_bytes(data['download']))
        self.side_scope.configure(text='代理活动连接 · 累计' if data.get('proxy') else '近5分钟 · 当前采集窗口')
        self.history_points.append((data['upload'], data['download']))
        self.spark.delete('all')
        maximum = max([v for pair in self.history_points for v in pair] or [1])
        for column, color in ((0, TEAL), (1, BLUE)):
            points = [coord for i, pair in enumerate(self.history_points) for coord in (i*max(1, self.spark.winfo_width()-4)/59, 52-48*pair[column]/max(maximum, 1))]
            if len(points) >= 4:
                self.spark.create_line(*points, fill=color, width=2)
        self.start_button.configure(text='正在检测' if capture['running'] else '检测当前网络', state='disabled' if self.capture_pending else 'normal')
        state = '采集中' if capture['running'] else '已停止'
        error = capture['error'] or self.collector.connection_error or data.get('error')
        suffix = f" | 提前淘汰 {data.get('evicted')} 桶" if data.get('evicted') else ''
        session = result.get('capture_session')
        if session and self.source.get() == 'live':
            started, stopped, duration = capture_times(session)
            suffix += f" · 本次 {started} → {stopped} · 持续 {duration}"
            if self.capture_table.exists(session['id']):
                self.capture_table.set(session['id'], 'stopped', stopped)
                self.capture_table.set(session['id'], 'duration', duration)
        self.status_var.set(error or f"{self.network_status}  ·  {state}  ·  队列丢包 {capture['queue_dropped_packets']}{suffix}")
        usage = result['budget']
        self.budget_var.set(f"API 累计 {usage['calls']} 次（不限次数）  ·  费用预留 {usage['reserved']:.4f} / {self.agent.config.max_cost}  ·  当前数据源 {source_text}")

    def search_connections(self, *_):
        self.connection_page_index = 0
        self.render_connection_page()
        self.connection_list.master.yview_moveto(0)

    def change_connection_page(self, step):
        self.connection_page_index += step
        self.render_connection_page()
        self.connection_list.master.yview_moveto(0)

    def render_connection_page(self):
        page = connection_page(self.snapshot.get('connections', []), self.connection_page_index, self.connection_search.get())
        self.connection_page_index = page['page']
        self.current_connections = page['items']
        first = page['offset']+1 if page['matched'] else 0
        last = page['offset']+len(page['items'])
        self.list_hint.configure(text=f"当前视图共 {page['total']} 条 · 匹配 {page['matched']} 条 · 显示 {first}–{last} 条")
        self.page_indicator.configure(text=f"第 {page['page']+1} / {page['pages']} 页 · 每页10条")
        self.previous_page.configure(state='normal' if page['page'] > 0 else 'disabled')
        self.next_page.configure(state='normal' if page['page']+1 < page['pages'] else 'disabled')
        if not self.current_connections:
            self.empty.pack(fill='x')
            self.empty.configure(text='当前视图没有匹配连接\n\n可搜索应用名、域名、IP、端口或协议；清除搜索或切换网卡出口查看其他来源。' if self.connection_search.get().strip() else '还没有采集到连接\n\n点击“检测当前网络”后正常使用应用；当前网卡与代理核心的覆盖范围不同，可切换视图查看。')
        else:
            self.empty.pack_forget()
        largest = max((c['bytes'] for c in self.current_connections), default=1)
        for i, widgets in enumerate(self.cards):
            card, app, endpoint, amount, direction, badge, progress, number = widgets
            if i >= len(self.current_connections):
                card.pack_forget()
                continue
            c = self.current_connections[i]
            number.configure(text=f"{page['offset']+i+1:02}")
            card.pack(fill='x', pady=(0, 8))
            app.configure(text=c['app'] + ('  · 部分匹配' if c['owners'] and c['unknown_bytes'] else ''))
            target = endpoint_text(c.get('destination') or c['remote_ip'], c['remote_port'])
            recent = '代理活动连接' if c.get('proxy') else '最近有流量' if c['recent'] else '窗口内曾活动'
            endpoint.configure(text=f"{target}   ·   {c['protocol']}   ·   {recent}")
            amount.configure(text=format_bytes(c['bytes']))
            direction.configure(text='本机互连' if c['local_connection'] else f"↑ {format_bytes(c['upload'])}   ↓ {format_bytes(c['download'])}" if c['direction_known'] else '方向未识别')
            badge.configure(text='!' if c['anomaly'] else '›', fg=RED if c['anomaly'] else MUTED)
            progress.delete('all')
            progress.create_rectangle(0, 0, max(1, progress.winfo_width())*c['bytes']/max(largest, 1), 3, fill=RED if c['anomaly'] else BLUE, outline='')

    def open_index(self, index):
        if index < len(self.current_connections):
            self.connection_details(dict(self.current_connections[index]))

    def connection_details(self, c):
        window = tk.Toplevel(self.root, bg=BG)
        window.title('连接属性 · ' + c['app'])
        window.geometry(f"740x{min(800, self.root.winfo_screenheight()-100)}")
        window.minsize(580, 480)
        window.columnconfigure(0, weight=1)
        window.rowconfigure(1, weight=1)
        label(window, c['app'], size=20, anchor='w').grid(row=0, column=0, sticky='ew', padx=24, pady=20)
        outer, content = scroll_frame(window)
        outer.grid(row=1, column=0, sticky='nsew', padx=24)
        proxy = c.get('proxy', False)
        rows = [('连接实例', c.get('connection_id') or '未提供 / 代理逻辑连接'), ('数据来源', '本机代理 · 活动连接累计（与网卡抓包分开）' if proxy else {'live':'真实采集 · 本次运行近5分钟', 'csv':'CSV · 导入时间', 'simulation':'明确标注的模拟数据'}[c['source']]),
                ('本机端点' if c['direction_known'] else '端点 A', endpoint_text(c['local_ip'], c['local_port'])),
                ('通信对端' if c['direction_known'] else '端点 B', endpoint_text(c.get('destination') or c['remote_ip'], c['remote_port'])),
                ('协议', c['protocol']), ('总用量', format_bytes(c['bytes'])),
                ('上传 / 下载', '本机互连，不计为外网收发' if c['local_connection'] else f"{format_bytes(c['upload'])} / {format_bytes(c['download'])}" if c['direction_known'] else '未知：无法确认本机端点'),
                ('数据包', '未知（代理接口不含包数）' if proxy else f"{c['packets']:,}" if c['source'] != 'csv' else '未知（CSV不含包数）'),
                ('建立时间' if proxy else '观察时间', c.get('start', '未知') if proxy else time.strftime('%H:%M:%S', time.localtime(c['first'])) + ' — ' + time.strftime('%H:%M:%S', time.localtime(c['last']))),
                ('状态', '代理报告活动连接' if proxy else '最近10秒观察到流量' if c['recent'] else '窗口内曾活动；不代表连接仍建立'),
                ('SYN / RST', '未知（请查看网卡出口）' if proxy else '未知（CSV不含TCP标志位）' if c['source'] == 'csv' else f"{c['syn']} / {c['rst']}"),
                ('归属依据' if proxy else '应用匹配覆盖', c['basis'] if proxy else f"{c['ownership_ratio']:.0%} 的观察字节；其余未识别"),
                ('主机化名', self.store.alias(c['remote_ip']) if c['remote_ip'] else '代理未返回目标IP；域名仅本地显示')]
        for name, value in rows:
            row = tk.Frame(content, bg=BG)
            row.pack(fill='x', pady=7)
            label(row, name, color=MUTED, width=15, anchor='w').pack(side='left', anchor='n')
            label(row, value, wraplength=460, justify='left', anchor='w').pack(side='left', fill='x', expand=True)
        if c['owners']:
            label(content, '应用归属依据', size=13).pack(anchor='w', pady=(18, 6))
            for owner in c['owners']:
                label(content, f"{owner['app']} · PID {owner['pid']} · {format_bytes(owner['bytes'])}\n{owner['basis']}", color=MUTED, justify='left', wraplength=640).pack(anchor='w', pady=5)
        elif not proxy:
            label(content, '应用未识别：可能是短连接、非TCP/UDP、权限受限，或离线数据。不会用当前进程猜测历史归属。', color=MUTED, wraplength=640, justify='left').pack(anchor='w', pady=12)
        label(content, '该视图不提供逐包异常检测' if proxy else 'CSV缺少TCP标志位，无法按实时规则评估' if c['source'] == 'csv' else '!  异常迹象' if c['anomaly'] else '当前未命中本地异常提示', size=13, color=RED if c['anomaly'] else TEAL).pack(anchor='w', pady=(20, 8))
        for reason in c['alerts'] or ['CSV仅支持端口、字节和通信关系分析，不能由此判定安全。' if c['source'] == 'csv' else '未出现提示不等于安全。可让 Agent 结合历史和双向流量继续核查。']:
            label(content, reason, color=RED if c['anomaly'] else MUTED, wraplength=640, justify='left').pack(anchor='w', pady=5)
        commands = tk.Frame(window, bg=BG)
        commands.grid(row=2, column=0, sticky='ew', padx=24, pady=16)
        button(commands, '让 Agent 调查此连接', lambda: (window.destroy(), self.investigate(c)), primary=True).pack(side='left')
        if not proxy:
            button(commands, '历史 / 通信图', lambda: self.connection_history(c)).pack(side='left', padx=8)
        button(commands, '关闭', window.destroy).pack(side='right')

    def investigate(self, c):
        self.set_source(c['source'])
        self.show_page('agent')
        if c.get('proxy'):
            self.agent_scope_override = True
            question = f"请调用top_connections并传入local_port={c['local_port']}调查当前代理应用连接，目标端口为{c['remote_port']}。此视图为代理活动连接累计，目标域名未上传，不能直接对应网卡出口或历史数据；请明确证据范围，不推测原始报文或应用归属。"
        else:
            question = f"先调用session_summary，再用session_connection_history调查本次采集的 {c['protocol']} 双向连接，src={self.store.alias(c['local_ip'])}、dst={self.store.alias(c['remote_ip'])}、sport={c['local_port']}、dport={c['remote_port']}。请核对全程分钟行为、未查询页数与不确定性。"
        if c.get('connection_id') and not c.get('proxy'):
            question += ' 指定connection_id=' + c['connection_id'] + '，不要混合其他同五元组实例。'
        if c['alerts']:
            question += '本地提示：' + '；'.join(c['alerts'])
        self.prompt.delete('1.0', 'end')
        self.prompt.insert('1.0', question)
        self.ask()

    def connection_history(self, c):
        host, source = c['remote_ip'], c['source']
        session_id = self.collector.status().get('session_id') or self.collector.status().get('last_session_id') or self.latest_session_id
        if source == 'live' and session_id:
            self.background(lambda: self.store.session_connection_history(session_id,
                self.store.alias(c['local_ip']), self.store.alias(c['remote_ip']),
                c['protocol'], c['local_port'], c['remote_port'], connection_id=c.get('connection_id')), 'details_history')
        else:
            self.background(lambda: {'behavior': self.store.behavior(host, source), 'history': self.store.history(source, 3600, host),
                                     'graph': self.store.graph(source, 300, host)}, 'details_history')

    def show_alerts(self):
        alerts = [c for c in self.snapshot.get('connections', []) if c['anomaly']]
        if not alerts:
            messagebox.showinfo('异常提示', '当前窗口未命中本地异常迹象。这不代表所有流量均安全。')
            return
        window = tk.Toplevel(self.root, bg=BG)
        window.title('异常连接 · 待核实')
        window.geometry('760x550')
        label(window, f'{len(alerts)} 个连接有待核实的异常迹象', size=16).pack(anchor='w', padx=20, pady=20)
        outer, content = scroll_frame(window)
        outer.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        for c in alerts[:100]:
            b = button(content, '!  ' + c['app'] + '  ·  ' + endpoint_text(c['remote_ip'], c['remote_port']), lambda item=c: self.connection_details(item), anchor='w')
            b.configure(fg=RED)
            b.pack(fill='x', pady=4)

    def toggle_monitor(self):
        if self.auto.get():
            try:
                self.agent.config.validate()
                if not self.agent.api_key:
                    raise ValueError('请先配置 API Key')
            except ValueError as exc:
                self.auto.set(False)
                messagebox.showerror('自动研判', str(exc))
        self.monitor.enabled = self.auto.get()
        self.monitor.last_attempt = time.monotonic()

    def ask(self):
        if self.agent.lock.locked():
            self.network_status = 'Agent 正在调查，请等待或取消当前任务'
            return
        question, source = self.prompt.get('1.0', 'end').strip(), self.source.get()
        status = self.collector.status()
        session_id = (status.get('session_id') or self.selected_session_id or status.get('last_session_id') or self.latest_session_id) if source == 'live' else None
        if getattr(self, 'agent_scope_override', False):
            session_id = None
            self.agent_scope_override = False
        self.append(self.chat, '你 · ' + source, question)
        self.ask_button.configure(state='disabled')
        revision = self.store._session(session_id)['revision'] if session_id else None
        def run():
            result = self.agent.run(question, source, self.events.put, session_id=session_id)
            if session_id:
                result['session_id'] = session_id
                result['session_revision'] = revision
            return result
        self.background(run, 'agent_result')

    def new_chat(self):
        if not self.agent.lock.locked():
            self.agent.conversation.clear()
            self.append(self.chat, '系统', '已开启新会话；累计预算保持不变。')

    def settings(self):
        window = tk.Toplevel(self.root, bg=BG)
        window.title('AI 模型配置')
        window.geometry('560x340')
        window.resizable(False, False)
        window.columnconfigure(0, weight=1)
        frame = tk.Frame(window, bg=BG)
        frame.grid(row=0, column=0, sticky='ew', padx=24, pady=(22, 0))
        frame.columnconfigure(1, weight=1)
        provider = tk.StringVar(value=provider_for(self.agent.config))
        models = list(MODEL_PRESETS[provider.get()]['models'])
        model = tk.StringVar(value=self.agent.config.model if self.agent.config.model in models else models[0])
        label(frame, '服务商').grid(row=0, column=0, sticky='w', padx=(0, 16), pady=9)
        provider_box = ttk.Combobox(frame, textvariable=provider, values=list(MODEL_PRESETS), state='readonly')
        provider_box.grid(row=0, column=1, sticky='ew')
        label(frame, '模型').grid(row=1, column=0, sticky='w', pady=9)
        model_box = ttk.Combobox(frame, textvariable=model, values=models, state='readonly')
        model_box.grid(row=1, column=1, sticky='ew')
        label(frame, 'API Key').grid(row=2, column=0, sticky='w', pady=9)
        key = tk.Entry(frame, bg=CARD, fg=TEXT, insertbackground=TEXT, relief='flat', show='•')
        key.grid(row=2, column=1, sticky='ew', ipady=7)
        key_status = tk.StringVar()
        label(frame, textvariable=key_status, color=MUTED, wraplength=480, justify='left', anchor='w').grid(row=3, column=0, columnspan=2, sticky='w', pady=(4, 10))
        label(frame, '密钥按 Windows 当前用户加密保存；留空表示继续使用已保存的密钥。\n累计调用次数不限；仍检查费用预算，实际费用以服务商账单为准。',
              color=MUTED, wraplength=490, justify='left').grid(row=4, column=0, columnspan=2, sticky='w')

        def refresh_key_status(*_):
            key.delete(0, 'end')
            try:
                configured = bool(active_key(self.credentials, provider.get()))
                key_status.set('此服务商已配置 API Key；留空即可继续使用。' if configured else '此服务商尚未配置 API Key，请在此填写。')
            except Exception:
                key_status.set('已保存的密钥无法读取，请重新填写。')

        def change_provider(*_):
            options = list(MODEL_PRESETS[provider.get()]['models'])
            model_box['values'] = options
            model.set(options[0])
            refresh_key_status()

        provider_box.bind('<<ComboboxSelected>>', change_provider)
        refresh_key_status()

        def save():
            try:
                config = choose_model(self.agent.config, provider.get(), model.get())
                typed_key = key.get().strip()
                if typed_key:
                    self.credentials.save(provider.get(), typed_key)
                selected_key = active_key(self.credentials, provider.get())
                if not selected_key:
                    raise ValueError('请填写当前服务商的 API Key')
                config.save(self.home / 'config.local.json')
                self.config = self.agent.config = config
                self.agent.api_key = selected_key
                self.agent.conversation.clear()
                self.model_status_var.set(f'当前：{provider.get()} / {model.get()}')
                window.destroy()
            except Exception as exc:
                messagebox.showerror('设置未保存', str(exc), parent=window)
        button(window, '保存并使用', save, primary=True).grid(row=1, column=0, sticky='e', padx=24, pady=(14, 20))

    def poll(self):
        if self.closing:
            return
        for _ in range(100):
            try:
                event = self.events.get_nowait()
            except queue.Empty:
                break
            kind = event['type']
            if kind == 'snapshot':
                self.refresh_pending = False
                self.render_snapshot(event['result'])
            elif kind == 'jobs_snapshot':
                self.jobs_refresh_pending=False
                result=event['result']; tasks=result['tasks']
                selection=self.job_tree.selection()
                self.job_tree.delete(*self.job_tree.get_children())
                self.job_rows={r['job_id']:r for r in tasks['items']}
                for r in tasks['items']:
                    self.job_tree.insert('', 'end',iid=r['job_id'],values=(r['event_id'],r['event_revision'],r['status'],
                        f"{r['attempt_count']}/{r['max_attempts']}",f"{r['current_step']} · {r['tool_calls']}/{r['max_tools']}"))
                if selection and selection[0] in self.job_rows: self.job_tree.selection_set(selection[0])
                self.job_pages=tasks['pages']
                self.job_page_label.configure(text=f"第{tasks['page']}/{tasks['pages']}页 · {tasks['total']}项 " + (result['runtime_error'] or ''))
                self.job_event_ids={f"{e['event_id']} · {e['severity']} · r{e['revision']}":e['event_id'] for e in result['events']['items']}
                self.job_event_box['values']=list(self.job_event_ids)
                if self.job_event.get() not in self.job_event_ids:
                    self.job_event.set(next(iter(self.job_event_ids),''))
            elif kind == 'job_action':
                self.refresh_jobs()
            elif kind == 'job_detail':
                window=tk.Toplevel(self.root,bg=BG); window.title('事件调查报告与持久化步骤'); window.geometry('950x700')
                box=self._textbox(window,width=90,height=30); box.pack(fill='both',expand=True)
                box.insert('1.0',event['result']); box.configure(state='disabled')
            elif kind == 'interfaces':
                self.interfaces = event['result']
                self.interface_box['values'] = ['自动识别当前网络'] + [x['name'] for x in self.interfaces]
                self.interface_box.current(0)
            elif kind == 'capture_started':
                self.capture_pending = False
                self.interface_name = event['result']['name']
                self.network_status = '当前网络：' + self.interface_name
                self.latest_session_id = self.collector.status().get('session_id')
                self.selected_session_id = self.latest_session_id
                if self.latest_session_id:
                    number = self.store._session(self.latest_session_id)['number']
                    self.analysis_var.set(f'采集 #{number:03} 正在运行；停止后保存。')
                self.report_answer = ''
                self.start_button.configure(state='normal')
                if self.page == 'captures':
                    self.refresh_capture_records()
            elif kind == 'capture_stopped':
                self.capture_pending = False
                self.start_button.configure(state='normal')
                ended_session_id = event['result'].get('ended_session_id')
                self.latest_session_id = ended_session_id or self.latest_session_id
                self.selected_session_id = self.latest_session_id
                self.network_status = '本次采集已保存；连接列表仍显示最近5分钟'
                if ended_session_id:
                    number = self.store._session(ended_session_id)['number']
                    self.analysis_var.set(f'采集 #{number:03} 已保存。可在“采集记录”筛选连接或手动分析。')
                    if self.analyze_after_stop.get():
                        self.analyze_session(auto=True)
                if self.page == 'captures':
                    self.refresh_capture_records()
            elif kind in {'local', 'offline_loaded'}:
                self.append(self.local, '本地数据', json.dumps(event['result'], ensure_ascii=False, indent=2))
                if kind == 'offline_loaded':
                    self.show_page('connections')
            elif kind == 'details_history':
                window = tk.Toplevel(self.root, bg=BG)
                window.title('连接历史 / 通信图证据')
                window.geometry('800x650')
                text = self._textbox(window, width=50, height=12)
                text.pack(fill='both', expand=True)
                text.insert('1.0', json.dumps(event['result'], ensure_ascii=False, indent=2))
                text.configure(state='disabled')
            elif kind == 'session_analysis':
                result = event['result']['result']
                session_id = event['result']['session_id']
                self.append(self.chat, '本次采集 AI 分析' if result['ok'] else '本次分析未完成', result['answer'])
                self.ask_button.configure(state='normal')
                self._display_session_result(session_id, result)
            elif kind in {'agent_result', 'monitor_result'}:
                result = event['result']
                self.append(self.chat, 'AI 分析' if result['ok'] else '分析未完成', result['answer'])
                if result.get('session_id'):
                    self._display_session_result(result['session_id'], result)
                self.ask_button.configure(state='normal')
            elif kind == 'error':
                self.network_status = event['error']
                self.append(self.chat, '错误', event['error'])
                if event.get('task') == 'snapshot':
                    self.refresh_pending = False
                if event.get('task') == 'jobs_snapshot':
                    self.jobs_refresh_pending=False
                if event.get('task') in {'capture_started', 'capture_stopped'}:
                    self.capture_pending = False
                    self.start_button.configure(state='normal')
                self.ask_button.configure(state='normal')
            else:
                self.append(self.trace, kind, json.dumps(event, ensure_ascii=False, indent=2))
        if not self.refresh_pending and time.monotonic()-self.last_refresh >= 1:
            self.last_refresh = time.monotonic()
            self.refresh_snapshot()
        if self.page=='jobs' and not self.jobs_refresh_pending and time.monotonic()-self.jobs_last_refresh>=2:
            self.refresh_jobs()
        self.root.after(100, self.poll)

    def _display_session_result(self, session_id, result):
        if result['ok']:
            saved = self.store.save_session_report(session_id, result['answer'], result.get('citation_valid', False),
                                                   result.get('session_revision'))
            if not saved:
                if self.selected_session_id == session_id:
                    self.analysis_var.set('采集记录已变化或报告超过保存上限，结果未保存；请重新分析。')
                return
            if self.selected_session_id != session_id:
                return
            self.report_answer = result['answer']
            label = '已完成 · ' if result.get('citation_valid') else '证据引用待核查 · '
            self.analysis_var.set(label + result['answer'][:180].replace('\n', ' '))
        else:
            self.analysis_var.set('分析未完成：' + result['answer'][:180])
        if self.page == 'captures':
            self.refresh_capture_records()

    def close(self):
        if self.closing:
            return
        self.closing = True
        self.root.withdraw()
        self.monitor.close()
        self.agent.cancel.set()
        self.investigator.close(wait=False)
        def finish():
            try:
                for worker in self.threads:
                    worker.join()
                self.monitor.thread.join()
                self.investigator.close()
                self.collector.close()
                self.tracker.close()
                with self.agent.lock:
                    self.store.close()
            finally:
                self.events.put({'type': 'closed'})
        threading.Thread(target=finish, daemon=True).start()
        def wait():
            try:
                while self.events.get_nowait()['type'] != 'closed':
                    pass
            except queue.Empty:
                self.root.after(100, wait)
                return
            self.root.destroy()
        wait()
