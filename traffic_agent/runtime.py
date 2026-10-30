"""Single investigation worker; independent of packet collection and UI."""
import threading
import time
import uuid

from .investigation import SafeModelRetry
from .jobs import JobStopped, LimitReached


class InvestigationRuntime:
    def __init__(self,store,agent,start=True):
        if agent.store is not store or agent.budget_store is not store:
            raise ValueError('持久化事件任务、证据和共享用量必须使用同一个Store；用量统计与请求记录需要同库原子提交')
        self.store,self.agent,self.jobs=store,agent,store.jobs
        self.owner=uuid.uuid4().hex
        self.stop_event=threading.Event()
        self.automatic=False
        self.last_discovery=0
        self.last_error=None
        self.owned=False
        self.needs_recovery=False
        self.thread=None
        if start:
            self.thread=threading.Thread(target=self._loop,name='event-investigation',daemon=True)
            self.thread.start()

    def discover(self):
        """Only latest high-risk revisions; at most one/event/minute, bounded backlog."""
        if not self.automatic: return []
        candidates=self.jobs.discovery_candidates()
        result=[]
        for event in candidates:
            if self.stop_event.is_set(): break
            try: result.append(self.jobs.enqueue(event['event_id'],self.agent.config,revision=event['revision']))
            except Exception as exc: self.last_error='事件入队失败：'+type(exc).__name__
        return result

    def run_once(self):
        if not self.owned:
            self.owned=self.jobs.acquire_worker(self.owner)
            if not self.owned:
                self.last_error='已有调查执行器，当前实例不领取任务'
                return False
        if self.stop_event.is_set(): return False
        if self.needs_recovery:
            self.jobs.recover_worker(self.owner); self.needs_recovery=False
        if time.monotonic()-self.last_discovery>=5:
            self.last_discovery=time.monotonic(); self.discover()
        # Shares the old Agent lock with manual chat/old connection investigation.
        if not self.agent.lock.acquire(blocking=False): return False
        job=None
        try:
            job=self.jobs.claim(self.owner)
            if not job: return False
            try:
                report=self.agent.run_event(self.jobs,job,self.stop_event)
                self.jobs.finish(job['job_id'],report['调查完成状态'],report=report)
            except JobStopped:
                pass  # Cancel/deletion already persisted by the user action.
            except (SafeModelRetry,InterruptedError) as exc:
                # Retry only definite rejections or safe local interruptions.
                # Bound the delay, not the number of recoverable attempts.
                delay=0 if isinstance(exc,InterruptedError) else 30*2**min(job['attempt_count']-1,5)
                self.jobs.finish(job['job_id'],'retry_wait',str(exc),retry_at=time.time()+delay)
            except LimitReached as exc:
                # Provider truncation is not an unknown or retryable request.
                self.jobs.finish(job['job_id'],'partial',str(exc))
            except ValueError as exc:
                self.jobs.finish(job['job_id'],'failed',str(exc)[:200])
            except Exception as exc:
                # Pending request may have reached the provider: never blindly retry.
                self.jobs.finish(job['job_id'],'partial','调查未完成：'+type(exc).__name__+'；检查步骤记录，未知模型请求需人工确认')
            return True
        except Exception:
            # A DB commit error must not leave a running row blocking the queue
            # forever. No network call is in flight once this turn has unwound.
            self.needs_recovery=True
            raise
        finally:
            self.agent.lock.release()

    def _loop(self):
        try:
            while not self.stop_event.is_set():
                try: worked=self.run_once()
                except Exception as exc:
                    self.last_error='调查调度异常：'+type(exc).__name__; worked=False
                self.stop_event.wait(.05 if worked else 1)
        finally:
            if self.owned:
                self.jobs.release_worker(self.owner); self.owned=False

    def close(self, wait=True):
        self.stop_event.set()
        if self.thread:
            if wait: self.thread.join()
        elif self.owned:
            self.jobs.release_worker(self.owner); self.owned=False
