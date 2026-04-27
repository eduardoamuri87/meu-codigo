"""
Cliente da API v2 interna do TickTick.

Esta API nao e oficial nem documentada — o codigo abaixo faz engenharia
reversa do trafego do web app. Pode quebrar se o TickTick mudar algo.
"""

from __future__ import annotations

import json
import secrets
import time
from typing import Any, Optional

import requests


BASE = "https://api.ticktick.com"

X_DEVICE = json.dumps({
    "platform": "web",
    "os": "macOS",
    "device": "Chrome",
    "name": "",
    "version": 4531,
    "id": "",
    "channel": "website",
    "campaign": "",
    "websocket": "",
})

DEFAULT_HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
    ),
    "x-device": X_DEVICE,
    "Origin": "https://ticktick.com",
    "Referer": "https://ticktick.com/",
}


def new_object_id() -> str:
    """Gera um id compativel com o formato usado pelo TickTick (ObjectId hex de 24 chars)."""
    ts = int(time.time()).to_bytes(4, "big")
    rnd = secrets.token_bytes(8)
    return (ts + rnd).hex()


class TickTickError(Exception):
    pass


class TickTickClient:
    def __init__(
        self,
        email: str,
        password: str,
        user_id: Optional[str] = None,
        token: Optional[str] = None,
    ):
        self.email = email
        self.password = password
        self.user_id = str(user_id) if user_id else None
        self._token = token
        self._session = requests.Session()
        self._session.headers.update(DEFAULT_HEADERS)
        if token:
            self._session.cookies.set("t", token, domain=".ticktick.com")

    def _login(self) -> None:
        r = self._session.post(
            f"{BASE}/api/v2/user/signon",
            params={"wc": "true", "remember": "true"},
            json={"username": self.email, "password": self.password},
            timeout=20,
        )
        if r.status_code != 200:
            raise TickTickError(f"login HTTP {r.status_code}: {r.text[:300]}")
        data = r.json()
        token = data.get("token")
        uid = data.get("userId") or data.get("userid")
        if not token:
            raise TickTickError(f"login sem token: {data}")
        self._token = token
        self._session.cookies.set("t", token, domain=".ticktick.com")
        if uid and not self.user_id:
            self.user_id = str(uid)

    def _ensure_auth(self) -> None:
        if self._token:
            return
        self._login()

    def _request(self, method: str, path: str, **kwargs) -> Any:
        self._ensure_auth()
        url = f"{BASE}{path}"
        r = self._session.request(method, url, timeout=30, **kwargs)
        if r.status_code in (401, 403):
            # sessao morreu: tenta re-login uma vez
            self._token = None
            self._session.cookies.clear()
            self._login()
            r = self._session.request(method, url, timeout=30, **kwargs)
        if r.status_code >= 400:
            raise TickTickError(f"{method} {path} -> HTTP {r.status_code}: {r.text[:300]}")
        if not r.content:
            return None
        ctype = r.headers.get("content-type", "")
        if "application/json" in ctype:
            return r.json()
        return r.text

    # ---------- sync ----------

    def sync(self) -> dict:
        """Sync inicial: retorna projects, tasks abertas, tags, inbox etc."""
        return self._request("GET", "/api/v2/batch/check/0")

    # ---------- projects ----------

    def list_projects(self) -> list[dict]:
        data = self.sync()
        projects = data.get("projectProfiles") or []
        inbox_id = data.get("inboxId")
        if inbox_id and not any(p.get("id") == inbox_id for p in projects):
            projects = [{"id": inbox_id, "name": "Inbox", "isInbox": True}] + list(projects)
        return projects

    def get_inbox_id(self) -> Optional[str]:
        return self.sync().get("inboxId")

    # ---------- tasks ----------

    def _all_open_tasks(self) -> list[dict]:
        data = self.sync()
        return (data.get("syncTaskBean") or {}).get("update") or []

    def list_my_tasks(self, only_assigned: bool = True) -> list[dict]:
        """
        Tarefas abertas atribuidas ao user_id configurado.

        Se only_assigned=False, inclui tambem tarefas sem assignee
        (listas pessoais, onde o campo e -1 ou None).
        """
        if not self.user_id:
            raise TickTickError("user_id nao configurado")
        uid = str(self.user_id)
        tasks = self._all_open_tasks()
        if only_assigned:
            return [t for t in tasks if str(t.get("assignee", "")) == uid]
        out = []
        for t in tasks:
            a = t.get("assignee")
            if a is None or a == -1 or str(a) == uid:
                out.append(t)
        return out

    def list_project_tasks(self, project_id: str) -> list[dict]:
        tasks = self._all_open_tasks()
        return [t for t in tasks if t.get("projectId") == project_id]

    def search_tasks(self, query: str, limit: int = 50) -> list[dict]:
        data = self._request("GET", "/api/v2/search/all", params={"keywords": query})
        if not isinstance(data, dict):
            return []
        tasks = data.get("tasks") or []
        return tasks[:limit]

    def find_task(self, task_id: str) -> Optional[dict]:
        for t in self._all_open_tasks():
            if t.get("id") == task_id:
                return t
        return None

    def create_task(
        self,
        title: str,
        project_id: Optional[str] = None,
        content: str = "",
        priority: int = 0,
        start_date: Optional[str] = None,
        due_date: Optional[str] = None,
        is_all_day: bool = True,
        time_zone: str = "America/Sao_Paulo",
        assignee: Optional[str] = None,
    ) -> dict:
        if not project_id:
            project_id = self.get_inbox_id()
            if not project_id:
                raise TickTickError("nao consegui determinar inbox_id")

        task: dict = {
            "id": new_object_id(),
            "projectId": project_id,
            "title": title,
            "content": content,
            "priority": priority,
            "status": 0,
            "timeZone": time_zone,
            "isAllDay": is_all_day,
            "sortOrder": 0,
            "items": [],
        }
        if start_date:
            task["startDate"] = start_date
        if due_date:
            task["dueDate"] = due_date
        if assignee:
            task["assignee"] = assignee

        body = {"add": [task], "update": [], "delete": []}
        self._request("POST", "/api/v2/batch/task", json=body)
        return task

    def complete_task(self, task_id: str, project_id: Optional[str] = None) -> dict:
        existing = self.find_task(task_id)
        if not existing:
            raise TickTickError(f"tarefa {task_id} nao encontrada (talvez ja concluida)")
        existing["status"] = 2
        existing["completedTime"] = time.strftime(
            "%Y-%m-%dT%H:%M:%S.000+0000", time.gmtime()
        )
        body = {"add": [], "update": [existing], "delete": []}
        self._request("POST", "/api/v2/batch/task", json=body)
        return existing

    def update_task(
        self,
        task_id: str,
        fields: dict,
        project_id: Optional[str] = None,
    ) -> dict:
        existing = self.find_task(task_id)
        if not existing:
            raise TickTickError(f"tarefa {task_id} nao encontrada")
        existing.update(fields)
        body = {"add": [], "update": [existing], "delete": []}
        self._request("POST", "/api/v2/batch/task", json=body)
        return existing
