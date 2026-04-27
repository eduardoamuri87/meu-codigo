"""
MCP server remoto do TickTick (Eleonora).

Rodar local (stdio):
    python server.py

Rodar local (HTTP):
    python server.py http

Deploy (Fly.io): usa Dockerfile + CMD, que chama `python server.py http`.
"""

from __future__ import annotations

import os
import sys
from typing import Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from fastmcp import FastMCP

from ticktick_client import TickTickClient, TickTickError


EMAIL = os.environ.get("TICKTICK_EMAIL")
PASSWORD = os.environ.get("TICKTICK_PASSWORD")
USER_ID = os.environ.get("TICKTICK_USER_ID")
TOKEN = os.environ.get("TICKTICK_TOKEN") or None
MCP_TOKEN = os.environ.get("MCP_TOKEN")

if not (EMAIL and PASSWORD and USER_ID):
    raise RuntimeError(
        "Configure TICKTICK_EMAIL, TICKTICK_PASSWORD e TICKTICK_USER_ID no ambiente/.env"
    )

_client: Optional[TickTickClient] = None


def get_client() -> TickTickClient:
    global _client
    if _client is None:
        _client = TickTickClient(
            email=EMAIL,
            password=PASSWORD,
            user_id=USER_ID,
            token=TOKEN,
        )
    return _client


def slim_task(t: dict) -> dict:
    return {
        "id": t.get("id"),
        "projectId": t.get("projectId"),
        "title": t.get("title"),
        "content": (t.get("content") or "")[:500],
        "startDate": t.get("startDate"),
        "dueDate": t.get("dueDate"),
        "priority": t.get("priority"),
        "status": t.get("status"),
        "assignee": t.get("assignee"),
        "tags": t.get("tags"),
    }


mcp = FastMCP("Eleonora TickTick")


@mcp.tool()
def list_my_tasks(include_unassigned: bool = False) -> dict:
    """
    Lista tarefas abertas atribuidas a Eduardo (assignee = seu userId).
    Use include_unassigned=True para incluir tambem tarefas sem assignee
    (listas pessoais nao compartilhadas). Padrao: so as explicitamente suas.
    """
    tasks = get_client().list_my_tasks(only_assigned=not include_unassigned)
    return {"count": len(tasks), "tasks": [slim_task(t) for t in tasks]}


@mcp.tool()
def list_projects() -> list[dict]:
    """Lista todos os projetos (listas) do usuario, incluindo a Inbox."""
    projects = get_client().list_projects()
    return [
        {
            "id": p.get("id"),
            "name": p.get("name"),
            "color": p.get("color"),
            "groupId": p.get("groupId"),
            "userCount": p.get("userCount"),
            "isInbox": p.get("isInbox", False),
        }
        for p in projects
    ]


@mcp.tool()
def list_project_tasks(project_id: str) -> dict:
    """Lista tarefas abertas de um projeto especifico (pelo id)."""
    tasks = get_client().list_project_tasks(project_id)
    return {"count": len(tasks), "tasks": [slim_task(t) for t in tasks]}


@mcp.tool()
def search_tasks(query: str, limit: int = 30) -> dict:
    """Busca tarefas por texto no titulo ou conteudo."""
    tasks = get_client().search_tasks(query, limit=limit)
    return {"count": len(tasks), "tasks": [slim_task(t) for t in tasks]}


@mcp.tool()
def create_task(
    title: str,
    project_id: Optional[str] = None,
    content: str = "",
    priority: int = 0,
    start_date: Optional[str] = None,
    due_date: Optional[str] = None,
) -> dict:
    """
    Cria uma tarefa nova.

    project_id: opcional. Se vazio, cai na Inbox.
    priority: 0 (nenhuma), 1 (baixa), 3 (media), 5 (alta).
    start_date / due_date: ISO 8601, ex "2026-04-25T03:00:00+0000".
    Se so due_date for passado, a tarefa vira "data unica"; se ambos,
    vira "duracao" (intervalo start -> due).
    """
    t = get_client().create_task(
        title=title, project_id=project_id,
        content=content, priority=priority,
        start_date=start_date, due_date=due_date,
    )
    return {"id": t["id"], "title": t["title"], "projectId": t["projectId"]}


@mcp.tool()
def complete_task(task_id: str) -> dict:
    """Marca uma tarefa como concluida."""
    t = get_client().complete_task(task_id)
    return {"id": t.get("id"), "status": "completed"}


@mcp.tool()
def update_task(
    task_id: str,
    title: Optional[str] = None,
    content: Optional[str] = None,
    priority: Optional[int] = None,
    start_date: Optional[str] = None,
    due_date: Optional[str] = None,
    clear_start_date: bool = False,
    clear_due_date: bool = False,
    project_id: Optional[str] = None,
) -> dict:
    """
    Edita campos de uma tarefa. Passe apenas os campos que quer alterar.

    Datas (ISO 8601, ex "2026-05-15T03:00:00+0000"):
    - start_date / due_date: define os valores.
    - clear_start_date=True: remove o startDate (util pra converter tarefa
      com "duracao" em data unica — deixe clear_start_date=True sozinho).
    - clear_due_date=True: remove o dueDate.

    project_id: move a tarefa para outro projeto.
    """
    fields: dict = {}
    if title is not None:
        fields["title"] = title
    if content is not None:
        fields["content"] = content
    if priority is not None:
        fields["priority"] = priority
    if start_date is not None:
        fields["startDate"] = start_date
    if due_date is not None:
        fields["dueDate"] = due_date
    if clear_start_date:
        fields["startDate"] = None
    if clear_due_date:
        fields["dueDate"] = None
    if project_id is not None:
        fields["projectId"] = project_id
    t = get_client().update_task(task_id, fields)
    return {"id": t.get("id"), "updated": list(fields.keys())}


def run_http():
    if not MCP_TOKEN:
        raise RuntimeError("Configure MCP_TOKEN para rodar em HTTP (auth via path secreto).")

    port = int(os.environ.get("PORT", 8000))
    path = f"/{MCP_TOKEN}/mcp"
    print(f"Starting MCP on 0.0.0.0:{port}{path}")
    mcp.run(
        transport="http",
        host="0.0.0.0",
        port=port,
        path=path,
        stateless_http=True,
        json_response=True,
    )


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "stdio"
    if mode == "http":
        run_http()
    else:
        mcp.run()
