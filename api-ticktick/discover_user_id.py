"""
Descobre o userId interno do TickTick.

Dois modos:
  A) Login via email+senha (se TICKTICK_TOKEN estiver vazio).
  B) Fallback via cookie de sessao (se TICKTICK_TOKEN estiver preenchido).
"""

import json
import os
import sys
from collections import Counter

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("AVISO: python-dotenv nao instalado. Lendo direto do ambiente.")

try:
    import requests
except ImportError:
    print("ERRO: requests nao instalado. Rode: pip install -r requirements-discover.txt")
    sys.exit(1)


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
HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
    ),
    "x-device": X_DEVICE,
    "Origin": "https://ticktick.com",
    "Referer": "https://ticktick.com/",
}


def sep(title):
    print()
    print("=" * 60)
    print(title)
    print("=" * 60)


def fingerprint(value):
    """Mostra length e extremos de um segredo sem vazar."""
    if not value:
        return "(vazio)"
    s = str(value)
    if len(s) <= 3:
        return f"len={len(s)} conteudo=***"
    return f"len={len(s)} primeiro={s[0]!r} ultimo={s[-1]!r}"


def login_with_password(session, email, password):
    print(f"Logando como {email} via email+senha...")
    r = session.post(
        f"{BASE}/api/v2/user/signon",
        params={"wc": "true", "remember": "true"},
        json={"username": email, "password": password},
        timeout=20,
    )
    if r.status_code != 200:
        print(f"FALHA no login (HTTP {r.status_code}):")
        print(f"  {r.text[:500]}")
        print()
        print("Dicas:")
        print("  - Se a conta foi criada por Google/Apple e voce acabou de definir")
        print("    senha: faca logoff e login pelo site antes de tentar aqui.")
        print("  - Se tentou muitas vezes, TickTick pode ter ativado captcha.")
        print("    Use a Opcao B: cole o cookie 't' do browser em TICKTICK_TOKEN.")
        return None

    data = r.json()
    token = data.get("token")
    user_id = data.get("userId") or data.get("userid")
    if not token or not user_id:
        print("Login retornou 200 mas sem token/userId. Payload:")
        print(json.dumps(data, indent=2)[:800])
        return None

    session.cookies.set("t", token, domain=".ticktick.com")
    return user_id, token, data


def login_with_token(session, token):
    print("Usando TICKTICK_TOKEN (cookie do browser)...")
    session.cookies.set("t", token, domain=".ticktick.com")
    # Valida chamando /user/status
    r = session.get(f"{BASE}/api/v2/user/status", timeout=20)
    if r.status_code != 200:
        print(f"Token invalido ou expirado (HTTP {r.status_code}):")
        print(f"  {r.text[:500]}")
        return None
    data = r.json()
    user_id = data.get("userId") or data.get("userid")
    if not user_id:
        print("Resposta de /user/status nao trouxe userId. Payload:")
        print(json.dumps(data, indent=2)[:800])
        return None
    return user_id, token, data


def fetch_tasks_and_summarize(session, user_id):
    sep("Sync inicial (/batch/check/0)")
    r = session.get(f"{BASE}/api/v2/batch/check/0", timeout=30)
    if r.status_code != 200:
        print(f"Sync falhou (HTTP {r.status_code}): {r.text[:300]}")
        return

    sync = r.json()
    tasks = (sync.get("syncTaskBean") or {}).get("update") or []
    projects = sync.get("projectProfiles") or []
    print(f"  Tarefas carregadas: {len(tasks)}")
    print(f"  Projetos: {len(projects)}")

    sep("Assignees encontrados nas suas tarefas abertas")
    counter = Counter()
    assignors = Counter()
    for t in tasks:
        if not isinstance(t, dict):
            continue
        a = t.get("assignee")
        if a is not None and a != -1:
            counter[str(a)] += 1
        ag = t.get("assignor")
        if ag is not None and ag != -1:
            assignors[str(ag)] += 1

    if counter:
        print("  assignee -> quantas tarefas")
        for aid, count in counter.most_common():
            mark = "  <-- VOCE" if str(aid) == str(user_id) else ""
            print(f"    {aid}  ->  {count}{mark}")
    else:
        print("  Nenhuma tarefa aberta tem campo assignee preenchido.")

    if assignors:
        print()
        print("  assignor (quem delegou) -> quantas tarefas")
        for aid, count in assignors.most_common():
            print(f"    {aid}  ->  {count}")

    sep("Listas com mais de 1 usuario (provaveis compartilhadas)")
    shared = [p for p in projects if (p.get("userCount") or 1) > 1]
    if shared:
        for p in shared:
            print(f"  - {p.get('name')}  (id={p.get('id')}, userCount={p.get('userCount')})")
    else:
        print("  Nenhuma detectada via userCount (nao bloqueia).")


def main():
    email = os.environ.get("TICKTICK_EMAIL")
    password = os.environ.get("TICKTICK_PASSWORD")
    token = os.environ.get("TICKTICK_TOKEN")

    sep("Checagem das variaveis do .env")
    print(f"  TICKTICK_EMAIL    : {email or '(vazio)'}")
    print(f"  TICKTICK_PASSWORD : {fingerprint(password)}")
    print(f"  TICKTICK_TOKEN    : {fingerprint(token)}")

    session = requests.Session()
    session.headers.update(HEADERS)

    result = None
    if token and token.strip():
        result = login_with_token(session, token.strip())
    elif email and password:
        result = login_with_password(session, email, password)
    else:
        print("ERRO: preencha TICKTICK_EMAIL + TICKTICK_PASSWORD no .env, OU TICKTICK_TOKEN.")
        sys.exit(1)

    if not result:
        sys.exit(1)

    user_id, _token, data = result
    print("Autenticado OK.")

    sep("Dados basicos da sessao")
    for k, v in data.items():
        if k == "token":
            v = f"{str(v)[:12]}... (ocultado)"
        print(f"  {k}: {v}")

    fetch_tasks_and_summarize(session, user_id)

    sep("RESUMO")
    print(f"  Seu userId: {user_id}")
    print()
    print("Copie o userId acima e me envie.")


if __name__ == "__main__":
    main()
