"""
demo_generator.py
-----------------
Gerador de eventos simulados para o modo demonstração no Linux.

Cria um conjunto realista de eventos de autenticação fictícios
que cobrem todos os cenários detectáveis pela ferramenta:
  - Logins SSH normais bem-sucedidos
  - Falhas de login esporádicas
  - Ataque de brute force SSH em andamento
  - Criação e exclusão de contas suspeitas

Nenhum arquivo real do sistema é lido neste modo.
"""

from datetime import datetime, timedelta
import random


def generate_demo_events() -> list[dict]:
    """
    Gera uma lista de eventos de segurança Linux simulados.

    Cenários incluídos:
        1. Logins SSH normais de usuários do dia a dia
        2. Algumas falhas esporádicas (usuário errou a senha)
        3. Ataque de brute force SSH contra 'root' (IP externo)
        4. Ataque de brute force SSH contra 'ubuntu' (outro IP)
        5. Criação de usuário suspeito às 03h da manhã
        6. Exclusão de um usuário

    Returns:
        list[dict]: Lista de eventos no mesmo formato retornado
                    por event_reader.read_security_events().
    """
    events = []
    now = datetime.now()

    # ── Helpers internos ──────────────────────────────────────────────

    def fmt(dt: datetime) -> str:
        return dt.strftime("%m/%d/%Y %H:%M:%S")

    def make_inserts(username: str, source_ip: str = "-", event_id: int = 4624) -> tuple:
        inserts = ["-"] * 20
        inserts[5] = username
        if event_id == 4624:
            inserts[18] = source_ip
        elif event_id == 4625:
            inserts[9]  = "Wrong password or invalid user"
            inserts[19] = source_ip
        elif event_id in (4720, 4726):
            inserts[0] = username
            inserts[4] = "root"
        return tuple(inserts)

    def login_ok(username: str, delta_minutes: int = 0, ip: str = "192.168.1.10") -> dict:
        t = now - timedelta(minutes=delta_minutes)
        return {
            "event_id":       4624,
            "time_generated": fmt(t),
            "source_name":    "auth.log",
            "event_category": "Successful Login",
            "string_inserts": make_inserts(username, ip, 4624),
        }

    def login_fail(username: str, delta_minutes: int = 0, ip: str = "192.168.1.50") -> dict:
        t = now - timedelta(minutes=delta_minutes)
        return {
            "event_id":       4625,
            "time_generated": fmt(t),
            "source_name":    "auth.log",
            "event_category": "Failed Login",
            "string_inserts": make_inserts(username, ip, 4625),
        }

    def user_created(username: str, delta_minutes: int = 0) -> dict:
        t = now - timedelta(minutes=delta_minutes)
        return {
            "event_id":       4720,
            "time_generated": fmt(t),
            "source_name":    "auth.log",
            "event_category": "User Account Created",
            "string_inserts": make_inserts(username, event_id=4720),
        }

    def user_deleted(username: str, delta_minutes: int = 0) -> dict:
        t = now - timedelta(minutes=delta_minutes)
        return {
            "event_id":       4726,
            "time_generated": fmt(t),
            "source_name":    "auth.log",
            "event_category": "User Account Deleted",
            "string_inserts": make_inserts(username, event_id=4726),
        }

    # ── Cenário 1: Logins SSH normais ─────────────────────────────────
    normal_users = [
        ("joao.silva",    "192.168.1.11"),
        ("maria.souza",   "192.168.1.22"),
        ("pedro.alves",   "192.168.1.33"),
        ("ana.lima",      "10.0.0.5"),
        ("carlos.santos", "10.0.0.8"),
    ]
    for user, ip in normal_users:
        for _ in range(random.randint(10, 25)):
            events.append(login_ok(user, delta_minutes=random.randint(0, 480), ip=ip))

    # ── Cenário 2: Falhas esporádicas (senha errada) ──────────────────
    events.append(login_fail("joao.silva",  delta_minutes=240, ip="192.168.1.11"))
    events.append(login_fail("joao.silva",  delta_minutes=239, ip="192.168.1.11"))
    events.append(login_fail("joao.silva",  delta_minutes=238, ip="192.168.1.11"))
    events.append(login_ok  ("joao.silva",  delta_minutes=237, ip="192.168.1.11"))

    events.append(login_fail("maria.souza", delta_minutes=300, ip="192.168.1.22"))
    events.append(login_ok  ("maria.souza", delta_minutes=299, ip="192.168.1.22"))

    # ── Cenário 3: Brute force SSH contra 'root' ──────────────────────
    # 14 tentativas em ~3 minutos vindo de IP externo
    bf_ip_root = "203.0.113.47"   # RFC 5737 — bloco reservado para exemplos
    for _ in range(14):
        events.append(login_fail("root", delta_minutes=60, ip=bf_ip_root))

    # ── Cenário 4: Brute force SSH contra 'ubuntu' ────────────────────
    # 8 tentativas em ~2 minutos vindo de outro IP externo
    bf_ip_ubuntu = "198.51.100.23"
    for _ in range(8):
        events.append(login_fail("ubuntu", delta_minutes=30, ip=bf_ip_ubuntu))

    # ── Cenário 5: Criação de usuário suspeito às 03h ─────────────────
    events.append(user_created("hacker_temp01", delta_minutes=420))

    # ── Cenário 6: Exclusão de usuário legítimo ───────────────────────
    events.append(user_deleted("carlos.santos", delta_minutes=15))

    # Embaralha para simular ordem real dos eventos no log
    random.shuffle(events)

    return events


def print_demo_notice():
    """Exibe aviso claro de que o modo demo está ativo."""
    notice = """
  ╔══════════════════════════════════════════════════════════════╗
  ║   ⚠️   MODO DEMONSTRAÇÃO ATIVO  —  DADOS SIMULADOS   ⚠️     ║
  ║                                                              ║
  ║  Os eventos abaixo são FICTÍCIOS e gerados localmente.       ║
  ║  Para analisar seu sistema real, execute sem --demo.         ║
  ╚══════════════════════════════════════════════════════════════╝
"""
    print(notice)
