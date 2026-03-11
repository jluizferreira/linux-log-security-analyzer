"""
login_analyzer.py
-----------------
Módulo responsável por analisar eventos de login (4624 e 4625).

Extrai informações de usuários que realizaram logins bem-sucedidos
e falhados, gerando estatísticas para o relatório final.
"""

from collections import defaultdict
from datetime import datetime
from analyzer.event_reader import parse_event_time


# Índices dos campos em StringInserts para eventos 4624 e 4625
# (baseado na estrutura padrão do Windows Security Event Log)
FIELD_INDEX = {
    4624: {
        "username": 5,       # Target User Name
        "domain": 6,         # Target Domain Name
        "logon_type": 8,     # Logon Type
        "source_ip": 18,     # Source Network Address
    },
    4625: {
        "username": 5,       # Target User Name
        "domain": 6,         # Target Domain Name
        "logon_type": 10,    # Logon Type
        "source_ip": 19,     # Source Network Address
        "failure_reason": 9, # Failure Reason
    },
}


def _safe_get(string_inserts: tuple | None, index: int) -> str:
    """
    Obtém um campo de StringInserts com segurança.

    Args:
        string_inserts: Tupla de strings do evento.
        index (int): Índice do campo desejado.

    Returns:
        str: Valor do campo ou '-' se não disponível.
    """
    if string_inserts and len(string_inserts) > index:
        value = string_inserts[index]
        return str(value).strip() if value else "-"
    return "-"


def analyze_logins(events: list[dict]) -> dict:
    """
    Analisa eventos de login bem-sucedido (4624) e falhos (4625).

    Args:
        events (list[dict]): Lista de todos os eventos lidos.

    Returns:
        dict: Dicionário com os resultados da análise:
            - successful_logins (int): Total de logins bem-sucedidos.
            - failed_logins (int): Total de logins falhados.
            - success_by_user (dict): {username: count} de logins OK.
            - failures_by_user (dict): {username: [datetime, ...]} de falhas.
            - failure_details (list): Lista de detalhes de cada falha.
    """
    successful_logins = 0
    failed_logins = 0
    success_by_user = defaultdict(int)
    failures_by_user = defaultdict(list)  # username -> lista de datetimes
    failure_details = []

    for event in events:
        eid = event["event_id"]
        inserts = event.get("string_inserts")
        time_str = event.get("time_generated", "")
        event_time = parse_event_time(time_str)

        # ── Logins bem-sucedidos ──────────────────────────────────────
        if eid == 4624:
            username = _safe_get(inserts, FIELD_INDEX[4624]["username"])
            domain = _safe_get(inserts, FIELD_INDEX[4624]["domain"])

            # Ignora contas de sistema internas (SYSTEM, ANONYMOUS, etc.)
            if username in ("-", "SYSTEM", "ANONYMOUS LOGON", ""):
                continue

            successful_logins += 1
            success_by_user[username] += 1

        # ── Logins falhados ───────────────────────────────────────────
        elif eid == 4625:
            username = _safe_get(inserts, FIELD_INDEX[4625]["username"])
            domain = _safe_get(inserts, FIELD_INDEX[4625]["domain"])
            source_ip = _safe_get(inserts, FIELD_INDEX[4625]["source_ip"])
            failure_reason = _safe_get(inserts, FIELD_INDEX[4625]["failure_reason"])

            if username in ("-", ""):
                username = "Unknown"

            failed_logins += 1

            if event_time:
                failures_by_user[username].append(event_time)

            failure_details.append({
                "username": username,
                "domain": domain,
                "source_ip": source_ip,
                "failure_reason": failure_reason,
                "time": time_str,
            })

    return {
        "successful_logins": successful_logins,
        "failed_logins": failed_logins,
        "success_by_user": dict(success_by_user),
        "failures_by_user": dict(failures_by_user),
        "failure_details": failure_details,
    }


def get_top_failed_users(failures_by_user: dict, top_n: int = 5) -> list[tuple]:
    """
    Retorna os usuários com mais falhas de login.

    Args:
        failures_by_user (dict): {username: [datetime, ...]}
        top_n (int): Quantidade de usuários a retornar.

    Returns:
        list[tuple]: Lista de (username, count) ordenada por count desc.
    """
    counted = [(user, len(times)) for user, times in failures_by_user.items()]
    return sorted(counted, key=lambda x: x[1], reverse=True)[:top_n]
