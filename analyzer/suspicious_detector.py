"""
suspicious_detector.py
----------------------
Módulo de detecção de atividades suspeitas nos eventos do Windows.

Detecta padrões como:
  - Possíveis ataques de brute force (muitas falhas num curto intervalo)
  - Criação e exclusão de contas de usuário (eventos 4720 e 4726)
"""

from datetime import datetime, timedelta
from collections import defaultdict
from analyzer.event_reader import parse_event_time


# ── Configurações de detecção ─────────────────────────────────────────────────

# Número mínimo de falhas para considerar brute force
BRUTE_FORCE_THRESHOLD = 5

# Janela de tempo (em minutos) para análise de brute force
BRUTE_FORCE_WINDOW_MINUTES = 5

# Índices em StringInserts para eventos de gerenciamento de usuários
USER_MGMT_FIELDS = {
    4720: {
        "new_username": 0,    # Nome do novo usuário criado
        "new_domain": 1,      # Domínio
        "actor_username": 4,  # Quem criou
        "actor_domain": 5,    # Domínio de quem criou
    },
    4726: {
        "deleted_username": 0,  # Nome do usuário deletado
        "deleted_domain": 1,    # Domínio
        "actor_username": 4,    # Quem deletou
        "actor_domain": 5,      # Domínio de quem deletou
    },
}


def _safe_get(string_inserts: tuple | None, index: int) -> str:
    """Obtém campo de StringInserts com segurança."""
    if string_inserts and len(string_inserts) > index:
        value = string_inserts[index]
        return str(value).strip() if value else "-"
    return "-"


def detect_brute_force(failures_by_user: dict) -> list[dict]:
    """
    Detecta possíveis ataques de brute force baseado em falhas de login.

    Algoritmo: Para cada usuário, verifica se há N ou mais falhas
    dentro de uma janela deslizante de X minutos.

    Args:
        failures_by_user (dict): {username: [datetime, ...]}
                                 Gerado pelo login_analyzer.

    Returns:
        list[dict]: Lista de alertas, cada um contendo:
            - username (str)
            - failed_attempts (int)
            - window_minutes (int)
            - first_attempt (datetime)
            - last_attempt (datetime)
    """
    alerts = []
    window = timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)

    for username, timestamps in failures_by_user.items():
        if len(timestamps) < BRUTE_FORCE_THRESHOLD:
            continue  # Usuário com poucas falhas — sem suspeita

        # Ordena os timestamps para análise de janela deslizante
        sorted_times = sorted(timestamps)
        max_count = 0
        best_window_start = None
        best_window_end = None

        # Janela deslizante: para cada ponto inicial, conta quantas
        # falhas ocorreram dentro da janela de tempo
        for i, start_time in enumerate(sorted_times):
            end_time = start_time + window
            count_in_window = sum(
                1 for t in sorted_times[i:] if t <= end_time
            )

            if count_in_window > max_count:
                max_count = count_in_window
                best_window_start = start_time
                best_window_end = end_time

        # Verifica se o pico ultrapassou o threshold
        if max_count >= BRUTE_FORCE_THRESHOLD:
            alerts.append({
                "username": username,
                "failed_attempts": max_count,
                "window_minutes": BRUTE_FORCE_WINDOW_MINUTES,
                "first_attempt": best_window_start,
                "last_attempt": best_window_end,
                "total_failures": len(timestamps),
            })

    # Ordena pelos mais críticos (mais tentativas primeiro)
    return sorted(alerts, key=lambda x: x["failed_attempts"], reverse=True)


def detect_user_management_events(events: list[dict]) -> dict:
    """
    Detecta eventos de criação e exclusão de contas de usuário.

    Args:
        events (list[dict]): Lista completa de eventos lidos.

    Returns:
        dict:
            - created_users (list[dict]): Usuários criados.
            - deleted_users (list[dict]): Usuários deletados.
    """
    created_users = []
    deleted_users = []

    for event in events:
        eid = event["event_id"]
        inserts = event.get("string_inserts")
        time_str = event.get("time_generated", "")

        # ── Novo usuário criado (4720) ────────────────────────────────
        if eid == 4720:
            new_user = _safe_get(inserts, USER_MGMT_FIELDS[4720]["new_username"])
            actor = _safe_get(inserts, USER_MGMT_FIELDS[4720]["actor_username"])
            created_users.append({
                "username": new_user,
                "created_by": actor,
                "time": time_str,
            })

        # ── Usuário deletado (4726) ───────────────────────────────────
        elif eid == 4726:
            deleted_user = _safe_get(inserts, USER_MGMT_FIELDS[4726]["deleted_username"])
            actor = _safe_get(inserts, USER_MGMT_FIELDS[4726]["actor_username"])
            deleted_users.append({
                "username": deleted_user,
                "deleted_by": actor,
                "time": time_str,
            })

    return {
        "created_users": created_users,
        "deleted_users": deleted_users,
    }


def calculate_risk_score(
    brute_force_alerts: list[dict],
    user_mgmt: dict,
    failed_logins: int,
) -> tuple[int, str]:
    """
    Calcula um score de risco geral baseado nos eventos detectados.

    Args:
        brute_force_alerts: Alertas de brute force.
        user_mgmt: Dicionário de criação/exclusão de usuários.
        failed_logins: Total de falhas de login.

    Returns:
        tuple[int, str]: (score de 0-100, nível de risco)
    """
    score = 0

    # Pontuação por brute force
    score += min(len(brute_force_alerts) * 20, 50)

    # Pontuação por falhas de login em geral
    if failed_logins > 100:
        score += 20
    elif failed_logins > 50:
        score += 10
    elif failed_logins > 20:
        score += 5

    # Pontuação por criação/exclusão de usuários
    score += len(user_mgmt.get("created_users", [])) * 5
    score += len(user_mgmt.get("deleted_users", [])) * 10

    score = min(score, 100)  # Cap em 100

    # Determina o nível textual
    if score >= 70:
        level = "CRITICAL 🔴"
    elif score >= 40:
        level = "HIGH 🟠"
    elif score >= 20:
        level = "MEDIUM 🟡"
    else:
        level = "LOW 🟢"

    return score, level
