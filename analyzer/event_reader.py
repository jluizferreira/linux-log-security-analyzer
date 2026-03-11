"""
event_reader.py
---------------
Módulo responsável por ler e parsear eventos de autenticação
do Linux a partir dos arquivos de log do sistema.

Arquivos suportados:
  - /var/log/auth.log      → Ubuntu, Debian, Kali
  - /var/log/secure        → CentOS, RHEL, Fedora
  - /var/log/auth.log.1    → Rotação de logs (dia anterior)

Os eventos são normalizados para o mesmo formato usado pelo
módulo original do Windows, garantindo compatibilidade com
os módulos de análise.
"""

import re
import os
import gzip
from datetime import datetime
from pathlib import Path


# Arquivos de log procurados em ordem de prioridade
LOG_CANDIDATES = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/auth.log.1",
    "/var/log/auth.log.2.gz",
]

# Equivalência entre eventos Linux e Event IDs do Windows
EVENT_ID_MAP = {
    "successful_login": 4624,
    "failed_login":     4625,
    "user_created":     4720,
    "user_deleted":     4726,
}

# Padrões regex para identificar cada tipo de evento no auth.log
PATTERNS = {
    # Login bem-sucedido via SSH: "Accepted password/publickey for USER from IP"
    4624: re.compile(
        r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*"
        r"Accepted (?:password|publickey) for (?P<username>\S+) from (?P<source_ip>\S+)"
    ),
    # Falha de login SSH: "Failed password for USER from IP"
    # Também captura: "Invalid user USER from IP"
    4625: re.compile(
        r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*"
        r"(?:Failed password for(?: invalid user)?|Invalid user) (?P<username>\S+) from (?P<source_ip>\S+)"
    ),
    # Novo usuário criado: "new user: name=USER"
    4720: re.compile(
        r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*"
        r"new user: name=(?P<username>\S+)"
    ),
    # Usuário deletado: "delete user 'USER'"
    4726: re.compile(
        r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*"
        r"delete user '?(?P<username>[^']+)'?"
    ),
}

# Mapeamento de mês abreviado para número
MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _find_log_file() -> str | None:
    """
    Detecta automaticamente o arquivo de log disponível no sistema.

    Returns:
        str | None: Caminho do arquivo encontrado ou None.
    """
    for path in LOG_CANDIDATES:
        if os.path.exists(path):
            return path
    return None


def _parse_log_time(month: str, day: str, time_str: str) -> str:
    """
    Converte os campos de data/hora do auth.log para o formato
    padrão usado pelo restante do projeto (MM/DD/YYYY HH:MM:SS).

    O auth.log não inclui o ano, então usa o ano atual.
    """
    try:
        month_num = MONTH_MAP.get(month, 1)
        year = datetime.now().year
        dt = datetime.strptime(
            f"{year}/{month_num:02d}/{int(day):02d} {time_str}",
            "%Y/%m/%d %H:%M:%S"
        )
        return dt.strftime("%m/%d/%Y %H:%M:%S")
    except ValueError:
        return datetime.now().strftime("%m/%d/%Y %H:%M:%S")


def _open_log(path: str):
    """Abre o arquivo de log (suporta .gz comprimido)."""
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="ignore")
    return open(path, "r", encoding="utf-8", errors="ignore")


def read_security_events(max_events: int = 5000, log_path: str | None = None) -> list[dict]:
    """
    Lê e normaliza eventos de segurança do log de autenticação Linux.

    Args:
        max_events (int): Número máximo de eventos a processar.
        log_path (str | None): Caminho customizado do log.
                               Se None, detecta automaticamente.

    Returns:
        list[dict]: Lista de eventos normalizados com os campos:
            - event_id (int): ID equivalente ao Windows Event ID
            - time_generated (str): Data/hora no formato MM/DD/YYYY HH:MM:SS
            - source_name (str): Nome da fonte (ex: sshd, useradd)
            - event_category (str): Descrição legível do evento
            - string_inserts (tuple): Campos extraídos (username, source_ip, ...)
    """
    path = log_path or _find_log_file()

    if not path:
        print("[ERROR] Nenhum arquivo de log encontrado.")
        print("        Tentei: " + ", ".join(LOG_CANDIDATES))
        return []

    if not os.access(path, os.R_OK):
        print(f"[ERROR] Sem permissão para ler: {path}")
        print("        Execute com: sudo python main.py")
        return []

    events = []
    total_lines = 0

    category_map = {
        4624: "Successful Login",
        4625: "Failed Login",
        4720: "User Account Created",
        4726: "User Account Deleted",
    }

    try:
        with _open_log(path) as f:
            for line in f:
                if total_lines >= max_events * 10:
                    break
                total_lines += 1

                for event_id, pattern in PATTERNS.items():
                    match = pattern.search(line)
                    if not match:
                        continue

                    groups = match.groupdict()
                    time_str = _parse_log_time(
                        groups.get("month", "Jan"),
                        groups.get("day", "1"),
                        groups.get("time", "00:00:00"),
                    )
                    username   = groups.get("username", "-")
                    source_ip  = groups.get("source_ip", "-")

                    # Normaliza string_inserts no mesmo formato esperado
                    # pelos módulos login_analyzer e suspicious_detector
                    inserts = ["-"] * 20
                    inserts[5] = username
                    if event_id == 4624:
                        inserts[18] = source_ip
                    elif event_id == 4625:
                        inserts[9]  = "Wrong password or invalid user"
                        inserts[19] = source_ip
                    elif event_id in (4720, 4726):
                        inserts[0] = username
                        inserts[4] = "system"

                    events.append({
                        "event_id":       event_id,
                        "time_generated": time_str,
                        "source_name":    "auth.log",
                        "event_category": category_map[event_id],
                        "string_inserts": tuple(inserts),
                    })

                    if len(events) >= max_events:
                        return events
                    break  # Cada linha casa com no máximo 1 padrão

    except PermissionError:
        print(f"[ERROR] Permissão negada: {path}")
        print("        Execute com: sudo python main.py")
    except Exception as e:
        print(f"[ERROR] Erro ao ler {path}: {e}")

    return events


def get_event_summary(events: list[dict]) -> dict:
    """
    Gera um resumo rápido da quantidade de eventos por tipo.

    Args:
        events (list[dict]): Lista de eventos lidos.

    Returns:
        dict: Contagem de eventos por event_id.
    """
    summary = {}
    for event in events:
        eid = event["event_id"]
        summary[eid] = summary.get(eid, 0) + 1
    return summary


def parse_event_time(time_str: str) -> datetime | None:
    """
    Converte a string de tempo para um objeto datetime.

    Args:
        time_str (str): Data/hora no formato MM/DD/YYYY HH:MM:SS

    Returns:
        datetime | None
    """
    try:
        return datetime.strptime(time_str, "%m/%d/%Y %H:%M:%S")
    except ValueError:
        return None
