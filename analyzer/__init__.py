"""
analyzer/
---------
Pacote de análise de logs de segurança do Linux.

Módulos:
    event_reader        - Leitura e parse do /var/log/auth.log
    login_analyzer      - Análise de logins bem-sucedidos e falhados
    suspicious_detector - Detecção de brute force e gestão de usuários
    demo_generator      - Gerador de eventos simulados (modo --demo)
"""

from analyzer.event_reader import read_security_events, get_event_summary, parse_event_time
from analyzer.login_analyzer import analyze_logins, get_top_failed_users
from analyzer.suspicious_detector import (
    detect_brute_force,
    detect_user_management_events,
    calculate_risk_score,
)
from analyzer.demo_generator import generate_demo_events, print_demo_notice

__all__ = [
    "read_security_events",
    "get_event_summary",
    "parse_event_time",
    "analyze_logins",
    "get_top_failed_users",
    "detect_brute_force",
    "detect_user_management_events",
    "calculate_risk_score",
    "generate_demo_events",
    "print_demo_notice",
]
