"""
main.py
-------
Linux Log Security Analyzer
=============================
Ponto de entrada do programa. Orquestra a leitura dos eventos,
análise e exibição do relatório de segurança no terminal.

Uso:
    sudo python main.py
    sudo python main.py --max-events 2000
    sudo python main.py --log /caminho/para/auth.log
         python main.py --demo
         python main.py --help

Requer sudo para acessar /var/log/auth.log ou /var/log/secure.
O modo --demo não requer permissões especiais.
"""

import sys
import argparse
from datetime import datetime

from analyzer.event_reader import read_security_events, get_event_summary
from analyzer.login_analyzer import analyze_logins, get_top_failed_users
from analyzer.suspicious_detector import (
    detect_brute_force,
    detect_user_management_events,
    calculate_risk_score,
)
from analyzer.demo_generator import generate_demo_events, print_demo_notice


# ── Constantes visuais ────────────────────────────────────────────────────────

BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║        Linux Log Security Analyzer  v1.0                    ║
║        Detecção de atividades suspeitas via auth.log         ║
╚══════════════════════════════════════════════════════════════╝
"""

SEPARATOR       = "─" * 64
SEPARATOR_THICK = "═" * 64


# ── Funções de exibição ───────────────────────────────────────────────────────

def print_banner():
    """Exibe o banner inicial do programa."""
    print(BANNER)
    print(f"  Análise iniciada em: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    print(f"  {SEPARATOR}\n")


def print_section(title: str):
    """Imprime um cabeçalho de seção formatado."""
    print(f"\n{SEPARATOR}")
    print(f"  {title}")
    print(SEPARATOR)


def print_summary(login_data: dict, event_summary: dict):
    """Exibe o resumo geral dos eventos analisados."""
    print_section("📊  RESUMO GERAL")
    total_events = sum(event_summary.values())
    print(f"  Total de eventos relevantes lidos : {total_events}")
    print(f"  Logins bem-sucedidos (SSH OK)     : {login_data['successful_logins']}")
    print(f"  Falhas de login (SSH FAIL)        : {login_data['failed_logins']}")
    print(f"  Usuários criados                  : {event_summary.get(4720, 0)}")
    print(f"  Usuários deletados                : {event_summary.get(4726, 0)}")


def print_top_failed_users(failures_by_user: dict):
    """Exibe os usuários com mais tentativas de login falhadas."""
    print_section("❌  TOP USUÁRIOS COM MAIS FALHAS DE LOGIN")

    top_users = get_top_failed_users(failures_by_user, top_n=10)

    if not top_users:
        print("  Nenhuma falha de login registrada.")
        return

    print(f"  {'Usuário':<30} {'Tentativas':>10}")
    print(f"  {'─' * 30} {'─' * 10}")

    for username, count in top_users:
        flag = " ⚠️" if count >= 10 else ""
        print(f"  {username:<30} {count:>10}{flag}")


def print_brute_force_alerts(alerts: list[dict]):
    """Exibe alertas de possível brute force SSH."""
    print_section("🚨  ALERTAS DE POSSÍVEL BRUTE FORCE SSH")

    if not alerts:
        print("  Nenhum padrão de brute force detectado.")
        return

    for alert in alerts:
        print()
        print("  ┌─────────────────────────────────────────────────────┐")
        print("  │                  [ALERT] BRUTE FORCE                │")
        print("  ├─────────────────────────────────────────────────────┤")
        print(f"  │  Usuário          : {alert['username']:<33}│")
        print(f"  │  Tentativas falhas: {alert['failed_attempts']:<33}│")
        print(f"  │  Janela de tempo  : {alert['window_minutes']} minutos{'':<26}│")

        if alert.get("first_attempt"):
            ts = alert["first_attempt"].strftime("%d/%m/%Y %H:%M:%S")
            print(f"  │  Início da janela : {ts:<33}│")
        if alert.get("last_attempt"):
            ts = alert["last_attempt"].strftime("%d/%m/%Y %H:%M:%S")
            print(f"  │  Fim da janela    : {ts:<33}│")

        print(f"  │  Total de falhas  : {alert['total_failures']:<33}│")
        print("  └─────────────────────────────────────────────────────┘")


def print_user_management(user_mgmt: dict):
    """Exibe eventos de criação e exclusão de usuários."""
    print_section("👤  CRIAÇÃO E EXCLUSÃO DE USUÁRIOS")

    created = user_mgmt.get("created_users", [])
    deleted = user_mgmt.get("deleted_users", [])

    if not created and not deleted:
        print("  Nenhum evento de criação/exclusão de usuário detectado.")
        return

    if created:
        print(f"\n  ✅ Usuários CRIADOS ({len(created)} evento(s)):")
        print(f"  {'Usuário':<25} {'Criado por':<25} {'Data/Hora'}")
        print(f"  {'─' * 25} {'─' * 25} {'─' * 20}")
        for u in created:
            print(f"  {u['username']:<25} {u['created_by']:<25} {u['time']}")

    if deleted:
        print(f"\n  🗑️  Usuários DELETADOS ({len(deleted)} evento(s)):")
        print(f"  {'Usuário':<25} {'Deletado por':<25} {'Data/Hora'}")
        print(f"  {'─' * 25} {'─' * 25} {'─' * 20}")
        for u in deleted:
            print(f"  {u['username']:<25} {u['deleted_by']:<25} {u['time']}")


def print_risk_score(score: int, level: str):
    """Exibe o score de risco calculado."""
    print_section("🎯  SCORE DE RISCO GERAL")
    bar_filled = int(score / 5)
    bar = "█" * bar_filled + "░" * (20 - bar_filled)
    print(f"\n  [{bar}] {score}/100")
    print(f"\n  Nível de risco: {level}")


def print_footer():
    """Exibe o rodapé do relatório."""
    print(f"\n  {SEPARATOR_THICK}")
    print(f"  Relatório concluído em: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    print(f"  {SEPARATOR_THICK}\n")


# ── Argumentos da linha de comando ────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    """Configura e processa os argumentos da linha de comando."""
    parser = argparse.ArgumentParser(
        description="Linux Log Security Analyzer — Analisa logs de autenticação do Linux.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  sudo python main.py
  sudo python main.py --max-events 1000
  sudo python main.py --log /var/log/auth.log
       python main.py --demo
        """,
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=5000,
        metavar="N",
        help="Número máximo de eventos a processar (default: 5000)",
    )
    parser.add_argument(
        "--log",
        type=str,
        default=None,
        metavar="PATH",
        help="Caminho customizado do arquivo de log (ex: /var/log/auth.log)",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Executa com eventos simulados (não requer sudo)",
    )
    return parser.parse_args()


# ── Ponto de entrada ──────────────────────────────────────────────────────────

def main():
    """Função principal que coordena toda a análise."""
    args = parse_args()

    print_banner()

    # ── Modo demonstração ─────────────────────────────────────────────
    if args.demo:
        print_demo_notice()
        print("  [*] Gerando eventos simulados de ataque SSH...")
        events = generate_demo_events()
        print(f"  [✓] {len(events)} eventos simulados gerados.\n")

    # ── Modo real: leitura do auth.log ────────────────────────────────
    else:
        print(f"  [*] Lendo até {args.max_events} eventos do auth.log...")
        events = read_security_events(
            max_events=args.max_events,
            log_path=args.log,
        )

        if not events:
            print("\n  [!] Nenhum evento relevante encontrado ou erro de acesso.")
            print("      Verifique se está executando com: sudo python main.py")
            print("      Dica: para testar sem sudo, use: python main.py --demo")
            sys.exit(1)

        print(f"  [✓] {len(events)} eventos relevantes carregados.\n")

    # ── Análise ───────────────────────────────────────────────────────
    print("  [*] Analisando eventos de login...")
    login_data = analyze_logins(events)

    event_summary = get_event_summary(events)

    print("  [*] Verificando padrões de brute force SSH...")
    brute_force_alerts = detect_brute_force(login_data["failures_by_user"])

    print("  [*] Verificando criação/exclusão de usuários...")
    user_mgmt = detect_user_management_events(events)

    score, level = calculate_risk_score(
        brute_force_alerts,
        user_mgmt,
        login_data["failed_logins"],
    )

    # ── Relatório ─────────────────────────────────────────────────────
    print_summary(login_data, event_summary)
    print_top_failed_users(login_data["failures_by_user"])
    print_brute_force_alerts(brute_force_alerts)
    print_user_management(user_mgmt)
    print_risk_score(score, level)
    print_footer()


if __name__ == "__main__":
    main()
