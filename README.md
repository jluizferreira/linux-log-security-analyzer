# 🛡️ Linux Log Security Analyzer

[![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?logo=linux&logoColor=black)](https://www.linux.org/)
[![Security](https://img.shields.io/badge/Focus-Security%20Analysis-red?logo=shield)](.)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

> Ferramenta em Python para análise de logs de autenticação do Linux.  
> Detecta padrões suspeitos como brute force SSH, criação de usuários e falhas de autenticação.  
> Lê diretamente o `/var/log/auth.log` (Ubuntu/Debian) ou `/var/log/secure` (CentOS/RHEL).

---

## 📋 Índice

- [Sobre o Projeto](#-sobre-o-projeto)
- [Funcionalidades](#-funcionalidades)
- [Estrutura do Projeto](#-estrutura-do-projeto)
- [Pré-requisitos](#-pré-requisitos)
- [Instalação](#-instalação)
- [Como Executar](#-como-executar)
- [Modo Demonstração](#-modo-demonstração)
- [Exemplos de Saída](#-exemplos-de-saída)
- [Distribuições Suportadas](#-distribuições-suportadas)
- [Tecnologias](#-tecnologias)
- [Autor](#-autor)

---

## 🎯 Sobre o Projeto

O **Linux Log Security Analyzer** é uma ferramenta de linha de comando desenvolvida em Python que lê eventos reais do arquivo de log de autenticação do Linux (`/var/log/auth.log` ou `/var/log/secure`) e os analisa em busca de atividades potencialmente maliciosas.

O projeto foi desenvolvido como parte de um portfólio profissional em **Segurança da Informação**, demonstrando habilidades em:

- Parse de arquivos de log do sistema Linux com regex
- Análise e correlação de eventos de autenticação SSH
- Detecção de padrões de ataque (brute force)
- Organização de código em módulos Python
- **Zero dependências externas** — usa apenas a biblioteca padrão do Python

---

## ✨ Funcionalidades

| Funcionalidade | Descrição |
|---|---|
| 📥 Leitura de eventos | Lê e parseia o auth.log em tempo real |
| 🔐 Análise de logins SSH | Conta logins bem-sucedidos e falhados por usuário |
| 🚨 Detecção de Brute Force | Identifica muitas falhas SSH num curto intervalo de tempo |
| 👤 Gestão de usuários | Detecta criação e exclusão de contas via useradd/userdel |
| 📊 Score de risco | Calcula um índice de risco geral (0–100) |
| 📋 Relatório no terminal | Exibe relatório formatado no console |
| 🎭 Modo Demo | Simula cenários de ataque sem precisar de sudo |
| 📦 Zero dependências | Funciona com Python puro, sem pip install |

---

## 📁 Estrutura do Projeto

```
linux-log-security-analyzer/
│
├── analyzer/
│   ├── __init__.py            # Exportações do pacote
│   ├── event_reader.py        # Parse do /var/log/auth.log com regex
│   ├── login_analyzer.py      # Análise de logins bem-sucedidos e falhados
│   ├── suspicious_detector.py # Detecção de brute force e gestão de usuários
│   └── demo_generator.py      # Gerador de eventos simulados (modo --demo)
│
├── main.py                    # Ponto de entrada — orquestra a análise
├── requirements.txt           # Sem dependências externas
└── README.md                  # Este arquivo
```

---

## 📦 Pré-requisitos

- **Sistema Operacional:** Linux (Ubuntu, Debian, Kali, CentOS, RHEL, Fedora)
- **Python:** 3.12 ou superior
- **Permissões:** `sudo` para acessar `/var/log/auth.log` ou `/var/log/secure`

Verificar versão do Python:
```bash
python3 --version
```

---

## 🚀 Instalação

### 1. Clone o repositório

```bash
git clone https://github.com/seu-usuario/linux-log-security-analyzer.git
cd linux-log-security-analyzer
```

### 2. (Opcional) Crie um ambiente virtual

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Instale as dependências

```bash
pip install -r requirements.txt
```

> ✅ Nenhuma dependência externa necessária. O projeto usa apenas a biblioteca padrão do Python 3.12.

---

## ▶️ Como Executar

> **Importante:** Use `sudo` para acessar os logs do sistema.

### Execução padrão

```bash
sudo python3 main.py
```

### Limitar o número de eventos processados

```bash
sudo python3 main.py --max-events 1000
```

### Especificar um arquivo de log customizado

```bash
sudo python3 main.py --log /var/log/auth.log
sudo python3 main.py --log /var/log/secure
```

### Ver ajuda

```bash
python3 main.py --help
```

---

## 🎭 Modo Demonstração

Não requer `sudo` e funciona em qualquer máquina.  
Simula um cenário realista de ataque SSH com eventos fictícios.

```bash
python3 main.py --demo
```

> 💡 **Para desativar o modo demo** e analisar seu sistema real, basta executar `sudo python3 main.py` sem a flag `--demo`.  
> Lembre-se de usar **sudo** para acessar os logs do sistema.

### Cenários simulados

| Cenário | Detalhes |
|---|---|
| Logins normais | 5 usuários com 10–25 logins SSH bem-sucedidos |
| Falhas esporádicas | `joao.silva` errou a senha 3x antes de conseguir |
| **Brute force #1** | 14 tentativas contra `root` em 3 min (IP: `203.0.113.47`) |
| **Brute force #2** | 8 tentativas contra `ubuntu` em 2 min (IP: `198.51.100.23`) |
| Usuário suspeito criado | `hacker_temp01` criado às 03h da manhã |
| Usuário deletado | `carlos.santos` deletado por `root` |

---

## 🖥️ Exemplos de Saída

### Saída real (sistema saudável)

```
╔══════════════════════════════════════════════════════════════╗
║        Linux Log Security Analyzer  v1.0                    ║
║        Detecção de atividades suspeitas via auth.log         ║
╚══════════════════════════════════════════════════════════════╝

  Análise iniciada em: 11/03/2026 01:34:31

  [*] Lendo até 5000 eventos do auth.log...
  [✓] 125 eventos relevantes carregados.

────────────────────────────────────────────────────────────────
  📊  RESUMO GERAL
────────────────────────────────────────────────────────────────
  Total de eventos relevantes lidos : 125
  Logins bem-sucedidos (SSH OK)     : 125
  Falhas de login (SSH FAIL)        : 0
  Usuários criados                  : 0
  Usuários deletados                : 0

  🎯  SCORE DE RISCO GERAL: [░░░░░░░░░░░░░░░░░░░░] 0/100
  Nível de risco: LOW 🟢
```

### Saída do modo demo (ataque simulado)

```
  ╔══════════════════════════════════════════════════════════════╗
  ║   ⚠️   MODO DEMONSTRAÇÃO ATIVO  —  DADOS SIMULADOS   ⚠️     ║
  ╚══════════════════════════════════════════════════════════════╝

────────────────────────────────────────────────────────────────
  📊  RESUMO GERAL
────────────────────────────────────────────────────────────────
  Total de eventos relevantes lidos : 138
  Logins bem-sucedidos (SSH OK)     : 97
  Falhas de login (SSH FAIL)        : 38
  Usuários criados                  : 1
  Usuários deletados                : 1

────────────────────────────────────────────────────────────────
  🚨  ALERTAS DE POSSÍVEL BRUTE FORCE SSH
────────────────────────────────────────────────────────────────

  ┌─────────────────────────────────────────────────────┐
  │                  [ALERT] BRUTE FORCE                │
  ├─────────────────────────────────────────────────────┤
  │  Usuário          : root                            │
  │  Tentativas falhas: 14                              │
  │  Janela de tempo  : 5 minutos                       │
  │  Total de falhas  : 14                              │
  └─────────────────────────────────────────────────────┘

  🎯  SCORE DE RISCO GERAL: [████████████████░░░░] 75/100
  Nível de risco: CRITICAL 🔴
```

---

## 🐧 Distribuições Suportadas

| Distro | Arquivo de log |
|---|---|
| Ubuntu / Debian / Kali | `/var/log/auth.log` |
| CentOS / RHEL / Fedora | `/var/log/secure` |
| Arch Linux | `/var/log/auth.log` |

O programa detecta automaticamente qual arquivo está disponível.  
Você também pode especificar manualmente com `--log /caminho/do/arquivo`.

---

## 🛠️ Tecnologias

| Tecnologia | Uso |
|---|---|
| **Python 3.12** | Linguagem principal |
| **re** | Parse de logs com expressões regulares |
| **pathlib** | Manipulação de caminhos de arquivo |
| **gzip** | Leitura de logs comprimidos (.gz) |
| **collections** | Estruturas de dados para análise |
| **datetime** | Manipulação de janelas de tempo |
| **argparse** | Interface de linha de comando |

---

## 🔒 Permissões Necessárias

```bash
# Verificar se tem acesso ao log
ls -la /var/log/auth.log

# Executar com sudo
sudo python3 main.py

# Ou adicionar seu usuário ao grupo adm (Ubuntu/Debian)
sudo usermod -aG adm $USER
# (requer logout e login para aplicar)
```

---

## 👤 Autor

**Jefferson Ferreira**  
[![LinkedIn](https://img.shields.io/badge/LinkedIn-seu--perfil-blue?logo=linkedin)](https://www.linkedin.com/in/jefferson-ferreira-ti/)
[![GitHub](https://img.shields.io/badge/GitHub-seu--usuario-black?logo=github)](https://github.com/jluizferreira)

---

## 📄 Licença

Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.
