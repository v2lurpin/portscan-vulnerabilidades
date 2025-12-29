# Network Vulnerability Scanner

A multi-threaded network reconnaissance tool written in Python. This utility performs port scanning, DNS resolution, service banner grabbing, and basic vulnerability identification based on common risk signatures.

Designed for network administrators and security auditors to quickly assess the exposure of target hosts.

## Features

- **Multi-threaded Architecture:** Utilizes `concurrent.futures` for high-performance parallel scanning.
- **Service Enumeration:** Captures service banners (HEAD requests) to identify running applications.
- **Risk Assessment:** Automatic detection of potential vulnerabilities based on open ports (e.g., cleartext protocols, known exploit vectors).
- **Smart DNS Resolution:** Validates targets and resolves hostnames to IP addresses.
- **Reporting:** Exports scan results to structured JSON files for further analysis.
- **Interactive CLI:** User-friendly interface for configuration (Target, Port Range, Threads, Timeout).

## Prerequisites

- **OS:** Windows, Linux, or macOS.
- **Python:** Version 3.10, 3.11, or 3.12.
- **Network:** Active internet connection to the target host.

## Installation

1. Clone the repository:
   ```bash
   git clone [https://github.com/nytstalk/port-scanner-python.git](https://github.com/nytstalk/port-scanner-python.git)
   cd port-scanner-python
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Option 1: GUI Version (Recommended)
For a modern visual experience with dark mode and interactive controls:

```bash
python portscan_gui.py

### Option 2: CLI Version (Server/Terminal)
For headless servers or quick command-line usage:
```bash
python portscan.py

The application will prompt for the following configurations:
1.  **Target:** Enter the IP address or Hostname (e.g., `scanme.nmap.org`).
2.  **Ports:** Define the range (e.g., `20-100`, `80,443`) or press Enter for the default range (1-1024).
3.  **Threads:** Define the concurrency level (default: 100).
4.  **Timeout:** Socket connection timeout in seconds (default: 1.0).

### Output
If open ports are detected, a report file will be generated in the root directory with the format:
`scan_<TARGET_IP>.json`

## Disclaimer

This tool is intended for **educational purposes and authorized security auditing only**. The author is not responsible for any misuse or damage caused by this program. Scanning networks without permission is illegal in many jurisdictions. Always obtain explicit authorization before scanning any target.

---

# Scanner de Vulnerabilidades de Rede (PT-BR)

Ferramenta de reconhecimento de rede multi-thread desenvolvida em Python. O utilitário executa varredura de portas, resolução de DNS, captura de banner de serviços e identificação básica de vulnerabilidades baseada em assinaturas de risco conhecidas.

Projetado para administradores de rede e auditores de segurança para a avaliação rápida de exposição de hosts.

## Funcionalidades

- **Arquitetura Multi-thread:** Utiliza `concurrent.futures` para varreduras paralelas de alta performance.
- **Enumeração de Serviços:** Captura banners de serviço (requisições HEAD) para identificar aplicações em execução.
- **Avaliação de Risco:** Detecção automática de vulnerabilidades potenciais baseada em portas abertas (ex: protocolos de texto claro, vetores de exploit conhecidos).
- **Resolução DNS Inteligente:** Valida alvos e resolve hostnames para endereços IP.
- **Relatórios:** Exporta os resultados da varredura para arquivos JSON estruturados.
- **CLI Interativa:** Interface amigável para configuração (Alvo, Range de Portas, Threads, Timeout).

## Pré-requisitos

- **SO:** Windows, Linux ou macOS.
- **Python:** Versão 3.10, 3.11 ou 3.12.
- **Rede:** Conexão ativa com o host alvo.

## Instalação

1. Clone o repositório:
   ```bash
   git clone [https://github.com/nytstalk/port-scanner-python.git](https://github.com/nytstalk/port-scanner-python.git)
   cd port-scanner-python
   ```

2. Instale as dependências necessárias:
   ```bash
   pip install -r requirements.txt
   ```

## Utilização

### Opção 1: Versão GUI Version (Recomendada)
Para uma experiência visual moderna com dark mode e controles interativos:
Execute o script diretamente via terminal:
```bash
python portscan_gui.py

### Opção 2: Versão CLI (Server/Terminal)
Para servidores sem interface gráfica ou uso rápido pela linha de comando:
```bash
python portscan.py
```

O sistema solicitará as seguintes configurações:
1.  **Alvo:** Digite o IP ou Hostname (ex: `scanme.nmap.org`).
2.  **Portas:** Defina o intervalo (ex: `20-100`, `80,443`) ou pressione Enter para o padrão (1-1024).
3.  **Threads:** Defina o nível de concorrência (padrão: 100).
4.  **Timeout:** Tempo limite de conexão do socket em segundos (padrão: 1.0).

### Resultados
Se portas abertas forem detectadas, um arquivo de relatório será gerado no diretório raiz com o formato:
`scan_<IP_DO_ALVO>.json`

## Aviso Legal

Esta ferramenta destina-se apenas a **fins educacionais e auditorias de segurança autorizadas**. O autor não se responsabiliza por qualquer uso indevido ou danos causados por este programa. A varredura de redes sem permissão é ilegal em muitas jurisdições. Obtenha sempre autorização explícita antes de escanear qualquer alvo.