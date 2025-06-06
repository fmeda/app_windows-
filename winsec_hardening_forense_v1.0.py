"""
Windows Security Toolkit v1.0

Script modular para hardening, análise de segurança e coleta forense básica em ambientes Windows 10/11.
Segue padrões PEP8, PEP257, PEP484 e boas práticas de segurança ofensiva e defensiva.
"""

import argparse
import os
import subprocess
import datetime
import logging
import shutil
import hashlib
import json
from typing import List, Tuple

# Configurações de log
logging.basicConfig(
    filename="security_toolkit.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

EXPORT_DIR = os.path.join(os.getcwd(), f"evidencias_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}")
os.makedirs(EXPORT_DIR, exist_ok=True)


def verificar_admin() -> bool:
    """Verifica se o script está sendo executado como administrador."""
    try:
        return os.getuid() == 0
    except AttributeError:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0


def executar_comando(cmd: str) -> str:
    """Executa comando via subprocess e retorna saída."""
    try:
        resultado = subprocess.check_output(cmd, shell=True, text=True)
        return resultado.strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"Erro ao executar comando: {cmd} - {e}")
        return ""


def desabilitar_servicos_perigosos() -> None:
    """Desativa serviços perigosos no Windows."""
    comandos = [
        "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
        "Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient"
    ]
    for cmd in comandos:
        executar_comando(f"powershell -Command \"{cmd}\"")
        logging.info(f"Comando executado: {cmd}")


def ativar_defender_agressivo() -> None:
    """Ativa o Windows Defender com configurações agressivas."""
    comandos = [
        "Set-MpPreference -PUAProtection 1",
        "Set-MpPreference -DisableRealtimeMonitoring 0",
        "Set-MpPreference -DisableBehaviorMonitoring 0",
        "Set-MpPreference -SignatureUpdateInterval 1"
    ]
    for cmd in comandos:
        executar_comando(f"powershell -Command \"{cmd}\"")
        logging.info(f"Comando executado: {cmd}")


def criar_ponto_restauração() -> None:
    """Cria ponto de restauração do sistema."""
    script = "Checkpoint-Computer -Description 'HardeningPoint' -RestorePointType 'MODIFY_SETTINGS'"
    executar_comando(f"powershell -Command \"{script}\"")


def aplicar_politicas_senha() -> None:
    """Define política de senha mínima e bloqueio por tentativas."""
    comandos = [
        "net accounts /minpwlen:12 /maxpwage:30",
        "net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30"
    ]
    for cmd in comandos:
        executar_comando(cmd)


def verificar_contas_adm_ocultas() -> List[str]:
    """Verifica contas administrativas ocultas."""
    saida = executar_comando("net user")
    contas = [l for l in saida.splitlines() if l.strip() and 'Conta convidado' not in l]
    ocultas = [c for c in contas if 'true' in executar_comando(f"net user {c} | findstr Ativo")]
    return ocultas


def listar_compartilhamentos() -> List[str]:
    """Lista compartilhamentos abertos."""
    saida = executar_comando("net share")
    return saida.splitlines()[4:]


def listar_logins_recentes() -> str:
    """Lista logins recentes e falhas."""
    return executar_comando("wevtutil qe Security /q:\"*[System[EventID=4624 or EventID=4625]]\" /f:text /c:10")


def verificar_permissoes_ntfs(pasta: str) -> str:
    """Verifica permissões NTFS em pastas sensíveis."""
    return executar_comando(f"icacls \"{pasta}\"")


def gerar_hash_arquivo(caminho: str) -> str:
    """Gera hash SHA256 de um arquivo."""
    h = hashlib.sha256()
    with open(caminho, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def exportar_dados(nome: str, conteudo: str) -> None:
    """Exporta conteúdo para arquivo no diretório de evidências."""
    caminho = os.path.join(EXPORT_DIR, f"{nome}.txt")
    with open(caminho, 'w', encoding='utf-8') as f:
        f.write(conteudo)
    logging.info(f"Exportado: {caminho}")


def coletar_evidencias() -> None:
    """Coleta evidências básicas de segurança."""
    exportar_dados("processos", executar_comando("tasklist"))
    exportar_dados("conexoes", executar_comando("powershell Get-NetTCPConnection"))
    exportar_dados("eventos", executar_comando("wevtutil qe System /f:text /c:20"))

    for pasta in ["C:\\Windows", "C:\\Program Files"]:
        resultado = verificar_permissoes_ntfs(pasta)
        exportar_dados(f"permissoes_{os.path.basename(pasta)}", resultado)

    for arquivo in ["C:\\Windows\\System32\\cmd.exe"]:
        hash_val = gerar_hash_arquivo(arquivo)
        exportar_dados(f"hash_{os.path.basename(arquivo)}", hash_val)


def gerar_relatorio_html() -> None:
    """Gera um relatório HTML simples com sumário de riscos."""
    html = "<html><head><title>Relatório de Risco</title></head><body><h1>Resumo de Segurança</h1><ul>"
    html += f"<li>Contas ocultas: {verificar_contas_adm_ocultas()}</li>"
    html += f"<li>Compartilhamentos: {listar_compartilhamentos()}</li>"
    html += f"<li>Últimos logins: {listar_logins_recentes()}</li>"
    html += "</ul></body></html>"
    with open(os.path.join(EXPORT_DIR, "relatorio.html"), 'w', encoding='utf-8') as f:
        f.write(html)


if __name__ == '__main__':
    if not verificar_admin():
        print("[!] Execute este script como administrador.")
        exit(1)

    parser = argparse.ArgumentParser(description="Toolkit de Segurança para Windows")
    parser.add_argument("--hardening", action="store_true", help="Executa hardening básico")
    parser.add_argument("--analise", action="store_true", help="Executa análise de segurança")
    parser.add_argument("--forense", action="store_true", help="Coleta evidências forenses")

    args = parser.parse_args()

    if args.hardening:
        criar_ponto_restauração()
        desabilitar_servicos_perigosos()
        ativar_defender_agressivo()
        aplicar_politicas_senha()

    if args.analise:
        exportar_dados("contas_ocultas", str(verificar_contas_adm_ocultas()))
        exportar_dados("compartilhamentos", "\n".join(listar_compartilhamentos()))
        exportar_dados("logins", listar_logins_recentes())
        gerar_relatorio_html()

    if args.forense:
        coletar_evidencias()

    print(f"[+] Operações concluídas. Evidências exportadas para: {EXPORT_DIR}")
