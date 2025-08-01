#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import argparse
import ipaddress
import re

APP_NAME = "easysnort"
VERSION = "2.0"
SNORT_LOG_PATH = "/var/log/snort"
SNORT_CONFIG_PATH = "/usr/local/etc/snort"
SNORT_LUA_PATH = "/usr/local/etc/snort/snort.lua"
LOCAL_RULES_PATH = "/usr/local/etc/snort/rules/local.rules"
SNORT_LOG_FILE = f"{SNORT_LOG_PATH}/snort_logs.log"
SYSTEMD_SERVICE_PATH = "/etc/systemd/system/snort.service"
GLOBAL_LINK_PATH = f"/usr/local/bin/{APP_NAME}"

class CustomHelpFormatter(argparse.RawTextHelpFormatter):
    def __init__(self, prog, indent_increment=2, max_help_position=35, width=None):
        super().__init__(prog, indent_increment, max_help_position, width)

def run_command(command, error_message, capture=False):
    try:
        if capture:
            return subprocess.run(command, check=True, shell=False, text=True, capture_output=True)
        else:
            subprocess.run(command, check=True, shell=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        print(f"\n[ERRO FATAL] {error_message}: {e}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"\n[ERRO FATAL] Comando '{command[0]}' não encontrado.")
        sys.exit(1)

def run_command_verbose(command, error_message):
    try:
        subprocess.run(command, check=True, shell=False)
    except subprocess.CalledProcessError as e:
        print(f"\n[ERRO FATAL] {error_message}: {e}")
        sys.exit(1)

def write_file_as_root(filepath, content):
    command = ["sudo", "tee", filepath]
    try:
        subprocess.run(command, input=content, text=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        print(f"\n[ERRO FATAL] Falha ao escrever o arquivo {filepath}: {e}")
        sys.exit(1)

def read_file_as_root(filepath):
    if not os.path.exists(filepath):
        print(f"[ERRO FATAL] Arquivo de configuração não encontrado em: {filepath}")
        print("O Snort foi instalado por este script?")
        sys.exit(1)
    result = run_command(["sudo", "cat", filepath], f"Falha ao ler o arquivo {filepath}", capture=True)
    return result.stdout

def confirm_action(prompt):
    response = input(f"--> {prompt} (s/N): ").lower().strip()
    return response == 's'


def install_dependencies():
    print(">>> PASSO 1: Instalando dependências do sistema...")
    dependencies = [
        'build-essential', 'cmake', 'make', 'gcc', 'g++', 'git', 'wget',
        'libpcre3-dev', 'libdumbnet-dev', 'bison', 'flex', 'zlib1g-dev',
        'liblzma-dev', 'openssl', 'libssl-dev', 'libnghttp2-dev', 'libdnet-dev',
        'autoconf', 'libtool', 'libpcap-dev', 'libhwloc-dev',
        'libluajit-5.1-dev', 'luajit', 'pkg-config', 'libmnl-dev',
        'libunwind-dev', 'libdaq-dev', 'libpcre2-dev'
    ]
    print("--> Atualizando a lista de pacotes (pode pedir a senha)...")
    run_command_verbose(["sudo", "apt-get", "update"], "Falha ao atualizar o apt.")
    print(f"--> Instalando {len(dependencies)} pacotes...")
    run_command_verbose(["sudo", "apt-get", "install", "-y"] + dependencies, "Falha ao instalar dependências.")
    print("[SUCESSO] Dependências instaladas.")

def download_sources():
    print("\n>>> PASSO 2: Baixando códigos-fonte...")
    work_dir = os.path.expanduser("~/snort_src")
    if not os.path.exists(work_dir):
        os.makedirs(work_dir)
    os.chdir(work_dir)
    print(f"--> Trabalhando no diretório: {work_dir}")
    if not os.path.exists(os.path.join(work_dir, "libdaq")):
        print("--> Clonando libdaq...")
        run_command_verbose(['git', 'clone', 'https://github.com/snort3/libdaq.git'], "Falha ao clonar o repositório do libdaq.")
    else:
        print("--> Diretório libdaq já existe. Pulando download.")
    if not os.path.exists(os.path.join(work_dir, "snort3")):
        print("--> Clonando snort3...")
        run_command_verbose(['git', 'clone', 'https://github.com/snort3/snort3.git'], "Falha ao clonar o repositório do snort3.")
    else:
        print("--> Diretório snort3 já existe. Pulando download.")
    print("[SUCESSO] Códigos-fonte prontos.")
    return work_dir

def compile_and_install(work_dir):
    print("\n>>> PASSO 3: Compilando e instalando...")
    cpu_cores = str(os.cpu_count())
    print("--> Compilando e instalando libdaq...")
    daq_path = os.path.join(work_dir, "libdaq")
    try:
        os.chdir(daq_path)
        run_command_verbose(['./bootstrap'], "Falha ao executar ./bootstrap do DAQ.")
        run_command_verbose(['./configure'], "Falha ao configurar o DAQ.")
        run_command_verbose(['make', '-j', cpu_cores], "Falha ao compilar o DAQ.")
        run_command_verbose(['sudo', 'make', 'install'], "Falha ao instalar o DAQ.")
    finally:
        os.chdir(work_dir)
    print("\n--> Compilando e instalando snort3...")
    snort_path = os.path.join(work_dir, "snort3")
    try:
        os.chdir(snort_path)
        run_command_verbose(['./configure_cmake.sh', '--prefix=/usr/local'], "Falha ao executar o configure_cmake.sh do Snort.")
        build_path = os.path.join(snort_path, "build")
        os.chdir(build_path)
        run_command_verbose(['make', '-j', cpu_cores], "Falha ao compilar o Snort.")
        run_command_verbose(['sudo', 'make', 'install'], "Falha ao instalar o Snort.")
    finally:
        os.chdir(work_dir)
    print("\n--> Atualizando os links de bibliotecas dinâmicas...")
    run_command_verbose(['sudo', 'ldconfig'], "Falha ao executar ldconfig.")
    print("[SUCESSO] DAQ e Snort compilados e instalados.")

def setup_snort_environment():
    print("\n>>> PASSO 4: Configurando ambiente do Snort...")
    print("--> Criando grupo 'snort' (se não existir)...")
    try:
        subprocess.run("getent group snort &> /dev/null", check=True, shell=True)
    except subprocess.CalledProcessError:
        run_command_verbose(['sudo', 'groupadd', 'snort'], "Falha ao criar o grupo snort.")
    print("--> Criando usuário 'snort' (se não existir)...")
    try:
        subprocess.run("id -u snort &> /dev/null", check=True, shell=True)
    except subprocess.CalledProcessError:
        run_command_verbose(['sudo', 'useradd', '-r', '-g', 'snort', '-s', '/usr/sbin/nologin', '-c', 'Snort IDS', 'snort'], "Falha ao criar o usuário snort.")
    print("--> Criando diretórios para o Snort...")
    snort_dirs = [SNORT_CONFIG_PATH, f"{SNORT_CONFIG_PATH}/rules", SNORT_LOG_PATH, '/usr/local/lib/snort_dynamicrules']
    for d in snort_dirs:
        run_command_verbose(['sudo', 'mkdir', '-p', d], f"Falha ao criar o diretório {d}.")
    print("--> Acertando permissões dos diretórios...")
    for d in snort_dirs:
        run_command_verbose(['sudo', 'chown', '-R', 'snort:snort', d], f"Falha ao dar permissão (chown) para {d}.")
    print("--> Criando arquivos de regras vazios...")
    rule_files = [LOCAL_RULES_PATH, f"{SNORT_CONFIG_PATH}/rules/white_list.rules", f"{SNORT_CONFIG_PATH}/rules/black_list.rules"]
    for f in rule_files:
        if not os.path.exists(f):
            run_command_verbose(['sudo', 'touch', f], f"Falha ao criar o arquivo vazio {f}.")
            run_command_verbose(['sudo', 'chown', 'snort:snort', f], f"Falha ao dar permissão (chown) para {f}.")
    print("[SUCESSO] Ambiente do Snort configurado.")

def deploy_lua_and_rules():
    print("\n>>> PASSO 5: Implantando arquivos de configuração...")
    local_rules_content = 'alert icmp any any -> any any (msg:"ICMP test detected"; sid:1000002; rev:1;)'
    snort_lua_template = """
HOME_NET = 'HOME_NET_PLACEHOLDER'
EXTERNAL_NET = 'any'
include 'snort_defaults.lua'
ips = { enable_builtin_rules = true, rules = [[ include rules/local.rules ]], }
outputs = {}
"""
    print("--> Por favor, configure sua rede local (HOME_NET).")
    while True:
        home_net_input = input("    Digite o endereço da sua rede no formato CIDR (ex: 192.168.1.0/24): ")
        try:
            ipaddress.ip_network(home_net_input, strict=False)
            break
        except ValueError:
            print("    [ERRO] Formato inválido! Tente novamente.")
    final_snort_lua = snort_lua_template.replace('HOME_NET_PLACEHOLDER', home_net_input)
    write_file_as_root(SNORT_LUA_PATH, final_snort_lua)
    write_file_as_root(LOCAL_RULES_PATH, local_rules_content)
    run_command_verbose(['sudo', 'chown', '-R', 'snort:snort', SNORT_CONFIG_PATH], f"Falha ao dar permissão para {SNORT_CONFIG_PATH}.")
    print("[SUCESSO] Arquivos de configuração implantados.")

def create_systemd_service():
    print("\n>>> PASSO 6: Criando o serviço systemd...")
    net_interface = input("--> Digite o nome da interface de rede que o Snort deve monitorar (ex: enp0s3, eth0): ")
    service_content = f"""
[Unit]
Description=Snort 3 IDS Service
After=network.target
[Service]
Type=simple
ExecStart=/bin/sh -c '/usr/local/bin/snort -c {SNORT_LUA_PATH} -i {net_interface} -A alert_full > {SNORT_LOG_FILE} 2>&1'
ExecStop=/bin/pkill snort
Restart=on-failure
[Install]
WantedBy=multi-user.target
"""
    write_file_as_root(SYSTEMD_SERVICE_PATH, service_content.strip())
    print("--> Recarregando o daemon do systemd...")
    run_command_verbose(['sudo', 'systemctl', 'daemon-reload'], "Falha ao recarregar o systemd.")
    print("[SUCESSO] Serviço systemd criado.")

def finalize_installation():
    print("\n>>> PASSO 7: Finalizando e tornando o comando acessível...")
    script_path = os.path.abspath(sys.argv[0])
    if os.path.lexists(GLOBAL_LINK_PATH):
        run_command_verbose(['sudo', 'rm', GLOBAL_LINK_PATH], "Falha ao remover o link antigo.")
    run_command_verbose(['sudo', 'ln', '-s', script_path, GLOBAL_LINK_PATH], "Falha ao criar o link simbólico.")
    print("\n[SUCESSO] Ferramenta instalada!")
    print("-----------------------------------------------------------------")
    print("IMPORTANTE: Para que o comando funcione, você precisa:")
    print("1. Abrir um NOVO terminal, ou")
    print("2. Executar o comando: hash -r")
    print(f"\nDepois disso, use 'sudo {APP_NAME} --help' para ver todos os comandos.")
    print("-----------------------------------------------------------------")

def uninstall_snort():
    print("--- INICIANDO DESINSTALAÇÃO DO SNORT ---")
    if not confirm_action("Você tem certeza que deseja continuar?"):
        sys.exit(0)
    print("--> Parando e desabilitando o serviço systemd...")
    run_command_verbose(['sudo', 'systemctl', 'stop', 'snort'], "Falha ao parar o serviço.")
    run_command_verbose(['sudo', 'systemctl', 'disable', 'snort'], "Falha ao desabilitar o serviço.")
    if os.path.exists(SYSTEMD_SERVICE_PATH):
        run_command_verbose(['sudo', 'rm', SYSTEMD_SERVICE_PATH], "Falha ao remover o arquivo de serviço.")
    run_command_verbose(['sudo', 'systemctl', 'daemon-reload'], "Falha ao recarregar o systemd.")
    if confirm_action("Remover PERMANENTEMENTE todos os arquivos de configuração e regras?"):
        run_command_verbose(['sudo', 'rm', '-rf', SNORT_CONFIG_PATH], "Falha ao remover configurações.")
    if confirm_action("Remover PERMANENTEMENTE todos os arquivos de log?"):
        run_command_verbose(['sudo', 'rm', '-rf', SNORT_LOG_PATH], "Falha ao remover logs.")
    if confirm_action("Remover o usuário e grupo 'snort' do sistema?"):
        try:
            run_command_verbose(['sudo', 'userdel', 'snort'], "Falha ao remover usuário.")
        except: pass
        try:
            run_command_verbose(['sudo', 'groupdel', 'snort'], "Falha ao remover grupo.")
        except: pass
    if os.path.lexists(GLOBAL_LINK_PATH):
        run_command_verbose(['sudo', 'rm', GLOBAL_LINK_PATH], "Falha ao remover o link simbólico.")
    print("\n[AVISO] Os binários e bibliotecas em /usr/local não foram removidos.")
    print("[SUCESSO] Desinstalação concluída.")

def systemctl_wrapper(action):
    run_command_verbose(['sudo', 'systemctl', action, 'snort'], f"Falha ao executar {action} no serviço.")

def view_logs():
    print(f"--> Mostrando logs em tempo real de: {SNORT_LOG_FILE}")
    print("    (Pressione Ctrl+C para sair)")
    try:
        p = subprocess.Popen(['sudo', 'tail', '-f', SNORT_LOG_FILE])
        p.wait()
    except KeyboardInterrupt:
        print("\n--> Encerrando visualização de logs.")

def set_homenet(new_net):
    try:
        ipaddress.ip_network(new_net, strict=False)
    except ValueError:
        print(f"[ERRO] Formato de rede inválido: '{new_net}'. Use o formato CIDR (ex: 192.168.1.0/24).")
        sys.exit(1)
    
    content = read_file_as_root(SNORT_LUA_PATH)
    current_net = re.search(r"HOME_NET\s*=\s*'(.*)'", content).group(1)
    print(f"--> O HOME_NET atual é: {current_net}")
    print(f"--> Alterando para: {new_net}")
    new_content = re.sub(r"HOME_NET\s*=\s*'.*'", f"HOME_NET = '{new_net}'", content)
    write_file_as_root(SNORT_LUA_PATH, new_content)
    print("[SUCESSO] HOME_NET atualizado.")
    if confirm_action("Deseja reiniciar o Snort agora para aplicar as alterações?"):
        systemctl_wrapper('restart')

def set_alert_type(new_type):
    if not new_type:
        print("[ERRO] Nenhum tipo de alerta fornecido.")
        return
    content = read_file_as_root(SYSTEMD_SERVICE_PATH)
    current_type = re.search(r"-A\s+(\w+)", content).group(1)
    print(f"--> O tipo de alerta atual é: {current_type}")
    print(f"--> Alterando para: {new_type}")
    new_content = re.sub(r"-A\s+\w+", f"-A {new_type}", content)
    write_file_as_root(SYSTEMD_SERVICE_PATH, new_content)
    run_command_verbose(['sudo', 'systemctl', 'daemon-reload'], "Falha ao recarregar o systemd.")
    print("[SUCESSO] Tipo de alerta atualizado.")
    if confirm_action("Deseja reiniciar o Snort agora para aplicar as alterações?"):
        systemctl_wrapper('restart')

def show_paths():
    print("--- Caminhos Principais do Snort ---")
    print(f"  Configuração Principal: {SNORT_LUA_PATH}")
    print(f"  Diretório de Regras:    {SNORT_CONFIG_PATH}/rules/")
    print(f"  Arquivo de Regras Locais: {LOCAL_RULES_PATH}")
    print(f"  Diretório de Logs:      {SNORT_LOG_PATH}/")
    print(f"  Arquivo de Log Principal: {SNORT_LOG_FILE}")
    print(f"  Serviço Systemd:        {SYSTEMD_SERVICE_PATH}")

def show_version():
    print(f"{APP_NAME.capitalize()} version {VERSION}")

def main():
    parser = argparse.ArgumentParser(
        description=f"Instalador e Gerenciador Não Oficial do Snort 3 - {APP_NAME.capitalize()}",
        formatter_class=CustomHelpFormatter,
        usage=argparse.SUPPRESS
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-v', '--version', action='store_true', help='Mostra a versão do programa.')
    group.add_argument('--install', action='store_true', help='Executa a instalação completa do Snort do zero.')
    group.add_argument('--uninstall', action='store_true', help='Executa a desinstalação do Snort.')
    group.add_argument('--start', action='store_true', help='Inicia o serviço do Snort via systemd.')
    group.add_argument('--stop', action='store_true', help='Para o serviço do Snort via systemd.')
    group.add_argument('--restart', action='store_true', help='Reinicia o serviço do Snort via systemd.')
    group.add_argument('--status', action='store_true', help='Mostra o status do serviço do Snort.')
    group.add_argument('--view-logs', action='store_true', help='Mostra os logs de alerta em tempo real.')
    group.add_argument('--set-homenet', type=str, metavar='[CIDR]', help='Define o HOME_NET (ex: 192.168.1.0/24).')
    group.add_argument('--set-alert-type', type=str, metavar='[TYPE]', help='Define o tipo de alerta (ex: alert_fast).')
    group.add_argument('--path', action='store_true', help='Mostra os caminhos principais dos arquivos do Snort.')
    
    args = parser.parse_args()

    if args.install:
        print(f"--- INICIANDO INSTALAÇÃO COMPLETA - {APP_NAME.capitalize()} ---")
        install_dependencies()
        work_dir = download_sources()
        compile_and_install(work_dir)
        setup_snort_environment()
        deploy_lua_and_rules()
        create_systemd_service()
        finalize_installation()
        print("\n--- INSTALAÇÃO CONCLUÍDA! ---")
    elif args.uninstall:
        uninstall_snort()
    elif args.start:
        systemctl_wrapper('start')
    elif args.stop:
        systemctl_wrapper('stop')
    elif args.restart:
        systemctl_wrapper('restart')
    elif args.status:
        systemctl_wrapper('status')
    elif args.view_logs:
        view_logs()
    elif args.set_homenet:
        set_homenet(args.set_homenet)
    elif args.set_alert_type:
        set_alert_type(args.set_alert_type)
    elif args.path:
        show_paths()
    elif args.version:
        show_version()

if __name__ == "__main__":
    needs_sudo = not any(arg in sys.argv for arg in ['--help', '-h', '--version', '-v'])
    if needs_sudo and os.geteuid() != 0:
        print("[ERRO] Este script precisa ser executado com privilégios de root (use sudo).")
        sys.exit(1)
    main()
