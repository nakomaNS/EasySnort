#!/usr/bin/env python3

import os
import sys
import subprocess
import argparse
import ipaddress

SNORT_LOG_PATH = "/var/log/snort"
SNORT_CONFIG_PATH = "/usr/local/etc/snort"
SNORT_LUA_PATH = "/usr/local/etc/snort/snort.lua"
LOCAL_RULES_PATH = "/usr/local/etc/snort/rules/local.rules"


def run_command(command, error_message):
    try:
        subprocess.run(command, check=True, shell=False)
    except subprocess.CalledProcessError as e:
        print(f"\n[ERRO FATAL] {error_message}: {e}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"\n[ERRO FATAL] Comando '{command[0]}' não encontrado.")
        sys.exit(1)

def write_file_as_root(filepath, content):
    command = ["sudo", "tee", filepath]
    try:
        subprocess.run(command, input=content, text=True, check=True, stdout=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        print(f"\n[ERRO FATAL] Falha ao escrever o arquivo {filepath}: {e}")
        sys.exit(1)


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
    run_command(["sudo", "apt-get", "update"], "Falha ao atualizar o apt.")
    print(f"--> Instalando {len(dependencies)} pacotes...")
    run_command(["sudo", "apt-get", "install", "-y"] + dependencies, "Falha ao instalar dependências.")
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
        run_command(['git', 'clone', 'https://github.com/snort3/libdaq.git'], "Falha ao clonar o repositório do libdaq.")
    else:
        print("--> Diretório libdaq já existe. Pulando download.")
    if not os.path.exists(os.path.join(work_dir, "snort3")):
        print("--> Clonando snort3...")
        run_command(['git', 'clone', 'https://github.com/snort3/snort3.git'], "Falha ao clonar o repositório do snort3.")
    else:
        print("--> Diretório snort3 já existe. Pulando download.")
    print("[SUCESSO] Códigos-fonte prontos.")
    return work_dir


def compile_and_install(work_dir):
    """Compila e instala o DAQ e depois o Snort."""
    print("\n>>> PASSO 3: Compilando e instalando...")
    cpu_cores = str(os.cpu_count())
    
    print("--> Compilando e instalando libdaq...")
    daq_path = os.path.join(work_dir, "libdaq")
    try:
        os.chdir(daq_path)
        run_command(['./bootstrap'], "Falha ao executar ./bootstrap do DAQ.")
        run_command(['./configure'], "Falha ao configurar o DAQ.")
        run_command(['make', '-j', cpu_cores], "Falha ao compilar o DAQ.")
        run_command(['sudo', 'make', 'install'], "Falha ao instalar o DAQ.")
    finally:
        os.chdir(work_dir)

    print("\n--> Compilando e instalando snort3...")
    snort_path = os.path.join(work_dir, "snort3")
    try:
        os.chdir(snort_path)
        run_command(['./configure_cmake.sh', '--prefix=/usr/local'], "Falha ao executar o configure_cmake.sh do Snort.")
        build_path = os.path.join(snort_path, "build")
        os.chdir(build_path)
        run_command(['make', '-j', cpu_cores], "Falha ao compilar o Snort.")
        run_command(['sudo', 'make', 'install'], "Falha ao instalar o Snort.")
    finally:
        os.chdir(work_dir)

    print("\n--> Atualizando os links de bibliotecas dinâmicas...")
    run_command(['sudo', 'ldconfig'], "Falha ao executar ldconfig.")
    print("[SUCESSO] DAQ e Snort compilados e instalados.")


def setup_snort_environment():
    """Cria usuários, pastas, e acerta as permissões para o Snort."""
    print("\n>>> PASSO 4: Configurando ambiente do Snort...")
    
    print("--> Criando grupo 'snort' (se não existir)...")
    try:
        subprocess.run("getent group snort > /dev/null", check=True, shell=True)
        print("--> Grupo 'snort' já existe. Pulando.")
    except subprocess.CalledProcessError:
        run_command(['sudo', 'groupadd', 'snort'], "Falha ao criar o grupo snort.")

    print("--> Criando usuário 'snort' (se não existir)...")
    try:
        subprocess.run("id -u snort > /dev/null", check=True, shell=True)
        print("--> Usuário 'snort' já existe. Pulando.")
    except subprocess.CalledProcessError:
        run_command(['sudo', 'useradd', '-r', '-g', 'snort', '-s', '/usr/sbin/nologin', '-c', 'Snort IDS', 'snort'], "Falha ao criar o usuário snort.")
    
    print("--> Criando diretórios para o Snort...")
    snort_dirs = [
        SNORT_CONFIG_PATH,
        f"{SNORT_CONFIG_PATH}/rules",
        SNORT_LOG_PATH,
        '/usr/local/lib/snort_dynamicrules',
    ]
    for d in snort_dirs:
        run_command(['sudo', 'mkdir', '-p', d], f"Falha ao criar o diretório {d}.")

    print("--> Acertando permissões dos diretórios...")
    for d in snort_dirs:
        run_command(['sudo', 'chown', '-R', 'snort:snort', d], f"Falha ao dar permissão (chown) para {d}.")
        run_command(['sudo', 'chmod', '-R', '755', d], f"Falha ao dar permissão (chmod) para {d}.")
    
    print("--> Criando arquivos de regras vazios...")
    rule_files = [
        LOCAL_RULES_PATH,
        f"{SNORT_CONFIG_PATH}/rules/white_list.rules",
        f"{SNORT_CONFIG_PATH}/rules/black_list.rules"
    ]
    for f in rule_files:
        if not os.path.exists(f):
            run_command(['sudo', 'touch', f], f"Falha ao criar o arquivo vazio {f}.")
            run_command(['sudo', 'chown', 'snort:snort', f], f"Falha ao dar permissão (chown) para {f}.")

    print("[SUCESSO] Ambiente do Snort configurado.")


def deploy_lua_and_rules():
    print("\n>>> PASSO 5: Implantando arquivos de configuração...")
    local_rules_content = 'alert icmp any any -> any any (msg:"ICMP test detected"; sid:1000002; rev:1;)'
    snort_lua_template = """
-- Snort++ configuration
HOME_NET = 'HOME_NET_PLACEHOLDER'
EXTERNAL_NET = 'any'
include 'snort_defaults.lua'
ips =
{
    enable_builtin_rules = true,
    rules = [[
    include rules/local.rules
]],
}
outputs = {}
"""
    print("--> Por favor, configure sua rede local (HOME_NET).")
    while True:
        home_net_input = input("    Digite o endereço da sua rede no formato CIDR (ex: 192.168.1.0/24): ")
        try:
            ipaddress.ip_network(home_net_input, strict=False)
            print(f"    [INFO] Rede '{home_net_input}' validada com sucesso.")
            break
        except ValueError:
            print("    [ERRO] Formato inválido! O valor deve ser uma rede em notação CIDR. Tente novamente.")

    print("--> Configurando e salvando snort.lua...")
    final_snort_lua = snort_lua_template.replace('HOME_NET_PLACEHOLDER', home_net_input)
    write_file_as_root(SNORT_LUA_PATH, final_snort_lua)
    
    print("--> Criando local.rules...")
    write_file_as_root(LOCAL_RULES_PATH, local_rules_content)

    print("--> Acertando permissões dos arquivos de configuração...")
    run_command(['sudo', 'chown', '-R', 'snort:snort', SNORT_CONFIG_PATH], f"Falha ao dar permissão para {SNORT_CONFIG_PATH}.")
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
ExecStart=/bin/sh -c '/usr/local/bin/snort -c {SNORT_LUA_PATH} -i {net_interface} -A alert_full > {SNORT_LOG_PATH}/snort_logs.log 2>&1'
ExecStop=/bin/pkill snort
Restart=on-failure

[Install]
WantedBy=multi-user.target
"""
    service_path = "/etc/systemd/system/snort.service"
    print(f"--> Criando arquivo de serviço em {service_path}...")
    write_file_as_root(service_path, service_content.strip())
    
    print("--> Recarregando o daemon do systemd...")
    run_command(['sudo', 'systemctl', 'daemon-reload'], "Falha ao recarregar o systemd.")
    
    print("[SUCESSO] Serviço systemd criado.")
    print("\nPara gerenciar o serviço, use os comandos:")
    print("  sudo systemctl start snort")
    print("  sudo systemctl stop snort")
    print("  sudo systemctl status snort")
    print("  sudo systemctl enable snort  (para iniciar no boot)")


def main():
    """Função principal que gerencia os argumentos da linha de comando."""
    parser = argparse.ArgumentParser(
        description="Instalador e Gerenciador Não Oficial do Snort 3 para Servidores.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--install', action='store_true', help='Executa a instalação completa do Snort do zero.')
    args = parser.parse_args()
    if not args.install:
        parser.print_help(sys.stderr)
        sys.exit(1)

    if args.install:
        print("--- INICIANDO INSTALADOR NÃO OFICIAL DO SNORT ---")
        install_dependencies()
        work_dir = download_sources()
        compile_and_install(work_dir)
        setup_snort_environment()
        deploy_lua_and_rules()
        create_systemd_service()
        print("\n--- INSTALAÇÃO CONCLUÍDA! ---")
        print(f"--> O log principal do Snort será salvo em: {SNORT_LOG_PATH}/snort_logs.log")

if __name__ == "__main__":
    main()
