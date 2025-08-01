#!/usr/bin/env python3

import os
import sys
import subprocess
import argparse
import ipaddress
import re
import signal

SNORT_LOG_PATH = "/var/log/snort"
SNORT_CONFIG_PATH = "/usr/local/etc/snort"
SNORT_LUA_PATH = "/usr/local/etc/snort/snort.lua"
LOCAL_RULES_PATH = "/usr/local/etc/snort/rules/local.rules"
SNORT_LOG_FILE = f"{SNORT_LOG_PATH}/snort_logs.log"


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


def create_systemd_service(net_interface, alert_type='alert_full'):
    """Gera e escreve o arquivo de serviço do systemd para o Snort."""
    print(f"--> Gerando arquivo de serviço com interface '{net_interface}' e alerta '{alert_type}'...")

    exec_commands = (
        f"echo '' >> {SNORT_LOG_FILE}; "
        f"echo '--- SNORT SERVICE (RE)STARTED AT $(date) ---' >> {SNORT_LOG_FILE}; "
        f"stdbuf -oL /usr/local/bin/snort -c {SNORT_LUA_PATH} -i {net_interface} -A {alert_type} >> {SNORT_LOG_FILE} 2>&1"
    )

    service_content = f"""
[Unit]
Description=Snort 3 IDS Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/sh -c "{exec_commands}"
ExecStop=/bin/pkill snort
Restart=on-failure

[Install]
WantedBy=multi-user.target
"""
    service_path = "/etc/systemd/system/snort.service"
    write_file_as_root(service_path, service_content.strip())
    
    print("--> Recarregando o daemon do systemd...")
    run_command(['sudo', 'systemctl', 'daemon-reload'], "Falha ao recarregar o systemd.")
    print("[SUCESSO] Arquivo de serviço do Snort atualizado.")

def change_alert_type(new_type):
    """Muda o tipo de alerta no arquivo de serviço e reinicia o Snort."""
    print(f"\n>>> Alterando tipo de alerta para: {new_type}")
    service_path = "/etc/systemd/system/snort.service"

    if not os.path.exists(service_path):
        print(f"[ERRO FATAL] O arquivo de serviço {service_path} não foi encontrado.")
        print("--> Execute a instalação com '--install' primeiro.")
        sys.exit(1)

    try:
        with open(service_path, 'r') as f:
            service_content = f.read()
        
        match = re.search(r'-i\s+([^\s]+)', service_content)
        if not match:
            print("[ERRO FATAL] Não foi possível encontrar a interface de rede (-i) no arquivo de serviço.")
            sys.exit(1)
        
        current_interface = match.group(1)
        print(f"--> Interface de rede atual encontrada: {current_interface}")

        create_systemd_service(net_interface=current_interface, alert_type=new_type)

        print("--> Verificando status do serviço Snort...")
        is_active = subprocess.run(['sudo', 'systemctl', 'is-active', '--quiet', 'snort']).returncode == 0
        
        if is_active:
            print("--> Serviço está ativo. Reiniciando para aplicar as alterações...")
            run_command(['sudo', 'systemctl', 'restart', 'snort'], "Falha ao reiniciar o serviço Snort.")
            print("[SUCESSO] Serviço Snort reiniciado com o novo tipo de alerta.")
        else:
            print("--> Serviço não está ativo. A nova configuração será usada na próxima inicialização.")

    except Exception as e:
        print(f"\n[ERRO FATAL] Ocorreu um erro ao tentar alterar o tipo de alerta: {e}")
        sys.exit(1)

def setup_command_path():
    """Torna o script um comando global do sistema (ex: 'easysnort')."""
    print("\n>>> PASSO 7: Instalando o comando global 'easysnort'...")
    
    command_name = "easysnort"
    command_path = "/usr/local/bin"
    
    try:
        script_path = os.path.abspath(__file__)
        destination_path = os.path.join(command_path, command_name)

        print(f"--> Copiando o script para {destination_path} para uma instalação permanente...")
        run_command(['sudo', 'cp', script_path, destination_path], f"Falha ao copiar o script para {command_path}.")

        print(f"--> Dando permissão de execução para o comando instalado...")
        run_command(['sudo', 'chmod', '+x', destination_path], f"Falha ao dar permissão de execução para {destination_path}.")
        
        print(f"[SUCESSO] Comando '{command_name}' instalado com sucesso!")
        print(f"--> Agora você pode usar o comando '{command_name}' de qualquer lugar.")
        print("--> O diretório original do script não é mais necessário para o funcionamento do comando.")

    except Exception as e:
        print(f"\n[AVISO] Não foi possível instalar o comando global: {e}")
        print(f"--> A instalação continuará, mas você terá que executar o script usando 'python3 {__file__}'.")

def show_logs():
    """Mostra os logs do Snort em tempo real usando 'tail -f'."""
    print(f"--> Mostrando logs de {SNORT_LOG_FILE}")
    print("--> Pressione Ctrl+C para sair.")
    
    if not os.path.exists(SNORT_LOG_FILE):
        print(f"\n[ERRO] O arquivo de log {SNORT_LOG_FILE} ainda não existe.")
        print("--> Inicie o serviço Snort primeiro com 'sudo systemctl start snort' para gerar o log.")
        sys.exit(1)
        
    command = ['sudo', 'tail', '-f', SNORT_LOG_FILE]
    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        if e.returncode == -signal.SIGINT:
            print("\n--> Parando de mostrar os logs...")
        else:
            print(f"\n[ERRO FATAL] Falha ao executar o tail: {e}")
            print("--> Verifique se você tem permissões de 'sudo' e se o 'tail' está instalado.")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n--> Parando de mostrar os logs...")
        sys.exit(0)

def start_service():
    """Inicia o serviço Snort via systemctl."""
    print("--> Iniciando o serviço Snort...")
    run_command(['sudo', 'systemctl', 'start', 'snort.service'], "Falha ao iniciar o serviço Snort.")
    print("[SUCESSO] Serviço Snort iniciado.")

def stop_service():
    """Para o serviço Snort via systemctl."""
    print("--> Parando o serviço Snort...")
    try:
        run_command(['sudo', 'systemctl', 'stop', 'snort.service'], "Falha ao parar o serviço.")
        print("[SUCESSO] Serviço Snort parado.")
    except subprocess.CalledProcessError:
        print("--> Aviso: O serviço Snort já estava parado ou não foi encontrado.")

def restart_service():
    """Reinicia o serviço Snort via systemctl."""
    print("--> Reiniciando o serviço Snort...")
    run_command(['sudo', 'systemctl', 'restart', 'snort.service'], "Falha ao reiniciar o serviço Snort.")
    print("[SUCESSO] Serviço Snort reiniciado.")

def status_service():
    """Mostra o status do serviço Snort via systemctl."""
    print("--> Verificando o status do serviço Snort...")
    try:
        subprocess.run(['sudo', 'systemctl', 'status', 'snort.service'])
    except FileNotFoundError:
        print("\n[ERRO FATAL] Comando 'systemctl' não encontrado.")

def uninstall_snort():
    """Remove completamente o Snort, suas configurações, usuários e serviços."""
    print("\n>>> INICIANDO DESINSTALAÇÃO COMPLETA DO SNORT <<<")
    print("\n[AVISO] Esta ação é DESTRUTIVA e removerá:")
    print("  - O serviço Snort (systemd)")
    print("  - O comando 'easysnort'")
    print("  - Todas as configurações, regras e logs do Snort")
    print("  - O usuário e grupo 'snort'")
    
    confirm = input("\n--> Para confirmar, digite 'SIM' em maiúsculas: ")
    if confirm != "SIM":
        print("\n[CANCELADO] A desinstalação foi cancelada.")
        sys.exit(0)

    print("\n--> Parando e desabilitando o serviço Snort...")
    try:
        run_command(['sudo', 'systemctl', 'stop', 'snort.service'], "Falha ao parar o serviço.")
        run_command(['sudo', 'systemctl', 'disable', 'snort.service'], "Falha ao desabilitar o serviço.")
    except subprocess.CalledProcessError:
        print("--> Aviso: O serviço Snort não foi encontrado ou já estava parado. Continuando a desinstalação.")

    files_to_remove = [
        "/etc/systemd/system/snort.service",
        "/usr/local/bin/easysnort"
    ]
    dirs_to_remove = [
        SNORT_LOG_PATH,
        SNORT_CONFIG_PATH,
        '/usr/local/lib/snort_dynamicrules'
    ]

    print("\n--> Removendo arquivos e diretórios do sistema...")
    for f in files_to_remove:
        if os.path.exists(f):
            run_command(['sudo', 'rm', f], f"Falha ao remover o arquivo {f}.")
    
    for d in dirs_to_remove:
        if os.path.exists(d):
            run_command(['sudo', 'rm', '-rf', d], f"Falha ao remover o diretório {d}.")

    print("\n--> Removendo usuário e grupo 'snort'...")
    try:
        if subprocess.run("id -u snort > /dev/null 2>&1", shell=True).returncode == 0:
            run_command(['sudo', 'userdel', '-r', 'snort'], "Falha ao remover o usuário snort.")
    except Exception: pass 

    try:
        if subprocess.run("getent group snort > /dev/null 2>&1", shell=True).returncode == 0:
            run_command(['sudo', 'groupdel', 'snort'], "Falha ao remover o grupo snort.")
    except Exception: pass
    
    print("\n[SUCESSO] Desinstalação concluída.")

def show_help(parser):
    """Exibe a ajuda e algumas dicas de uso."""
    parser.print_help()
    print("\nExemplos de uso:")
    print("  sudo easysnort --install          # Instalação completa do zero.")
    print("  sudo easysnort --uninstall        # Remoção completa do Snort.")
    print("  sudo easysnort --start            # Inicia o serviço Snort.")
    print("  sudo easysnort --stop             # Para o serviço Snort.")
    print("  sudo easysnort --restart          # Reinicia o serviço Snort.")
    print("  sudo easysnort --status           # Mostra o status do serviço.")
    print("  sudo easysnort --logs             # Ver logs em tempo real.")
    print("  sudo easysnort --alert-type fast  # Mudar tipo de alerta para 'fast'.")

def main():
    """Função principal que gerencia os argumentos da linha de comando."""
    parser = argparse.ArgumentParser(
    description="--- EasySnort - Instalador e Gerenciador do Snort 3 ---",
    usage=argparse.SUPPRESS,
    formatter_class=argparse.RawTextHelpFormatter,
    add_help=False
    )
    
    group = parser.add_argument_group('Ações de Instalação')
    group.add_argument('--install', action='store_true', help='Executa a instalação completa do Snort 3.')
    group.add_argument('--uninstall', action='store_true', help='Remove COMPLETAMENTE o Snort, seus arquivos e configurações.')

    mgmt_group = parser.add_argument_group('Comandos de Gerenciamento')
    mgmt_group.add_argument('--start', action='store_true', help='Inicia o serviço Snort.')
    mgmt_group.add_argument('--stop', action='store_true', help='Para o serviço Snort.')
    mgmt_group.add_argument('--restart', action='store_true', help='Reinicia o serviço Snort.')
    mgmt_group.add_argument('--status', action='store_true', help='Mostra o status detalhado do serviço Snort.')
    mgmt_group.add_argument('--logs', action='store_true', help='Mostra os logs do Snort em tempo real (use Ctrl+C para sair).')
    mgmt_group.add_argument('--alert-type', type=str, metavar='TYPE', help='Muda o tipo de alerta (ex: alert_full) e reinicia o serviço.')
    
    parser.add_argument('-h', '--help', action='store_true', help='Mostra esta mensagem de ajuda e sai.')

    args = parser.parse_args()

    if args.help or len(sys.argv) == 1:
        show_help(parser)
    elif args.install:
        print("--- INICIANDO INSTALADOR NÃO OFICIAL DO SNORT ---")
        install_dependencies()
        work_dir = download_sources()
        compile_and_install(work_dir)
        setup_snort_environment()
        deploy_lua_and_rules()
        print("\n>>> PASSO 6: Configurando o serviço systemd...")
        net_interface = input("--> Digite o nome da interface de rede que o Snort deve monitorar (ex: enp0s3, eth0): ")
        create_systemd_service(net_interface)
        setup_command_path()
        print("\n--- INSTALAÇÃO CONCLUÍDA! ---")
        print(f"--> O log principal do Snort será salvo em: {SNORT_LOG_FILE}")
        print("\nUse 'sudo easysnort --start' para iniciar o monitoramento.")
    elif args.uninstall:
        uninstall_snort()
    elif args.start:
        start_service()
    elif args.stop:
        stop_service()
    elif args.restart:
        restart_service()
    elif args.status:
        status_service()
    elif args.logs:
        show_logs()
    elif args.alert_type:
        change_alert_type(args.alert_type)
    else:
        show_help(parser)

if __name__ == "__main__":
    main()
