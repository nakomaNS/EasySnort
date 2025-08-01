# EasySnort

![Licença](https://img.shields.io/badge/licen%C3%A7a-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.x-brightgreen.svg)
![Plataforma](https://img.shields.io/badge/plataforma-Linux-lightgrey.svg)

**EasySnort** é uma ferramenta de linha de comando para simplificar a instalação, o gerenciamento e a remoção do Snort 3 em sistemas baseados em Debian e Ubuntu.

---

### Pré-requisitos

* **Sistema:** Debian 11/12 ou Ubuntu 22.04/24.04 (ou derivados).
* **Acesso:** Privilégios de `root` ou um usuário com acesso `sudo`.

* **Pacotes Iniciais:** `git` e `python3` devem estar instalados.
```bash
sudo apt update && sudo apt install git python3 -y
```

---

### Instalação

```bash
# Clone o repositório
git clone https://github.com/nakomaNS/EasySnort

# Entre no diretório
cd EasySnort

# Dê permissão de execução ao script
chmod +x easysnort.py
```

**2. Execução da Instalação**

```bash
sudo ./easysnort.py --install
```
> **Nota:** Durante a execução, o script irá pausar para solicitar o **nome da interface de rede** (ex: `eth0, enp0s3 ou wlan0`) e o **endereço de sua rede local** em formato CIDR (ex: `192.168.1.0/24`).

---

### Comandos Disponíveis

Use os seguintes argumentos para gerenciar sua instalação do Snort.

**Caso deseje remover o EasySnort do seu sistema use o comando:**
* `sudo easysnort --uninstall`: Remove completamente o Snort, seus arquivos, logs e configurações.

**Controle do Serviço**
* `sudo easysnort --start`: Inicia o serviço do Snort.
* `sudo easysnort --stop`: Para o serviço do Snort.
* `sudo easysnort --restart`: Reinicia o serviço do Snort.
* `sudo easysnort --status`: Mostra o status detalhado do serviço.

**Gerenciamento de Logs**
* `sudo easysnort --logs`: Exibe os logs de alerta em tempo real. Pressione `Ctrl+C` para sair.
* `sudo easysnort --alert-type [TIPO]`: Muda o formato dos alertas (ex: `alert_full`, `alert_fast`) e reinicia o serviço para aplicar a mudança.

**Ajuda**
* `sudo easysnort -h`, `--help`: Mostra a mensagem de ajuda com todos os comandos.
