# EasySnort

![Licença](https://img.shields.io/badge/licen%C3%A7a-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.x-brightgreen.svg)
![Plataforma](https://img.shields.io/badge/plataforma-Linux-lightgrey.svg)

**EasySnort** é uma ferramenta que automatiza a instalação completa do Snort 3 em sistemas Debian e Ubuntu. Ele transforma o processo complexo de compilação e configuração em um único comando interativo.

---

### Pré-requisitos

* **Sistema:** Debian 11/12 ou Ubuntu 22.04/24.04 (ou derivados).
* **Acesso:** Privilégios de `root` ou um usuário com acesso `sudo`.

---

### Instalação

**ATENÇÃO:** O script irá pausar durante a execução para solicitar algumas informações de rede necessárias.

### 1. Instalação

**Baixe as dependências de pré-instação**
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install git python3
```

**Clone o repositório e entre no diretório:**
```bash
git clone https://github.com/nakomaNS/EasySnort
cd EasySnort
```

**Dê permissão de execução ao script:**
```bash
chmod +x easysnort.py
```

**Execute a instalação:**
```bash
sudo ./easysnort.py --install
```
---

### 2. Informações Solicitadas pelo Script

Veja como encontrá-las:

* **Nome da Interface de Rede:**
    Execute `ip a` para listar suas interfaces. Procure por nomes como `enp0s3` ou `eth0` que contenham seu endereço IP principal.

* **Endereço de Rede (HOME_NET) em Formato CIDR:**
    Na saída do comando `ip a`, observe o seu endereço `inet` (ex: `192.168.1.10/24`). O endereço de rede correspondente é o mesmo, mas com o final `.0` (ex: **`192.168.1.0/24`**).

---

### 3. Gerenciamento do Serviço Snort

Após a instalação, o script cria um serviço `systemd`. Use os seguintes comandos para gerenciá-lo:

* **Iniciar o Serviço:**
    ```bash
    sudo systemctl start snort
    ```

* **Parar o Serviço:**
    ```bash
    sudo systemctl stop snort
    ```

* **Verificar o Status (erros, atividade):**
    ```bash
    sudo systemctl status snort
    ```
    
* **Ver os Logs de Alerta em Tempo Real:**
    ```bash
    tail -f /var/log/snort/snort_logs.log
    ```

* **(Opcional) Habilitar início automático com o sistema:**
    ```bash
    sudo systemctl enable snort
    ```

* **(Opcional) Desabilitar o início automático:**
    ```bash
    sudo systemctl disable snort
    ```
---
