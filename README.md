# Análise de Log Apache

Esta ferramenta Python foi desenvolvida para analisar logs de acesso do Apache, identificando atividades suspeitas relacionadas a ferramentas de segurança comuns, como Nmap, Nikto e SQLmap. Ela extrai informações cruciais como IPs suspeitos, ferramentas utilizadas e o período em que as atividades de ataque ocorreram.

---

### Funcionalidades

* **Identificação de IPs Suspeitos:** Detecta e lista endereços IP que estão associados ao uso de ferramentas de varredura ou exploração.
* **Contagem de Ferramentas:** Quantifica as ocorrências de Nmap, Nikto e sqlmap nos logs.
* **Período de Ataque:** Determina o intervalo de tempo (início e fim) em que as atividades suspeitas foram registradas.
* **Interface de Linha de Comando (CLI):** Permite a execução fácil da ferramenta passando o caminho do arquivo de log como argumento.

---

### Como Usar

1.  **Pré-requisitos:**
    * Python 3.x
    * Bibliotecas Python: `colorama` e `babel`
    Você pode instalá-las usando pip:
    ```sh
    pip install colorama babel
    ```

2.  **Execução:**
    Para analisar um arquivo de log, execute o script `getatt.py` seguido pelo caminho do seu arquivo de log:

    ```sh
    python getatt.py /caminho/para/seu/access.log
    ```

    **Exemplo:**
    ```sh
    python getatt.py /var/log/apache2/access.log
    ```

---

### Exemplo de Saída

```
IP suspeito: 192.168.1.1
A ferramenta Nmap foi usada 2 vezes e Nikto 1 vezes.
Outras ferramentas (como sqlmap) foram usadas 1 vezes.
O ataque começou em 26/05/2025:10:00:00 e terminou em 26/05/2025:10:05:00.
```

---

### Testes Unitários (Pytest)

O projeto inclui uma suíte de testes unitários desenvolvida com `pytest` e `pytest-mock` para garantir a funcionalidade e a robustez da ferramenta.

Para executar os testes:

1.  **Pré-requisitos:**
    * Instale `pytest` e `pytest-mock`:
        ```sh
        pip install pytest pytest-mock
        ```

2.  **Execução dos Testes:**
    No diretório onde se encontram o arquivo de testes (`unit_tests.py`) e o arquivo principal (`getatt.py`), execute:
    ```sh
    pytest unit_tests.py
    ```

---
