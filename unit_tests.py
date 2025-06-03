import pytest
from unittest.mock import mock_open
import sys # Para simular sys.exit

# Importe a classe LogAnalyzer do seu arquivo principal (getatt.py)
from getatt import LogAnalyzer, main # Importa main também para o teste de sys.exit

# --- Cenários de Conteúdo de Log Mockado ---
# Os mocks de conteúdo podem ser definidos fora das funções de teste
# ou mesmo como fixtures, mas como constantes globais aqui funciona bem.

# Cenário 1: Arquivo de log com dados de Nmap, Nikto e sqlmap
MOCK_LOG_CONTENT_1 = """
192.168.1.1 - - [26/May/2025:10:00:00 -0300] "GET /nmap_scan HTTP/1.1" 200 1234 "-" "Nmap Script Engine"
192.168.1.1 - - [26/May/2025:10:00:10 -0300] "GET /nikto_scan HTTP/1.1" 200 5678 "-" "Nikto/2.1.6"
192.168.1.2 - - [26/May/2025:10:01:00 -0300] "GET /normal_request HTTP/1.1" 200 9876 "-" "Mozilla/5.0"
192.168.1.1 - - [26/May/2025:10:02:00 -0300] "GET /sqlmap_test HTTP/1.1" 200 123 "-" "sqlmap scanner"
"""

# Cenário 2: Arquivo de log sem ferramentas suspeitas
MOCK_LOG_CONTENT_2 = """
10.0.0.1 - - [26/May/2025:11:00:00 -0300] "GET /index.html HTTP/1.1" 200 100 "-" "Mozilla/5.0"
10.0.0.2 - - [26/May/2025:11:00:05 -0300] "POST /login HTTP/1.1" 302 0 "-" "Chrome/90"
"""

# Cenário 3: Arquivo de log vazio
MOCK_LOG_CONTENT_3 = ""

# Cenário 4: Log com IP suspeito único
MOCK_LOG_CONTENT_4 = """
172.16.0.1 - - [26/May/2025:12:00:00 -0300] "GET /nmap_exploit HTTP/1.1" 404 500 "-" "Nmap Script Engine"
172.16.0.1 - - [26/May/2025:12:00:15 -0300] "GET /another_nmap HTTP/1.1" 200 1000 "-" "Nmap"
"""
    
# Cenário 5: Log com múltiplos IPs suspeitos (ajustado para ter 3 IPs suspeitos)
MOCK_LOG_CONTENT_5 = """
192.168.1.1 - - [26/May/2025:10:00:00 -0300] "GET /nmap_scan HTTP/1.1" 200 1234 "-" "Nmap Script Engine"
192.168.1.2 - - [26/May/2025:10:00:10 -0300] "GET /nikto_scan HTTP/1.1" 200 5678 "-" "Nikto/2.1.6"
192.168.1.3 - - [26/May/2025:10:00:20 -0300] "GET /sqlmap_test HTTP/1.1" 200 123 "-" "sqlmap scanner"
"""

# --- Funções de Teste ---

def test_load_and_parse_log_with_data(mocker):
    """
    Testa o carregamento e parseamento de um log com dados esperados
    de ferramentas e IPs.
    """
    mocker.patch('builtins.open', mock_open(read_data=MOCK_LOG_CONTENT_1))
    analyzer = LogAnalyzer("my_log.log")
    assert len(analyzer._parsed_entries) == 4
    # CORREÇÃO AQUI: Apenas um IP (192.168.1.1) é suspeito no MOCK_LOG_CONTENT_1
    assert len(analyzer.suspect_ips) == 1
    assert len(analyzer.used_tools_raw) == 3
    assert len(analyzer.timestamps) == 3
    
    assert '192.168.1.1' in analyzer.suspect_ips
    assert 'Nmap Script Engine' in analyzer.used_tools_raw
    assert 'Nikto/2.1.6' in analyzer.used_tools_raw
    assert 'sqlmap scanner' in analyzer.used_tools_raw

def test_load_and_parse_log_no_threats(mocker):
    """
    Testa o carregamento de um log sem ferramentas suspeitas,
    garantindo que as listas de suspeitos estejam vazias.
    """
    mocker.patch('builtins.open', mock_open(read_data=MOCK_LOG_CONTENT_2))
    analyzer = LogAnalyzer("my_log.log")
    assert len(analyzer.suspect_ips) == 0
    assert len(analyzer.used_tools_raw) == 0
    assert len(analyzer.timestamps) == 0

def test_load_and_parse_log_empty_file(mocker):
    """
    Testa o carregamento de um arquivo de log vazio,
    verificando se todas as listas de dados permanecem vazias.
    """
    mocker.patch('builtins.open', mock_open(read_data=MOCK_LOG_CONTENT_3))
    analyzer = LogAnalyzer("empty.log")
    assert len(analyzer._parsed_entries) == 0
    assert len(analyzer.suspect_ips) == 0
    assert len(analyzer.used_tools_raw) == 0
    assert len(analyzer.timestamps) == 0

def test_count_used_tools(mocker):
    """
    Testa a contagem correta das ocorrências de Nmap, Nikto e outras (sqlmap)
    ferramentas.
    """
    mocker.patch('builtins.open', mock_open(read_data=MOCK_LOG_CONTENT_1))
    analyzer = LogAnalyzer("my_log.log")
    nmap_c, nikto_c, other_c = analyzer.count_used_tools()
    assert nmap_c == 1
    assert nikto_c == 1
    assert other_c == 1 # sqlmap

def test_get_attack_time_range(mocker):
    """
    Testa a extração do período de início e fim dos ataques registrados,
    garantindo o formato correto da saída.
    """
    mocker.patch('builtins.open', mock_open(read_data=MOCK_LOG_CONTENT_1))
    analyzer = LogAnalyzer("my_log.log")
    start, end = analyzer.get_attack_time_range()
    assert start == "26/05/2025:10:00:00"
    assert end == "26/05/2025:10:02:00"

def test_get_suspect_ip_single(mocker):
    """
    Testa a identificação de um único IP suspeito quando todas as ocorrências
    de ferramentas vêm do mesmo IP.
    """
    mocker.patch('builtins.open', mock_open(read_data=MOCK_LOG_CONTENT_4))
    analyzer = LogAnalyzer("my_log.log")
    suspect_ip = analyzer.get_suspect_ip()
    assert suspect_ip == "172.16.0.1"

def test_get_suspect_ip_multiple(mocker):
    """
    Testa o comportamento de `get_suspect_ip` quando há múltiplos IPs suspeitos.
    (Neste caso, retorna o primeiro IP encontrado no set de IPs suspeitos).
    """
    mocker.patch('builtins.open', mock_open(read_data=MOCK_LOG_CONTENT_5))
    analyzer = LogAnalyzer("my_log.log")
    suspect_ip = analyzer.get_suspect_ip()
    # O set não garante ordem, então verificamos se o IP retornado está entre os esperados.
    assert suspect_ip in ["192.168.1.1", "192.168.1.2", "192.168.1.3"]

def test_get_suspect_ip_no_threats(mocker):
    """
    Testa o caso em que não há ameaças/IPs suspeitos no log,
    garantindo que a função retorne uma string vazia.
    """
    mocker.patch('builtins.open', mock_open(read_data=MOCK_LOG_CONTENT_2))
    analyzer = LogAnalyzer("my_log.log")
    suspect_ip = analyzer.get_suspect_ip()
    assert suspect_ip == ""

def test_file_not_found_error(mocker, capsys):
    """
    Testa o tratamento de erro quando o arquivo de log não é encontrado.
    Espera-se que a função main imprima uma mensagem de erro e saia com código 1.
    """
    mocker.patch('builtins.open', side_effect=FileNotFoundError)
    # Mock sys.argv para simular o argumento de linha de comando
    mocker.patch.object(sys, 'argv', ['getatt.py', 'non_existent_file.log'])

    with pytest.raises(SystemExit) as excinfo:
        main() # Chama a função main, que é quem lida com o sys.exit(1)
    
    assert excinfo.value.code == 1 # Verifica se o código de saída é 1
    
    # Captura a saída impressa no console
    captured = capsys.readouterr()
    assert "Erro: Arquivo 'non_existent_file.log' não encontrado." in captured.out


def test_parsing_error_handling(mocker):
    """
    Testa se o parser lida com linhas de log malformadas sem quebrar.
    """
    mocker.patch('builtins.open', mock_open(read_data="invalid log line without expected pattern\n"))
    try:
        analyzer = LogAnalyzer("malformed_log.log")
        # A regex não deve encontrar correspondência, então essas listas devem estar vazias
        assert len(analyzer._parsed_entries) == 0
        assert len(analyzer.suspect_ips) == 0
        assert len(analyzer.used_tools_raw) == 0
        assert len(analyzer.timestamps) == 0
    except Exception as e:
        pytest.fail(f"Loading and parsing failed with unexpected error: {e}")