import re
from datetime import datetime
from babel.dates import format_datetime
import argparse
from colorama import Fore, Style, init

class LogAnalyser:
    """
    Classe para analisar logs, extraindo informações sobre IPs
    e ferramentas utilizadas.
    """
    def __init__(self, log_file_path):
        self.log_file_path = log_file_path
        self._parsed_entries = []   # Armazenará as entradas completas do log parseadas.
        self.suspect_ips = set()    # Usar um set para armazenar IPs suspeitos únicos.
        self.used_tools_raw = []    # Armazenará as strings de comando das ferramentas usadas.
        self.timestamps = []        # Armazenará os timestamps dos logs relevantes para o intervalo de tempo.
        self._load_and_parse_log()  # Chama o método de carregamento e parseamento no construtor.

    def _load_and_parse_log(self):
        """
        Carrega o arquivo de log e parseia cada linha, extraindo informações
        relevantes como IP, timestamp e comando executado (ferramenta).
        """
        log_pattern = re.compile(
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(.*?)(?:\s[+-]\d{4})?\] ".*?" \d{3} \d+ ".*?" "(.*?)"'
        )

        try:
            with open(self.log_file_path, 'r') as file:
                for line in file:
                    match = log_pattern.search(line)
                    if match:
                        ip_address = match.group(1)
                        raw_timestamp = match.group(2)
                        tool_user_agent = match.group(3)

                        self._parsed_entries.append({
                            'ip': ip_address,
                            'timestamp': raw_timestamp,
                            'tool_user_agent': tool_user_agent
                        })

                        # Verifica se o User-Agent contém as ferramentas suspeitas
                        if any(tool_name.lower() in tool_user_agent.lower() for tool_name in ["nmap", "nikto", "sqlmap"]):
                            self.suspect_ips.add(ip_address)
                            self.used_tools_raw.append(tool_user_agent)
                            self.timestamps.append(raw_timestamp)
        except FileNotFoundError:
            print(f"Erro: Arquivo {self.log_file_path} não encontrado.")
            raise
        except Exception as e:
            print(f"Erro inesperado ao carregar ou parsear o arquivo de log: {e}")
            raise
    
    def get_suspect_ip(self):
        """
        Retorna o endereço IP suspeito se apenas um IP único for identificado
        como possível atacante.
        Retorna uma string vazia se nenhum IP suspeito for encontrado.
        """
        if not self.suspect_ips:
            return ""
        
        return list(self.suspect_ips)[0]
    
    def count_used_tools(self):
        """
        Conta as ocorrências das ferramentas Nmap, Nikto e outras (sqlmap)
        encontradas nas atividades de log.
        Retorna uma tupla (nmap_count, nikto_count, other_count).
        """
        nmap_count = 0
        nikto_count = 0
        other_count = 0

        for tool_user_agent_string in self.used_tools_raw:
            if "nmap" in tool_user_agent_string.lower():
                nmap_count+=1
            if "nikto" in tool_user_agent_string.lower():
                nikto_count+=1
            if "sqlmap" in tool_user_agent_string.lower():
                other_count+=1

        return nmap_count,nikto_count,other_count
    
    def get_attack_time_range(self):
        """
        Retorna a data e hora de início e fim das atividades de ataque registradas,
        formatadas para exibição.
        Retorna "N/A" se não houver timestamps para análise.
        """

        if not self.timestamps:
            return "N/A", "N/A"
        
        try:
            parsed_datatimes = []
            for ts_str in self.timestamps:
                parsed_datatimes.append(datetime.strptime(ts_str, '%d/%b/%Y:%H:%M:%S'))

            sorted_datetimes = sorted(parsed_datatimes)

            start_datetime = sorted_datetimes[0]
            end_datetime = sorted_datetimes[1]

            start_formatted = format_datetime(start_datetime, format="dd/MM/yyyy:HH:mm:ss")
            end_formatted =  format_datetime(end_datetime, format="dd/MM/yyyy:HH:mm:ss")

            return start_formatted, end_formatted
        except ValueError as e:
            print(f"Erro ao parsear data/hora: {e}. Verifique o formato no arquivo de log.")
            return "Erro de formato", "Erro de formato"
        except IndexError:
            return "N/A", "N/A"  # Caso a lista de timestamps esteja vazia. 

def main():
    init(autoreset=True)
    parser = argparse.ArgumentParser(description="Analisa um arquivo de log para identificar atividades de ferramentas de segurança como Nmap e Nikto.")
    parser.add_argument("file", help="O caminho do arquivo de log a ser analisado.")
    args = parser.parse_args()

    try:
        analyzer = LogAnalyser(args.file)
    except FileNotFoundError: # Captura a exceção específica para arquivo não encontrado
        return 1
    except Exception as e: # Captura outras exceções
        return 1

    suspect_ip = analyzer.get_suspect_ip()

    if not analyzer.suspect_ips:
        print(f"\n{Style.BRIGHT}{Fore.GREEN}Nenhuma ameaça foi encontrada no log.")
        return 0

    nmap_count, nikto_count, other_count = analyzer.count_used_tools()
    start_time, end_time = analyzer.get_attack_time_range()

    print(f"\n{Style.BRIGHT}IP suspeito: {Fore.RED}{Style.BRIGHT}{suspect_ip}")
    print(f"{Style.BRIGHT}A ferramenta {Style.BRIGHT}Nmap foi usada {Fore.RED}{nmap_count}{Fore.RESET}{Style.BRIGHT} vezes e {Style.BRIGHT}Nikto {Fore.RED}{nikto_count}{Fore.RESET} vezes.")
    if other_count > 0:
        print(f"{Style.BRIGHT}Outras ferramentas (como {Fore.RED}sqlmap{Fore.RESET}{Style.BRIGHT}) foram usadas {Fore.RED}{other_count}{Fore.RESET} vezes.")
    print(f"{Style.BRIGHT}O ataque começou em {Fore.YELLOW}{start_time}{Fore.RESET} e terminou em {Fore.YELLOW}{end_time}{Fore.RESET}.")
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main())