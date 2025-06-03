import re
from datetime import datetime
from babel.dates import format_datetime
import argparse
from colorama import Fore, Style, init


nList = []  # Raw log in list format.
tool = [] # Tools that were used.
starEnd = []

class LogAnalyser:
    def __init__(self, log_file_path):
        self.log_file_path = log_file_path
        self._parsed_entries = []
        self.suspect_ips = set()
        self.used_tools_raw = []
        self.timestamps = []
        self._load_and_parse_log()

    def _load_and_parse_log(self):
        log_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(.*?)(?:\s[+-]\d{4})?\] ".*?" \d{3} \d+ ".*?" "(.*?)"')
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

def main():
    init(autoreset=True)
    parser = argparse.ArgumentParser(description="Analisa um arquivo de log para identificar atividades de ferramentas de segurança como Nmap e Nikto.")
    parser.add_argument("file", help="O caminho do arquivo de log a ser analisado.")
    args = parser.parse_args()

    try:
        analyzer = LogAnalyser(args.file)
    except FileNotFoundError:
        return 1
    except Exception as e:
        return 1

    if not analyzer.suspect_ips:
        print(f"\n{Style.BRIGHT}{Fore.GREEN}Nenhuma ameaça foi encontrada no log.")
        return 1

    # nmap_C,nikto_C, other = usedTools()
    # start, end = getTime()

    # print(f"\n{Style.BRIGHT}Suspect IP Address: {Fore.RED}{Style.BRIGHT}{suspect}")
    # print(f"{Style.BRIGHT}The {Style.BRIGHT}Nmap tool was used {Fore.RED}{nmap_C}{Fore.RESET}{Style.BRIGHT} times and {Style.BRIGHT}Nikto {Fore.RED}{nikto_C}{Fore.RESET} times.")
    # print(f"{Style.BRIGHT}The attack started in {Fore.YELLOW}{start}{Fore.RESET} and ended in {Fore.YELLOW}{end}{Fore.RESET}.")


if __name__ == '__main__':
    import sys
    sys.exit(main())

