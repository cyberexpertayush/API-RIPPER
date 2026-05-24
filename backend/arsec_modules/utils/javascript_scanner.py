from modules import sub_output
from colorama import Fore
import os


def spider(domain: str):
    directory = os.getcwd()
    output_dir = os.path.join(directory, "output")
    os.makedirs(output_dir, exist_ok=True)
    javascript_file_path = os.path.join(output_dir, "javascript")
    open(javascript_file_path, 'a').close() # Create file if it doesn't exist
    sub_output.subpro_scan(f"echo {domain} | waybackurls | grep '\\.js$' | uniq >> {javascript_file_path}")
    sub_output.subpro_scan(f"echo {domain} | gau | grep -Eo 'https?://\\S+?\\.js' | uniq >> {javascript_file_path}")
    with open(javascript_file_path, "r") as f:
        lines = [x.strip() for x in f.readlines()]
        if lines:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} JavaScript files: {Fore.GREEN}{len(lines)}") 