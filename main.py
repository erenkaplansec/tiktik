import nmap
import requests
import json
import argparse

def scan_target(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-sV')

    results = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                service = nm[host][proto][port]
                service_name = service.get('name', 'unknown')
                service_version = service.get('version', 'unknown')
                results.append((port, service_name, service_version))
    return results


def search_exploitdb(service_name, service_version):
    query = f"{service_name} {service_version}"
    url = f"https://www.exploit-db.com/search?q={query}"
    headers = {'User -Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return f"Exploit-DB üzerinde sorgulama yapıldı, detaylar için: {url}"
    else:
        return "Exploit-DB'ye erişilemedi."


def main():
    parser = argparse.ArgumentParser(description="Hedef IP veya domain tarayıcı.")
    parser.add_argument("target", help="Taranacak hedef IP veya domain")
    args = parser.parse_args()

    print("Taranıyor...")
    results = scan_target(args.target)

    if results:
        for port, service_name, service_version in results:
            print(f"[+] {port}/tcp - {service_name} {service_version}")
            exploit_result = search_exploitdb(service_name, service_version)
            print(exploit_result)
    else:
        print("Açık port bulunamadı veya servis tespit edilemedi.")


if __name__ == "__main__":
    main()