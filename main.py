import nmap
import requests
import argparse
import time

def scan_target(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-sV')

    results = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                service = nm[host][proto][port]
                service_name = service.get('name', '').strip()
                service_version = service.get('version', '').strip()
                if service_name and service_version: 
                    results.append((port, service_name, service_version))
    return results


def search_exploitdb(service_name, service_version):
    query = f"{service_name} {service_version}"
    url = f"https://www.exploit-db.com/search?q={query}"
    headers = {'User-Agent': 'Mozilla/5.0'}

    print(f"[*] Exploit-DB sorgusu: {query}")
    time.sleep(3)  

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return f"[+] Exploit bulundu (manuel kontrol et): {url}"
    else:
        return f"[-] Exploit-DB sorgusu başarısız. Kod: {response.status_code}"


def main():
    parser = argparse.ArgumentParser(description="Hedef IP için servis ve versiyon tarayıcı.")
    parser.add_argument("target", help="Taranacak hedef IP veya domain")
    args = parser.parse_args()

    print("[*] Tarama başlatılıyor...")
    results = scan_target(args.target)

    if results:
        for port, service_name, service_version in results:
            print(f"\n[+] {port}/tcp - {service_name} {service_version}")
            exploit_result = search_exploitdb(service_name, service_version)
            print(exploit_result)
    else:
        print("[-] Açık port ya da versiyon bilgisi bulunamadı.")


if __name__ == "__main__":
    main()
