# Tıktık

NMAP aracı ile port taramasi yapıp ExploitDB'den zafiyet tespiti yapan Python betiği.

## Kurulum

Araç, Kali Linux, Parrot Security OS ve Arch Linux ve Windows işletim sistemleri üzerinde test edilmiştir. 

```shell
python3 -m venv tiktik
source tiktik/bin/activate
pip3 install -r requirements.txt
```

## Kullanım

`<target>` kısmına yerel ağımızdaki veya dış ip'den bir cihazın ip adresini yazıyoruz.

```shell
python3 main.py <target>
```

### TODO



- [x] ExploitDB çıktısı.
- [ ] MaxRetryError sorununun giderilmesi.
