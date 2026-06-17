import scapy.all as scapy
import threading
import time
import csv
import socket
import os
import re
import subprocess
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox
import ipaddress
import concurrent.futures
import ctypes

# Intentar configurar sockets nativos de Windows si no hay Npcap
NPCAP_AVAILABLE = True
try:
    if os.name == 'nt':
        from scapy.arch.windows import conf
except:
    NPCAP_AVAILABLE = False

class NetworkScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Escáner de Red Pro - Real Time (Fix)")
        self.root.geometry("1100x650")
        
        # Variables de estado
        self.scanning = False
        self.devices = {}  # MAC: {data}
        self.fail_count = {} # MAC: int (conteo de escaneos fallidos)
        self.MAX_FAILS = 3   # Número de escaneos fallidos antes de marcar como INACTIVO
        self.csv_file = "inventario_red.csv"
        self.scan_mode = "Desconocido"
        self.is_admin = self.check_admin()
        
        self.setup_ui()
        self.load_from_csv()
        self.update_table()
        
        if not NPCAP_AVAILABLE:
            messagebox.showwarning("Dependencia Faltante", 
                "No se detectó Npcap/WinPcap. El escáner usará el modo de compatibilidad (Ping + ARP Cache).\n\n"
                "Para mejores resultados, se recomienda instalar Npcap.")

    def check_admin(self):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False

    def get_default_interface(self):
        try:
            return scapy.conf.iface
        except:
            return "N/A"

    def setup_ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        
        # Panel Superior (Controles)
        top_frame = ttk.Frame(self.root, padding="10")
        top_frame.pack(fill=tk.X)
        
        self.btn_scan = ttk.Button(top_frame, text="Iniciar Escaneo", command=self.toggle_scan)
        self.btn_scan.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(top_frame, text="Rango IP:").pack(side=tk.LEFT, padx=5)
        self.entry_range = ttk.Entry(top_frame, width=20)
        self.entry_range.insert(0, self.get_local_ip_range())
        self.entry_range.pack(side=tk.LEFT, padx=5)
        
        self.mode_label = ttk.Label(top_frame, text=f"Modo: {self.scan_mode}", foreground="blue")
        self.mode_label.pack(side=tk.LEFT, padx=15)

        self.status_label = ttk.Label(top_frame, text="Estado: Detenido", foreground="red", font=('Arial', 10, 'bold'))
        self.status_label.pack(side=tk.RIGHT, padx=10)

        # Tabla (Treeview)
        table_frame = ttk.Frame(self.root, padding="10")
        table_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ("IP", "MAC", "HOSTNAME", "PRIMERA_DETECCION", "ULTIMA_DETECCION", "TIEMPO_VISIBLE_MIN", "ESTADO")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120, anchor=tk.CENTER)
            
        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Barra inferior de información
        info_frame = ttk.Frame(self.root, padding="5")
        info_frame.pack(fill=tk.X)
        self.admin_label = ttk.Label(info_frame, text="Admin: " + ("SÍ" if self.is_admin else "NO"), 
                                    foreground="green" if self.is_admin else "orange")
        self.admin_label.pack(side=tk.LEFT, padx=10)
        
        self.count_label = ttk.Label(info_frame, text="Dispositivos: 0")
        self.count_label.pack(side=tk.RIGHT, padx=10)

    def get_local_ip_range(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            network = ipaddress.ip_network(f"{ip}/24", strict=False)
            return str(network)
        except:
            return "192.168.1.0/24"

    def get_hostname(self, ip):
        """Intenta obtener el hostname usando múltiples métodos."""
        try:
            # Método 1: gethostbyaddr
            return socket.gethostbyaddr(ip)[0]
        except:
            try:
                # Método 2: getfqdn
                name = socket.getfqdn(ip)
                if name != ip:
                    return name
            except:
                pass
        
        # Si falla, intentar una resolución rápida vía shell (nbtstat para nombres NetBIOS)
        if os.name == 'nt':
            try:
                output = subprocess.check_output(f"nbtstat -A {ip}", shell=True).decode("cp850")
                # Buscar el primer nombre en la tabla NetBIOS
                match = re.search(r'"([^"]+)"', output) # A veces viene entre comillas
                if not match:
                    # Alternativa: buscar el primer nombre que no sea la IP
                    lines = output.splitlines()
                    for line in lines:
                        if "<00>" in line and "UNIQUE" in line:
                            return line.split()[0].strip()
            except:
                pass
                
        return "Desconocido"

    def ping_ip(self, ip):
        """Envía un solo ping para refrescar la caché ARP."""
        try:
            # -n 1: un paquete, -w 80: esperar 80ms (más rápido)
            subprocess.run(["ping", "-n", "1", "-w", "80", str(ip)], 
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass

    def get_arp_cache(self, target_network):
        """Obtiene y parsea la tabla ARP, filtrando por la red objetivo."""
        devices = []
        try:
            net = ipaddress.ip_network(target_network, strict=False)
            output = subprocess.check_output("arp -a", shell=True).decode("cp850")
            pattern = r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{17})\s+(\w+)"
            matches = re.findall(pattern, output)
            
            for ip_str, mac, type_ in matches:
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    if ip_obj in net: # SOLO añadir si está en el rango actual
                        mac = mac.replace("-", ":").lower()
                        # Filtrar broadcast/multicast
                        if not mac.startswith("ff:ff") and not ip_str.startswith("224."):
                            devices.append((ip_str, mac))
                except:
                    continue
        except Exception as e:
            print(f"Error parseando ARP: {e}")
        return devices

    def scan_network(self):
        ip_range = self.entry_range.get()
        while self.scanning:
            current_scan_results = [] # Lista de (ip, mac)
            now = datetime.now()
            
            try:
                # INTENTO 1: Scapy ARPing (Requiere Npcap)
                try:
                    self.scan_mode = "Scapy (ARP)"
                    self.root.after(0, lambda: self.mode_label.config(text=f"Modo: {self.scan_mode}"))
                    answered, _ = scapy.arping(ip_range, timeout=1.5, verbose=False)
                    for snd, rcv in answered:
                        current_scan_results.append((rcv.psrc, rcv.hwsrc))
                except Exception as e:
                    # FALLBACK: Ping + ARP Cache
                    self.scan_mode = "Fallback (Ping+ARP)"
                    self.root.after(0, lambda: self.mode_label.config(text=f"Modo: {self.scan_mode}"))
                    
                    # Pinging range en paralelo (Turbo)
                    net = ipaddress.ip_network(ip_range, strict=False)
                    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                        executor.map(self.ping_ip, net.hosts())
                    
                    # Leer caché ARP filtrada
                    current_scan_results = self.get_arp_cache(ip_range)

                # Procesar resultados
                current_scan_macs = set()
                
                # Actualizar o añadir dispositivos encontrados
                for ip, mac in current_scan_results:
                    mac = mac.lower()
                    current_scan_macs.add(mac)
                    self.fail_count[mac] = 0 # Resetear contador de fallos
                    
                    if mac not in self.devices:
                        hostname = self.get_hostname(ip)
                        self.devices[mac] = {
                            "IP": ip,
                            "MAC": mac,
                            "HOSTNAME": hostname,
                            "PRIMERA_DETECCION": now.isoformat(),
                            "ULTIMA_DETECCION": now.isoformat(),
                            "TIEMPO_VISIBLE_MIN": 0.0,
                            "ESTADO": "ACTIVO"
                        }
                    else:
                        dev = self.devices[mac]
                        dev["IP"] = ip
                        dev["ULTIMA_DETECCION"] = now.isoformat()
                        dev["ESTADO"] = "ACTIVO"
                        
                        first = datetime.fromisoformat(dev["PRIMERA_DETECCION"])
                        diff = (now - first).total_seconds() / 60.0
                        dev["TIEMPO_VISIBLE_MIN"] = round(diff, 2)

                # Gestionar dispositivos que NO respondieron en este ciclo (Grace Period)
                for mac, data in list(self.devices.items()):
                    if mac not in current_scan_macs:
                        self.fail_count[mac] = self.fail_count.get(mac, 0) + 1
                        if self.fail_count[mac] >= self.MAX_FAILS:
                            data["ESTADO"] = "INACTIVO"
                    else:
                        data["ESTADO"] = "ACTIVO"

                # Guardar y actualizar UI
                self.save_to_csv()
                self.root.after(0, self.update_table)
                self.print_to_console(now)
                
            except Exception as e:
                print(f"Error crítico en bucle de escaneo: {e}")
            
            time.sleep(5) # Modo Turbo: 5 segundos

    def print_to_console(self, timestamp):
        # Útil para depuración
        print(f"\n[{timestamp.strftime('%H:%M:%S')}] Escaneo completado. Modo: {self.scan_mode}. Dispositivos: {len(self.devices)}")

    def update_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        activos = 0
        for mac, data in self.devices.items():
            is_active = data["ESTADO"] == "ACTIVO"
            if is_active: activos += 1
            
            tags = ("activo",) if is_active else ("inactivo",)
            self.tree.insert("", tk.END, values=(
                data["IP"], 
                data["MAC"], 
                data["HOSTNAME"], 
                data["PRIMERA_DETECCION"].split(".")[0].replace("T", " "), 
                data["ULTIMA_DETECCION"].split(".")[0].replace("T", " "), 
                data["TIEMPO_VISIBLE_MIN"], 
                data["ESTADO"]
            ), tags=tags)
        
        self.tree.tag_configure("activo", foreground="green")
        self.tree.tag_configure("inactivo", foreground="gray")
        self.count_label.config(text=f"Dispositivos: {len(self.devices)} (Activos: {activos})")

    def toggle_scan(self):
        if not self.scanning:
            # Detectar y actualizar el rango de IP automáticamente al iniciar
            new_range = self.get_local_ip_range()
            self.entry_range.delete(0, tk.END)
            self.entry_range.insert(0, new_range)
            
            self.scanning = True
            self.btn_scan.config(text="Detener Escaneo")
            self.status_label.config(text="Estado: Escaneando...", foreground="green")
            threading.Thread(target=self.scan_network, daemon=True).start()
        else:
            self.scanning = False
            self.btn_scan.config(text="Iniciar Escaneo")
            self.status_label.config(text="Estado: Detenido", foreground="red")

    def save_to_csv(self):
        try:
            with open(self.csv_file, mode='w', newline='') as f:
                fieldnames = ["IP", "MAC", "HOSTNAME", "PRIMERA_DETECCION", "ULTIMA_DETECCION", "TIEMPO_VISIBLE_MIN", "ESTADO"]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for data in self.devices.values():
                    writer.writerow(data)
        except Exception as e:
            print(f"Error al guardar CSV: {e}")

    def load_from_csv(self):
        if os.path.exists(self.csv_file):
            try:
                with open(self.csv_file, mode='r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        try:
                            row["TIEMPO_VISIBLE_MIN"] = float(row["TIEMPO_VISIBLE_MIN"])
                            self.devices[row["MAC"]] = row
                            self.fail_count[row["MAC"]] = 0
                        except:
                            continue
            except Exception as e:
                print(f"Error al cargar CSV: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()
