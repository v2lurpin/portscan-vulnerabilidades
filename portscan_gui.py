import customtkinter as ctk
import concurrent.futures
import dns.resolver
import socket
import threading
import json
import os
from datetime import datetime

# --- CONFIGURAÇÃO VISUAL ---
ctk.set_appearance_mode("Dark")  
ctk.set_default_color_theme("blue")

class PortScannerLogic:
    def __init__(self, log_callback):
        self.log_callback = log_callback
        self.vuln_db = {
            21: "FTP: Risco de Sniffing (Texto Claro)",
            22: "SSH: Verificar chaves fracas/Brute-force",
            23: "TELNET: INSEGURO. Use SSH.",
            80: "HTTP: Sem criptografia (Sniffing/XSS)",
            443: "HTTPS: Verificar Heartbleed/Certificados",
            445: "SMB: Risco Crítico (Ransomware/WannaCry)",
            3306: "MySQL: Banco de Dados exposto",
            3389: "RDP: Acesso Remoto (Alvo de Brute-force)"
        }

    def log(self, text, color=None):
        self.log_callback(text)

    def resolve_dns(self, hostname):
        self.log(f"[*] Resolvendo DNS para {hostname}...\n")
        try:
            socket.inet_aton(hostname)
            return hostname
        except socket.error:
            try:
                ip_address = dns.resolver.resolve(hostname, 'A')
                ip_val = ip_address[0].to_text()
                self.log(f"[OK] IP Encontrado: {ip_val}\n")
                return ip_val
            except Exception:
                self.log(f"[!] Erro: DNS não encontrado para '{hostname}'.\n")
                return None

    def scan_port(self, target_ip, port, timeout):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((target_ip, port))
                
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    
                    self.log(f"[+] Porta {port:<5} ABERTA ({service})\n")
                    
                    vuln = self.vuln_db.get(port)
                    if vuln:
                        self.log(f"    ⚠️  ALERTA: {vuln}\n")
                    
                    # Banner Grabbing
                    banner_str = ""
                    try:
                        s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        banner_bytes = s.recv(1024)
                        banner_str = banner_bytes.decode().strip()
                        if banner_str:
                            self.log(f"    |_ Banner: {banner_str[:50]}...\n")
                    except:
                        pass
                    
                    return {
                        "port": port,
                        "service": service,
                        "vuln": vuln,
                        "banner": banner_str
                    }
        except:
            pass
        return None

    def run_scan(self, target, ports_str, threads, timeout):
        target_ip = self.resolve_dns(target)
        if not target_ip: 
            # Reabilita botão se falhar DNS
            self.log("[!] Falha no DNS. Abortando.\n")
            return

        # Parse Ports
        ports = []
        try:
            if "-" in ports_str:
                s, e = map(int, ports_str.split("-"))
                ports = list(range(s, e + 1))
            elif "," in ports_str:
                ports = [int(p) for p in ports_str.split(",")]
            elif ports_str == "all":
                ports = list(range(1, 65536))
            else:
                ports = [int(ports_str)]
        except:
            self.log("[!] Erro no formato das portas. Usando 1-1024.\n")
            ports = list(range(1, 1025))

        self.log(f"[*] Iniciando scan em: {target_ip}\n")
        self.log(f"[*] Portas: {len(ports)} | Threads: {threads}\n")
        self.log("="*40 + "\n")

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self.scan_port, target_ip, p, timeout): p for p in ports}
            for future in concurrent.futures.as_completed(futures):
                data = future.result()
                if data:
                    results.append(data)

        results.sort(key=lambda x: x['port'])
        self.save_json(target_ip, results)
        self.log("\n[*] Varredura Concluída!\n")

    def save_json(self, ip, data):
        filename = f"scan_{ip}.json"
        try:
            with open(filename, "w") as f:
                json.dump({"target": ip, "results": data}, f, indent=4)
            self.log(f"[!] Relatório salvo: {filename}\n")
        except:
            pass

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Python Port Scanner Pro")
        self.geometry("700x600")

        # --- LAYOUT ---
        # Título
        self.lbl_title = ctk.CTkLabel(self, text="🛡️ NETWORK VULNERABILITY SCANNER", font=("Roboto", 20, "bold"))
        self.lbl_title.pack(pady=10)

        # Frame de Configuração
        self.frame_config = ctk.CTkFrame(self)
        self.frame_config.pack(pady=10, padx=20, fill="x")

        # Input Alvo
        self.entry_target = ctk.CTkEntry(self.frame_config, placeholder_text="Alvo (ex: scanme.nmap.org)", width=300)
        self.entry_target.grid(row=0, column=0, padx=10, pady=10)

        # Input Portas
        self.entry_ports = ctk.CTkEntry(self.frame_config, placeholder_text="Portas (ex: 1-1024)", width=150)
        self.entry_ports.grid(row=0, column=1, padx=10, pady=10)
        self.entry_ports.insert(0, "1-1024")

        # Sliders e Configs Extras
        self.lbl_threads = ctk.CTkLabel(self.frame_config, text="Threads: 100")
        self.lbl_threads.grid(row=1, column=0, sticky="w", padx=10)
        
        self.slider_threads = ctk.CTkSlider(self.frame_config, from_=10, to=200, number_of_steps=19, command=self.update_thread_label)
        self.slider_threads.set(100)
        self.slider_threads.grid(row=1, column=0, padx=100, sticky="ew")

        # Botão Scan
        self.btn_scan = ctk.CTkButton(self.frame_config, text="INICIAR SCAN", command=self.start_scan_thread, fg_color="green", hover_color="darkgreen")
        self.btn_scan.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        # Área de Log
        self.textbox_log = ctk.CTkTextbox(self, width=600, height=400, font=("Consolas", 12))
        self.textbox_log.pack(pady=10, padx=20, fill="both", expand=True)
        self.textbox_log.insert("0.0", "Pronto para iniciar...\n")

    def update_thread_label(self, value):
        self.lbl_threads.configure(text=f"Threads: {int(value)}")

    def log_to_gui(self, text):
        # Garante que a atualização da GUI ocorra sem travar
        self.textbox_log.insert("end", text)
        self.textbox_log.see("end")

    def start_scan_thread(self):
        # Pega os valores
        target = self.entry_target.get()
        ports = self.entry_ports.get()
        threads = int(self.slider_threads.get())
        
        if not target:
            self.log_to_gui("[!] Erro: Alvo vazio!\n")
            return

        self.btn_scan.configure(state="disabled", text="Escaneando...")
        self.textbox_log.delete("1.0", "end") # Limpa log anterior

        # Cria uma thread separada para não travar a janela
        threading.Thread(target=self.run_logic, args=(target, ports, threads)).start()

    def run_logic(self, target, ports, threads):
        # Instancia a lógica passando a função de log da GUI
        scanner = PortScannerLogic(self.log_to_gui)
        scanner.run_scan(target, ports, threads, 1.0)
        
        # Reabilita o botão após terminar
        self.btn_scan.configure(state="normal", text="INICIAR SCAN")

if __name__ == "__main__":
    app = App()
    app.mainloop()