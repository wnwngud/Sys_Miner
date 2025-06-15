import os
import subprocess
import sys
import ctypes
import shutil
import getpass
import tkinter as tk
import winreg
import psutil
from tkinter import messagebox
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
import time
from datetime import datetime, timedelta
import threading
import json

class SysMiner: # 메인 클래스
    total_tasks = 17
    checklist = [
                 "크롬 방문기록", "크롬 쿠키", "크롬 캐시",
                 "엣지 방문기록", "엣지 쿠키", "엣지 캐시",
                 "이벤트 로그", "방화벽 로그",
                 "프리패치", "Srum",
                 "QuickLaunch", "최근 파일", "휴지통",
                 "방화벽 상태확인", "윈도우 업데이트 기록",
                 "설치된 소프트웨어", "패스워드 정책"
    ]
    checknum = [0 for _ in range(total_tasks)]
    checked_tasks = 0

    def __init__(self, progress_callback, selected_tasks):
        self.username = getpass.getuser()
        self.desktop_path = f"C:\\Users\\{self.username}\\Desktop\\result\\Data_Hub"
        os.makedirs(self.desktop_path, exist_ok=True)
        self.progress_callback = progress_callback
        self.selected_tasks = selected_tasks
        SysMiner.checked_tasks = 0

        self.browser_history = BrowserHistories(self.desktop_path, self.username, self._progress_proxy)
        self.system_logs = SystemLogs(self.desktop_path, self.username, self._progress_proxy)
        self.application_cache = ApplicationCache(self.desktop_path, self.username, self._progress_proxy)
        self.user_activities = UserActivites(self.desktop_path, self.username, self._progress_proxy)
        self.security_check = SecurityCheck(self.desktop_path, self.username, self._progress_proxy)
        self.final_report = FinalReport(self.desktop_path)

    def _progress_proxy(self, check, success=True):
        if success:
            SysMiner.checknum[check] = 1
        self.progress_callback(check, success)

    def extract_all(self):
        if self.selected_tasks[0]: self.browser_history.get_chrome_history(0); SysMiner.checked_tasks += 1;
        if self.selected_tasks[1]: self.browser_history.get_chrome_cookie(1); SysMiner.checked_tasks += 1;
        if self.selected_tasks[2]: self.browser_history.get_chrome_cache(2); SysMiner.checked_tasks += 1;
        if self.selected_tasks[3]: self.browser_history.get_edge_history(3); SysMiner.checked_tasks += 1;
        if self.selected_tasks[4]: self.browser_history.get_edge_cookie(4); SysMiner.checked_tasks += 1;
        if self.selected_tasks[5]: self.browser_history.get_edge_cache(5); SysMiner.checked_tasks += 1;
        if self.selected_tasks[6]: self.system_logs.get_eventlog(6); SysMiner.checked_tasks += 1;
        if self.selected_tasks[7]: self.system_logs.get_firewall_log(7); SysMiner.checked_tasks += 1;
        if self.selected_tasks[8]: self.application_cache.get_prefetch(8); SysMiner.checked_tasks += 1;
        if self.selected_tasks[9]: self.application_cache.get_srum(9); SysMiner.checked_tasks += 1;
        if self.selected_tasks[10]: self.user_activities.get_quicklaunch(10); SysMiner.checked_tasks += 1;
        if self.selected_tasks[11]: self.user_activities.get_recent(11); SysMiner.checked_tasks += 1;
        if self.selected_tasks[12]: self.user_activities.get_recycle(12); SysMiner.checked_tasks += 1;
        if self.selected_tasks[13]:
            self.security_check.run_command(13, "Firewall_Status", "Get-NetFirewallProfile | Select-Object -Property Name, Enabled")
            SysMiner.checked_tasks += 1
        if self.selected_tasks[14]:
            self.security_check.run_command(14, "Windows_Update", "Get-WindowsUpdateLog")
            SysMiner.checked_tasks += 1
        if self.selected_tasks[15]:
            self.security_check.run_command(15, "Installed_Software", "Get-WmiObject -Class Win32_Product | Select-Object -Property Name, Version")
            SysMiner.checked_tasks += 1
        if self.selected_tasks[16]:
            self.security_check.run_command(16, "Password_Policy", "Get-LocalUser | Select-Object -Property Name, PasswordNeverExpires, UserMayNotChangePassword")
            SysMiner.checked_tasks += 1

    def run(self):
        self.extract_all()
        self.final_report.generate_html_report()

class StartManager: # 윈도우 시작 프로그램 등록 클래스

    run_key = r"Software\Microsoft\Windows\CurrentVersion\Run"

    @staticmethod
    def register(app_name, exe_path, state):
        try:
            key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            StartManager.run_key,
            0,
            winreg.KEY_SET_VALUE
            )
            command = f'"{exe_path}" {state}'.strip()
            winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, command)
            key.close()
        except Exception as e:
            pass

    @staticmethod
    def unregister(app_name: str):
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                StartManager.run_key,
                0,
                winreg.KEY_SET_VALUE
            )
            winreg.DeleteValue(key, app_name)
            key.Close()
        except FileNotFoundError:
            pass

    @staticmethod
    def is_registered(app_name:str) -> bool:
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                StartManager.run_key,
                0,
                winreg.KEY_READ
            )
            winreg.QueryValueEx(key, app_name)
            key.Close()
            return True
        except FileNotFoundError:
            return False
        except Exception:
            return False

class Admin: # 프로그램 관리자 권한 실행 클래스
    @staticmethod
    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    @staticmethod
    def run_as_admin():
        if not Admin.is_admin():
            messagebox.showinfo("관리자 권한 실행",
                                "본 프로그램은 관리자 권한으로 실행되어야 합니다. \n\n"
                                "잠시 후 관리자 권한을 요청하는 창이 뜨면,\n"
                                "'예' 버튼을 눌러 권한을 부여해 주세요.\n"
                                "프로그램이 관리자 권한으로 실행됩니다."
                                )
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit()

class ConfigManager: # 추출일 저장 클래스
    def __init__(self, filename: str = None):
        if filename:
            self.config_path = filename
        else:
            appdata = os.getenv("APPDATA", os.path.expanduser("~"))
            cfg_dir = os.path.join(appdata, "SysMiner")
            os.makedirs(cfg_dir, exist_ok=True)
            self.config_path = os.path.join(cfg_dir, "config.json")
        self.config = {}
        self.load()

    def load(self) -> dict:
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                self.config = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.config = {}
        return self.config

    def save(self) -> None:
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(self.config, f, indent=2, ensure_ascii=False)

    def get(self, key: str, default=None):
        return self.config.get(key, default)

    def set(self, key: str, value) -> None:
        self.config[key] = value
        self.save()

class BrowserHistories:  # 브라우저 정보 복사
    def __init__(self, desktop_path, username, progress_callback):
        self.desktop_path = desktop_path
        self.username = username
        self.progress_callback = progress_callback
        self.source = f"C:\\Users\\{self.username}\\AppData\\Local"

    def get_chrome_history(self, check):
        path = os.path.join(self.desktop_path, "Chrome_Info")
        folder_path = os.path.join(path, "Chrome_History")
        os.makedirs(folder_path, exist_ok=True)

        source = os.path.join(self.source, "Google", "Chrome", "User Data", "Default", "History")

        self.copy_folder(source, folder_path, check)

    def get_chrome_cookie(self, check):
        path = os.path.join(self.desktop_path, "Chrome_Info")
        folder_path = os.path.join(path, "Chrome_Cookie")
        os.makedirs(folder_path, exist_ok=True)

        source = os.path.join(self.source, "Google", "Chrome", "User Data", "Default", "Network", "Cookies")

        self.copy_folder(source, folder_path, check)

    def get_chrome_cache(self, check):
        path = os.path.join(self.desktop_path, "Chrome_Info")
        folder_path = os.path.join(path, "Chrome_Cache")
        os.makedirs(folder_path, exist_ok=True)

        source = os.path.join(self.source, "Google", "Chrome", "User Data", "Default", "Cache", "Cache_Data")

        self.copy_folder(source, folder_path, check)

    def get_edge_history(self, check):
        path = os.path.join(self.desktop_path, "Edge_Info")
        folder_path = os.path.join(path, "Edge_History")
        os.makedirs(folder_path, exist_ok=True)

        source = os.path.join(self.source, "Microsoft", "Edge", "User Data", "Default", "History")

        self.copy_folder(source, folder_path, check)

    def get_edge_cookie(self, check):
        path = os.path.join(self.desktop_path, "Edge_Info")
        folder_path = os.path.join(path, "Edge_Cookie")
        os.makedirs(folder_path, exist_ok=True)

        source = os.path.join(self.source, "Microsoft", "Edge", "User Data", "Default", "Network", "Cookies")

        self.copy_folder(source, folder_path, check)

    def get_edge_cache(self, check):
        path = os.path.join(self.desktop_path, "Edge_Info")
        folder_path = os.path.join(path, "Edge_Cache")
        os.makedirs(folder_path, exist_ok=True)

        source = os.path.join(self.source, "Microsoft", "Edge", "User Data", "Default", "Cache", "Cache_Data")

        self.copy_folder(source, folder_path, check)

    def copy_folder(self, source, dest, check):
        if (
            check == 0 or
            check == 1 or
            check == 3 or
            check == 4
        ):
            try:
                shutil.copy(source, dest)
                self.progress_callback(check)
            except Exception as e:
                self.progress_callback(check, False)
        else:
            try:
                shutil.copytree(source, dest, dirs_exist_ok=True)
                self.progress_callback(check)
            except Exception as e:
                self.progress_callback(check, False)
                pass

class SystemLogs:  # 시스템 로그들 복사

    def __init__(self, desktop_path, username, progress_callback):
        self.desktop_path = desktop_path
        self.username = username
        self.progress_callback = progress_callback
        self.source = "C:\\Windows\\System32"

    def get_eventlog(self, check):
        event_path = os.path.join(self.source, "winevt", "Logs")
        event_dest = os.path.join(self.desktop_path, "Event_Logs")

        try:
            shutil.copytree(event_path, event_dest, dirs_exist_ok=True)
            self.progress_callback(check)
        except Exception as e:
            self.progress_callback(check, False)

    def get_firewall_log(self, check):
        firewall_path = os.path.join(self.source, "LogsFiles", "Firewall", "pfirewall.log")
        old_firewall_path = os.path.join(firewall_path, "LogFiles", "Firewall", "pfirewall.log.old")
        firewall_dest = os.path.join(self.desktop_path, "Firewall_Logs")

        try:
            shutil.copy(firewall_path, firewall_dest)
            shutil.copy(old_firewall_path, firewall_dest)
            self.progress_callback(check)
        except Exception as e:
            self.progress_callback(check, False)

class ApplicationCache:  # 프래패치, srum 복사
    def __init__(self, desktop_path, username, progress_callback):
        self.desktop_path = desktop_path
        self.username = username
        self.progress_callback = progress_callback

    def get_prefetch(self, check):
        prefetch_path = "C:\\Windows\\Prefetch"
        prefetch_dest = os.path.join(self.desktop_path, "Prefetch")

        try:
            shutil.copytree(prefetch_path, prefetch_dest, dirs_exist_ok=True)
            self.progress_callback(check)
        except Exception as e:
            self.progress_callback(check, False)

    def get_srum(self, check):
        srum_path = "C:\\Windows\\System32\\sru"
        srum_dest = os.path.join(self.desktop_path, "Srum")

        try:
            shutil.copytree(srum_path, srum_dest, dirs_exist_ok=True)
            self.progress_callback(check)
        except Exception as e:
            self.progress_callback(check, False)

class UserActivites:  # 사용자 활동 기록 복사

    def __init__(self, desktop_path, username, progress_callback):
        self.desktop_path = desktop_path
        self.username = username
        self.progress_callback = progress_callback
        self.source = f"C:\\Users\\{self.username}\\AppData\\Roaming\\Microsoft"

    def get_quicklaunch(self, check):
        quicklaunch_path = os.path.join(self.source, "Internet Explorer", "Quick Launch")
        quicklaunch_dest = os.path.join(self.desktop_path, "QuickLaunch")
        self.copy_folder(quicklaunch_path, quicklaunch_dest, check)

    def get_recent(self, check):
        recent_path = os.path.join(self.source, "Windows", "Recent")
        recent_dest = os.path.join(self.desktop_path, "Recent")

        self.copy_folder(recent_path, recent_dest, check)

    def get_recycle(self, check):
        recycle_path = "C:\\$Recycle.Bin"
        recycle_dest = os.path.join(self.desktop_path, "RecycleBin")
        self.copy_folder(recycle_path, recycle_dest, check)

    def copy_folder(self, source_path, dest_path, check):
        try:
            shutil.copytree(source_path, dest_path, dirs_exist_ok=True)
            self.progress_callback(check)
        except Exception as e:
            self.progress_callback(check, False)

class SecurityCheck:  # 방화벽 상태, 윈도우 업데이트 기록, 설치된 소프트웨어, 패스워드 정책 확인

    def __init__(self, desktop_path, username, progress_callback):
        self.desktop_path = desktop_path
        self.username = username
        self.progress_callback = progress_callback
        self.folder_path = os.path.join(self.desktop_path, "Security_Check")

    def run_command(self, check, file_name, command):
        try:
            os.makedirs(self.folder_path, exist_ok=True)
            result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True)
            output = result.stdout
            file_path = f"{self.folder_path}\\{file_name}.txt"
            with open(file_path, 'w', encoding="utf-8") as file:
                file.write(output)
            if os.path.exists(f"C:\\Users\\{self.username}\\Desktop\\WindowsUpdate.log"):
                shutil.move(f"C:\\Users\\{self.username}\\Desktop\\WindowsUpdate.log",
                            f"{self.folder_path}\\Windows_Update.log")
            self.progress_callback(check)
        except Exception as e:
            print(f"{e}")
            self.progress_callback(check, False)

class BackgroundAlarming: # 백그라운드 검사 및 알람 클래스
    def __init__(self, progress_callback, selected_tasks, directory_path=None):
        self.cfg = ConfigManager()
        last_date = self.cfg.get("last_extracted_date", None)
        if last_date:
            try:
                self.last_extracted_date = datetime.fromisoformat(last_date).date()
            except ValueError:
                self.last_extracted_date = None
        else:
            self.last_extracted_date = None

        self.username = getpass.getuser()
        self.progress_callback = progress_callback
        self.selected_tasks = selected_tasks

        self.cpu_threshold = 80
        self.directory_path = directory_path
        self.alert_period_days = self.cfg.get("alert_period_days", None)
        self.last_alert_date = None
        self.stop_event = threading.Event()

    def monitor_cpu(self):
        while not self.stop_event.is_set():
            usage = psutil.cpu_percent(interval=1)
            if usage >= self.cpu_threshold:
                messagebox.showwarning("CPU 경고",
                                       f"CPU 사용량이 {usage}%로 임계치를 초과했습니다.")
            if self.stop_event.wait(600):
                break

    def check_file_extensions(self):
        while not self.stop_event.is_set():
            if self.directory_path:
                for file_name in os.listdir(self.directory_path):
                    full_path = os.path.join(self.directory_path, file_name)
                    _, ext = os.path.splitext(file_name)
                    if ext.lower() in [".locked", ".enc", ".encrypted", ".crypt", ".crypt1"]:
                        messagebox.showwarning("파일 확장자 경고",
                                               f"파일 {file_name}의 확장자가 비정상입니다.")
            if self.stop_event.wait(7200):
                break

    def check_last_extracted_date(self):
        while not self.stop_event.is_set():
            if self.last_extracted_date and self.alert_period_days is not None:
                today = datetime.now().date()
                expiration = self.last_extracted_date + timedelta(days=self.alert_period_days)
                if today > expiration:
                    self.show_alert()
            if self.stop_event.wait(86400):
                break

    def show_alert(self):
        today = datetime.now().date()
        if self.last_alert_date != today:
            messagebox.showinfo("알림",
                                f"마지막 추출일로부터 {self.alert_period_days}일이 경과했습니다. 프로그램 정보를 최신화하세요.")
            self.last_alert_date = today

    def set_last_extracted_date(self, date_obj):
        self.last_extracted_date = date_obj
        self.cfg.set("last_extracted_date", date_obj.isoformat())

    def set_alert_period(self, days):
        self.alert_period_days = days
        self.cfg.set("alert_period_days", days)

    def run(self):
        threading.Thread(target=self.monitor_cpu, daemon=True).start()
        threading.Thread(target=self.check_file_extensions, daemon=True).start()
        threading.Thread(target=self.check_last_extracted_date, daemon=True).start()

    def stop(self):
        self.stop_event.set()

class FinalReport: # 결과 보고서 생성 클래스
    def __init__(self, desktop_path):
        self.desktop_path = desktop_path
    @staticmethod
    def sep_col(arr):
        dic = {}
        chk = 0
        for line in arr:
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                if key == "프로세서":
                    dic[key] = []
                    chk = 1

                elif key == "핫픽스":
                    dic[key] = []
                    chk = 2

                elif key == "네트워크 카드":
                    break

                elif key.startswith("[") and chk == 1:
                    if "프로세서" in dic:
                        dic["프로세서"].append(value)

                elif key.startswith("[") and chk == 2:
                    if "핫픽스" in dic:
                        dic["핫픽스"].append(value)
                else:
                    dic[key] = value
                    chk = 0
        return dic
    def get_system_info(self):
        system_info = subprocess.check_output('systeminfo', encoding='cp949').strip().split('\n')
        system_info_dic = self.sep_col(system_info)

        process_info = {}
        for proc in psutil.process_iter(attrs=['pid', 'name']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                connections = proc.net_connections(kind='inet')
                process_info[pid] = {
                    'name': name,
                    'ports': [conn.laddr.port for conn in connections]
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        open_ports = set()
        for info in process_info.values():
            open_ports.update(info['ports'])

        return {
            "system_info": system_info_dic,
            "process": process_info,
            "open_ports": sorted(open_ports)
        }

    def generate_html_report(self):
        os.makedirs(self.desktop_path, exist_ok=True)
        html_file = os.path.join(self.desktop_path, 'REPORT.html')
        data = self.get_system_info()
        system_info = data.get("system_info", {})
        process = data.get("process", {})
        open_ports = data.get("open_ports", [])

        html_content = '''
        <html>
        <head>
            <title>System Info Report</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f4;
                    margin: 0;
                    padding: 20px;
                }
                h1 {
                    text-align: center;
                    color: #333;
                }
                table {
                    width: 80%;
                    margin: 20px auto;
                    border-collapse: collapse;
                    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                }
                th, td {
                    padding: 12px;
                    text-align: left;
                    border: 1px solid #ddd;
                }
                th {
                    background-color: #4CAF50;
                    color: white;
                }
                tr:nth-child(even) {
                    background-color: #f2f2f2;
                }
                tr:hover {
                    background-color: #ddd;
                }
                ul {
                    width: 80%;
                    margin: 20px auto;
                    list-style: none;
                    padding: 0;
                }
                li.collected {
                    background-color: #d4edda;
                    color: #155724;
                    padding: 10px;
                    border-left: 5px solid #28a745;
                    margin-bottom: 5px;
                }
                li.not-collected {
                    background-color: #f8d7da;
                    color: #721c24;
                    padding: 10px;
                    border-left: 5px solid #dc3545;
                    margin-bottom: 5px;
                }
            </style>
        </head>
        <body>
            <h1>OVERVIEW</h1>
            <table>
                <tr>
                    <th>항목</th>
                    <th>값</th>
                </tr>
        '''

        for key, value in system_info.items():
            html_content += f'<tr><td>{key}</td><td>{value}</td></tr>\n'

        html_content += '''
            </table>
            <table>
                <tr>
                    <th>프로세스 수</th>
                    <th>열린 포트 수</th>
                </tr>
                <tr>
        '''
        html_content += f'<td>{len(process)}</td><td>{len(open_ports)}</td>\n'
        html_content += '''
                </tr>
            </table>
            <ul>
        '''

        for i in range(len(SysMiner.checklist)):
            item = SysMiner.checklist[i]
            if SysMiner.checknum[i]:
                html_content += f'<li class="collected">✔️ {item} (수집됨)</li>\n'
            else:
                html_content += f'<li class="not-collected">❌ {item} (수집되지 않음)</li>\n'

        html_content += '''
            </ul>
        </body>
        </html>
        '''

        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

class SysMinerGUI: # 메인 GUI 생성 및 추출 시작 클래스
    def __init__(self, root):
        self.root = root
        self.root.title("SysMiner")
        self.root.geometry("730x310")

        self.selected_checks = [tk.BooleanVar() for _ in range(SysMiner.total_tasks)]

        self.build_intro_frame()

        self.selected = [var.get() for var in self.selected_checks]
        self.miner = SysMiner(progress_callback=self._progress_proxy, selected_tasks=[False]*SysMiner.total_tasks)

        self.cfg = ConfigManager()
        saved_period = self.cfg.get("alert_period_days", None)
        if isinstance(saved_period, int):
            self.period_entry.insert(0, str(saved_period))
            self.monitor.set_alert_period(saved_period)

        self.monitor = BackgroundAlarming(progress_callback=self._progress_proxy, selected_tasks=self.selected, directory_path=f"C:\\Users\\{getpass.getuser()}\\Desktop")
        initial_check = StartManager.is_registered("SysMiner")
        self.auto_scan.set(initial_check)
        if initial_check:
            self.monitor.run()

        self.build_progress_frame()

    def build_intro_frame(self):
        self.intro_frame = tk.Frame(self.root)
        self.intro_frame.pack(fill="both", expand=True)

        left_frame = tk.Frame(self.intro_frame)
        left_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        self.auto_scan = tk.BooleanVar(value=False)
        auto_scan = tk.Checkbutton(
            left_frame,
            text="자동 검사 활성화",
            variable=self.auto_scan,
            command = self.set_autoscan
        )
        auto_scan.pack(anchor="w", pady=5)

        msg = (
            " 🛡️시스템 정보 수집 도구입니다.\n\n"
            "✅   필요에 따라 항목을 선택하고\n"
            "⏭️   '다음' 버튼을 눌러 수집을 시작하세요.\n\n"
            "⚠️   방화벽 로그는 방화벽 로깅이 활성화돼있어야합니다.\n"
        )
        msg_label = tk.Label(left_frame, text=msg, justify="left", font=("Arial", 11))
        msg_label.pack(anchor="nw", fill="both", expand=True)

        self.period_frame = tk.Frame(left_frame)
        self.period_frame.pack(side="top", pady=5)

        self.period_label = tk.Label(self.period_frame, text="검사 주기 설정 (일):", font=("Arial", 12))
        self.period_label.pack(side="left", padx=5)

        self.period_entry = tk.Entry(self.period_frame, font=("Arial", 12))
        self.period_entry.pack(side="left", padx=5)

        self.set_period_button = tk.Button(self.period_frame, text="설정", command=self.set_alert_period)
        self.set_period_button.pack(side="left", pady=5)

        right_frame = tk.Frame(self.intro_frame)
        right_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)

        canvas = tk.Canvas(right_frame)
        scrollbar = ttk.Scrollbar(right_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        rows = [
            [0, 1, 2],
            [3, 4, 5],
            [6, 7],
            [8, 9],
            [10, 11, 12],
            [13, 14],
            [15, 16],
        ]

        for row in rows:
            row_frame = tk.Frame(scrollable_frame)
            row_frame.pack(anchor="w", pady=5)
            for idx in row:
                cb = tk.Checkbutton(row_frame, text=SysMiner.checklist[idx], variable=self.selected_checks[idx])
                cb.pack(side="right", padx=5)

        button_frame = tk.Frame(scrollable_frame)
        button_frame.pack(side="top", pady=10, fill="x")

        self.select_all_button = tk.Button(button_frame, text="전체 선택", command=self.select_all)
        self.select_all_button.pack(side="left", padx=10)

        self.deselect_all_button = tk.Button(button_frame, text="전체 해제", command=self.deselect_all)
        self.deselect_all_button.pack(side="left", padx=10)


        self.next_button = tk.Button(button_frame, text="다음 ▶", command=self.start_collection)
        self.next_button.pack(side="right", padx=10)

    def set_autoscan(self):
        if self.auto_scan.get():
            StartManager.register("SysMiner", sys.executable, "--silent")
            self.monitor.run()
            messagebox.showinfo("자동 검사",
                                "시작 프로그램 등록이 완료되었습니다.\n"
                                "컴퓨터 부팅시, 자동으로 프로그램이 검사를 실시합니다.")
        else:
            StartManager.unregister("SysMiner")
            self.monitor.stop()
            messagebox.showinfo("자동 검사", "자동 검사가 해제되었습니다.")


    def deselect_all(self):
        for check in self.selected_checks:
            check.set(False)

    def select_all(self):
        for check in self.selected_checks:
            check.set(True)

    def set_alert_period(self):
        try:
            alert_period = int(self.period_entry.get())
            self.monitor.set_alert_period(alert_period)
            self.cfg.set("alert_period_days", alert_period)
            messagebox.showinfo("설정 완료", f"알림 주기가 {alert_period}일로 설정되었습니다.")
        except ValueError:
            messagebox.showerror("입력 오류", "유효한 숫자를 입력해 주세요.")

    def build_progress_frame(self):
        self.progress_frame = tk.Frame(self.root)

        self.progress_label = tk.Label(self.progress_frame, text="수집 준비 중...", font=("Arial", 12))
        self.progress_label.pack(pady=10)

        self.progress = ttk.Progressbar(self.progress_frame, length=400, mode="determinate", maximum=SysMiner.checked_tasks)
        self.progress.pack(pady=10)

        self.progress_text = ScrolledText(self.progress_frame, height=10, width=70, font=("Arial", 10))
        self.progress_text.pack(pady=10)

        self.progress_text.tag_configure("success", foreground="green")
        self.progress_text.tag_configure("fail", foreground="red")

        self.progress_text.configure(state="disabled")

    def start_collection(self):
        chrome_list = [0, 1, 2]
        edge_list = [3, 4, 5]

        if any(self.selected_checks[i].get() for i in chrome_list):
            answer = messagebox.askyesno(
                "경고",
                "Chrome 관련 항목이 선택되었습니다\n"
                "원활한 수집을 위해 Chrome 브라우저를 강제 종료합니다\n"
                "계속 하시겠습니까?"
            )
            if answer:
                for p in psutil.process_iter(["name"]):
                    if p.info["name"] and p.info["name"].lower().startswith("chrome"):
                        try: p.kill()
                        except: pass
            else:
                return

        if any(self.selected_checks[i].get() for i in edge_list):
            answer = messagebox.askyesno(
                "경고",
                "Edge 관련 항목이 선택되었습니다\n"
                "원활한 수집을 위해 Edge 브라우저를 강제 종료합니다\n"
                "계속 하시겠습니까?"
            )
            if answer:
                for p in psutil.process_iter(["name"]):
                    if p.info["name"].lower().startswith("edge"):
                        try: p.kill()
                        except: pass
            else:
                return

        self.intro_frame.pack_forget()
        self.progress_frame.pack(fill="both", expand=True)
        self.root.update()

        self.miner.selected_tasks = [var.get() for var in self.selected_checks]
        checked_task_count = sum(self.miner.selected_tasks)
        self.progress["maximum"] = checked_task_count

        threading.Thread(target=self.run_sysminer, daemon=True).start()

    def run_sysminer(self):
        try:
            self.miner.run()
            today = datetime.now().date()
            self.monitor.set_last_extracted_date(today)
            self.cfg.set("last_extracted_date", today.isoformat())
            self.progress_label.config(text="✅ 수집 완료! HTML 리포트가 생성되었습니다.")
        except Exception as e:
            messagebox.showerror("에러", f"실행 중 문제 발생: {e}")

    def _progress_proxy(self, index, success=True):
        name = SysMiner.checklist[index]
        current = int(self.progress["value"]) + 1
        max_val = int(self.progress["maximum"])
        status_text = f"[{current}/{max_val}] {name} {'수집 완료 ✅' if success else '수집 실패 ❌'}\n"

        self.progress_label.config(text=status_text.strip())
        self.progress["value"] = current

        self.progress_text.configure(state="normal")
        tag = "success" if success else "fail"
        self.progress_text.insert(tk.END, status_text, tag)
        self.progress_text.see(tk.END)
        self.progress_text.configure(state="disabled")

        self.root.update_idletasks()

if __name__ == "__main__":
    admin = Admin()
    admin.run_as_admin()

    if "--silent" in sys.argv:
        user = getpass.getuser()
        check_path = f"C:\\Users\\{user}\\Desktop"
        monitor = BackgroundAlarming(
            None,
            selected_tasks=[],
            directory_path=check_path
        )
        monitor.run()
        while True:
            time.sleep(86400)
    else:
        root = tk.Tk()
        app = SysMinerGUI(root)
        root.mainloop()

