import requests
import json
import os
import subprocess
import time
import sys
import logging
import tkinter as tk
from tkinter import scrolledtext
from threading import Thread, Event

# 设置输出编码为 UTF-8


# 自定义日志处理器
class ScrolledTextHandler(logging.Handler):
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record):
        msg = self.format(record)

        def append():
            self.text_widget.insert(tk.END, msg + '\n')
            self.text_widget.see(tk.END)

        self.text_widget.after(0, append)


# 通用函数递归提取代理信息
def extract_proxy_info(data):
    logging.debug(f"解析返回的数据: {data}")

    possible_keys = {
        "ip": ["IP", "ip", "IpAddress", "ip_address"],
        "port": ["Port", "port"],
        "address": ["Address", "address", "Location", "location", "IpAddress", "ip_address"]
    }

    def recursive_extract(data, keys):
        if isinstance(data, dict):
            for key, value in data.items():
                if key in keys:
                    return value
                elif isinstance(value, (dict, list)):
                    result = recursive_extract(value, keys)
                    if result is not None:
                        return result
        elif isinstance(data, list):
            for item in data:
                result = recursive_extract(item, keys)
                if result is not None:
                    return result
        return None

    ip = recursive_extract(data, possible_keys["ip"])
    port = recursive_extract(data, possible_keys["port"])
    address = recursive_extract(data, possible_keys["address"])

    if not ip or not port:
        raise Exception("无法从返回的数据中提取IP和端口")

    return ip, port, address


# 从API获取代理IP和端口
def get_proxy(api_url):
    response = requests.get(api_url)
    response.encoding = 'utf-8'  # 确保正确解析中文

    # 添加详细的日志记录
    logging.debug(f"API返回的原始数据: {response.text}")

    try:
        data = response.json()
        logging.debug(f"API返回的数据: {data}")

        ip, port, address = extract_proxy_info(data)
        logging.info(f"获取到的代理IP: {ip}, 端口: {port}, 地址: {address if address else '未知地址'}")
        return ip, port, address
    except Exception as e:
        logging.error(f"解析数据时发生错误: {e}")
        logging.error(f"无法解析的原始数据: {response.text}")
        raise


# 配置HTTP代理
def set_http_proxy(ip, port):
    os.environ['HTTP_PROXY'] = f"http://{ip}:{port}"
    os.environ['HTTPS_PROXY'] = f"http://{ip}:{port}"


# 关闭HTTP代理
def disable_http_proxy():
    if 'HTTP_PROXY' in os.environ:
        del os.environ['HTTP_PROXY']
    if 'HTTPS_PROXY' in os.environ:
        del os.environ['HTTPS_PROXY']
    logging.info("已关闭Python HTTP代理")


# 设置Windows全局代理
def set_windows_proxy(ip, port):
    proxy = f"{ip}:{port}"
    command_enable = [
        'reg', 'add', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings', '/v', 'ProxyServer',
        '/t', 'REG_SZ', '/d', proxy, '/f'
    ]
    command_enable_proxy = [
        'reg', 'add', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings', '/v', 'ProxyEnable',
        '/t', 'REG_DWORD', '/d', '1', '/f'
    ]
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    subprocess.run(command_enable, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=startupinfo)
    subprocess.run(command_enable_proxy, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=startupinfo)
    logging.info("已设置Windows全局代理")


# 关闭Windows全局代理
def disable_windows_proxy():
    command_disable_proxy = [
        'reg', 'add', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings', '/v', 'ProxyEnable',
        '/t', 'REG_DWORD', '/d', '0', '/f'
    ]
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    subprocess.run(command_disable_proxy, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=startupinfo)
    logging.info("已关闭Windows全局代理")


# 访问百度并检查HTTP状态码
def check_baidu():
    url = "http://www.baidu.com"
    try:
        response = requests.get(url)
        logging.info(f"HTTP状态码: {response.status_code}")
        logging.info(f"响应头: {response.headers}")
        if response.status_code == 200:
            logging.info("访问成功")
            return True
        else:
            logging.warning("访问失败: HTTP状态码不为200")
            return False
    except Exception as e:
        logging.error(f"访问失败: {e}")
        return False


def run_proxy(api_url, stop_event, switch_interval):
    try:
        while not stop_event.is_set():
            try:
                disable_windows_proxy()
                disable_http_proxy()
                ip, port, address = get_proxy(api_url)
                set_http_proxy(ip, port)
                if check_baidu():
                    set_windows_proxy(ip, port)
                for _ in range(switch_interval):
                    if stop_event.is_set():
                        break
                    time.sleep(1)
            except Exception as e:
                logging.error(f"发生错误: {e}")
                for _ in range(switch_interval):
                    if stop_event.is_set():
                        break
                    time.sleep(1)
    finally:
        disable_windows_proxy()
        disable_http_proxy()
        logging.info("代理已停止，所有代理设置已清除")


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("IP代理")

        self.api_label = tk.Label(root, text="API地址:")
        self.api_label.grid(row=0, column=0, padx=10, pady=10)

        self.api_entry = tk.Entry(root, width=50)
        self.api_entry.grid(row=0, column=1, padx=10, pady=10)

        self.interval_label = tk.Label(root, text="切换间隔(秒):")
        self.interval_label.grid(row=0, column=2, padx=10, pady=10)

        self.interval_entry = tk.Entry(root, width=10)
        self.interval_entry.insert(0, "10")  # 默认值为10秒
        self.interval_entry.grid(row=0, column=3, padx=10, pady=10)

        self.start_button = tk.Button(root, text="启动代理", command=self.toggle_proxy)
        self.start_button.grid(row=0, column=4, padx=10, pady=10)

        self.console = scrolledtext.ScrolledText(root, width=100, height=30)
        self.console.grid(row=1, column=0, columnspan=5, padx=10, pady=10)

        # 添加自定义日志处理器
        handler = ScrolledTextHandler(self.console)
        handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logging.getLogger().addHandler(handler)

        # 设置日志记录器的级别
        logging.getLogger().setLevel(logging.DEBUG)

        self.proxy_thread = None
        self.stop_event = Event()

    def toggle_proxy(self):
        if self.proxy_thread is None or not self.proxy_thread.is_alive():
            api_url = self.api_entry.get()
            try:
                switch_interval = int(self.interval_entry.get())
                if api_url and switch_interval > 0:
                    self.stop_event.clear()
                    self.proxy_thread = Thread(target=self.run_proxy_thread, args=(api_url, switch_interval),
                                               daemon=True)
                    self.proxy_thread.start()
                    self.start_button.config(text="停止代理")
                    logging.info("代理已启动")
                else:
                    logging.error("请提供有效的API地址和切换间隔")
            except ValueError:
                logging.error("请提供有效的切换间隔")
        else:
            self.stop_event.set()
            self.root.after(100, self.check_thread_status)

    def check_thread_status(self):
        if self.proxy_thread.is_alive():
            self.root.after(100, self.check_thread_status)
        else:
            self.start_button.config(text="启动代理")
            logging.info("代理已停止")

    def run_proxy_thread(self, api_url, switch_interval):
        run_proxy(api_url, self.stop_event, switch_interval)


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()