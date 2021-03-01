from scapy.all import *
from datetime import datetime
import requests, os, re


def ssh_log():
    user_input = input("please make sure your running this as root!")
    os.system('apt install net-tools -y')
    os.system('ifconfig | grep "flags"')
    adapter = input("what adapter are you using (example: wlan0) : ")
    os.system('sudo cat /var/log/auth.log* | grep "ssh" >> ssh_attempts')
    print('ssh logs:')
    os.system('sudo cat ssh_attempts | grep "Accepted"')
    continue_ = input(" run IDS.. enter")
