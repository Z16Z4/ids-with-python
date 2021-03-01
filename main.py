from scapy.all import *
from datetime import datetime
import requests, os, re, ssh_log, ids

def main():
    choice = input("admin@ids> ")
    if choice == 'ssh_log':
        ssh_log.ssh_log()
        main()
    elif choice == 'tcp_ids':
        ids.main()
        main()
    elif choice == 'close':
        exit = input("wish to exit (y/n)")
        if exit == 'n':
            print("Not exiting")
            main()
        elif exit == 'y':
            print("Bye!")
        else:
            print("Please try again")
            main()
    elif choice == 'help':
        print("commands:")
        print("ssh_log - (SSH auth logs)")
        print("tcp_ids - (for IDS system)")
        print("close - (terminate program)")
        main()
    else:
        print("Not a possible command")
        print("try entering help to see current commands")
        main()
    

main()
