#!/usr/bin/env python3
import time
import os

class Profiler:
	"""functions to filter and profile targets"""

#------------------------------------------------------------------
# Initialization
#------------------------------------------------------------------
	def __init__(self): # {{{
		self.load_ouis()
		self.aplist = []
		self.beaconswarming = False

		### keep up with everything we've seen
		if not os.path.exists('db'):
			os.mkdir('db')
		self.beacondb = {}
		self.database = { 'access_points': {}, 'clients': {} }
		self.database_file = 'db/seen.db'
		self.beacondb_file = 'db/beacons.db'
	# }}}
	def load_ouis(self): # {{{
		"""Loads Oui List"""
		self.ouis = {}
		res = os.path.abspath(os.path.dirname(__file__))
		with open(os.path.join(res, '../oui.txt'), 'r') as ouilist:
			for line in ouilist:
				oui = line.split('|')
				self.ouis[oui[0]] = oui[1].strip()
	# }}}

#------------------------------------------------------------------
# Parsing and Profiling
# -----------------------------------------------------------------
	def read_auths(self, auths): #{{{
		for a in auths:
			try:
				auth = a.split('|')
				bssid = a[0]
				mac = a[1]
				if mac == bssid: continue
				cl = self.database['clients'][mac.replace(':','')]
				if bssid not in cl['auths']: cl['auths'].append(bssid)
			except:
				continue
	# }}}
	def parse_ap(self, l): # {{{
		"""Parses Access Point Data from a csv parsed line"""
		try:
			# (0) BSSID, (1) First time seen, (2) Last time seen, 
			# (3) channel, (4) Speed, (5) Privacy, (6) Cipher,
			# (7) Authentication, (8) Power, (9) # beacons, (10) # IV,
			# (11) LAN IP, (12) ID-length, (13) ESSID, (14) Key
			ap = {
				'bssid':		str(l[0].strip()),
				'fseen':		str(l[1].strip()),
				'lseen':		str(l[2].strip()),
				'channel':	int(l[3].strip()),
				'crypt':		str(l[5].strip()),
				'auth':			str(l[7].strip()),
				'power':		int(l[8].strip()),
				'essid':		str(l[13].strip()),
				'cracked':	False,
				'whitelisted': False,
				'handshake':False,
				'clients':	[]
			}
			# convert data
			if ap['power'] != -1: ap['power'] += 100
			ap['last_epoch'] = int(time.mktime(time.strptime(ap['lseen'],'%Y-%m-%d %H:%M:%S')))
			ap['first_epoch'] = int(time.mktime(time.strptime(ap['fseen'],'%Y-%m-%d %H:%M:%S')))
			if ap['essid'] == '': ap['essid'] = '_HIDDEN_'

			try: # search for oui
				oui = str(str(ap['bssid']).replace(':',''))[0:6]
				ap['oui'] = self.ouis[oui]
			except: # oui not found
				ap['oui'] = 'Unknown'

			# profile and return data
			self.profile_ap(ap)
			return ap
		except Exception as e:
			# if we couldnt parse for wtv reason, return False and continue operations
			raise e
			return False
	# }}} 
	def profile_ap(self, ap): # {{{
		"""Profiles Access Point into the database"""
		# parse access point data
		seen_ap = {
			'bssid':				ap['bssid'],
			'first_epoch':	ap['first_epoch'],
			'last_epoch':		ap['last_epoch'],
			'oui':					ap['oui'],
			'networks': [] #{essid:str, channel:int, crypt:str, auth:str}
		}
		bssid = str(ap['bssid']).replace(':','')
		network = { 'essid': ap['essid'], 'channel': ap['channel'],
								'crypt': ap['crypt'], 'auth': ap['auth'] }
		seen_ap['networks'].append(network)

		# profile access point
		try: #update key, if exists
			access_point = self.database['access_points'][bssid]
			# update last_epoch unless were swarming beacons
			if not self.beaconswarming: access_point['last_epoch'] = seen_ap['last_epoch']
			#check if new network
			if not network in access_point['networks']:
				access_point['networks'].append(network)
		except KeyError: # create key if doesnt exist
			self.database['access_points'][bssid] = seen_ap
	# }}}
	def parse_client(self, l): # {{{
		"""Parses Client Data from a csv parsed line"""
		try:
			# (0)Station_MAC, (1)First_time_seen, (2)Last_time_seen,
			# (3)Power, (4)#packets, (5)BSSID, (6)Probed_ESSIDs
			client = {
				'mac':		str(l[0].strip()),
				'lseen':	str(l[2].strip()),
				'fseen':	str(l[1].strip()),
				'power':	int(l[3].strip()),
				'bssid':	str(l[5].strip()),
				'probes': l[6:len(l)]
			}

			# remove empty probe requests
			if '' in client['probes']:
				client['probes'].remove('')

			# convert data
			if client['power'] != -1: client['power'] += 100
			client['last_epoch'] = int(time.mktime(time.strptime(client['lseen'],'%Y-%m-%d %H:%M:%S')))
			client['first_epoch'] = int(time.mktime(time.strptime(client['fseen'],'%Y-%m-%d %H:%M:%S')))

			try: # search for oui
				oui = str(str(client['mac']).replace(':',''))[0:6]
				client['oui'] = self.ouis[oui]
			except: # oui not found
				client['oui'] = 'Unknown'

			# profile and return data
			self.profile_client(client)
			return client
		except Exception as e:
			# if we couldnt parse for wtv reason, return False and continue operations
			raise e
			return False
	# }}}
	def profile_client(self, cl): # {{{
		"""Profiles Client into the database"""
		# parse data
		seen_cl = {
			'mac': cl['mac'],
			'oui': cl['oui'],
			'probes': cl['probes'],
			'first_epoch': cl['first_epoch'],
			'last_epoch': cl['last_epoch'],
			'auths': [],
			'bssids': []
		}
		# add associated bssid to list of bssids
		if not 'not associated' in cl['bssid']:
			seen_cl['bssids'].append(cl['bssid'].replace(':', ''))

		# profile our client
		mac = str(seen_cl['mac']).replace(':','')
		try: #updating existing key
			client = self.database['clients'][mac]
			# update times
			client['last_epoch'] = seen_cl['last_epoch']
			# check if new probe requests
			if seen_cl['probes'] != []:
				for p in seen_cl['probes']:
					if not p in client['probes']: 
						client['probes'].append(p)
			# check if new bssids
			if seen_cl['bssids'] != []:
				if not cl['bssid'] in client['bssids']:
					client['bssids'].append(cl['bssid'])
		except KeyError: # create key instead
			self.database['clients'][mac] = seen_cl
	# }}}
	def findtargets(self, data): # {{{
		"""Finds Suitable Targets from Airosuite.parse object"""
		curtime = int(time.time())
		ap_list = []
		# check access points -------------------------------
		for line in data['access_points']:
			ap = self.parse_ap(line)
			#skip if we could not parse
			if ap == False: continue

			# until proven unsuitable
			ap['suitable'] = True

			# check if hidden
			if ap['essid'] == '_HIDDEN_':
				ap['hidden'] = True
				ap['suitable'] = False
			else:
				ap['hidden'] = False
			
			# convert and check power level
			if ap['power'] < 25:
				ap['suitable'] = False

			# check freshness
			if curtime - ap['last_epoch'] >= 60: continue # dont add to list

			# ignore neg one channels
			if ap['channel'] == -1: ap['suitable'] = False

			ap_list.append(ap)

		# check clients ------------------------------------
		for line in data['clients']:
			cl = self.parse_client(line)
			#skip if we could not parse
			if cl == False: continue

			# until proven unsuitable
			cl['suitable'] = True

			# convert and check power level
			if cl['power'] < 25: cl['suitable'] = False

			# check freshness
			if curtime - cl['last_epoch'] >= 60: continue # skip if not fresh

			# check if associated
			if 'not associated' in cl['bssid']:
				cl['associated'] = False
				cl['suitable'] = False
			else:
				cl['associated'] = True
				#add client to its associated access point
				for ap in ap_list:
					if ap['bssid'] == cl['bssid']:
						ap['clients'].append(cl)

		# check which aps have clients ----------------------
		for ap in ap_list:
			if len(ap['clients']) == 0:
				ap['suitable'] = False
			else:
				# check if suitable clients exist
				scl = []
				for cl in ap['clients']:
					if cl['suitable']:
						scl.append(cl)
				if len(scl) == 0:
					ap['suitable'] = False
		return ap_list
	# }}}

#------------------------------------------------------------------
# Printing functions for our curses interface
# -----------------------------------------------------------------
	def format_ap(self, ap): # {{{
		"""Returns a Formated Access Point, suitable for printing"""

		essid = str(ap['essid'])
		if essid == '_HIDDEN_':
			essid = ' '

		columns = {
			'address': str(ap['bssid']).replace(':',''),
			'power'  : str(ap['power']),
			'oui'    : str(ap['oui']),
			'channel': str(ap['channel']),
			'network': essid,
			'client_count': str(len(ap['clients']))
		}

		attributes = []
		if ap['suitable']: attributes.append('suitable')
		if ap['handshake']: attributes.append('handshake')
		if ap['cracked']: attributes.append('cracked')
		if ap['whitelisted']: attributes.append('whitelisted')

		return[attributes, columns, ap]
	# }}}
	def format_cl(self, cl): # {{{ NEED TO CREATE
		"""Returns a Formated Client, suitable for printing"""
		pass
	# }}}
