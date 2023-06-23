from subprocess import Popen, PIPE
import signal
import os
import re

class iptools():
	def __init__(self):
		pass

	def randomize_mac(self, interface):
		"""Uses Macchanger -r to change Mac"""
		cmds=['ifconfig '+str(interface)+' down',
					'macchanger -r '+str(interface),
					'ifconfig '+str(interface)+' up']
		for cmd in cmds:
			proc=Popen(cmd.split(' '), stdin=PIPE, stdout=PIPE, stderr=PIPE)
			proc.wait()

	def change_channel(self, interface, channel):
		"""Uses iptools to change interfaces channel"""
		cmds=[
			'iwconfig '+str(interface)+' channel '+str(channel)
		]
		for cmd in cmds:
			proc=Popen(cmd.split(' '), stdin=PIPE, stdout=PIPE, stderr=PIPE)
			proc.wait()
		
	def check_monitor_mode(self, interface):
		mode = re.findall('Mode:[A-Za-z]+', Popen(['iwconfig',str(interface)], stdout=PIPE, encoding='utf-8').communicate()[0])[0]
		if 'Monitor' in mode: return True
		else: return False
