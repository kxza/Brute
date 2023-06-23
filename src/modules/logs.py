import pickle
import time
import os

class Logger:
	"""Logging Module, functions for logging and disk operations"""
	def __init__(self): # {{{
		self.accesspfile = 'accessp.csv'
		self.clientsfile = 'clients.csv'
	# }}}
	def log(self, string): # {{{
		pass
	# }}}
	def save_db(self, db, file): # {{{
		"""Dumps db into file"""
		with open(file, 'wb') as df:
			pickle.dump(db, df)
	# }}}
	def load_db(self, file): # {{{
		"""Loads file and returns, if file doesnt exist, returns False"""
		if os.path.exists(file):
			with open(file, 'rb') as df:
				db = pickle.load(df)
				return db
		else:
			return False
	# }}}
