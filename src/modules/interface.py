#!/usr/bin/env python3
import curses

class Interface:
	"""Curses Interface"""

# ------------------------------------------------------------
# Initialization and screen creation
	def __init__(self): # {{{
		self.startpos = 0 # data printing position
		self.selection = 0 # data cursur selection position
		self.body_data = []
		self.column_names = ['Pow','Ch','Cl','Essid','Bssid','Manufacturer']
		self.sort_order = 'Pow'
		self.spacer = 2 # space to the left of body and column titles
		self.cursurline_color = ''
		self.old_cursurline_color = ''
	# }}}
	def start(self): # {{{
		#cbreak mode, turns off echo, enables the terminal keypad, and initializes colors if the terminal has color support.
		self.s = curses.initscr()
		self.s.keypad(True)
		curses.start_color()
		curses.noecho()
		curses.cbreak()
		curses.curs_set(0) # hides the cursur
		self.refresh_all()
	# }}}
	def close(self): # {{{
		self.s.keypad(False)
		curses.nocbreak()
		curses.echo()
		curses.endwin()
	# }}}
	def refresh_all(self): # {{{
		"""regenerates everything"""
		try:
			self.initscr()
			self.set_colors()
			self.refresh_subwins()
			self.set_column_titles()
			self.refresh_body()
		except:
			pass
	# }}}
# ------------------------------------------------------------
# Order of refresh_all
	def initscr(self): # {{{
		"""Creates each subwin, and sets Terminal Bounds"""

		# get coordinate plane
		self.maxY, self.maxX = self.s.getmaxyx()
		self.bodyMaxY, self.bodyMaxX = self.maxY - 4, self.maxX

		# create subwins
		self.title = self.s.subwin(1, self.maxX, 0, 0)
		self.header = self.s.subwin(1, self.maxX, 1, 0)
		self.footer = self.s.subwin(1, self.maxX, self.maxY-2, 0)
		self.status = self.s.subwin(1, self.maxX, self.maxY-1, 0)

		# create main body
		self.body = curses.newpad(self.maxY-4, self.maxX)
		self.body.keypad(1) # allows arrow keys
		self.body.nodelay(True) # Non-Blocking getch()
	# }}}
	def set_colors(self): # {{{
		"""Defines and sets our colors"""
		curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_GREEN)
		curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
		curses.init_pair(3, curses.COLOR_WHITE, curses.COLOR_BLUE)
		curses.init_pair(4, curses.COLOR_WHITE, curses.COLOR_RED)
		curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_CYAN)
		curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_BLACK)
		curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_MAGENTA)
		curses.init_pair(8, curses.COLOR_BLUE, curses.COLOR_WHITE)

		self.title.bkgd(curses.color_pair(1))
		self.header.bkgd(curses.color_pair(3))
		self.footer.bkgd(curses.color_pair(3))
		self.status.bkgd(curses.color_pair(1))
	# }}}
	def refresh_subwins(self): # {{{
		"""refreshes each subwindow"""
		self.footer.noutrefresh()
		self.header.noutrefresh()
		self.title.noutrefresh()
		self.status.noutrefresh()
		curses.doupdate()
	# }}}
	def refresh_body(self): # {{{
		"""Refreshes the Body, this is run each iteration"""
		self.body.erase()
		self.body.move(0,0)
		maxDisplay = self.bodyMaxY

		if self.body_data == []:
			self.body.refresh(0,0, 2,0, self.bodyMaxY+1,self.bodyMaxX)
			return

		# data sorter
		if self.sort_order == 'Pow':
			self.body_data = sorted(self.body_data, key=lambda x: int(x[1]['power']), reverse=True)
		elif self.sort_order == 'Cl':
			self.body_data = sorted(self.body_data, key=lambda x: int(x[1]['client_count']), reverse=True)
		elif self.sort_order == 'Ch':
			self.body_data = sorted(self.body_data, key=lambda x: int(x[1]['channel']))
		elif self.sort_order == 'Essid':
			self.body_data = sorted(self.body_data, key=lambda x: str(x[1]['network']).lower())
		elif self.sort_order == 'Bssid':
			self.body_data = sorted(self.body_data, key=lambda x: str(x[1]['address']).lower())
		elif self.sort_order == 'Manufacturer':
			self.body_data = sorted(self.body_data, key=lambda x: str(x[1]['oui']).lower())

		# display range of data on screen
		for idx in range(maxDisplay):

			if(idx > maxDisplay):
				break # we have reached the displays edge

			mw = self.maxX - self.spacer

			try: # print each visible row of data
				item = self.body_data[idx + self.startpos]

				# parse columns
				cols = item[1]
				# macaddr = 17, power = 3, clients = 3, essid = 30, oui = unl
				stringdata = '|'.join([
					cols['power'].rjust(3),
					cols['channel'].rjust(3),
					cols['client_count'].rjust(3),
					cols['network'][:30].ljust(30),
					#cols['address'][9:], # get last 3 hex
					cols['address'],
					cols['oui'] # dont limit length, addnstr will do its thing
				])

				# Color this line?
				cursorline_color = curses.color_pair(6)
				string_color = curses.color_pair(6)
				attributes = item[0]
				if 'suitable' in attributes:
					string_color = curses.color_pair(3)
					cursorline_color = string_color
				if 'handshake' in attributes:
					string_color = curses.color_pair(5)
					cursorline_color = string_color
					#if 'suitable' in attributes:
					#	cursorline_color = curses.color_pair(1)
				if 'cracked' in attributes:
					#string_color = curses.color_pair(3)
					string_color = curses.color_pair(1)
					cursorline_color = string_color
					#cursurline_color = string_color
				if 'whitelisted' in attributes:
					string_color = curses.color_pair(8)
					cursorline_color = string_color
				if 'attacking' in attributes:
					cursorline_color = curses.color_pair(4)

				# string line
				self.body.addnstr(idx, self.spacer, stringdata, mw-1, string_color)
				# cursurline
				if idx+self.startpos == self.selection:
					self.current_select = item[2]
					self.body.addstr(idx, 0, '->', cursorline_color)
				else:
					self.body.hline(idx, 0, ' ', 2, cursorline_color)



			except Exception as e:
				if isinstance(e, IndexError):
					break # we have reached the end of the data
				else:
					# something is wrong with the data row
					raise e
					self.body.addstr(idx, self.spacer, '???ERROR???')

		# update screen
		self.body.refresh(0,0, 2,0, self.bodyMaxY+1,self.bodyMaxX)
	# }}}
# ------------------------------------------------------------
# Various Functions
	def nxt_sort_col(self, reverse=False): # {{{
		"""Change to next Sorting Order"""
		opts = self.column_names
		current = opts.index(self.sort_order)

		if reverse:
			nextopt = current-1
		else:
			nextopt = current+1

		if nextopt == len(opts):
			self.sort_order = opts[0]
		elif nextopt < 0:
			self.sort_order = opts[len(opts)-1]
		else:
			self.sort_order = opts[nextopt]
		self.set_column_titles()
	# }}}
	def set_column_titles(self): # {{{
		"""Sets the column names, highlights sorting column"""
		# macaddr = 17, power = 3, clients = 3, essid = 30, oui = unl
		self.header.erase()
		x = self.spacer
		for i in self.column_names:
			if i == 'Pow' or i == 'Manufacturer':
				s = i
			elif i == 'Ch' or i == 'Cl':
				s = str(i).rjust(3)
			elif i == 'Essid':
				s = str(i).ljust(30)
			elif i == 'Bssid':
				s = str(i).ljust(12)
			try: # if window too small dont print
				if i == self.sort_order:
					self.header.addstr(0, x, s, curses.color_pair(1))
				else:
					self.header.addstr(0, x, s)
			except:
				pass
			x = x+(len(s)+1)
		self.header.refresh()
	# }}}
	def set_text(self, string, target='status', refresh=True): # {{{
		"""Sets the text inside of a subwin"""
		if target == 'title':
			self.title.erase()
			self.title.addstr(0, 2, string)
			if refresh:	self.title.refresh()
		elif target == 'header':
			self.header.erase()
			self.header.addstr(0, 2, string)
			if refresh:	self.header.refresh()
		elif target == 'footer':
			self.footer.erase()
			self.footer.addstr(0, 2, string)
			if refresh:	self.footer.refresh()
		elif target == 'status':
			self.status.erase()
			self.status.addstr(0, 2, string)
			if refresh:	self.status.refresh()
	# }}}
	def set_select(self, number, page=False): # {{{
		"""Sets the current highlighted option"""
		# bounds checking
		number = max(0, number)
		number = min(number, len(self.body_data)-1)
		
		maxDisplayedItems = self.bodyMaxY
		if page: # move page view
			pass
		else: # move data selector
			self.selection = number
			#if at bottom, move data pos
			if self.selection-self.startpos >= maxDisplayedItems:
				self.startpos = self.selection-maxDisplayedItems+1
			#if at top, move data pos
			elif self.selection < self.startpos:
				self.startpos = self.selection
	# }}}
# ------------------------------------------------------------
# User Input
	def keypress(self, char): # {{{
		"""Handles Interface Keypresses"""
		curses.flushinp() # prevents lag from holding key

		# refresh terminal, on resize or manually
		if char == ord('#') or char == curses.KEY_RESIZE:
			self.refresh_all()

		# keys for exiting program
		if char == curses.KEY_EXIT or char == ord('Q'):
			return -1

		# keys for navigation
		if char == ord('k') or char == curses.KEY_UP:
			self.set_select(self.selection-1)
		if char == ord('j') or char == curses.KEY_DOWN:
			self.set_select(self.selection+1)
		if char == ord('K') or char == curses.KEY_PPAGE:
			self.set_select(self.selection-10)
		if char == ord('J') or char == curses.KEY_NPAGE:
			self.set_select(self.selection+10)
		if char == curses.KEY_HOME or char == ord('g'):
			self.set_select(self.selection-100000)
		if char == curses.KEY_END or char == ord('G'):
			self.set_select(self.selection+100000)

		# keys for sorting
		if char == ord('s'):
			self.nxt_sort_col()
		if char == ord('S'):
			self.nxt_sort_col(reverse=True)

		# enter, and leave
		#if char == curses.KEY_ENTER or char == 10 or char == 13 or char == ord('l') or char == ord('L'):
		#	self.set_text(self.current_select[1], target='title')
		#	self.set_text(self.current_select[1], target='header')
		#	self.set_text(self.current_select[1], target='status')
		#	self.set_text(self.current_select[1], target='footer')
		if char == curses.KEY_BACKSPACE or char == ord('q') or char == ord('h') or char == ord('H'):
			pass
		
		self.refresh_body()
		return 0 # returns something
	# }}}
# ------------------------------------------------------------
