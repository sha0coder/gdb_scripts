
class Decode:

	def __init__(self,ins):
		self.clear()
		self.ins = ins

		try:
			'''
			spl = ins.split(':')
			self.addr = getAddr(spl[0])
			self.name = spl[1].split(' ')[0]
			self.regs = re.findall('%([a-z0-9]+)',spl[1])
			self.sym = re.findall('<([^>]*)>',spl[0])[0]
			pspl = spl[1].split(',')
			'''

			if ',' in ins:
				d = re.findall('0x([a-f0-9]+) <([^>]+)>:\t([a-z]+) *([^,]+),([^ ]+)',ins)[0]
				self.left  = d[3]
				self.right = d[4]

			elif '%' in ins:
				d = re.findall('0x([a-f0-9]+) <([^>]+)>:\t([a-z]+) *(%[a-z0-9]+)',ins)[0]
				self.reg = d[3]
				self.left = d[3]
				self.right = ''

			elif '0x' in ins.split(':')[1]:
				d = re.findall('0x([a-f0-9]+) <([^>]+)>:\t([a-z]+) *(0x[0-9a-f]+)',ins)[0]
				self.addr = d[3]
				self.left = d[3]
				self.right = ''

	
			else:
				d = re.findall('0x([a-f0-9]+) <([^>]+)>:\t([a-z]+)',ins)[0]
				self.right = ''
				self.left = ''


			self.regs = {
				'left':  re.findall('%([a-z0-9]+)', self.left),
				'right': re.findall('%([a-z0-9]+)',self.right),
			}

			self.mems = {
				'left':  re.findall('0x([a-f0-9]+)', self.left),
				'right': re.findall('0x([a-f0-9]+)',self.right),
			}

			self.addr  = d[0]
			self.sym   = d[1]
			self.name  = d[2]

		except:
			#print('decoder err')
			pass

	def _str_(self):
		return '%s <%s>: %s ' % (self.addr,self.sym,self.name)

	def clear(self):
		self.ins = ''
		self.addr = 0
		self.sym = ''
		self.name = ''
		self.regs = []

