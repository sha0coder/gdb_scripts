# -*- coding: utf-8 -*-
'''
Copyright (C) @sha0coder

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.




This create 3 gdb commands:
	- syscalls <start> <end>  (look for syscalls)
	- gomain 	(locate main function, when you haven't symbols)
	- flow 		(execute all the code breakpointing all rets, from ret to ret, displaying the flow throw functions) 
	- goret 	(bp the ret of current function and continue execution)
	- fuzz [function addr] <buffer> (fuzz the given function, if no buffer is specified, this will create a new buffer)
	- S2 stepping engine

'''



import re
import sys
import json
import random
import struct


dbg = False

class Decode:

	def __init__(self,ins):
		self.clear()
		self.ins = ins
		self.value = ''

		log(ins)
		if ',' in ins:
			log(1)
			d = re.findall('0x([a-f0-9]+)[^:]*:\t([a-z]+) *([^,]+),([^ ]+)',ins)[0]
			log(d)
			self.left  = d[2]
			self.right = d[3]

		elif '%' in ins:
			log(2)
			d = re.findall('0x([a-f0-9]+)[^:]*:\t([a-z]+) *([a-z0-9*()%]+)',ins)[0]
			log(d)

			self.reg = d[2]
			self.left = d[2]
			self.right = ''

		elif '$0x' in ins.split(':')[1]:
			log(33)
			d = re.findall('0x([a-f0-9]+)[^:]*:\t([a-z]+) *\$(0x[0-9a-f]+)',ins)[0]
			#0x42036a <_rt0_go+266>:	pushq  $0x4ebba0

			log(d)
			self.value = d[2]
			self.left = ''
			self.right = ''

		elif '0x' in ins.split(':')[1]:
			log(3)
			#bugs: 0x806e0b8 <runtime.setldt+56>:	call   *0x8149298

			d = re.findall('0x([a-f0-9]+)[^:]*:\t([a-z]+) *(\*?0x[0-9a-f]+)',ins)[0]
			log(d)
			self.left = d[2]
			self.right = ''

		else:			
			log(4)
			d = re.findall('0x([a-f0-9]+)[^:]*:\t([a-z]+)',ins)[0]
			log(d)

			self.right = ''
			self.left = ''


		self.aregs =  re.findall('%([a-z0-9]+)',ins)

		log(5)
		self.regs = {
			'left':  re.findall('%([a-z0-9]+)', self.left),
			'right': re.findall('%([a-z0-9]+)',self.right),
		}

		log(6)
		'''
		self.mems = {
			'left':  re.findall('0x([a-f0-9]+)', self.left),16),
			'right': int(re.findall('0x([a-f0-9]+)',self.right),16),
		}
		'''

		log(7)
		self.addr  = int(d[0],16)
		#self.sym   = d[1]
		self.name  = d[1]
		log(8)


	def _str_(self):
		return '%s <%s>: %s ' % (self.addr,self.sym,self.name)

	def clear(self):
		self.ins = ''
		self.addr = 0
		self.sym = ''
		self.name = ''
		self.regs = []
		self.left = ''
		self.right = ''
		self.aregs = []



'''
	HELPERS
'''

rAddr = re.compile('(0x[0-9a-f]*)')

def g(cmd):
	return gdb.execute(cmd,to_string=True)

def cont():
	g('c')

def log(msg):
	if dbg:
		print(msg)

def bp(where):
	g('b *0x%x'%where)

def getReg(r):
	if type(r) is str:
		if '%' in r:
			r = r[1:]
		r = g('i r '+r)
	elif type(r) is int:
		r = g('i r 0x%x',r)
	else:
		r =''

	tbl = re.findall('([a-z0-9]+) +0x([0-9a-f]+)',r)
	return int(tbl[0][1],16)

def regs():
	r =  g('i r')
	tbl = re.findall('([a-z]+) +([0-9a-fx]+)',r)
	out = {}
	for l in tbl:
		out.update({l[0]:int(l[1],16)})	
	return out

def alloc(size):
	out = g('print (char *)malloc(%d)' %size)
	return getAddr(out)

def write(where,what):
	g('set *(unsigned char *)0x%x = %s' % (where,what))

def unprotect(where,length):
	g('print (int)mprotect(0x%x,%d, 0x1|0x2|0x4 )' % (where,length))

def getSectionRange(section):
	for s in g('info files').split('\n'):
		if 	section in s:
			addrs = rAddr.findall(s)
			return (int(addrs[0],16),int(addrs[1],16))
	return (0,0)

def getNextInst():
	out = g('x/2i $pc')
	out = out.split('\n')[1]
	return out

def getNextAddr():
	out = g('x/2i $pc')
	out = out.split('\n')[1]
	return getAddr(out)

def getRetAddr(where=None):
	if not where:
		where = regs()['eip']
	
	code = g('x/i 0x%x' % where)
	while not re.findall('ret',code):
		code = g('x/i')

	return getAddr(code)

def readExMem(addr):
	try:
		if type(addr) is int:
			mem = g('x/x 0x%x' % addr)
		elif type(addr) is str:
			mem = g('x/x '+addr)
		else:
			mem=''
			
	except:
		mem = ''
	return clsp(mem.split(':')[1])

def gotoret():
	g('b *0x%x'%getRetAddr())
	g('c')
	g('si')

def getAddr(txt):
	res = re.findall('([a-f0-9x]+)',txt)
	if res:
		return int(res[0],16)
	else:
		return 0

def getSym(txt):
	res = re.findall('<([^>]+)>',txt)
	if res:
		return res[0]
	else:
		return ''

def getBps():
	bps = g('info break')
	return rAddr.findall(bps)

def getEntry():
	out = g('info files')
	entry = re.findall('Entry point: (0x[a-f0-9]+)',out)
	if entry:
		return int(entry[0],16)
	return 0x00000000

def clsp(d):
	return d.replace(' ','').replace('\t','').replace('\n','').reaplace('\r','')


conditionals = {
	'jnb':	'>= (u)',
	'jbe':	'<= (u)',
	'jna':	'<= (u)',
	'jae':	'>= (u)',
	'jne':	'!= (s)',
	'jze':	'!= (u)',
	'jle':	'<= (s)',
	'jge':	'>= (s)',
	'jl':	'< (s)',
	'jg':	'> (s)',
	'jb':	'< (s)',
	'ja':	'> (u)',
	'je':	'= (s)',
	'jz':	'= (u)',
}

color = {
    'clean'   : '\033[0m',  # Clear color
    'clear'   : '\033[2K',  # Clear line
    'bold'      : ['\033[1m',  '\033[22m'],
    'italic'    : ['\033[3m',  '\033[23m'],
    'underline' : ['\033[4m',  '\033[24m'],
    'inverse'   : ['\033[7m',  '\033[27m'],

    #grayscale
    'white'     : ['\033[37m', '\033[39m'],
    'grey'      : ['\033[90m', '\033[39m'],
    'black'     : ['\033[30m', '\033[39m'],

    #colors
    'blue'      : ['\033[34m', '\033[39m'],
    'cyan'      : ['\033[36m', '\033[39m'],
    'green'     : ['\033[32m', '\033[39m'],
    'magenta'   : ['\033[35m', '\033[39m'],
    'red'       : ['\033[31m', '\033[39m'],
    'yellow'    : ['\033[33m', '\033[39m']
}


syscall = [
	'sys_read',
	'sys_write',
	'sys_open',
	'sys_close',
	'sys_stat',
	'sys_fstat',
	'sys_lstat',
	'sys_poll',
	'sys_lseek',
	'sys_mmap',
	'sys_mprotect',
	'sys_munmap',
	'sys_brk',
	'sys_rt_sigaction',
	'sys_rt_sigprocmask',
	'sys_rt_sigreturn',
	'sys_ioctl',
	'sys_pread ',
	'sys_pwrite',
	'sys_readv',
	'sys_writev',
	'sys_access',
	'sys_pipe',
	'sys_select',
	'sys_sched_yield',
	'sys_mremap',
	'sys_msync',
	'sys_mincore',
	'sys_madvise',
	'sys_shmget',
	'sys_shmat',
	'sys_shmctl',
	'sys_dup',
	'sys_dup',
	'sys_pause',
	'sys_nanosleep',
	'sys_getitimer',
	'sys_alarm',
	'sys_setitimer',
	'sys_getpid',
	'sys_sendfile',
	'sys_socket',
	'sys_connect',
	'sys_accept',
	'sys_sendto',
	'sys_recvfrom',
	'sys_sendmsg',
	'sys_recvmsg',
	'sys_shutdown',
	'sys_bind',
	'sys_listen',
	'sys_getsockname',
	'sys_getpeername',
	'sys_socketpair',
	'sys_setsockopt',
	'sys_getsockopt',
	'sys_clone',
	'sys_fork',
	'sys_vfork',
	'sys_execve',
	'sys_exit',
	'sys_wait',
	'sys_kill',
	'sys_uname',
	'sys_semget',
	'sys_semop',
	'sys_semctl',
	'sys_shmdt',
	'sys_msgget',
	'sys_msgsnd',
	'sys_msgrcv',
	'sys_msgctl',
	'sys_fcntl',
	'sys_flock',
	'sys_fsync',
	'sys_fdatasync',
	'sys_truncate',
	'sys_ftruncate',
	'sys_getdents',
	'sys_getcwd',
	'sys_chdir',
	'sys_fchdir',
	'sys_rename',
	'sys_mkdir',
	'sys_rmdir',
	'sys_creat',
	'sys_link',
	'sys_unlink',
	'sys_symlink',
	'sys_readlink',
	'sys_chmod',
	'sys_fchmod',
	'sys_chown',
	'sys_fchown',
	'sys_lchown',
	'sys_umask',
	'sys_gettimeofday',
	'sys_getrlimit',
	'sys_getrusage',
	'sys_sysinfo',
	'sys_times',
	'sys_ptrace',
	'sys_getuid',
	'sys_syslog',
	'sys_getgid',
	'sys_setuid',
	'sys_setgid',
	'sys_geteuid',
	'sys_getegid',
	'sys_setpgid',
	'sys_getppid',
	'sys_getpgrp',
	'sys_setsid',
	'sys_setreuid',
	'sys_setregid',
	'sys_getgroups',
	'sys_setgroups',
	'sys_setresuid',
	'sys_getresuid',
	'sys_setresgid',
	'sys_getresgid',
	'sys_getpgid',
	'sys_setfsuid',
	'sys_setfsgid',
	'sys_getsid',
	'sys_capget',
	'sys_capset',
	'sys_rt_sigpending',
	'sys_rt_sigtimedwait',
	'sys_rt_sigqueueinfo',
	'sys_rt_sigsuspend',
	'sys_sigaltstackcons',
	'sys_utime',
	'sys_mknod',
	'sys_uselib',
	'sys_personality',
	'sys_ustat',
	'sys_statfs',
	'sys_fstatfs',
	'sys_sysfs',
	'sys_getpriority',
	'sys_setpriority',
	'sys_sched_setparam',
	'sys_sched_getparam',
	'sys_sched_setscheduler',
	'sys_sched_getscheduler',
	'sys_sched_get_priority_max',
	'sys_sched_get_priority_min',
	'sys_sched_rr_get_interval',
	'sys_mlock',
	'sys_munlock',
	'sys_mlockall',
	'sys_munlockall',
	'sys_vhangup',
	'sys_modify_ldt',
	'sys_pivot_root',
	'sys__sysctl',
	'sys_prctl',
	'sys_arch_prctl',
	'sys_adjtimex',
	'sys_setrlimit',
	'sys_chroot',
	'sys_sync',
	'sys_acct',
	'sys_settimeofday',
	'sys_mount',
	'sys_umount',
	'sys_swapon',
	'sys_swapoff',
	'sys_reboot',
	'sys_sethostname',
	'sys_setdomainname ',
	'sys_iopl',
	'sys_ioperm',
	'sys_create_module',
	'sys_init_module',
	'sys_delete_module',
	'sys_get_kernel_syms',
	'sys_query_module',
	'sys_quotactl',
	'sys_nfsservctl',
	'sys_getpmsg',
	'sys_putpmsg',
	'sys_afs_syscall',
	'sys_tuxcall',
	'sys_security',
	'sys_gettid',
	'sys_readahead',
	'sys_setxattr',
	'sys_lsetxattr',
	'sys_fsetxattr',
	'sys_getxattr',
	'sys_lgetxattr',
	'sys_fgetxattr',
	'sys_listxattr',
	'sys_llistxattr',
	'sys_flistxattr',
	'sys_removexattr',
	'sys_lremovexattr',
	'sys_fremovexattr',
	'sys_tkill',
	'sys_time',
	'sys_futex',
	'sys_sched_setaffinity',
	'sys_sched_getaffinity',
	'sys_set_thread_area',
	'sys_io_setup',
	'sys_io_destroy',
	'sys_io_getevents',
	'sys_io_submit',
	'sys_io_cancel',
	'sys_get_thread_area',
	'sys_lookup_dcookie',
	'sys_epoll_create',
	'sys_epoll_ctl_old',
	'sys_epoll_wait_old',
	'sys_remap_file_pagesd',
	'sys_getdentsunsign',
	'sys_set_tid_address',
	'sys_restart_syscall',
	'sys_semtimedop',
	'sys_fadvise',
	'sys_timer_create',
	'sys_timer_settime',
	'sys_timer_gettime',
	'sys_timer_getoverrun',
	'sys_timer_delete',
	'sys_clock_settime',
	'sys_clock_gettime',
	'sys_clock_getres',
	'sys_clock_nanosleep',
	'sys_exit_group',
	'sys_epoll_wait',
	'sys_epoll_ctl',
	'sys_tgkill',
	'sys_utimes',
	'sys_vserver',
	'sys_mbind',
	'sys_set_mempolicy',
	'sys_get_mempolicy',
	'sys_mq_open',
	'sys_mq_unlink',
	'sys_mq_timedsend',
	'sys_mq_timedreceive',
	'sys_mq_notify',
	'sys_mq_getsetattr',
	'sys_kexec_load',
	'sys_waitid',
	'sys_add_key',
	'sys_request_key',
	'sys_keyctl',
	'sys_ioprio_set',
	'sys_ioprio_get',
	'sys_inotify_init',
	'sys_inotify_add_watch',
	'sys_inotify_rm_watch',
	'sys_migrate_pagesng ',
	'sys_openat',
	'sys_mkdirat',
	'sys_mknodat',
	'sys_fchownat',
	'sys_futimesat',
	'sys_newfstatat',
	'sys_unlinkat',
	'sys_renameat',
	'sys_linkat',
	'sys_symlinkat',
	'sys_readlinkat',
	'sys_fchmodat',
	'sys_faccessat',
	'sys_pselect',
	'sys_ppollstru',
	'sys_unshareunsig',
	'sys_set_robust_list',
	'sys_get_robust_list',
	'sys_splice',
	'sys_tee',
	'sys_sync_file_range',
	'sys_vmsplice',
	'sys_move_pages  ',
	'sys_utimensat',
	'sys_epoll_pwait',
	'sys_signalfd',
	'sys_timerfd_create',
	'sys_eventfd',
	'sys_fallocate',
	'sys_timerfd_settime',
	'sys_timerfd_gettime',
	'sys_accept',
	'sys_signalfd',
	'sys_eventfd',
	'sys_epoll_create',
	'sys_dup',
	'sys_pipe',
	'sys_inotify_init',
	'sys_preadv',
	'sys_pwritev',
	'sys_rt_tgsigqueueinfo',
	'sys_perf_event_open',
	'sys_recvmmsg',
	'sys_fanotify_init',
	'sys_fanotify_mark',
	'sys_prlimit',
	'sys_name_to_handle_at',
	'sys_open_by_handle_at',
	'sys_clock_adjtime',
	'sys_syncfs',
	'sys_sendmmsg',
	'sys_setns',
	'sys_getcpu',
	'sys_process_vm_readv',
	'sys_process_vm_writev'
]


names = {}




'''
	COMMAND SUPERCLASS
'''

class GDBCMD(gdb.Command):
	def __init__(self,cmd):
		gdb.Command.__init__(self, cmd, gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)

	def invoke(self,arg,tty):
		args = gdb.string_to_argv(arg)
		self.invoked(args)


'''
	COMMANDS
'''


class Syscalls(GDBCMD):

	def invoked(self,args):

		s = g('find /h %s, %s, 0x050f'%(args[0],args[1])).split('\n')
		if s[0].find('Pattern not found')<0:
			for i in s:
				print(g('x/4i %s-10'%i))

		s = g('find /h %s, %s, 0x80cd'%(args[0],args[1])).split('\n')
		if s[0].find('Pattern not found')<0:
			for i in s:
				print(g('x/4i %s-10'%i))


class Gomain(GDBCMD):

	def invoked(self,args):
		
		'''
			[entry] --> libc --> _init --> libc -> main
		'''

		g('set pagination offb   ')
		entry = getEntry()
		print(" Entry point at: 0x%x" % entry)
		bp(entry)
		g('r')

		init = False
		libc = False
		while True:
			try:
				out = g('si')
			except gdb.MemoryError:
				print("error capturado .. ")
				continue

			addr = getAddr(out)
			#print "0x%x  \r" % addr
			if addr > 0x10000000:
				libc = True

			if libc and addr < 0x10000000:
				libc = False
				if init:
					break
				init = True
				print("        _init at: 0x%x" % addr)

		g('set pagination on')
		print("Main function at: 0x%x" % addr)
		print(g('x/10i $eip'))

		'''
        def invoke_old(self,arg,tty):
		stack = []
		g('set pagination off')
		g('b _init')
		g('r')
		print g('x/i $eip')
		found = False
		ret = getRetAddr()
		eip = regs()['eip']

		while not found:
			while True:
				out = g('x/i')

				if out.find('ret') > -1:
					break
lb,m -
					found = True
					
				
			if not found:
				gotoret().-..-,l.                                  
				ret = getRetAddr()
				eip = regs()['eip']
				func = g('x/i 0x%x'%eip)
				print "0x%x - 0x%x %s" % (eip,ret,getSym(func))
			

		
		'''

class Flow(GDBCMD):

	def invoked(self,args):
		stack = []
		g('set pagination off')
		g('b _init')
		g('r')
		print(g('x/i $eip'))
		found = False
		ret = getRetAddr()
		eip = regs()['eip']

		try:
			while True:
				gotoret()
				ret = getRetAddr()
				eip = regs()['eip']
				func = g('x/i 0x%x'%eip)
				print("0x%x - 0x%x %s" % (eip,ret,getSym(func)))
		except:
			pass
			

		g('set pagination on')






class Fuzz(GDBCMD):

	def invoked(self,args):
		self.randlength = 5

		target = args[0]
		print("Fuzzing %s" % target)

		#If the user provides the address of the input buffer, this will fuzz that buffer.
		if len(args)>1:
			buff = int(args[1],16)
			unprotect(buff, self.randlength)

		#Else new buffer is allocated on the binary and supplied by first parameter
		else:
			buff = alloc(1024)


		for i in range(0,self.randlength):
			write(buff+i,random.randint(0,254))

		write(buff+self.randlength,0x00)
		ret = getRetAddr(int(target,16))
		bp(ret)
		g('jump *%s'%target)
		

class Name(GDBCMD):

	def invoked(self,args):
		global names

		if len(args)== 0:
			mode = '?'
		else:
			mode = args[0]

		if mode == '?' or mode == 'h' or mode == 'help':
			print('name load [filename]')
			print('name save [filename]')
			print('name add  [0xaddr] [name]')
			print('name del  [0xaddr]')
			print('name clear')
			print('name list')

		elif mode == 'load':
			fname = args[1]
			names = json.loads(open(fname).read())

		elif mode == 'save':
			fname = args[1]
			open(fname,'w').write(json.dumps(names))

		elif mode == 'add':
			addr = args[1]
			name = args[2]
			names.update({addr: name})
			print('name added.')

		elif mode == 'del':
			addr = args[1]
			name.pop(args)

		elif mode == 'clear':
			names = {}

		elif mode == 'list':
			print(names)

		else:
			print('mode no recognized, try help')






class Stepper(GDBCMD):
	'''
		   0x0000000000400545 <+24>:	callq  0x400410 <printf@plt>
	'''

	def ask(self,msg,t,f):
		return t
		sys.stdout.write('%s? [%s] or %s? ' % (msg,t,f))
		sys.stdout.flush()
		key = sys.stdin.readline()[:-1]
		if key in ['q','Q']:
			sys.exit(1)
		return key != f



	def display(self,op):
		for o in op:
			o = clsp(o)
			if '$0x' in o:
				n = int(o[3:],16)
				print('\t%s: %d'%(o,n))


			elif o[0] == '%':
				try:
					print('\t%s: 0x%x' % (o,getReg(o[1:])))
				except:
					print('err')
					print('-'+o[1:]+'-')
					print(getReg(o[1:]))
		print(' ')

	def makeIf(self,prev,curr):
		'''
			cmp a,b + je    a == b   => 0xaddr
			cmp a,b + jl    a < b    => 0xaddr
			cmp a,b + jle   a <= b   => 0xaddr
			cmp a,b + jg    a > b    => 0xaddr
			cmp a,b + jge   a >= b   => 0xaddr

			cmp a,b + jae	a <= b   => 0xaddr
			cmp a,b + jna	a >= b   => 0xaddr
			cmp a,b + jbe	a >= b   => 0xaddr
			cmp a,b + jnb	a <= b   => 0xaddr

			TODO: jump taken or not taken?
		'''
		addr = rAddr.findall(curr)[0]
		branch = re.findall(':\t([jnaeblg]{2,3})',curr)[0]
		cond = conditionals[branch]
		op = re.findall('cmp ([^,]+),(.*)',prev)[0]

		print('\n%sif (%s %s %s)   => %s%s' % (color['green'][0],clsp(op[0]),cond,clsp(op[1]),addr,color['clean']))
		self.display(op)
		if not self.ask('Continue','y','n'):
			self.stop = True


	def makeIf2(self,prev,curr):
		'''
			test %eax, %eax
			je 0xaddr
		'''
		addr = rAddr.findall(curr)[0]
		regs = re.findall('%[a-z]{3}',prev)
		if regs[0] == regs[1]:
			print('\n%sif (%s == 0)  => %s%s' % (color['green'][0],regs[0],addr,color['clean']))
		else:
			print('%sif ((%s - %s) == 0) => %s%s' % (color['green'][0],regs[0],regs[1],addr,color['clean']))
		self.display(regs)
		if not self.ask('Continue','y','n'):
			self.stop = True

	def makeJump(self,ins):
		ins = ins.split(':')[1]
		addr = getAddr(ins)
		sym = getSym(ins)
		#print('\n%s---> %s %s%s' % (color['blue'][0],hex(addr),sym,color['clean']))
		print('%s ---> %s %s' % (color['blue'][0], ins, color['clean']))

		if '(%' in ins:
			regs = re.findall('\(%([a-z]+)\)',ins)
			print(regs)
			self.display(regs)

		if not self.ask('Jump (i)nto or (o)ver','i','o'):
			addr = getNextAddr()
			print('debug: bp en 0x%x' % addr)
			bp(addr)
			cont()


	def invoked(self,args):
		global names, syscall

		#TODO: KeyboardInterrupt
		self.stop = True
		prev = ins = ''
		text = getSectionRange('.text')
		if 0 in text:
			print('/!\ cant get .text section :/')
			return

		g('set pagination off')
		try:	
			while not self.stop:
				try:
					for k in names.keys():
						try:
							v = readExMem(k)
						except:
							v=0
						print('%s(%s): %s' % (names[k],k,v))
				except:
					print('err init')


				prev = ins
				g('si')
				ins = g('x/i $pc')[3:-1]

				deco = Decode(ins)
				addr = int(rAddr.findall(ins)[0],16)
				try:
					print('<<%s>>' % names[deco.addr])
				except:
					pass


				'''
					Visualización

						- no mostrar si:
							- es un push/pop
							- un xor a,a
							- call
							- jmp
							- leave/reat

						- modificar ifs	 cmp/test
						- elegir stepi stepo en los calls
				'''

				if 'syscall' in ins:
					eax = getReg('eax')
					print('%s %s (0x%x %d)%s' % (color['red'][0],syscall[eax],eax,eax,color['clean']))
				elif 'jmp' in ins or 'call' in ins:
					self.makeJump(ins)
				elif 'ret' in ins:
					print('---')
				elif 'leave' in ins or 'push' in ins or 'pop' in ins:
					pass
				elif 'cmp' in ins or 'test' in ins:
					nxt = getNextInst()
					if 'cmp' in ins and 'j' in nxt:
						self.makeIf(ins,nxt)
					elif 'test' in ins and 'je' in nxt:
						self.makeIf2(ins,nxt)
					else:
						print('caso raro:')
						print(ins)
						print(nxt)

				#print('add: %x [%x-%x]'%(addr,text[0],text[1]))

				if text[0] <= addr and addr <= text[1]:
					pass
				else:
					
					'''
					print('out of module %x' % addr)
					if 'call' in prev:
						print('from a call')
						g('finish')
					else:
						print('not from a call')
					'''
		except KeyboardInterrupt:
			return


class S2(GDBCMD):

	def makeIf(self,prev,curr):
		'''
			cmp a,b + je    a == b   => 0xaddr
			cmp a,b + jl    a < b    => 0xaddr
			cmp a,b + jle   a <= b   => 0xaddr
			cmp a,b + jg    a > b    => 0xaddr
			cmp a,b + jge   a >= b   => 0xaddr

			cmp a,b + jae	a <= b   => 0xaddr
			cmp a,b + jna	a >= b   => 0xaddr
			cmp a,b + jbe	a >= b   => 0xaddr
			cmp a,b + jnb	a <= b   => 0xaddr

			TODO: jump taken or not taken?
		'''
		log('<makeif>')

		cond = ''
		try:
			cond = conditionals[curr.name]
		except:
			log('</makeif>')
			return





		msg = '0x%x: if (%s %s%s)   goto %s%s' % (prev.addr,prev.left,conditionals[curr.name],prev.right,curr.left,self.regDisplay(prev).replace('\x00',''))
		
		self.log(msg)
		print('%s%s%s' % (color['green'][0],msg,color['clean']))
		log('</makeif>')

	def makeIf2(self,prev,curr):
		'''
			test %eax, %eax
			je 0xadd
		'''

		log('<makeif2>')
		
		'''
		addr = rAddr.findall(curr)[0]
		regs = re.findall('%[a-z]{3}',prev)
		'''

		if regs[0] == regs[1]:
			msg = '0x%x: if (%s == 0)  goto %s%s' % (prev.addr,prev.left,curr.left,self.regDisplay(prev))
		else:
			msg = '0x%x: if ((%s - %s) == 0) goto %s%s' % (prev.addr,prev.left,prev.right,curr.left,self.regDisplay(prev))
		

		self.log(msg)
		print('%s%s%s' % (color['green'][0],msg,color['clean']))
		log('</makeif2>')

	def regDisplay(self,din):
		log('<regdisp>')
		if len(din.aregs) == 0:
			return ''

		s = '\t#'
		for reg in din.aregs:
			try:
				v = getReg(reg)
				s += ' %s: 0x%x ' % (reg,v)
				s += struct.pack('>L',v)
			except:
				pass
			try:
				s += ' '+struct.pach('>L', readExMem(v))
			except:
				pass

		#for mem in din.mems['left']:
		
		mem = din.left
		if '$' not in mem and '0x' in mem:
			if '(' in mem:
				try:
					spl = mem.split('(')
					mem = spl[0]
					reg = getReg(spl[1].split(')')[0])
					m=0
					if mem[0] == '-':
						m = reg-int(mem[2:],16)
					else:
						m = reg+int(mem,16)

					s += '%s: %s xl' % (din.left,readExMem(m))
				except:
					pass
					#print('wtfl>',mem,reg,spl[1].split(')')[0],getReg(spl[1].split(')')[0]))

			else:
				try:
					v = readExMem(mem)
					s +=' %s: %s' % (mem,v)
					s += ' '+struct.pach('>L', v)
				except:
					pass

		#for mem in din.mems['right']:
		mem = din.right
		if '$' not in mem and '0x' in mem:
			if '(' in mem:
				try:
					spl = mem.split('(')
					mem = spl[0]
					reg = getReg(spl[1].split(')')[0])
					m=0
					if mem[0] == '-':
						m = reg-int(mem[2:],16)
					else:
						m = reg+int(mem,16)

					s += '%s: %sxr' % (din.right,readExMem(m))
				except:
					pass

			else:
				try:
					v = readExMem(mem)
					s +=' %s: %s' % (mem,v)
					s += ' '+struct.pach('>L', v)
				except:
					pass

		log('</regdisp>')
		return s

	def log(self,msg):
		self.fd.write(msg+'\n') #TODO: quitar los bytes de colores

	def invoked(self,args):
		g('set pagination off')
		systop = True
		low = False
		self.running = True
		stepsAmmount = -1

		if len(args)>0:
			if args[0] == 'help' or args[0] == 'h' or args[0] == '?':
				print('s2 [mode]')
				print('modes:')
				print('    s2 all ----> show full trace and stop on the end of execution')
				print('    s2 sys ----> show full trace and stop on the next syscall')
				print('    s2 low ----> show only ifs and syscals')
				return

			elif args[0] == 'sys':
				systop = True

			elif args[0] == 'low':
				low = True

			elif args[0] == 'n':
				stepsAmmount = int(args[1])



		self.fd = open('s2.log','a+')
		self.log('-----------------')


		self.bps = getBps()


		try:
			prev_syscall = False
			while self.running:
				if stepsAmmount == 0:
					break
				if stepsAmmount > 0:
					stepsAmmount-=1

				log(0)
				g('si')
				log(11)

				log('<decode>')
				inss = g('x/2i $pc').split('\n')
				ins = inss[0][3:]
				nxt = Decode(inss[1][3:])
				din = Decode(ins)
				log('</decode>')


				#respect breakpoints
				saddr = '0x%x' % din.addr
				if saddr in self.bps:
					print('breakpoint!')
					self.running = False



				#avoid stepping libs?
				#if din.addr > 0x7ffff00000:
				if din.name == 'call' and din.left[:2] == '0x':
					if  int(din.left[2:],16) > 0x7ffff00000:
						print('skipping call %s ' % din.left)
						g('si')
						g('finish')
						log('<decode2>')
						inss = g('x/2i $pc').split('\n')
						ins = inss[0][3:]
						nxt = Decode(inss[1][3:])
						din = Decode(ins)
						log('</decode2>')

				if prev_syscall:
					prev_syscall = False
					ret = getReg('eax')
					msg = '# return eax: 0x%x' % ret
					self.log(msg)
					print('%s%s%s' % (color['red'][0],msg,color['clean']))
					if systop:
						return

				if din.name == 'syscall' or din.name == 'int':
					if din.name == 'syscall':
						for i in 'rdi,rsi,rdx,rcx,r8,r9'.split(','):
							print('%s# %s: 0x%x%s' % (color['red'][0],i,getReg(i),color['clean']))
					else:
						for i in 'ebx,ecx,edx,esi,edi,ebp'.split(','):
							print('%s# %s: 0x%x%s' % (color['red'][0],i,getReg(i),color['clean']))	

					msg = ins+'\t# return '+syscall[getReg('eax')]
					self.log(msg)
					print('%s%s%s' % (color['red'][0],msg,color['clean']))
					prev_syscall = True
				
				else:

					if 'cmp' in din.name:
						self.makeIf(din,nxt)
						continue

					elif din.name == 'text':
						self.makeIf2(dis,nxt)
						continue

					elif din.name in conditionals:
						continue

					elif low:
						continue

					self.log(ins+self.regDisplay(din))
					print(ins+self.regDisplay(din))

				'''
				elif conditionals.has_keys(din.name):
					fd.write('# '+conditionals[din.name])
					print('# '+conditionals[din.name])
					print(ins+self.regDisplay(din))
				'''

		except KeyboardInterrupt:
			self.fd.close()
			

		#clone
		#0x02000000


Flow('flow')
Gomain('gomain')
Fuzz('fuzz')
Syscalls('syscalls')
Stepper('stepper')
Name('name')
S2('s2')
print("loaded.")

