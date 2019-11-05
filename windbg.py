'''
	Widbg commands on gdb
	@sha0coder

	-- control flow --
	g
	-- dump --
	dd
	dq
	db
	ds
	du
	-- threads --
	t
	t 3
	-- break points --
	bp 
	bl
	bc
	-- dissassm --
	u
	-- registers --
	r 
	-- search --
	sa
	sd
	sq


	TODO:
		dt with gdb's p
		?? with eval
		sd and sq use same algorithm than sa instead using gdb's find
'''


import sys
import re
import os



rAddr = re.compile('(0x[0-9a-f]*)')

def p(msg):
    print(msg)

def g(cmd):
	return gdb.execute(cmd,to_string=True).strip()

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


DBG=False
def toNum(s):
	s = str(s).strip()
	if ' ' in s:
		s = s.split(' ')[0].strip()
	if s.startswith('poi('):
		s = s[4:-1]
		n = toNum(s)
	

		if DBG:
			print('recursion result: %x' % n)
		s = g('x/wx 0x%x' % n).split(':')[1][1:]
		if DBG:
			print('dereferenced to: '+s)

	if s.startswith('@'):
		s = g('i r '+s[1:]).split('\t')[-1]
		if DBG:
			print('register value: '+s)

	if s.startswith('0x'):
		if ' ' in s:
			s = s.split(' ')[0].strip()
		h = int(s[2:],16)
		if DBG:
			print('hex string to int %d' % h)
		return h
	try:
		if DBG:
			print('decimal integer')
		return int(s)
	except:
		pass

	if 'No symbol' in s:
		print('wrong symbol '+s)
		return 0

	if DBG:
		print('symbol')
	return int(g('x/x '+s).split(':')[0],16)
    
class Go(GDBCMD):
	def invoked(self,args):
		print('go')
		try:
			p(g("c"))
		except:
			p(g("r"))

class DumpAscii(GDBCMD):
    def invoked(self,args):
        addr = args[0]
        n = 0
        if (len(args) == 2):
            n=toNum(args[1]) #TODO: implement display n strings
        
        print(g("x/s "+addr))   
        

class DumpUnicode(GDBCMD):
    def invoked(self,args):
        addr = args[0]
        n = 0
        if (len(args) == 2):
            n=toNum(args[1]) #TODO: implement display n strings
        
        print(g("x/s "+addr))   

class DumpDword(GDBCMD):
	def invoked(self,args):
		addr = toNum(args[0])
		n = 1

		if (len(args) == 2):
			n=toNum(args[1])

		for i in range(n):
			#val = g("p (unsigned long *) 0x%x" % (addr)).split(' ')[-1]
			val = g('x/wx 0x%x' % addr).split(':')[1].strip()
			print('0x%x: %s' % (addr, val))
			addr += 4
	
class DumpQword(GDBCMD):
	def invoked(self,args):
		addr = toNum(args[0])
		n = 1

		if (len(args) == 2):
			n=toNum(args[1])

		for i in range(n):
			#val = g("p (unsigned long long *) 0x%x" % (addr)).split(' ')[-1]
			val = g('x/gx 0x%x' % addr).split(':')[1].strip()
			print('0x%x: %s' % (addr, val))
			addr += 8     

class DumpBytes(GDBCMD):
	def invoked(self,args):
		addr = toNum(args[0])
		n = 16

		if (len(args) == 2):
			n=toNum(args[1])
			
		
		for l in g('x/%dbx  0x%x' % (n,addr)).split('\n'):
			spl = l.split(':')
			saddr = spl[0]
			bs = spl[1].split('\t')[1:]
			sys.stdout.write(saddr+': ')
			s = ''
			for x in bs:
				b = toNum(x)
				sys.stdout.write('%.2X ' % b)
				if b >= ord(' ') and b <= ord('~'):
					s += chr(b)
				else:
					s += '.'
			padd= '   ' * (8-len(bs))
			print(padd+'  '+s)
            
class BreakPoint(GDBCMD):
	def invoked(self,args):
		where = args[0]
		if where.startswith('0x'):		
			print(g('b *'+args[0]))
		else:
			print(g('b '+args[0]))
			

class BreakList(GDBCMD):
    def invoked(self,args):
        if len(args)>0:
            p(g('info break '+args[0]))
        else:
            p(g('info break'))

class BreakClear(GDBCMD):
    def invoked(self,args):
        if len(args)==0:
            print('set the breakpoint number to clear')
            return
        if args[0] == '*':
            p(g('delete break'))
        else:
            p(g('delete break '+args[0]))

class Stack(GDBCMD):
    def invoked(self,args):
        p(g('bt'))


class Threads(GDBCMD):
	def invoked(self,args):
		if len(args) == 0:
			p(g('info threads'))
		else:
			n = toNum(args[0])
			p(g('thread %d' % n))


class Disass(GDBCMD):
	def invoked(self,args):
		if len(args) == 0:
			p(g('x/10i $pc'))
		else:
			addr = toNum(args[0])
			p(g('x/10i 0x%x' % addr))


class Registers(GDBCMD):
	def invoked(self,args):
		if len(args) == 0:
			p(g('i r'))
		else:
			p(g('i r '+' '.join(args)))

class SearchAscii(GDBCMD):
	def invoked(self,args):
		if len(args) < 3:
			p('Search ascii:')
			p('  sa 0 L100 "test"')
			p('  sa 0 L?0x11223344 "test"')
			return
		
		
		addr = toNum(args[0])
		sz = args[1]
		search = args[2]
		

		if sz.startswith('L?'):
			sz = toNum(sz[2:])
			p(g('find 0x%x, 0x%x, "%s"' % (addr, sz, search)))
		elif sz.startswith('L'):
			sz = toNum(sz[1:])
			p(g('find 0x%x, +%d, "%s"' % (addr, sz, search)))

		else:
			print('size bad indicated L<relative amoutn of bytes>  L?<address>')
			print('type sa for more help.')

class SearchAscii2(GDBCMD):
	def invoked(self,args):
		if len(args) < 3:
			p('Search ascii:')
			p('  sa 0 L100 "test"')
			p('  sa 0 L?0x11223344 "test"')
			return
		
		addr = toNum(args[0])
		sz = args[1]
		search = args[2]

		if sz.startswith('L?'):
			sz = toNum(sz[2:])
			occ = 0
			for a in range(addr, addr+sz):
				try:
					sys.stdout.write('0x%x        \r' % a)
					sys.stdout.flush()
					o = g('x/1bx 0x%x' % a)
				except gdb.MemoryError:
					continue

				if 'Cannot' not in o:
					b = toNum(o.split(': ')[1])
					if ord(search[occ]) == b:   #TODO: optimize this
						occ+=1
						if occ >= len(search):
							print('0x%d: "%s"' % (a,search))
					else:
						occ = 0

			
		elif sz.startswith('L'):
			sz = toNum(sz[1:])
			if sz < addr:
				print('destination address has to be bigger than source address')
				return
			occ = 0
			for a in range(addr, sz):
				try:
					sys.stdout.write('0x%x        \r' % a)
					sys.stdout.flush()
					o = g('x/1bx 0x%x' % a)
				except gdb.MemoryError:
					continue

				if 'Cannot' not in o:
					b = toNum(o.split(': ')[1])
					if ord(search[occ]) == b:   #TODO: optimize this
						occ+=1
						if occ >= len(search):
							print('0x%d: "%s"' % (a,search))
					else:
						occ = 0

		else:
			print('size bad indicated L<relative amoutn of bytes>  L?<address>')
			print('type sa for more help.')

class SearchDword(GDBCMD):
	def invoked(self,args):
		if len(args) < 3:
			p('Search ascii:')
			p('  sd 0 L100 0x11223344')
			p('  sd 0 L?0x11223344 0x123')
			p("  sd 0 L?0x11223344 0x00000123")
			return
		
		
		addr = toNum(args[0])
		sz = args[1]
		search = args[2]
		

		if sz.startswith('L?'):
			sz = toNum(sz[2:])
			p(g('find /sw 0x%x, 0x%x, %s' % (addr, sz, search)))
		elif sz.startswith('L'):
			sz = toNum(sz[1:])
			p(g('find /sw 0x%x, +%d, %s' % (addr, sz, search)))

		else:
			print('size bad indicated L<relative amoutn of bytes>  L?<address>')
			print('type sd for more help.')


class SearchQword(GDBCMD):
	def invoked(self,args):
		if len(args) < 3:
			p('Search ascii:')
			p('  sq 0 L100 0x1122334455667788')
			p('  sq 0 L?0x11223344 0x0000012311221122')
			p("  sq 0 L?0x11223344 0x0000012311221122")
			return
		
		
		addr = toNum(args[0])
		sz = args[1]
		search = args[2]
		

		if sz.startswith('L?'):
			sz = toNum(sz[2:])
			p(g('find /sg 0x%x, 0x%x, %s' % (addr, sz, search)))
		elif sz.startswith('L'):
			sz = toNum(sz[1:])
			p(g('find /sg 0x%x, +%d, %s' % (addr, sz, search)))

		else:
			print('size bad indicated L<relative amoutn of bytes>  L?<address>')
			print('type sq for more help.')


class Maps(GDBCMD):
	def invoked(self,args):
		pid = toNum(g("print getpid()").split('= ')[1])
		p(open('/proc/self/maps','r').read())

class Help(GDBCMD):
	def invoked(self,args):
		a='''

	-- control flow --
	g
	-- dump --
	dd
	dq
	db
	ds
	du
	-- threads --
	t
	t 3
	-- break points --
	bp 
	bl
	bc
	-- dissassm --
	u
	-- registers --
	r 
	-- search --
	sa
	sd
	sq
	-- info --
	lm
'''

g('set pagination off')
Go("g")
DumpAscii("da")
DumpUnicode("du")
DumpDword("dd")
DumpQword("dq")
DumpBytes("db")
BreakPoint("bp")
BreakList("bl")
BreakClear("bc")
Stack("k")
Threads("t")
Disass("u")
Registers("r")
SearchAscii2("sa")
SearchDword("sd")
SearchQword("sq")
Maps("lm")
Help('hh')


print('Windbg loaded.')