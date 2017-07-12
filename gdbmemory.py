import sys,os,commands,subprocess


#########################################################
#														#
#														#
#				Created by zx							#
#														#
#														#
#########################################################




##################### Global ############################

LADDR = {}  #LADDR dict{name:[address,PID]}
BPINFO = {}  #breakpoint infomation {number:[command]}
BPLOG = "/tmp/bp_log"
BPWD = None
MEM_FILE = "/tmp/gdb_memory"
DEFAULE_SIZE = 6
LOG = False
LOGMEMFILE = '/tmp/gdb__memory_log'
LOGBPFILE = '/tmp/gdb_bp_log'


#################### PREPARE ########################
x = commands.getoutput("rm -r "+MEM_FILE+"*")
x = commands.getoutput("killall -9 tail")



#Log data to file
def Log(data,type_):
	if LOG:
		if type_ == "memdata":
			with open(LOGMEMFILE,'a') as f: f.write(w)
		elif type_ == "bpdata":
			with open(LOGMEMFILE,'a') as f: f.write(w)
		f.close()

#read memmory at addr
def Rmem(addr_,size = None):
	
	if size == None: size = DEFAULE_SIZE
	pointer=addr_.cast(gdb.lookup_type('char').pointer())
	memdict = []
	memdict.append(addr_)
	for i in range(0,size):
		for j in range(16): 
			val1= chr(pointer.dereference().cast(gdb.lookup_type('int')) & 0xff)
			pointer += 1
			memdict.append((val1))	
	return memdict

#convert data and write output
def write_fifo(name,data):
	w = ""
	for i in range(DEFAULE_SIZE):
		ascII = ""
		w += str(data[0]+i*16)+": \t"
		for j in range(16):
			val1 = data[i*16+j+1]
			w +=  val1.encode('hex')+" "
			if ord(val1) > 0x1f and ord(val1) < 0x7f:
				ascII += val1
			else:
				ascII += "."
		w += "|"+ascII+"|\n"
	w += "----------------------------------------------------------------------------------\n"
	
	outname = open(MEM_FILE+str(name), 'w')
	print >> outname,w
	Log(w,"memdata")



def newtrace(LADDR,addr):				#create new trace
	global DEFAULE_SIZE
	terminal_size = "85x"+str(DEFAULE_SIZE+4)
	try:
		last_name = LADDR.keys()[-1]+1 				#create file name of new trace
	except:
		last_name = 0
	MEM_FILE_ = MEM_FILE+str( last_name )
	os.mkfifo(MEM_FILE_)
	prc = Popen(["xterm","-title","window "+MEM_FILE_[-1],"-sb","-geometry",terminal_size,"-e","tail -f "+MEM_FILE_])    		#create new process
	LADDR[last_name]  = [addr,prc]

def remove_elem(value):     #remove element from dict

	global LADDR
	prc = LADDR[value][1]
	LADDR = {i:LADDR[i] for i in LADDR if prc not in LADDR[i]}
	x = commands.getoutput("rm -r "+MEM_FILE+str(value))

def valid_addr(addr):    #check for anddres is valid
	if "$" in addr:
		if "-" in addr:
			addr_ = gdb.parse_and_eval(addr.split("-")[0]) - gdb.parse_and_eval(addr.split("-")[1])
		if "+" in addr:
			addr_ = gdb.parse_and_eval(addr.split("+")[0]) + gdb.parse_and_eval(addr.split("+")[1])
		if "*" in addr:
			addr_ = gdb.parse_and_eval(addr.split("*")[0]) * gdb.parse_and_eval(addr.split("+")[1])
		if "/" in addr:
			addr_ = gdb.parse_and_eval(addr.split("/")[0]) / gdb.parse_and_eval(addr.split("+")[1])
		elif len(addr) > 4:
			print "[-]Invalid address"
		else:
			addr_ = gdb.parse_and_eval(addr)
	
	else:
		addr_ = gdb.parse_and_eval(addr)
	
	try:
		pointer = addr_.cast(gdb.lookup_type('char').pointer())
		pointer.dereference().cast(gdb.lookup_type('int'))
		return addr_
	
	except:
		print "[-] Invalid andress"
		return 0

def revalid_dict():			#check for some trace die
	global LADDR
	for name in LADDR:
		prc = LADDR[name][1]
		
		if prc.poll() == 0:
			
			remove_elem(name)
			


class setlog(gdb.Command):			#set outpur size
	"""	
	Set log 
	Using:
	- "flog <True/False>" .default is False

	"""
	def __init__ (self):
		gdb.Command.__init__(self, "flog", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
		
		
	def invoke (self, arg, from_tty):
		if len(arg) == 0:
			print "[+]Using flog <True/False> to set log. default is False"
			return
		global LOG
		try:
			LOG = arg
		except:
			print "[+]Using flog <True/False> to setup output size ex. default is False"
			return
setlog()

class setsize(gdb.Command):			#set outpur size
	"""	
	Set size of output
	Using:
	- "fsize <size>" ex setsize 10, default size is 6

	"""
	def __init__ (self):
		gdb.Command.__init__(self, "fsize", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
		
		
	def invoke (self, arg, from_tty):
		if len(arg) == 0: 
			print "[+]Using setsize <size> to setup output size ex. setsize 10 default size is 6"
			return
		global DEFAULE_SIZE
		try:
			DEFAULE_SIZE = int(arg)
		except:
			print "[+]Using setsize <size> to setup output size ex. setsize 10 default size is 6"
			return
setsize()

class initfollow(gdb.Command):				#start game
	"""
	Follow data at address every debugger break
	Using:
	- "fmem <address>" or "fmem new <address>" for set up follow ex. fmem 0x7fffff40,fmem $ebx+3,$
	- "fmem kill <window>" for kill window ex. fmem kill 0
	-**********address can be 0xffffff40 or 4294967104 or $ebx+12 ($ebx + 12 will be wrong)****************
	"""
	def __init__ (self):

		gdb.Command.__init__(self, "fmem", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
		
		
	def invoke (self, arg, from_tty):
		global LADDR
		revalid_dict()
		arg_ = arg.split(' ')
		if len(arg) == 0:
			print "Using\n[+]\"fmem <address>\" to start follow or replace first follow \n[+]\"fmem new <address>\" to start new follow\n[+]\"fmem kill <window>\" to kill invalid window or kill by your self"
			print "**********address can be 0xffffff40 or 4294967104 or $ebx+12 ($ebx + 12 will be wrong)****************"

		if len(LADDR) == 0:
			addr_ = valid_addr(arg_[-1])
			if not addr_: return						
			newtrace(LADDR,arg_[-1])
		
		elif len(arg_) == 1:
			for i in range(len(LADDR)):				
				name = LADDR.keys()[i]
				prc = LADDR[LADDR.keys()[i]][1]
				if prc.poll() != 0:
					addr_ = valid_addr(arg_[-1])
					if not addr_: return			
					LADDR[name][0] = arg_[0]				#change first trace to new trace
					break
		
		elif len(arg_) == 2:
			if arg_[0] == 'new':							#create new trace
				if len(arg_[1]) == 0:
					print "[+]Using fmem new <address>"
				addr_ = valid_addr(arg_[-1])
				if not addr_: return		
				newtrace(LADDR,arg_[1])
			
			elif arg_[0] == 'kill':							#kill trace
				if len(arg_[1]) == 0:
					print "[+]Using fmem kill <window>"
					return

				if int(arg_[1]) > len(LADDR) - 1:
					print "[-]Invalid window"
					return
				
				prc = LADDR[int(arg_[1])][1]
				prc.kill()
				if prc.poll() == None:
					
					remove_elem(int(arg_[1]))
					
					return
				print "[-]Cannot kill trace"
				return
				
		out = Rmem(addr_)
		write_fifo(LADDR.keys()[-1],out)
		
initfollow()




def stop_handler (event):

	global LADDR
	revalid_dict()
	if len(LADDR) == 0: return
	for i in range(len(LADDR)):
		name = LADDR.keys()[i]
		addr = LADDR[LADDR.keys()[i]][0]
		addr_ = valid_addr(addr)
		out = Rmem(addr_)
		write_fifo(name,out)

			
gdb.events.stop.connect (stop_handler)


def exit_hander(event):
	pass
	

gdb.events.exited.connect (exit_hander)





def readchangedata(org): # Comapre orgdata with new data input to change memory
	f = open("data",'r')
	dt = f.read()
	s = []
	rs = {}
	for i in range(DEFAULE_SIZE):
		s +=  dt.split("\n")[i].split(":")[1].split(" ")[1:-1]
	tmp = []
	for i in s: tmp += list(i.decode('hex'))
	
	if len(tmp) != DEFAULE_SIZE*16: 				#check size of new memory
		print "[-]Invalid memory to write"
		return 0
	
	for i in range(DEFAULE_SIZE):
			for j in range(16):
				if tmp[i*16+j] != org[i*16+j+1]:
					rs[org[0]+i*16+j ] = tmp[i*16+j]

	return rs


class wmemory(gdb.Command):
	"""
	Write memory using vim
	Using:
	- wmem <address>
		******* input mem can 00 11 22 33 44 or 0011223344; don't delete address *******
	"""
	def __init__ (self):
		gdb.Command.__init__(self, "wmem", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
		
		
	def invoke (self, arg, from_tty):
		if len(arg) == 0:
			print "Using:\n" \
				"- wmem <address>\n" \
				"******* input mem can 00 11 22 33 44 or 0011223344; don't delete address *******"
			return

		addr_ = valid_addr(arg)
		if not addr_: return				
		data = Rmem(addr_)
		
		w = ""
		for i in range(DEFAULE_SIZE):
			w += str(data[0]+i*16)+": "
			for j in range(16):
				w +=  (data[i*16+j+1]).encode('hex')+" "
			w +="\n"

		f = open('data','w')
		f.write(w)
		f.close()
		x = commands.getoutput("cp data orgdata")
		prc = Popen(["xterm","-title",str(data[0]),"-sb","-geometry","80x10","-e","vim data"])
		prc.wait()
		dt = readchangedata(data)
		if not dt: return
		for i in dt:
			if ord(dt[i]) > 0 and  ord(dt[i]) < 0xff:
				gdb.inferiors()[0].write_memory(int(str(i),16),dt[i],1)
			else:
				print "[-]Invalid value to write"
				return


wmemory()




class MyBreakpoint(gdb.Breakpoint):
	def genwindow(self):
		global BPWD
		x = commands.getoutput("rm -r "+BPLOG)
		os.mkfifo(BPLOG)
		prc = Popen(["xterm","-title","breakpoint tracing","-sb","-geometry","80x10","-e","tail -f "+BPLOG])
		BPWD = prc


	def write_(self,output):
		##print output
		if BPWD:
			if BPWD.poll() == 0:
				self.genwindow()
		else:
			self.genwindow()
		outname = open(BPLOG, 'w')
		print >> outname,output
		Log(output,'bpdata')

	def stop (self):

		#out = ""
		self.write_("[+]breakpoint  " +self.location[1:])
		for i in BPINFO[self.location]:	
			try:
				out = gdb.execute(i,False,True)
				out = "\t\t\t\t"+out[:-1]
			except:
				raise gdb.GdbError("[-]Invalid input")
			self.write_(out)


class bpmemory(gdb.Command):
	"""
	breakpoint an print anything you need
	Using:
	- bmem <address> <print something> ex. print $eax,x/4wx $eax,print $ebx \\n"
		
	"""
	def __init__ (self):
		gdb.Command.__init__(self, "bmem", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
		
	
	def invoke (self, arg, from_tty):
		global BPINFO
		if len(arg) == 0:
			print "Using:\n" \
				"- bmem <address> <print something> ex. bmem 0xffff1340 print $eax,x/4wx $eax,print $ebx+ \\n"
			return	
		addr = "*"+arg.split(" ")[:1][0]
		BPINFO[addr] = " ".join(arg.split(" ")[1:]).split(",")
		try:
			MyBreakpoint(addr) 
		except:
			raise gdb.GdbError("[-]Invalid address")
		#print bpoint.stop('asdsad')

bpmemory()
