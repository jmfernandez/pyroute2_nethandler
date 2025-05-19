#!/usr/bin/python

import datetime
import pprint
import os
import queue
import re
import resource
import signal
import stat
import sys
import time

import pyroute2

from xdg_base_dirs import (
    xdg_config_home,
)

# https://man7.org/linux/man-pages/man7/rtnetlink.7.html

IGNORABLE = {
	"RTM_NEWNEIGH",
	"RTM_DELNEIGH",
	"RTM_GETNEIGH",
}

IFACE_IGNORABLE = {
	"ppp0",
	"lo",
	"docker0",
}

IFACE_IGNORABLE_RE = (
	re.compile(r"^veth.*"),
	re.compile(r"^br-.*"),
)

# ifa_flags
IFA_F_SECONDARY = 0x01
IFA_F_TEMPORARY = IFA_F_SECONDARY
IFA_F_NODAD = 0x02
IFA_F_OPTIMISTIC = 0x04
IFA_F_DADFAILED = 0x08
IFA_F_HOMEADDRESS = 0x10
IFA_F_DEPRECATED = 0x20
IFA_F_TENTATIVE = 0x40
IFA_F_PERMANENT = 0x80		# When an address is set
IFA_F_MANAGETEMPADDR = 0x100
IFA_F_NOPREFIXROUTE = 0x200
IFA_F_MCAUTOJOIN = 0x400
IFA_F_STABLE_PRIVACY = 0x800

CONFIG_SUBDIR = "pyroute2_nethandler"

def get_maximum_file_descriptors() -> "int":
    """Get the maximum number of open file descriptors for this process.

    :return: The number (integer) to use as the maximum number of open
        files for this process.

    The maximum is the process hard resource limit of maximum number of
    open file descriptors. If the limit is “infinity”, a default value
    of ``MAXFD`` is returned.
    """
    (__, hard_limit) = resource.getrlimit(resource.RLIMIT_NOFILE)

    result = hard_limit
    if hard_limit == resource.RLIM_INFINITY:
        result = MAXFD

    return result

# Create Instance of IPDB
q = queue.Queue()

def cldhandler(signum, frame):
	while True:
		try:
			pid, exit_status = os.wait()
			# The less processing here, the better
			q.put((datetime.datetime.now(), None, exit_status, pid))
		except ChildProcessError as cpe:
			break

def cb(ipdb, msg, action):
	# These are the only actions being attended
	# see https://man7.org/linux/man-pages/man7/rtnetlink.7.html
	if action in ("RTM_NEWADDR","RTM_DELADDR", "RTM_GETADDR"):
		index = msg.get('index')
		if index is not None:
			interface = ipdb.interfaces[index]
			interface_name = interface.ifname
		else:
			interface = None
			interface_name = '(unset)'

		# events from ignorable interfaces are filtered out
		do_queue = True

		if interface_name in IFACE_IGNORABLE:
			do_queue = False
		else:
			for pat in IFACE_IGNORABLE_RE:
				if pat.search(interface_name):
					do_queue = False
					break

		if do_queue:
			q.put((datetime.datetime.now(), action, msg, interface))

with pyroute2.IPDB() as ipdb:
	action = 'RTM_NEWLINK'

	ipdb.register_callback(cb, mode='post')
	
	signal.signal(signal.SIGCLD, cldhandler)

	while(True):
		stamp, action, msg, interface = q.get()
		
		if action is None:
			print(f"{stamp.isoformat()} child {interface} {os.waitstatus_to_exitcode(msg)}")
			continue
		
		base_config_dir = xdg_config_home() / CONFIG_SUBDIR / action
		
		# If the directory does not exist, ignore the event!
		if base_config_dir.is_dir():
			if interface is not None:
				interface_name = interface.ifname
			else:
				interface_name = '(unset)'

			# msg is an instance of ifaddrmsg
			# msg['attrs'] is a list of instances of nla_slot
			print(f"{stamp.isoformat()} {interface_name} {action}")
			is_permanent = False
			is_addr_set = False
			for nla_attr in msg["attrs"]:
				if nla_attr.name == "IFA_FLAGS" and (nla_attr.value & IFA_F_PERMANENT) > 0:
					is_permanent = True
				elif nla_attr.name == "IFA_LOCAL":
					is_addr_set = True

			if is_permanent and is_addr_set:
				for possible_script in base_config_dir.iterdir():
					if possible_script.is_file() and possible_script.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
						job_id = os.fork()
						if job_id == 0:
							os.setsid()
							os.closerange(0, get_maximum_file_descriptors())
							
							os.execl(possible_script, possible_script, interface_name)
							# Unreachable code
							sys.exit(1)
						elif job_id > 0:
							print(f"{possible_script} => {job_id}")
						
				pprint.pprint(msg)
				
			#if interface is not None:
			#	pprint.pprint(interface)
