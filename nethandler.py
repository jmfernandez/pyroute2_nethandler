#!/usr/bin/python

import datetime
import pprint
import queue
import re
import time

import pyroute2

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

# Create Instance of IPDB
q = queue.Queue()

with pyroute2.IPDB() as ipdb:
	action = 'RTM_NEWLINK'
	def cb(ipdb, msg, action):
		index = msg.get('index')
		if index is not None:
			interface = ipdb.interfaces[index]
		else:
			interface = None
		q.put((datetime.datetime.now(), action, msg, interface))

	ipdb.register_callback(cb, mode='post')

	while(True):
		stamp, action, msg, interface = q.get()
		if action not in ("RTM_NEWADDR","RTM_DELADDR", "RTM_GETADDR"):
			continue

		if interface is not None:
			interface_name = interface.ifname
		else:
			interface_name = '(unset)'

		if interface_name in IFACE_IGNORABLE:
			continue
		do_ignore = False
		for pat in IFACE_IGNORABLE_RE:
			if pat.search(interface_name):
				do_ignore = True
				break
		if do_ignore:
			continue
		
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
			pprint.pprint(msg)
			
		#if interface is not None:
		#	pprint.pprint(interface)
