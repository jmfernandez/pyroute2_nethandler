#!/usr/bin/python

import datetime
import pprint
import queue
import time

import pyroute2

# https://man7.org/linux/man-pages/man7/rtnetlink.7.html

IGNORABLE = {
	"RTM_NEWNEIGH",
	"RTM_DELNEIGH",
	"RTM_GETNEIGH",
}

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
		if interface is not None:
			interface_name = interface.ifname
		else:
			interface_name = '(unset)'
		print(f"{stamp.isoformat()} {action} {action in IGNORABLE} {interface_name}")
		if action not in IGNORABLE:
			pprint.pprint(msg)
			if interface is not None:
				pprint.pprint(interface)
