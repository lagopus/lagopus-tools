# -*- coding: utf-8 -*-
# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.



from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.lib import ofctl_v1_0
from ryu.lib import ofctl_v1_2
from ryu.lib import ofctl_v1_3
from ryu.controller import network
from ryu.controller import dpset

from netaddr import valid_ipv4
from netaddr.core import AddrFormatError
import pprint
import sys
import threading
from select import select

class IPFilter(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	_CONTEXTS = {
		"dpset": dpset.DPSet
	}

	def __init__(self, *args, **kwargs):
		super(IPFilter, self).__init__(*args, **kwargs)
		self.dpset = kwargs["dpset"]
		self.waiters = {}
		self.input_thread = threading.Thread(target=self.input_handler)
		self.input_thread.start()

	@set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
	def flow_reply_handler(self, ev):
		msg = ev.msg
		dp = msg.datapath

		if dp.id not in self.waiters:
			return
		if msg.xid not in self.waiters[dp.id]:
			return
		lock, msgs = self.waiters[dp.id][msg.xid]
		msgs.append(msg)

		flags = 0
		if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
			flags = dp.ofproto.OFPSF_REPLY_MORE
		elif dp.ofproto.OFP_VERSION == ofproto_v1_2.OFP_VERSION:
			flags = dp.ofproto.OFPSF_REPLY_MORE
		elif dp.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
			flags = dp.ofproto.OFPMPF_REPLY_MORE

		if msg.flags & flags:
			return
		del self.waiters[dp.id][msg.xid]
		lock.set()

	def input_handler(self):
		waiting = False
		while True:
			if waiting is False:
				sys.stdout.write("input > ")
				sys.stdout.flush()
			read, _, _ = select([sys.stdin], [], [], 1)
			waiting = True
			if read:
				commands = sys.stdin.readline().strip().split()

				if len(commands) == 0:
					pass
				elif commands[0] == "show":
					self.show_command(commands)
				elif commands[0] == "add":
					self.add_command(commands)
				elif commands[0] == "del":
					self.del_command(commands)
				elif commands[0] == "dump":
					self.dump_command(commands)
				else:
					print "Unknown command: "+commands[0]

				waiting = False

	def add_command(self, commands):
		args = commands[1:]
		l_args = len(args)

		if l_args == 1:
			ip = args[0]
			if not self.valid_ip(ip):
				return
			for _, dp in self.dpset.get_all():
				self.add_ignored_ip(ip, dp)
		elif l_args == 2:
			dpid = args[0]
			ip = args[1]
			if not self.valid_ip(ip) or not self.valid_dpid(dpid):
				return
			dp = self.dpset.get(int(dpid))
			self.add_ignored_ip(ip, dp)
		else:
			print "Usage: add [dpid] ip"

	def del_command(self, commands):
		args = commands[1:]
		l_args = len(args)

		if l_args == 1:
			ip = args[0]
			if not self.valid_ip(ip):
				return
			for _, dp in self.dpset.get_all():
				self.del_ignored_ip(ip, dp)
		elif l_args == 2:
			dpid = args[0]
			ip = args[1]
			if not self.valid_ip(ip) or not self.valid_dpid(dpid):
				return
			dp = self.dpset.get(int(dpid))
			self.del_ignored_ip(ip, dp)
		else:
			print "Usage: del [dpid] ip"

	def valid_dpid(self, dpid):
		if not dpid.isdigit():
			print "Invalid DPID: "+str(dpid)
			return False
		if not int(dpid) in self.dpset.dps:
			print "Unknown DPID: "+str(dpid)
			return False
		return True

	def valid_ip(self, ip):
		if not valid_ipv4(ip):
			print "Invalid IPv4 Address: "+str(ip)
			return False
		return True

	def del_ignored_ip(self, ip, datapath):
		self.mod_flow(datapath, self.create_ip_flow(ip), datapath.ofproto.OFPFC_DELETE)

	def add_ignored_ip(self, ip, datapath):
		self.mod_flow(datapath, self.create_ip_flow(ip), datapath.ofproto.OFPFC_ADD)

	def create_ip_flow(self, ip):
		return {
			"priority": 1000,
			"match": {
				"ipv4_dst": ip,
				"eth_type": 0x0800
			}
		}

	def mod_flow(self, datapath, flow, command):
		if datapath.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
			ofctl_v1_0.mod_flow_entry(datapath, flow, command)
		elif datapath.ofproto.OFP_VERSION == ofproto_v1_2.OFP_VERSION:
			ofctl_v1_2.mod_flow_entry(datapath, flow, command)
		elif datapath.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
			ofctl_v1_3.mod_flow_entry(datapath, flow, command)

	def show_command(self, commands):
		args = commands[1:]
		l_args = len(args)

		if l_args == 0:
			flows = self.get_flows()
			print self.format_flows(flows)
		else:
			print "Usage: show"


	def dump_command(self, commands):
		args = commands[1:]
		l_args = len(args)

		if l_args == 0:
			flows = self.get_flows()
			pprint.pprint(flows)
		else:
			print "Usage: dump"

	def get_flows(self):
		flows = {}
		for dpid, dp in self.dpset.get_all():
			if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
				flows.update(ofctl_v1_0.get_flow_stats(dp, self.waiters, {}))
			elif dp.ofproto.OFP_VERSION == ofproto_v1_2.OFP_VERSION:
				flows.update(ofctl_v1_2.get_flow_stats(dp, self.waiters, {}))
			elif dp.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
				flows.update(ofctl_v1_3.get_flow_stats(dp, self.waiters, {}))
		return flows

	def format_flows(self, flow_dict):
		template = " {:^16} | {:^15} | {:^16}\n"
		format_header =  template.format("DPID", "IPv4", "COUNT")
		format_header += "------------------+-----------------+------------------\n"
		formatted_str = ""
		for dpid, flows in flow_dict.items():
			for flow in flows:
				match = flow["match"]
				if "nw_dst" in match and not flow["actions"]:
					formatted_str += template.format(int(dpid), match["nw_dst"], flow["packet_count"])
		return format_header+formatted_str if formatted_str else "Filters Not Found"




