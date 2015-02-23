# -*- coding: utf-8 -*-
# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#	 http://www.apache.org/licenses/LICENSE-2.0
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
from ryu.ofproto import ether
from ryu.lib import ofctl_v1_0
from ryu.lib import ofctl_v1_2
from ryu.lib import ofctl_v1_3
from ryu.lib import mac
from ryu.controller import network
from ryu.controller import dpset
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ethernet

from netaddr import valid_ipv4
from netaddr.core import AddrFormatError
import pprint
import sys
import threading
from select import select
import re

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
		self.ryu_ip = "10.0.0.100"
		self.ryu_mac = "fe:ee:ee:ee:ee:ef"
		self.server_info_list = []
		self.timeout = 20
		self.next_index = 0


	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
										  ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)


	def add_flow(self, datapath, priority, match, actions, timeout=None):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
											 actions)]
		if timeout:
			mod = parser.OFPFlowMod(
				datapath=datapath,
				priority=priority,
				match=match,
				instructions=inst,
				idle_timeout=self.timeout
			)
		else:
			mod = parser.OFPFlowMod(
				datapath=datapath,
				priority=priority,
				match=match,
				instructions=inst
			)

		datapath.send_msg(mod)

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg

		pkt = packet.Packet(msg.data)

		if pkt.get_protocols(ipv4.ipv4):
			self.handle_ipv4(msg)
		elif pkt.get_protocols(arp.arp):
			self.handle_arp(msg)
		else:
			return


	def get_next_server_info(self):
		if len(self.server_info_list) != 0:
			info = self.server_info_list[self.next_index]
			self.next_index = (self.next_index+1) % len(self.server_info_list)
			return info
		else:
			return None

	def handle_arp(self, msg):
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		pkt = packet.Packet(msg.data)

		in_port = msg.match["in_port"]

		p_arp = pkt.get_protocols(arp.arp)[0]
		src_ip = p_arp.src_ip
		src_mac = p_arp.src_mac
		dst_ip = p_arp.dst_ip
		opcode = p_arp.opcode

		if opcode == arp.ARP_REQUEST and in_port == 1 and dst_ip == self.ryu_ip:
			po = parser.OFPPacketOut(
				datapath,
				in_port=ofproto.OFPP_LOCAL,
				buffer_id = 0xffffffff,
				actions=[parser.OFPActionOutput(1)],
				data=self.create_arp_reply(src_mac, src_ip, self.ryu_mac, self.ryu_ip)
			)
			datapath.send_msg(po)
		elif opcode == arp.ARP_REQUEST and in_port != 1:
			po = parser.OFPPacketOut(
				datapath,
				in_port=ofproto.OFPP_LOCAL,
				buffer_id = 0xffffffff,
				actions=[parser.OFPActionOutput(in_port)],
				data=self.create_arp_reply(src_mac, src_ip, self.ryu_mac, dst_ip)
			)
			datapath.send_msg(po)

	def create_arp_reply(self, dst_mac, dst_ip, src_mac, src_ip):
		e = ethernet.ethernet(dst_mac, self.ryu_mac, ether.ETH_TYPE_ARP)
		a = arp.arp(
			opcode=arp.ARP_REPLY,
			src_mac=src_mac,
			src_ip=src_ip,
			dst_mac=dst_mac,
			dst_ip=dst_ip
		)
		p = packet.Packet()
		p.add_protocol(e)
		p.add_protocol(a)
		p.serialize()

		return p.data

	def handle_ipv4(self, msg):
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		pkt = packet.Packet(msg.data)
		p_ipv4 = pkt.get_protocols(ipv4.ipv4)[0]
		p_eth = pkt.get_protocols(ethernet.ethernet)[0]

		if p_ipv4.dst != self.ryu_ip:
			return

		src_ip = p_ipv4.src
		src_mac = p_eth.src

		next_server = self.get_next_server_info()

		if not next_server:
			print "Server list is empty"
			return

		match = parser.OFPMatch(in_port=1, ipv4_dst=self.ryu_ip, ipv4_src=src_ip, eth_type=0x0800)
		actions = [
			parser.OFPActionSetField(ipv4_dst=next_server["ip"]),
			parser.OFPActionSetField(eth_dst=next_server["mac"]),
			parser.OFPActionOutput(next_server["out_port"])
		]
		self.add_flow(datapath, 100, match, actions, 20)
		a = actions

		match = parser.OFPMatch(in_port=next_server["out_port"], ipv4_src=next_server["ip"], ipv4_dst=src_ip, eth_type=0x0800)
		actions = [
			parser.OFPActionSetField(ipv4_src=self.ryu_ip),
			parser.OFPActionSetField(eth_src=self.ryu_mac),
			parser.OFPActionSetField(eth_dst=src_mac),
			parser.OFPActionOutput(1)
		]
		self.add_flow(datapath, 100, match, actions, 20)

		out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
								  in_port=2, actions=a, data=msg.data)
		datapath.send_msg(out)

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

		if l_args == 3:
			ip = args[0]
			mac = args[1]
			port = args[2]
			if not self.valid_ip(ip) or not self.valid_mac(mac) or not self.valid_port(port):
				return
			for _, dp in self.dpset.get_all():
				self.add_server(ip, mac, port)
		else:
			print "Usage: add ip mac out_port"

	def del_command(self, commands):
		args = commands[1:]
		l_args = len(args)

		if l_args == 3:
			ip = args[0]
			mac = args[1]
			port = args[2]
			if not self.valid_ip(ip) or not self.valid_mac(mac) or not self.valid_port(port):
				return
			for _, dp in self.dpset.get_all():
				self.del_server(ip, mac, port)
		else:
			print "Usage: del ip mac out_port"

	def add_server(self, ip, mac, port):
		self.server_info_list.append(self.create_server_dict(ip, mac, port))

	def del_server(self, ip, mac, port):
		self.server_info_list.remove(self.create_server_dict(ip, mac, port))

	def create_server_dict(self, ip, mac, port):
		return {
			"ip": ip,
			"mac": mac,
			"out_port": int(port)
		}

	def valid_ip(self, ip):
		if not valid_ipv4(ip):
			print "Invalid IPv4 Address: "+str(ip)
			return False
		return True

	def valid_port(self, port):
		if not port.isdigit():
			print "Invalid Port: "+str(port)
			return False
		return True

	def valid_mac(self, mac):
		if not re.match("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$",mac):
			print "Invalid MAC Address: "+str(mac)
			return False
		return True

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
		template = " {:^16} | {:^17} | {:^8}\n"
		format_header =  template.format("IPv4", "MAC", "OUT_PORT")
		format_header += "------------------+-------------------+----------\n"
		formatted_str = ""
		for server in self.server_info_list:
			formatted_str += template.format(server["ip"], server["mac"], server["out_port"])
		return format_header+formatted_str if formatted_str else "Servers not found"




