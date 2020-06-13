from scapy import all as scapy
from scapy.contrib import pfcp

udp = scapy.UDP()
ip = scapy.IP()

ip.src = "172.17.0.3"
ip.dst = "192.168.84.222"

#fill pfcp header 
pfcp_header = pfcp.PFCP()
pfcp_header.version=1
pfcp_header.S=1
pfcp_header.message_type=52
pfcp_header.seid=1
pfcp_header.seq=2

mod = pfcp.PFCPSessionModificationRequest()
fseid = pfcp.IE_FSEID()
fseid.v4=1
fseid.seid=1
fseid.ipv4="1.1.1.1"
mod.IE_list.append(fseid)

far1 = pfcp.IE_UpdateFAR()
#FAR id
farid1 = pfcp.IE_FAR_Id()
farid1.id = 2
far1.IE_list.append(farid1)
#Apply Action
appAction1 = pfcp.IE_ApplyAction() 
appAction1.FORW = 1
far1.IE_list.append(appAction1)

updforwarding = pfcp.IE_UpdateForwardingParameters()

destintf1 = pfcp.IE_DestinationInterface()
destintf1.interface=0 #access
updforwarding.IE_list.append(destintf1)

outerHeader = pfcp.IE_OuterHeaderCreation()
outerHeader.GTPUUDPIPV4=1
outerHeader.ipv4="1.1.1.2"
outerHeader.TEID=111111
updforwarding.IE_list.append(outerHeader)

far1.IE_list.append(updforwarding)

mod.IE_list.append(far1)

final = ip/udp/pfcp_header/mod
