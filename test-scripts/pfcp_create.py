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
pfcp_header.message_type=50
pfcp_header.seid=0
pfcp_header.seq=1

est = pfcp.PFCPSessionEstablishmentRequest()
#add IEs into message
nodeid = pfcp.IE_NodeId()
nodeid.ipv4="172.17.0.3" #put self address
est.IE_list.append(nodeid)

fseid = pfcp.IE_FSEID()
fseid.v4=1
fseid.seid=1
fseid.ipv4="1.1.1.1"
est.IE_list.append(fseid)

pdn_type = pfcp.IE_PDNType()
est.IE_list.append(pdn_type)

pdr1 = pfcp.IE_CreatePDR()
pdr1_id = pfcp.IE_PDR_Id()
pdr1_id.id = 1
pdr1.IE_list.append(pdr1_id)
priority1 = pfcp.IE_Precedence()
priority1.precedence = 2
pdr1.IE_list.append(priority1)
pdi1 = pfcp.IE_PDI()

#soure interface
si1 = pfcp.IE_SourceInterface() 
si1.interface=0
pdi1.IE_list.append(si1)
#F-TEID
fteid1 = pfcp.IE_FTEID()
fteid1.V4=1
fteid1.TEID=123456
fteid1.ipv4="1.1.1.1"
pdi1.IE_list.append(fteid1)
#SDF filter 
sdf1 = pfcp.IE_SDF_Filter()
sdf1.FD=1
sdf1.flow_description="0.0.0.0/0 0.0.0.0/0 0 : 65535 0 : 65535 0x0/0x0"
pdi1.IE_list.append(sdf1)

pdr1.IE_list.append(pdi1)
outerHdrRml1 = pfcp.IE_OuterHeaderRemoval()
outerHdrRml1.header=0
pdr1.IE_list.append(outerHdrRml1)
farid1 = pfcp.IE_FAR_Id()
farid1.id = 1
pdr1.IE_list.append(farid1)
qerid1 = pfcp.IE_QER_Id()
qerid1.id = 1
pdr1.IE_list.append(qerid1)

est.IE_list.append(pdr1)

###
pdr2 = pfcp.IE_CreatePDR()
pdr2_id = pfcp.IE_PDR_Id()
pdr2_id.id = 2
pdr2.IE_list.append(pdr2_id)
priority2 = pfcp.IE_Precedence()
priority2.precedence = 2
pdr2.IE_list.append(priority2)

pdi2 = pfcp.IE_PDI()

#soure interface
si2 = pfcp.IE_SourceInterface() 
si2.interface=1
pdi2.IE_list.append(si2)
#network instance 
ni = pfcp.IE_NetworkInstance()
ni.instance = "internetinternetinternetinterne"
pdi2.IE_list.append(ni);

#ue IP address 
ueaddr = pfcp.IE_UE_IP_Address() 
ueaddr.V4 = 1
ueaddr.ipv4 = "12.1.1.1"
pdi2.IE_list.append(ueaddr);

#SDF filter 
sdf2 = pfcp.IE_SDF_Filter()
sdf2.FD=1
sdf2.flow_description="0.0.0.0/0 0.0.0.0/0 0 : 65535 0 : 65535 0x0/0x0"
pdi2.IE_list.append(sdf2)

pdr2.IE_list.append(pdi2)

farid2 = pfcp.IE_FAR_Id()
farid2.id = 2
pdr2.IE_list.append(farid2)
qerid2 = pfcp.IE_QER_Id()
qerid2.id = 2
pdr2.IE_list.append(qerid2)


est.IE_list.append(pdr2)

far1 = pfcp.IE_CreateFAR()
#fill far 1
#FAR id
farid1 = pfcp.IE_FAR_Id()
farid1.id = 1
far1.IE_list.append(farid1)
#Apply Action
appAction1 = pfcp.IE_ApplyAction() 
appAction1.FORW = 1
far1.IE_list.append(appAction1)
#Forwarding Parameters
forwardParam1 = pfcp.IE_ForwardingParameters()
destintf1 = pfcp.IE_DestinationInterface()
destintf1.interface=1 #core
forwardParam1.IE_list.append(destintf1)
far1.IE_list.append(forwardParam1)

est.IE_list.append(far1)

far2 = pfcp.IE_CreateFAR()

#fill far 2
#FAR id
farid2 = pfcp.IE_FAR_Id()
farid2.id = 2
far2.IE_list.append(farid2)
#Apply Action
appAction2 = pfcp.IE_ApplyAction() 
appAction2.FORW = 1
far2.IE_list.append(appAction2)
#Forwarding Parameters
forwardParam2 = pfcp.IE_ForwardingParameters()
destintf2 = pfcp.IE_DestinationInterface()
destintf2.interface=0 #access
forwardParam2.IE_list.append(destintf2)
far2.IE_list.append(forwardParam2)

est.IE_list.append(far2)

qer1 = pfcp.IE_CreateQER()
#QER ID
qerid1 = pfcp.IE_QER_Id()
qerid1.id = 1
qer1.IE_list.append(qerid1)
#Gate STtus 
gate1 = pfcp.IE_GateStatus()
qer1.IE_list.append(gate1)
#MBR
mbr1 = pfcp.IE_MBR()
mbr1.dl=12345678
mbr1.ul=12345678
qer1.IE_list.append(mbr1)
#GBR
gbr1 = pfcp.IE_GBR()
gbr1.dl=12345678
gbr1.ul=12345678
qer1.IE_list.append(gbr1)
est.IE_list.append(qer1)

qer2 = pfcp.IE_CreateQER()
#QER ID
qerid2 = pfcp.IE_QER_Id()
qerid2.id = 1
qer2.IE_list.append(qerid2)
#Gate STtus 
gate2 = pfcp.IE_GateStatus()
qer2.IE_list.append(gate2)
#MBR
mbr2 = pfcp.IE_MBR()
mbr2.dl=12345678
mbr2.ul=12345678
qer2.IE_list.append(mbr2)
#GBR
gbr2 = pfcp.IE_GBR()
gbr1.dl=12345678
gbr1.ul=12345678
qer2.IE_list.append(gbr2)

est.IE_list.append(qer2)
final = ip/udp/pfcp_header/est
