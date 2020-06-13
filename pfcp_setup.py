from scapy import all as scapy
from scapy.contrib import pfcp
import socket
def send_receive_message(final):
  scapy.send(final)
  data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
  print("received message: %s" % data)
  decoded_p1 = pfcp.PFCP()
  decoded_p1.dissect(data)
  if(decoded_p1.message_type == 6):
    #this is setup response 
    for ie in decoded_p1.payload.IE_list:
      if(ie.ie_type == 60):
        decoded_node_type = ie
        print("decoded node type : ")
      elif (ie.ie_type == 19):
        print("decoded cause : ",ie.cause)
      elif (ie.ie_type == 96):
        print("recovery timestamp received")
      elif (ie.ie_type == 116):
        print("decoded ip resource information received")

UDP_IP = "172.17.0.3"
UDP_PORT = 8805
sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.bind((UDP_IP, UDP_PORT))


#create PFCP packet 
pfcp_header = pfcp.PFCP()

#create setup request packet 
setupreq = pfcp.PFCPAssociationSetupRequest()
setupreq.version = 1

#Let's add IEs into the message 
ie1 = pfcp.IE_NodeId()
ie1.ipv4="172.17.0.3" #put self address 
setupreq.IE_list.append(ie1)
ie2 = pfcp.IE_RecoveryTimeStamp()
setupreq.IE_list.append(ie2)
udp = scapy.UDP()
ip = scapy.IP()
ip.src = "172.17.0.3"
ip.dst = "192.168.84.222"
final = ip/udp/pfcp_header/setupreq
send_receive_message(final)

