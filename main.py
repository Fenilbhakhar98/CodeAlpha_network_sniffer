from socket import *
import struct
import sys
import re


# receive a datagram
def receiveData(s):
    data = ''
    try:
        data = s.recvfrom(65565)
    except timeout:
        data = ''
    except:
        print("An error happened: ")
        sys.exc_info()
    return data[0]


# get Type of Service: 8 bits
def getTOS(data):
    precedence = {0: "Routine", 1: "Priority", 2: "Immediate", 3: "Flash", 4: "Flash override", 5: "CRITIC/ECP",
                  6: "Internetwork control", 7: "Network control"}
    delay = {0: "Normal delay", 1: "Low delay"}
    throughput = {0: "Normal throughput", 1: "High throughput"}
    reliability = {0: "Normal reliability", 1: "High reliability"}
    cost = {0: "Normal monetary cost", 1: "Minimize monetary cost"}

    #   get the 3rd bit and shift right
    D = data & 0x10
    D >>= 4
    #   get the 4th bit and shift right
    T = data & 0x8
    T >>= 3
    #   get the 5th bit and shift right
    R = data & 0x4
    R >>= 2
    #   get the 6th bit and shift right
    M = data & 0x2
    M >>= 1
    #   the 7th bit is empty and shouldn't be analyzed

    tabs = '\n\t\t\t'
    TOS = precedence[data >> 5] + tabs + delay[D] + tabs + throughput[T] + tabs + \
          reliability[R] + tabs + cost[M]
    return TOS


# get Flags: 3 bits
def getFlags(data):
    flagR = {0: "0 - Reserved bit"}
    flagDF = {0: "0 - Fragment if necessary", 1: "1 - Do not fragment"}
    flagMF = {0: "0 - Last fragment", 1: "1 - More fragments"}

    #   get the 1st bit and shift right
    R = data & 0x8000
    R >>= 15
    #   get the 2nd bit and shift right
    DF = data & 0x4000
    DF >>= 14
    #   get the 3rd bit and shift right
    MF = data & 0x2000
    MF >>= 13

    tabs = '\n\t\t\t'
    flags = flagR[R] + tabs + flagDF[DF] + tabs + flagMF[MF]
    return flags

HOST = gethostbyname(gethostname())

s = socket(AF_INET, SOCK_RAW, IPPROTO_IP)
s.bind((HOST, 0))

# Include IP headers
s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
s.ioctl(SIO_RCVALL, RCVALL_ON)
data = receiveData(s)

unpackedData = struct.unpack('!BBHHHBBH4s4s', data[:20])

version_IHL = unpackedData[0]
version = version_IHL >> 4  
IHL = version_IHL & 0xF  
TOS = unpackedData[1]  
totalLength = unpackedData[2]
ID = unpackedData[3]  
flags = unpackedData[4]
fragmentOffset = unpackedData[4] & 0x1FFF
TTL = unpackedData[5]  # time to live
# protocolNr = unpackedData[6]
checksum = unpackedData[7]
sourceAddress = inet_ntoa(unpackedData[8])
destinationAddress = inet_ntoa(unpackedData[9])

print("An IP packet with the size %i was captured." % (unpackedData[2]))
print("Raw data: \n", data)
# print("Raw data: " + data.decode())
# print("Raw data: {}".format(data.decode('utf-32')))

# print("Raw data: " + data.decode('utf-8').encode('utf-8'))

print("\nParsed data")
print("Version:\t\t" + str(version))
print("Header Length:\t\t" + str(IHL * 4) + " bytes")
print("Type of Service:\t" + getTOS(TOS))
print("Length:\t\t\t" + str(totalLength))
print("ID:\t\t\t" + str(hex(ID)) + " (" + str(ID) + ")")
print("Flags:\t\t\t" + getFlags(flags))
print("Fragment offset:\t" + str(fragmentOffset))
print("TTL:\t\t\t" + str(TTL))
print("Checksum:\t\t" + str(checksum))
print("Source:\t\t\t" + sourceAddress)
print("Destination:\t\t" + destinationAddress)
print("Payload:\n", data[20:])

s.ioctl(SIO_RCVALL, RCVALL_OFF)
