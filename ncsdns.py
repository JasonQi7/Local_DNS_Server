"""
Local DNS Server
Author: Jason Qi
UCL Electronic and Electrical Engineering

NOTE: There are SOA type records during some queries which I have discarded as invalid type;
therefore, sometimes an authoritative record may not have its glue record,
this is because the authoritative record is of SOA type.
Also, if you dig SOA type query, there will be no answers from this DNS server.
"""

#!/usr/bin/python

from copy import copy
from optparse import OptionParser, OptionValueError
import pprint
from random import seed, randint
import struct
from socket import *
from sys import exit, maxint as MAXINT
from time import time, sleep
import signal
from gz01.collections_backport import OrderedDict
from gz01.dnslib.RR import *
from gz01.dnslib.Header import Header
from gz01.dnslib.QE import QE
from gz01.inetlib.types import *
from gz01.util import *


# timeout in seconds to wait for reply
TIMEOUT = 5

# domain name and internet address of a root name server
ROOTNS_DN = "f.root-servers.net."   
ROOTNS_IN_ADDR = "192.5.5.241"




class ACacheEntry:
  ALPHA = 0.8

  def __init__(self, dict, srtt = None):
    self._srtt = srtt
    self._dict = dict

  def __repr__(self):
    return "<ACE %s, srtt=%s>" % \
      (self._dict, ("*" if self._srtt is None else self._srtt),)

  def update_rtt(self, rtt):
    old_srtt = self._srtt
    self._srtt = rtt if self._srtt is None else \
      (rtt*(1.0 - self.ALPHA) + self._srtt*self.ALPHA)
    logger.debug("update_rtt: rtt %f updates srtt %s --> %s" % \
       (rtt, ("*" if old_srtt is None else old_srtt), self._srtt,))


class CacheEntry:
  def __init__(self, expiration = MAXINT, authoritative = False):
    self._expiration = expiration
    self._authoritative = authoritative

  def __repr__(self):
    now = int(time())
    return "<CE exp=%ds auth=%s>" % \
           (self._expiration - now, self._authoritative,)


class CnameCacheEntry:
  def __init__(self, cname, expiration = MAXINT, authoritative = False):
    self._cname = cname
    self._expiration = expiration
    self._authoritative = authoritative

  def __repr__(self):
    now = int(time())
    return "<CCE cname=%s exp=%ds auth=%s>" % \
           (self._cname, self._expiration - now, self._authoritative,)


# >>> entry point of ncsdns.py <<<

# Seed random number generator with current time of day:
now = int(time())
seed(now)

# Initialize the pretty printer:
pp = pprint.PrettyPrinter(indent=3)

# Initialize the name server cache data structure; 
# [domain name --> [nsdn --> CacheEntry]]:
nscache = dict([(DomainName("."), 
            OrderedDict([(DomainName(ROOTNS_DN), 
                   CacheEntry(expiration=MAXINT, authoritative=True))]))])

# Initialize the address cache data structure;
# [domain name --> [in_addr --> CacheEntry]]:
acache = dict([(DomainName(ROOTNS_DN),
           ACacheEntry(dict([(InetAddr(ROOTNS_IN_ADDR),
                       CacheEntry(expiration=MAXINT,
                       authoritative=True))])))]) 

# Initialize the cname cache data structure;
# [domain name --> CnameCacheEntry]
cnamecache = dict([])


# Parse the command line and assign us an ephemeral port to listen on:
def check_port(option, opt_str, value, parser):
  if value < 32768 or value > 61000:
    raise OptionValueError("need 32768 <= port <= 61000")
  parser.values.port = value


parser = OptionParser()
parser.add_option("-p", "--port", dest="port", type="int", action="callback",
                  callback=check_port, metavar="PORTNO", default=0,
                  help="UDP port to listen on (default: use an unused ephemeral port)")
(options, args) = parser.parse_args()

# Create a server socket to accept incoming connections from DNS
# client resolvers (stub resolvers):
ss = socket(AF_INET, SOCK_DGRAM)
ss.bind(("127.0.0.1", options.port))
serveripaddr, serverport = ss.getsockname()

# NOTE: In order to pass the test suite, the following must be the
# first line that your dns server prints and flushes within one
# second, to sys.stdout:
print "%s: listening on port %d" % (sys.argv[0], serverport)
sys.stdout.flush()

# Create a client socket on which to send requests to other DNS
# servers:
setdefaulttimeout(TIMEOUT)
cs = socket(AF_INET, SOCK_DGRAM)


def saveToCache(currentRecord, authoritativeFlag):
    '''
    For a given RR record, classify its type and save it to cache
    If previously cached, refresh its TTL
    Set authoritative bit according to its flag passed in
    '''
    # A type record
    if currentRecord._type == RR.TYPE_A:
        # If not previously cached, add new entry
        if currentRecord._dn not in acache:
            acache[currentRecord._dn] = ACacheEntry(dict([(InetAddr.fromNetwork(currentRecord._inaddr), CacheEntry(expiration=currentRecord._ttl, authoritative=authoritativeFlag))]))
        
        # If previously cached, refresh the entry
        else:
            acache[currentRecord._dn]._dict[InetAddr.fromNetwork(currentRecord._inaddr)] = CacheEntry(expiration=currentRecord._ttl, authoritative=authoritativeFlag)
        
    # CNAME type record
    elif currentRecord._type == RR.TYPE_CNAME:
        cnamecache[currentRecord._dn] = CnameCacheEntry(currentRecord._cname, expiration=currentRecord._ttl)

    # NS type record
    elif currentRecord._type == RR.TYPE_NS:
        # If not previously cached, add new entry
        if currentRecord._dn not in nscache:
            nscache[currentRecord._dn] = OrderedDict([(currentRecord._nsdn, CacheEntry(expiration=currentRecord._ttl, authoritative=authoritativeFlag))])
        # If previously cached, refresh the entry
        else:
            nscache[currentRecord._dn][currentRecord._nsdn] = CacheEntry(expiration=currentRecord._ttl, authoritative=authoritativeFlag)
            
    # Discard other types of records
    else:
        print "Discard invalid type: ", currentRecord._type


def checkCache(resolverQueryHeader, resolverQueryQE):
    '''
    Check query in acache, cnamecache
    Return its type, header and result
    '''
    # Initialise reponses
    replyHeader = Header(resolverQueryHeader._id, resolverQueryHeader._opcode, Header.RCODE_NOERR, qdcount=1, qr=True, rd=resolverQueryHeader._rd, ra=True)
    replyRR=[]
    
    # A type record: return all matching addresses
    if resolverQueryQE._dn in acache:
        for key in acache[resolverQueryQE._dn]._dict.keys():
            replyRR.append(RR_A(resolverQueryQE._dn, acache[resolverQueryQE._dn]._dict[key]._expiration, key.toNetwork()))
            replyHeader._ancount += 1
        return 'a', replyHeader, replyRR
    
    # CNAME type record: return its CNAME
    elif resolverQueryQE._dn in cnamecache:
        replyRR = RR_CNAME(resolverQueryQE._dn, cnamecache[resolverQueryQE._dn]._expiration, cnamecache[resolverQueryQE._dn]._cname)
        return 'cname', replyHeader, replyRR

    # No record
    else:
        return 'none', replyHeader, []


def resolveQuery(clientQueryHeader, clientQueryQE, RaiseException = False, glueMode = False):
    '''
    Resolve a query for a given QE
    The function can also be called resursivly with RaiseException = True, see later
    The function can additionally be called when querying the address of a glue record with glueMode = True, see later
    '''
    # Initialise reponses
    resolverQueryID = randint(1, 65535)
    resolverQueryHeader = Header(resolverQueryID, Header.OPCODE_QUERY, Header.RCODE_NOERR, qdcount=1)
    resolverReplyRRAuthority = []
    resolverReplyRRGlue = []
    resolverReplyRRCNAME = []
    usedNameServer = []
    
    # Copy client's query QE
    resolverQueryQE = QE(clientQueryQE._type, clientQueryQE._dn)
    
    # Set root nameserver as default
    queryNameServer = ROOTNS_IN_ADDR
    
    
    # Keep querying until return
    while True:
        print "\n------------------------------------\n"
        print "sending query of:",resolverQueryQE
        print "nameserver:", queryNameServer
        
        # Check if current query is cached
        (cacheType, cacheHeader, cacheRR) = checkCache(resolverQueryHeader, resolverQueryQE)
        
        # If A type cache exists, append its CNAME and return results
        if cacheType == 'a':
            print "Cache hit (A) for query: ", resolverQueryQE._dn
            cacheRR = resolverReplyRRCNAME + cacheRR
            cacheHeader._ancount = len(cacheRR)
            return cacheHeader, cacheRR
        
        # If CNAME cache exists, keep searching all its CNAME in cache
        elif cacheType == 'cname':
            print "Cache hit (CNAME) for query: ", resolverQueryQE._dn
            resolverReplyRRCNAME.append(cacheRR)
            cacheQueryQE = QE(clientQueryQE._type, cacheRR._cname)
            
            while cacheType != 'none':
                (cacheType, cacheHeader, cacheRR) = checkCache(Header(resolverQueryID, Header.OPCODE_QUERY, Header.RCODE_NOERR, qdcount=1), cacheQueryQE)
                
                # If A record is found in cache, return
                if cacheType == 'a':
                    print "Cache hit (A) for query: ", cacheQueryQE._dn
                    cacheRR = resolverReplyRRCNAME + cacheRR
                    cacheHeader._ancount = len(cacheRR)
                    return cacheHeader, cacheRR
                
                # If another CNAME is found, append it and keep searching next one in cache
                elif cacheType == 'cname':
                    print "Cache hit (A) for query: ", cacheQueryQE._dn
                    resolverReplyRRCNAME.append(cacheRR)
                    cacheQueryQE._dn = cacheRR._cname
                    
                # If no A record found in cache, break loop and start a query
                else:
                    print "Cache miss for query: ", cacheQueryQE._dn
                    break

            # Initialise query header, QE and name server
            resolverQueryID = randint(1, 65535)
            resolverQueryHeader = Header(resolverQueryID, Header.OPCODE_QUERY, Header.RCODE_NOERR, qdcount=1)
            resolverQueryQE._dn = cacheRR._cname
            queryNameServer = ROOTNS_IN_ADDR

        # No cached answer
        else:
            print "Cache miss for query: ", resolverQueryQE._dn
            pass


        # Keep querying a name server for twice before giving up and catch timeout for each query
        cs.sendto(resolverQueryHeader.pack()+resolverQueryQE.pack(), (queryNameServer, 53))
        try:
            resolverReplyID = 0
            while resolverQueryID != resolverReplyID:
                exceptionFlag = False
                cs.settimeout(1)
                (resolverReply, resolverReplyAddress, ) = cs.recvfrom(512)
                cs.settimeout(None)
                resolverReplyID = Header.fromData(resolverReply)._id

        except timeout:
            cs.settimeout(None)
            print "Target Name Server is not responding, attempt: 1/2"
            print "\nDouble timeout period and retrying..."
            
            # If last attempt failed, double the timeout period and try again
            cs.sendto(resolverQueryHeader.pack()+resolverQueryQE.pack(), (queryNameServer, 53))
            try:
                resolverReplyID = 0
                while resolverQueryID != resolverReplyID:
                    exceptionFlag = False
                    cs.settimeout(2)
                    (resolverReply, resolverReplyAddress, ) = cs.recvfrom(512)
                    cs.settimeout(None)
                    resolverReplyID = Header.fromData(resolverReply)._id
                break
            except timeout:
                cs.settimeout(None)
                print "Target Name Server is not responding, attempt: 2/2"
                exceptionFlag = True
    

        # If query finally failed, change queryNameServer accordingly
        if exceptionFlag == True:

            # If root name server is not reponsive, give up query
            if queryNameServer == ROOTNS_IN_ADDR:
                print "\nRoot name server is not responding, abandoning query"
                return Header(clientQueryHeader._id, clientQueryHeader._opcode, Header.RCODE_SRVFAIL, qdcount= clientQueryHeader._qdcount, qr=True, rd=clientQueryHeader._rd, ra=True), []
            
            
            # If other NS records exist, select another name server for the same zone
            elif len(resolverReplyRRAuthority) > 1:
               print "\nTLD or authoritative name server is not responding, finding alternatives"
               
               # Save the failed name server to prevent further use
               usedNameServer.append(queryNameServer)
               
               # Find an alternative name server
               for currentRRAuthority in resolverReplyRRAuthority:
                    if currentRRAuthority._type == RR.TYPE_NS:
                        for currentRRGlue in resolverReplyRRGlue:
                                if currentRRAuthority._nsdn == currentRRGlue._dn and inet_ntoa(currentRRGlue._inaddr) not in usedNameServer:
                                    queryNameServer = inet_ntoa(currentRRGlue._inaddr)
                                    resolverQueryID = randint(1, 65535)
                                    resolverQueryHeader = Header(resolverQueryID, Header.OPCODE_QUERY, Header.RCODE_NOERR, qdcount=1)
                                    break
                        break
        
            # Otherwise, give up query
            else:
                print "\nTLD or authoritative name server is not responding, no alternatives found"
                return Header(clientQueryHeader._id, clientQueryHeader._opcode, Header.RCODE_SRVFAIL, qdcount= clientQueryHeader._qdcount, qr=True, rd=clientQueryHeader._rd, ra=True), []


        # If query is successful, process resource records
        else:
            resolverReplyHeader = Header.fromData(resolverReply)
            print "\nResponse received:"
            print resolverReplyHeader
            resolverReplyRR = []
            offset = len(resolverQueryHeader.pack()+resolverQueryQE.pack())

            for currentRecordIndex in range(resolverReplyHeader._ancount + resolverReplyHeader._nscount + resolverReplyHeader._arcount):
                (currentRecord, currentRecordOffset) = RR.fromData(resolverReply, offset)
                resolverReplyRR.append(currentRecord)
                print currentRecord
                
                authoritativeFlag = True if resolverReplyHeader._aa == 1 else False
                
                # Save current record in cache
                saveToCache(currentRecord, authoritativeFlag)
                offset += currentRecordOffset


            # If answer exists, classify the answer section
            if resolverReplyHeader._ancount > 0:
            
                # If type A answer is found, return it with all its CNAME records
                if resolverReplyRR[0]._type == RR.TYPE_A:
                    print "\nAddress answer found"
                    resolverReplyRR = resolverReplyRR[0:resolverReplyHeader._ancount]
                    resolverReplyRR = resolverReplyRRCNAME + resolverReplyRR
                    resolverReplyHeader._ancount = len(resolverReplyRR)
                    return resolverReplyHeader, resolverReplyRR
                
                # If type CNAME answer is found, save to cache and send query for the CNAME
                elif resolverReplyRR[0]._type == RR.TYPE_CNAME:
                    print "\nCNAME found"
                    resolverReplyRRCNAME.append(resolverReplyRR[0])
                    resolverQueryID = randint(1, 65535)
                    resolverQueryHeader = Header(resolverQueryID, Header.OPCODE_QUERY, Header.RCODE_NOERR, qdcount=1)
                    resolverQueryQE._dn = resolverReplyRR[0]._cname
                    queryNameServer = ROOTNS_IN_ADDR

                # Discard other types of answers
                else:
                    print "Unknown answer type, please verify your query\n"
                    return Header(clientQueryHeader._id, clientQueryHeader._opcode, Header.RCODE_SRVFAIL, qdcount= clientQueryHeader._qdcount, qr=True, rd=clientQueryHeader._rd, ra=True), []


            # If no answer is found, keep querying with NS type records
            elif resolverReplyHeader._ancount == 0:
                    print "\nNo answer received, processing AUTHORITY and ADDITIONAL sections"
                    resolverReplyRRAuthority = resolverReplyRR[:resolverReplyHeader._nscount]
                    
                    # Filter glue records
                    resolverReplyRRGlue = []
                    for currentRRGlue in resolverReplyRR[-resolverReplyHeader._arcount:]:
                        if currentRRGlue._type == RR.TYPE_A:
                            resolverReplyRRGlue.append(currentRRGlue)

                    # Determine whether correct glue records are available
                    glueRecordFlag = False
                    for currentRRAuthority in resolverReplyRRAuthority:
                        if currentRRAuthority._type == RR.TYPE_NS:
                            for currentRRGlue in resolverReplyRRGlue:
                                # Correct glue record found, use the glue record for next query
                                if currentRRAuthority._nsdn == currentRRGlue._dn:
                                    glueRecordFlag = True
                                    queryNameServer = inet_ntoa(currentRRGlue._inaddr)
                                    resolverQueryID = randint(1, 65535)
                                    resolverQueryHeader = Header(resolverQueryID, Header.OPCODE_QUERY, Header.RCODE_NOERR, qdcount=1)
                    
                    
                    # If no glue record is found, determine whether correct authoritative records available
                    if glueRecordFlag == False:
                        
                        matchFlag = False
                        for currentRRAuthority in resolverReplyRRAuthority:
                            if currentRRAuthority._type == RR.TYPE_NS:
                                matchFlag = True
                    
                        # If correct authoritative records available, send query of its address
                        if matchFlag:
                            for currentRRAuthority in resolverReplyRRAuthority:
                                if currentRRAuthority._type == RR.TYPE_NS:
                                    try:
                                        (missingHeader, missingRR) = resolveQuery(clientQueryHeader, QE(dn = currentRRAuthority._nsdn), True)
                                        queryNameServer = inet_ntoa(missingRR[0]._inaddr)
                                        resolverQueryID = randint(1, 65535)
                                        resolverQueryHeader = Header(resolverQueryID, Header.OPCODE_QUERY, Header.RCODE_NOERR, qdcount=1)
                                        break
                                    except Exception:
                                        pass

                        # If no correct authoritative records available, query/answer is invalid (Most likely SOA type).
                        else:
                            # This flag is set only when this function is called recursively (i.e.querying for address of authoritative records)
                            if RaiseException:
                                print "\nInvalid query/answer type: Re-trying"
                                raise Exception("Invalid query/answer type: Re-trying")

                            # This flag is set only when this function is called for appending the ADDITIONAL section of given ANSWER and AUTHORITY sections
                            if glueMode:
                                print "\nInvalid answer type to the glue record query, cannot be cached or returned"
                                return resolverReplyHeader, []

                            # Client query is invalid, re-try until timeout
                            else:
                                print "\nInvalid query/answer type:  please verify your query"
                                sleep (1)
                                continue
            
            # DNS packet received from name server is corrupted, re-try
            else:
                print "\nDNS packet corrupted: Answer number is negative\nRe-trying...\n"
                continue


def addAdditionalRecords(responseRRList):
    '''
    For a given set of query answers, search cache and append corresponding AUTHORITY and ADDITIONAL sections
    Resent query of an authority record if its glue record does not exist
    '''
    # Identify corresponding domain for AUTHORITY and ADDITIONAL sections
    targetDomain = responseRRList[-1]._dn.parent() if responseRRList[-1]._dn.parent() != None else "."

    while True:
    
        # If this domain exists in nscache
        if targetDomain in nscache:
        
            # Search in nscache and append matched results
            for currentNSCache in nscache[targetDomain].keys():
                responseRRAuthorityList.append(RR_NS(targetDomain, nscache[targetDomain][currentNSCache]._expiration, currentNSCache))
                responseHeader._nscount += 1
                
                # If corresponding glue record exists, append it
                if currentNSCache in acache:
                    for currentACache in acache[currentNSCache]._dict.keys():
                        responseRRGlueList.append(RR_A(currentNSCache, acache[currentNSCache]._dict[currentACache]._expiration, currentACache.toNetwork()))
                        responseHeader._arcount += 1
            
                # If corresponding glue record does not exist, send query of it
                else:
                    # Only query valid authoritative records, discard SOA type
                    if currentNSCache not in invalidRRAuthority:
                        print currentNSCache
                        print "\nOne or more additional glue record is missing, searching...."
                        (processHeader, processRR) = resolveQuery(clientQueryHeader, QE(dn=currentNSCache), glueMode = True)
                        for currentOne in processRR:
                            if currentOne._type == RR.TYPE_A:
                                responseRRGlueList.append(currentOne)
                                responseHeader._arcount += 1
                    else:
                        pass
            break
    
        # If this domain does not exist in nscache, try its parent domain
        else:
            targetDomain = targetDomain.parent() if targetDomain.parent() != None else  "."
            
    # Search and save authoritative records with invalid glue records (no A type)
    # Saved invalid authoritative records will not be queried again
    for currentGlue in responseRRGlueList:
        responseRRGlueDN.append(currentGlue._dn)
    for currentAuthority in responseRRAuthorityList:
        if currentAuthority._nsdn not in responseRRGlueDN:
            invalidRRAuthority.append(currentAuthority._nsdn)

    return responseRRAuthorityList, responseRRGlueList




def parseQuery(data):
    '''
    Parse a DNS query with fromData() provided in Header and QE classes
    '''
    return Header.fromData(data), QE.fromData(data, 12)


def timeoutHandler(sig, stack):
    '''
    Handler for signal alarm timeout
    '''
    raise Exception("TIMEOUT")

# Used for saving invalid authoritative records in addAdditionalRecords function
invalidRRAuthority = []

while 1:
    # Wait for query
    (data, address,) = ss.recvfrom(512)  # DNS limits UDP msgs to 512 bytes
    if not data:
        logger.error("client provided no data")
        continue
    
    else:
        # Parse client query
        (clientQueryHeader, clientQueryQE) = parseQuery(data)

        # Discard unqualified queries
        if clientQueryHeader._rd == False:
            logger.error("client requested iterative query")
            reply = Header(clientQueryHeader._id, clientQueryHeader._opcode, Header.RCODE_NIMPL, qdcount= clientQueryHeader._qdcount, qr=True, rd=clientQueryHeader._rd, ra=True).pack()
             
        if clientQueryHeader._qdcount != 1:
            logger.error("client requested more than one query")
            reply = Header(clientQueryHeader._id, clientQueryHeader._opcode, Header.RCODE_NIMPL, qdcount= clientQueryHeader._qdcount, qr=True, rd=clientQueryHeader._rd, ra=True).pack()

        if clientQueryQE._type != QE.TYPE_A or clientQueryHeader._opcode != Header.QUERY:
            logger.error("client's query is not A type or not standard")
            reply = Header(clientQueryHeader._id, clientQueryHeader._opcode, Header.RCODE_NIMPL, qdcount= clientQueryHeader._qdcount, qr=True, rd=clientQueryHeader._rd, ra=True).pack()

        # Resolve client query
        else:
            # Initialise response/reply to client
        
            responseRRList = []
            responseRRAuthorityList = []
            responseRRGlueList = []
            responseRRGlueDN = []
            responseHeader = Header(clientQueryHeader._id, clientQueryHeader._opcode, Header.RCODE_SRVFAIL, qdcount= clientQueryHeader._qdcount, qr=True, rd=clientQueryHeader._rd, ra=True)
        
            # Initiate timeout of 8 seconds
            signal.signal(signal.SIGALRM, timeoutHandler)
            signal.alarm(8)
            
            try:
                # Send query for ANSWER section
                (responseHeader, responseRRList) = resolveQuery(clientQueryHeader, clientQueryQE)
                
                # Clear responseHeader's nscount and arcount for appending corresponding AUTHORITY and ADDITIONAL sections
                responseHeader._nscount = 0
                responseHeader._arcount = 0
                
                # Append corresponding AUTHORITY and ADDITIONAL sections
                (responseRRAuthorityList, responseRRGlueList) = addAdditionalRecords(responseRRList)
            
                signal.alarm(0)

            # Handle exceptions
            except Exception as e:
                if e.message == "TIMEOUT":
                    signal.alarm(0)
                    print "Query Failed: TIMEOUT\n"
                else:
                    signal.alarm(0)
                    print "Query Exception: ", e
                    print "Please try again"

            # Fix reply header
            responseHeader._id = clientQueryHeader._id
            responseHeader._rd = clientQueryHeader._rd
            responseHeader._qdcount = clientQueryHeader._qdcount
            responseHeader._ra = True

            # Construct reply body
            reply = responseHeader.pack() + clientQueryQE.pack()
            responseRRList = responseRRList + responseRRAuthorityList + responseRRGlueList
            for currentResponseRR in range(responseHeader._ancount + responseHeader._nscount + responseHeader._arcount):
                reply += responseRRList[currentResponseRR].pack()
                
        logger.log(DEBUG2, "our reply in full:")
        logger.log(DEBUG2, hexdump(reply))

        # send DNS response to client
        ss.sendto(reply, address)

        print "\n\nEND QUERY\n\n"

