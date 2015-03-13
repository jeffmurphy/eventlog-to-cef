/*
  This code derived from http://support.microsoft.com/kb/831226

  jcmurphy@jeffmurphy.org
*/


/*
  This code is a modification of the modification of the original Eventlog to Syslog Script written by
  Curtis Smith of Purdue University. The original copyright notice can be found below.
  
  This modification of the modification of the original program was modified by Jeff Murphy
  of the University at Buffalo Information Security Office in order to:

  a) Insert the IP address of FQDN of the system into the messages
  b) Insert the OS name/revision into the messages
  c) Format the messages in CEF 

  for the express purposes of implementing a push model of event log messages into
  Arcsight ESM. The messages can then be delivered to the Arcsight Syslog Connector

     Jeff Murphy
	 3850 Rensch Rd
	 Amherst NY 14228
	 
	 
	Send all comments, suggestions, or bug reports related to the above modifications to:
		jcmurphy@jeffmurphy.org

*/
 /*
  This code is a modification of the original Eventlog to Syslog Script written by
  Curtis Smith of Purdue University. The original copyright notice can be found below.
  
  The original program was modified by Sherwin Faria for Rochester Institute of Technology
  in July 2009 to provide bug fixes and add several new features. Additions include
  the ability to ignore specific events, add the event timestamp to outgoing messages,
  a service status file, and compatibility with the new Vista/2k8 Windows Events service.

     Sherwin Faria
	 Rochester Institute of Technology
	 Information & Technology Services Bldg. 10
	 1 Lomb Memorial Drive
	 Rochester, NY 14623 U.S.A.
	 
	Send all comments, suggestions, or bug reports to:
		sherwin.faria@gmail.com
*/
 
/*
  Copyright (c) 1998-2007, Purdue University
  All rights reserved.

  Redistribution and use in source and binary forms are permitted provided
  that:

  (1) source distributions retain this entire copyright notice and comment,
      and
  (2) distributions including binaries display the following acknowledgement:

         "This product includes software developed by Purdue University."

      in the documentation or other materials provided with the distribution
      and in all advertising materials mentioning features or use of this
      software.

  The name of the University may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR IMPLIED
  WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
  MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.

  This software was developed by:
     Curtis Smith

     Purdue University
     Engineering Computer Network
     465 Northwestern Avenue
     West Lafayette, Indiana 47907-2035 U.S.A.

  Send all comments, suggestions, or bug reports to:
     software@ecn.purdue.edu

*/


#include "main.h"
#include "log.h"
#include "syslog.h"

#include <inaddr.h>
#include <winsock2.h>  //winsock
#include <windns.h>   //DNS api's
#include <stdio.h>    //standard i/o
#include <Winerror.h>

#define BUFFER 255



static PIP4_ARRAY get_dns_server() 
{
	PIP4_ARRAY pSrvList = NULL;
	char DnsServIp[BUFFER];

	pSrvList = (PIP4_ARRAY) LocalAlloc(LPTR, sizeof(IP4_ARRAY));
    if(!pSrvList) {
		printf("Memory allocation failed \n");
        exit(1);
    }
    strcpy_s(DnsServIp, BUFFER, "8.8.8.8"); // testing
    pSrvList->AddrCount = 1;
    pSrvList->AddrArray[0] = inet_addr(DnsServIp); //DNS server IP address
	return pSrvList;
}


static int dns_ptr(char *pOwnerName) 
{ 
    DNS_STATUS status;               //Return value of  DnsQuery_A() function.
    PDNS_RECORD pDnsRecord;          //Pointer to DNS_RECORD structure.
    PIP4_ARRAY pSrvList = NULL;      //Pointer to IP4_ARRAY structure.
    DNS_FREE_TYPE freetype ;

	//pSrvList = get_dns_server();

	freetype =  DnsFreeRecordListDeep;

    // Calling function DnsQuery to query PTR records  

    status = DnsQuery_A((PCSTR)pOwnerName,         //Pointer to OwnerName. 
                        DNS_TYPE_PTR,              //Type of the record to be queried.
                        DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_LOCAL_NAME | DNS_QUERY_NO_HOSTS_FILE | DNS_QUERY_NO_NETBT,     // Bypasses windows nonsense. 
                        0, //pSrvList,             //Contains DNS server IP address.
                        &pDnsRecord,               //Resource record that contains the response.
                        NULL);                     //Reserved for future use.

    if (status){
		return 0; // just leave pOwnerName as-is
		if (status != 9003) 
			printf("Failed to query the PTR record and the error is %d \n", status);
    } else {
        //printf("The host name is -> %s  \n",(pDnsRecord->Data.PTR.pNameHost));
		strcpy_s(pOwnerName, BUFFER, pDnsRecord->Data.PTR.pNameHost);
        // Free memory allocated for DNS records. 
        DnsRecordListFree(pDnsRecord, freetype);
    }
    LocalFree(pSrvList);
	return 1;
}

// obviously no ipv6 
static void ReverseIP(char* pIP)
{
    char seps[]   = ".";
    char *token, *context;
    char pIPSec[4][4];
    int i=0;
    token = strtok_s( pIP, seps, &context);
    while( token != NULL )
    {
        /* While there are "." characters in "string" */
        sprintf_s(pIPSec[i], 4, "%s", token);
        /* Get next "." character: */
        token = strtok_s( NULL, seps, &context);
        i++;
    }
    sprintf_s(pIP, BUFFER, "%s.%s.%s.%s.%s", pIPSec[3], pIPSec[2], pIPSec[1], pIPSec[0], "IN-ADDR.ARPA");
}



int get_hostname (char *buffer, int len) 
{
	int rv, i;
	struct hostent *pHost = 0;
	char aszIPAddresses[10][16]; // maximum of ten IP addresses
	struct sockaddr_in SocketAddress;
	char pReversedIP[BUFFER];		//Reversed IP address.

	if (!buffer) return 0;

	rv = gethostname(buffer, len);
	if (rv == 0) {
		pHost = gethostbyname(buffer);
		
		if (pHost) {
			for(i = 0; ((pHost->h_addr_list[i]) && (i < 1)); ++i)
			{
				memcpy(&SocketAddress.sin_addr, pHost->h_addr_list[i], pHost->h_length);
				strcpy_s(aszIPAddresses[i], 16, inet_ntoa(SocketAddress.sin_addr));
				sprintf_s(pReversedIP, BUFFER, "%s", aszIPAddresses[i]);
				ReverseIP(pReversedIP);

				if (dns_ptr(pReversedIP)) 
					strcpy_s(buffer, len, pReversedIP);
				else
					sprintf_s(buffer, BUFFER, "%s", aszIPAddresses[i]);
			}
		} else {
			printf("gethostname rv: %d (pHost == null). cant resolve localhost name/ip address. dont use the -a flag. sorry.\n", rv);
			exit(-1);
		}
	}
	return 1;
}

