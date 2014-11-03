/*
The MIT License (MIT)

Copyright (c) 2014 - Commonwealth of Australia (Represented by the Department of Defence)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

*/

/*

Portions of this code are derived from Ludovic Rousseau's sample at:
http://ludovicrousseau.blogspot.com.au/2010/04/pcsc-sample-in-c.html

This code is licensed under the Creative Commons Attribution-NonCommercial-ShareAlike 3.0 Unported License.
http://creativecommons.org/licenses/by-nc-sa/3.0/
*/

#include "StdAfx.h"
#include "PCSC.h"

#ifdef WIN32
#undef UNICODE
#endif

#include "Utility.h"

#include <stdio.h>
#include <stdlib.h>

extern "C"
{
#ifdef __APPLE__
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#else
#include <winscard.h>
#endif
}

PCSC::PCSC(void)
{
}


PCSC::~PCSC(void)
{
}

static char* GetPCSCErrorString(LONG rv)
{
    static char out[20];
    sprintf_s(out, sizeof(out), "0x%08X", rv);

    return out;
}

#define CHECK(f, rv) \
 if (SCARD_S_SUCCESS != rv) \
 { \
  Log::error("%s: %s\n", f, GetPCSCErrorString(rv)); \
  throw "PCSC Error"; \
 }


bool IsCommandOK(BYTE * response, int len) {
    return ((response[len - 2] == 0x90) && (response[len-1] == 0x00));
}

string PCSC::QueryCPLC(string reader) {

    LONG rv;

    SCARDCONTEXT hContext;
    SCARDHANDLE hCard;
    DWORD dwActiveProtocol, dwRecvLength;

    SCARD_IO_REQUEST pioSendPci;
    BYTE pbRecvBuffer[258];

// APDU's
    BYTE cmdSelectAid1[] = { 0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00 };
    BYTE cmdSelectAid2[] = { 0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00 };
    BYTE cmdGetData1[] = { 0x00, 0xCA, 0x9F, 0x7F };
    BYTE cmdGetData2[] = { 0x80, 0xCA, 0x9F, 0x7F, 00 };

    rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
    CHECK("SCardEstablishContext", rv);

#ifdef SCARD_AUTOALLOCATE
// dwReaders = SCARD_AUTOALLOCATE;
//rv = SCardListReaders(hContext, NULL, (LPTSTR)&mszReaders, &dwReaders);
//CHECK("SCardListReaders", rv);
#else
    rv = SCardListReaders(hContext, NULL, NULL, &dwReaders);
    CHECK("SCardListReaders", rv);

    mszReaders = calloc(dwReaders, sizeof(char));
    rv = SCardListReaders(hContext, NULL, mszReaders, &dwReaders);
    CHECK("SCardListReaders", rv);
#endif
// printf("reader name: %s\n", mszReaders);

    rv = SCardConnect(hContext, reader.c_str(), SCARD_SHARE_SHARED,
                      SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol);
    CHECK("SCardConnect", rv);

    switch(dwActiveProtocol)
    {
    case SCARD_PROTOCOL_T0:
        pioSendPci = *SCARD_PCI_T0;
        break;

    case SCARD_PROTOCOL_T1:
        pioSendPci = *SCARD_PCI_T1;
        break;
    }

// AID 1
    dwRecvLength = sizeof(pbRecvBuffer);
    rv = SCardTransmit(hCard, &pioSendPci, cmdSelectAid1, sizeof(cmdSelectAid1), NULL, pbRecvBuffer, &dwRecvLength);
    CHECK("SCardTransmit", rv);

    if (!IsCommandOK(pbRecvBuffer, dwRecvLength)) {
        // Attempt with AID 2
        dwRecvLength = sizeof(pbRecvBuffer);
        rv = SCardTransmit(hCard, &pioSendPci, cmdSelectAid2, sizeof(cmdSelectAid2), NULL, pbRecvBuffer, &dwRecvLength);
        CHECK("SCardTransmit", rv);
    }

#if defined(DEBUG)
    printf("response: ");

    for(i=0; i<dwRecvLength; i++) {
        printf("%02X ", pbRecvBuffer[i]);
    }

    printf("\n");
#endif

    dwRecvLength = sizeof(pbRecvBuffer);
    rv = SCardTransmit(hCard, &pioSendPci, cmdGetData1, sizeof(cmdGetData1), NULL, pbRecvBuffer, &dwRecvLength);
    CHECK("SCardTransmit", rv)


    if (!IsCommandOK(pbRecvBuffer, dwRecvLength)) {
        // Attempt with GetData 2
        dwRecvLength = sizeof(pbRecvBuffer);
        rv = SCardTransmit(hCard, &pioSendPci, cmdGetData2, sizeof(cmdGetData2), NULL, pbRecvBuffer, &dwRecvLength);
        CHECK("SCardTransmit", rv);
    }

#if defined(DEBUG)
    printf("RX: ");

    for(i=0; i<dwRecvLength; i++) {
        printf("%02X ", pbRecvBuffer[i]);
    }

    printf("\n");
#endif

    rv = SCardDisconnect(hCard, SCARD_LEAVE_CARD);
    CHECK("SCardDisconnect", rv);

    rv = SCardReleaseContext(hContext);

    CHECK("SCardReleaseContext", rv);


    // Parse the CPLC
    if (dwRecvLength == 0x2C) {

        // Response does not contain the BER-TLV formatted CPLC
        string result = Utility::ArraytoHexString((char*)&pbRecvBuffer[0x0C], 4);
        return result;

    }
    else if (dwRecvLength == 0x2F) {

        // Response does contain the BER-TLV formatted CPLC
        string result = Utility::ArraytoHexString((char*)&pbRecvBuffer[0x0F], 4);
        return result;

    } else {
        throw "Invalid CPLC Length";
    }
}