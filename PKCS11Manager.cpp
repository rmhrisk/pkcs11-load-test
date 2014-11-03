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

#include "stdafx.h"

#include <Windows.h>
#include <strstream>

#include "Utility.h"
#include "PKCS11Manager.h"
#include "Log.h"

using namespace std;

// Pointer to the Singleton instance
PKCS11Manager * PKCS11Manager::m_Instance = NULL;

// Handle to the PKCS library
HINSTANCE PKCS11Manager::hPKCS11 = NULL;

// PKCS11 Function Pointer
CK_FUNCTION_LIST * PKCS11Manager::pPKCS11 = NULL;

// TODO: Create ERR valeus for all exceptions thrown

PKCS11Manager::PKCS11Manager(void)
{

}

PKCS11Manager::~PKCS11Manager(void)
{
    this->Destroy();
}

PKCS11Manager* PKCS11Manager::Create(LPCTSTR libraryPath) {

    // Has this object already been created? If so, just pass it back
    if (m_Instance != NULL) {
        return m_Instance;
    }

    // Attempt to load the library via the supplied module path
    hPKCS11 = LoadLibrary(libraryPath);

    if (NULL == hPKCS11) {
        Log::error("PKCS11Manager::Create: Unable to load the supplied PKCS11 module.\n");
        throw;
    }

    // Load the reference to C_GetFunctionList
    CK_C_GetFunctionList pC_GetFunctionList = NULL;

    pC_GetFunctionList = (CK_C_GetFunctionList) GetProcAddress(hPKCS11, "C_GetFunctionList");
    if (pC_GetFunctionList == NULL)
    {
        Log::error("PKCS11Manager::Create: GetProcAddress on C_GetFunctionList failed.\n");
        FreeLibrary(hPKCS11);
        hPKCS11 = NULL;
        throw;
    }

    // Call C_GetFunctionList
    CK_RV result;

    result = (*pC_GetFunctionList) (&pPKCS11);
    if (result != CKR_OK)
    {
        FreeLibrary(hPKCS11);
        pPKCS11 = NULL;
        hPKCS11 = NULL;

        // Force a throw
        Utility::ThrowOnError(result, "PKCS11Manager::Create", "C_GetFunctionList");
    }

    // Call C_Initialize;
    result = pPKCS11->C_Initialize(NULL_PTR);
    if (result != CKR_OK) {

        FreeLibrary(hPKCS11);
        pPKCS11 = NULL;
        hPKCS11 = NULL;

        // Force a throw
        Utility::ThrowOnError(result, "PKCS11Manager::Create", "C_Initialize");
    }

    // Call C_GetInfo
    CK_INFO info;
    result = pPKCS11->C_GetInfo(&info);
    if (result != CKR_OK) {
        FreeLibrary(hPKCS11);
        pPKCS11 = NULL;
        hPKCS11 = NULL;

        // Force a throw
        Utility::ThrowOnError(result, "PKCS11Manager::Create", "C_GetInfo");
    }

    string manufacturer = Utility::CK_UTF8CHARtoString(info.manufacturerID, 32);
    string libraryDescription = Utility::CK_UTF8CHARtoString(info.libraryDescription, 32);

    Log::debug("PKCS11:Create: CryptoKi Version %d.%d\n", info.cryptokiVersion.major, info.cryptokiVersion.minor);
    Log::debug("PKCS11:Create: Manufacturer ID '%s'\n",  manufacturer.c_str());
    Log::debug("PKCS11:Create: Library Description '%s'\n", libraryDescription.c_str());
    Log::debug("PKCS11:Create: Library Version %d.%d\n", info.libraryVersion.major, info.libraryVersion.minor);

    // Create our new PKCS11Manager instance and return it;
    m_Instance = new PKCS11Manager();
    return m_Instance;
}



void PKCS11Manager::Destroy() {

    if (NULL == hPKCS11) return;

    pPKCS11->C_Finalize(NULL_PTR);
    FreeLibrary(hPKCS11);

    pPKCS11 = NULL;
    hPKCS11 = NULL;

}

int PKCS11Manager::QuerySlots(bool tokenPresent, vector<PKCS11Slot> * slots) {

    Log::debug("PKCS11Manager::QuerySlots: Called\n");
    // Get slot count
    CK_ULONG count;
    pPKCS11->C_GetSlotList(tokenPresent ? CK_TRUE : CK_FALSE, NULL_PTR, &count);

    // No point if there aren't any
    if (count == 0) return count;

    // List slots
    CK_SLOT_ID * slotIds = new CK_SLOT_ID[count];
    pPKCS11->C_GetSlotList(tokenPresent ? CK_TRUE : CK_FALSE, slotIds, &count);

    // Retrieve the slot info
    for (CK_ULONG i = 0; i < count; i++) {

        CK_SLOT_INFO info;
        PKCS11Slot slot(this->pPKCS11);

        CK_RV result;
        result = pPKCS11->C_GetSlotInfo(slotIds[i], &info);
        Utility::ThrowOnError(result, "PKCS11Manager::QuerySlots", "C_GetSlotInfo");

        slot.id = slotIds[i];
        slot.manufacturer = Utility::CK_UTF8CHARtoString(info.manufacturerID, 32);
        slot.description = Utility::CK_UTF8CHARtoString(info.slotDescription, 64);

        slot.isTokenPresent = (bool)((info.flags & CKF_TOKEN_PRESENT) != 0);
        slot.isTokenRemovable = (bool)((info.flags & CKF_REMOVABLE_DEVICE) != 0);
        slot.isHardware = (bool)((info.flags & CKF_HW_SLOT) != 0);

        Log::debug("PKCS11Manager::QuerySlots: ADDING SLOT %u\n", slot.id);
        Log::debug("PKCS11Manager::QuerySlots: Manufacturer = %s\n", slot.manufacturer.c_str());
        Log::debug("PKCS11Manager::QuerySlots: Description = %s\n", slot.description.c_str());

        slots->push_back(slot);
    }

    return count;
}