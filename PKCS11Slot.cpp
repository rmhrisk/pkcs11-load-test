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

#pragma once
#include "StdAfx.h"

#include <iomanip>

#include "PKCS11Slot.h"
#include "Utility.h"
#include "Log.h"


PKCS11Slot::PKCS11Slot(CK_FUNCTION_LIST * pPKCS11)
{
    m_pPKCS11 = pPKCS11;
    m_SessionHandle = NULL;

    this->id = 0;
    this->isTokenPresent = false;
    this->isHardware = false;
    this->isTokenRemovable = false;

}


PKCS11Slot::~PKCS11Slot(void)
{
    if (NULL != m_SessionHandle) {
        // Force the session closed
        Log::warn("PKCS11Slot::~PKCS11Slot: Forcing closure of open session.");
        this->CloseSession();
    }
}


void PKCS11Slot::QueryToken(PKCS11Token * token) {

    Log::debug("PKCS11Slot::QueryToken: Called\n");

    if (!this->isTokenPresent) {
        Log::error("PKCS11Slot::QueryToken: No token is present");
        throw "NO TOKEN PRESENT";
    }

    CK_TOKEN_INFO info;
    CK_RV result;
    CK_SLOT_ID slotId = this->id;

    result = m_pPKCS11->C_GetTokenInfo(slotId, &info);
    Utility::ThrowOnError(result, "PKCS11Slot::QueryToken", "C_GetTokenInfo");

    token->label = Utility::CK_UTF8CHARtoString(info.label, 32);
    token->manufacturer = Utility::CK_UTF8CHARtoString(info.manufacturerID, 32);
    token->model = Utility::CK_UTF8CHARtoString(info.model, 16);
    token->isLoginRequired = ((info.flags & CKF_LOGIN_REQUIRED) != 0);
    token->hasRNG = ((info.flags & CKF_RNG) != 0);

    Log::debug("PKCS11Slot::QueryToken: Label = %s\n", token->label.c_str());
    Log::debug("PKCS11Slot::QueryToken: Manufacturer = %s\n", token->manufacturer.c_str());
    Log::debug("PKCS11Slot::QueryToken: Model = %s\n", token->model.c_str());
    Log::debug("PKCS11Slot::QueryToken: Serial = %s\n", token->serial.c_str());
    Log::debug("PKCS11Slot::QueryToken: IsLoginRequired = %s\n", token->isLoginRequired ? "TRUE" : "FALSE");
    Log::debug("PKCS11Slot::QueryToken: hasRNG = %s\n", token->hasRNG ? "TRUE" : "FALSE");
}

void PKCS11Slot::OpenSession(bool rw) {
    Log::debug("PKCS11Slot::OpenSession: Called\n");

    if (!this->isTokenPresent) {
        Log::error("PKCS11Slot::QueryToken: No token is present");
        throw "NO TOKEN PRESENT";
    }

    if (NULL != m_SessionHandle) {
        Log::warn("PKCS11Slot::QueryToken: Session is already open, ignoring");
        return;
    }


    CK_RV result;

    // Open a session
    CK_SESSION_HANDLE sessionHandle;
    CK_FLAGS flags = CKF_SERIAL_SESSION;
    if (rw) flags |= CKF_RW_SESSION;
    result = this->m_pPKCS11->C_OpenSession(this->id, flags, NULL_PTR, NULL_PTR, &sessionHandle);
    Utility::ThrowOnError(result, "PKCS11Slot::OpenSession", "C_OpenSession");

    // Set our internal session handle
    Log::debug("PKCS11Slot::OpenSession: Session Opened\n");
    this->m_SessionHandle = sessionHandle;
}

void PKCS11Slot::CloseSession() {

    Log::debug("PKCS11Slot::CloseSession: Called\n");

    if (!this->isTokenPresent) {
        Log::error("PKCS11Slot::CloseSession: No token is present");
        throw "NO TOKEN PRESENT";
    }

    if (NULL == this->m_SessionHandle) {
        Log::warn("PKCS11Slot::CloseSession: Session must be opened first.");
        return;
    }

    CK_RV result;

    // Close the session
    result = this->m_pPKCS11->C_CloseSession(this->m_SessionHandle);

    // Regardless of whether the session is closed or not, get rid of the session handle so that
    // the destructor doesn't accidentally try to do this twice
    this->m_SessionHandle = NULL;

    Utility::ThrowOnError(result, "PKCS11Slot::CloseSession", "C_CloseSession");

    Log::debug("PKCS11Slot::CloseSession: Session Closed\n");

}

void PKCS11Slot::Login(string * pin) {

    Log::debug("PKCS11Slot::Login: Called\n");

    if (!this->isTokenPresent) {
        Log::error("PKCS11Slot::Login: No token is present");
        throw "NO TOKEN PRESENT";
    }

    if (NULL == this->m_SessionHandle) {
        Log::warn("PKCS11Slot::Login: Session must be opened first.");
        throw "NO SESSION OPEN";
    }

    CK_RV result;

    // Perform a login
    CK_UTF8CHAR * pinBuffer = (CK_UTF8CHAR*)pin->c_str();
    result = this->m_pPKCS11->C_Login(this->m_SessionHandle, CKU_USER, pinBuffer, pin->length());
    Utility::ThrowOnError(result, "PKCS11Slot::Login", "C_Login");
}

void PKCS11Slot::Logout() {
    Log::debug("PKCS11Slot::Logout: Called\n");

    if (!this->isTokenPresent) {
        Log::error("PKCS11Slot::Logout: No token is present");
        throw "NO TOKEN PRESENT";
    }

    if (NULL == this->m_SessionHandle) {
        Log::warn("PKCS11Slot::Logout: Session must be opened first.");
        throw "NO SESSION OPEN";
    }

    CK_RV result;

    // Perform a logout
    result = this->m_pPKCS11->C_Logout(this->m_SessionHandle);
    Utility::ThrowOnError(result, "PKCS11Slot::Logout", "C_Logout");
}

void PKCS11Slot::GenerateKeyPair() {

    Log::debug("PKCS11Slot::GenerateDigest: Called\n");

    CK_RV result;

    CK_OBJECT_HANDLE publicKey, privateKey;
    CK_MECHANISM mechanism = {
        CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0
    };

    CK_ULONG modulusBits = 2048;
    CK_BYTE publicExponent[] = { 1, 0, 1 };
    CK_BYTE label[] = "TestKey";
    CK_BYTE id[] = { 0x01 };

    CK_BBOOL trueValue = CK_TRUE;

    CK_ATTRIBUTE publicKeyTemplate[] = {
        {CKA_ID, id, sizeof(id)},
        {CKA_LABEL, label, sizeof(label)},
        {CKA_TOKEN, &trueValue, sizeof(true)},
        {CKA_ENCRYPT, &trueValue, sizeof(true)},
        {CKA_VERIFY, &trueValue, sizeof(true)},
        {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
        {CKA_PUBLIC_EXPONENT, publicExponent, 3}
    };

    CK_ATTRIBUTE privateKeyTemplate[] = {
        {CKA_ID, id, sizeof(id)},
        {CKA_LABEL, label, sizeof(label)},
        {CKA_TOKEN, &trueValue, sizeof(true)},
        {CKA_PRIVATE, &trueValue, sizeof(true)},
        {CKA_SENSITIVE, &trueValue, sizeof(true)},
        {CKA_DECRYPT, &trueValue, sizeof(true)},
        {CKA_SIGN, &trueValue, sizeof(true)}
    };

    result = m_pPKCS11->C_GenerateKeyPair( m_SessionHandle,
                                           &mechanism,
                                           publicKeyTemplate, 7,
                                           privateKeyTemplate, 7,
                                           &publicKey,
                                           &privateKey);

    Utility::ThrowOnError(result, "PKCS11Slot::GenerateKeyPair", "C_GenerateKeyPair");
}

void PKCS11Slot::GenerateDigest(const char * in, int inLength, char * out, int * outLength) {
    Log::debug("PKCS11Slot::GenerateDigest: Called\n");

    CK_MECHANISM mechanism;
    CK_RV result;

    Log::debug("PKCS11Slot::GenerateDigest: Mechanism is CKM_SHA_1\n");
    mechanism.mechanism = CKM_SHA_1;
    mechanism.pParameter = NULL;
    mechanism.ulParameterLen = 0;

    result = m_pPKCS11->C_DigestInit(m_SessionHandle, &mechanism);
    Utility::ThrowOnError(result, "PKCS11Slot::GenerateSHA1Digest", "C_DigestInit");

    result = m_pPKCS11->C_Digest(m_SessionHandle, (CK_BYTE_PTR)in, inLength, (CK_BYTE_PTR)out, (CK_ULONG_PTR)outLength);
    Utility::ThrowOnError(result, "PKCS11Slot::GenerateSHA1Digest", "C_Digest");
}

void PKCS11Slot::EncryptData(int key, const char * in, int inLength, char * out, int * outLength) {

    Log::debug("PKCS11Slot::EncryptData: Called\n");

    CK_MECHANISM mechanism;
    CK_RV result;

    Log::debug("PKCS11Slot::EncryptData: Mechanism is CKM_RSA_PKCS\n");
    mechanism.mechanism = CKM_RSA_PKCS;
    mechanism.pParameter = NULL;
    mechanism.ulParameterLen = 0;

    result = m_pPKCS11->C_EncryptInit(m_SessionHandle, &mechanism, key);
    Utility::ThrowOnError(result, "PKCS11Slot::EncryptData", "C_EncryptInit");

    result = m_pPKCS11->C_Encrypt(m_SessionHandle, (CK_BYTE_PTR)in, inLength, (CK_BYTE_PTR)out, (CK_ULONG_PTR)outLength);
    Utility::ThrowOnError(result, "PKCS11Slot::EncryptData", "C_Encrypt");
}

void PKCS11Slot::DecryptData(int key, const char * in, int inLength, char * out, int * outLength) {

    Log::debug("PKCS11Slot::DecryptData: Called\n");

    CK_MECHANISM mechanism;
    CK_RV result;

    Log::debug("PKCS11Slot::DecryptData: Mechanism is CKM_RSA_PKCS\n");
    mechanism.mechanism = CKM_RSA_PKCS;
    mechanism.pParameter = NULL;
    mechanism.ulParameterLen = 0;

    result = m_pPKCS11->C_DecryptInit(m_SessionHandle, &mechanism, key);
    Utility::ThrowOnError(result, "PKCS11Slot::DecryptData", "C_DecryptInit");

    result = m_pPKCS11->C_Decrypt(m_SessionHandle, (CK_BYTE_PTR)in, inLength, (CK_BYTE_PTR)out, (CK_ULONG_PTR)outLength);
    Utility::ThrowOnError(result, "PKCS11Slot::DecryptData", "C_Decrypt");
}


void PKCS11Slot::GenerateSignature(int key, const char * in, int inLength, char * out, int * outLength) {

    Log::debug("PKCS11Slot::GenerateSignature: Called\n");

    CK_MECHANISM mechanism;
    CK_RV result;

    Log::debug("PKCS11Slot::GenerateSignature: Mechanism is CKM_RSA_PKCS\n");
    mechanism.mechanism = CKM_RSA_PKCS;
    mechanism.pParameter = NULL;
    mechanism.ulParameterLen = 0;

    result = m_pPKCS11->C_SignInit(m_SessionHandle, &mechanism, key);
    Utility::ThrowOnError(result, "PKCS11Slot::GenerateSignature", "C_SignInit");

    result = m_pPKCS11->C_Sign(m_SessionHandle, (CK_BYTE_PTR)in, inLength, (CK_BYTE_PTR)out, (CK_ULONG_PTR)outLength);
    Utility::ThrowOnError(result, "PKCS11Slot::GenerateSignature", "C_Sign");


}

bool PKCS11Slot::VerifySignature(int key, const char * in, int inLength, char * signature, int signatureLength) {

    Log::debug("PKCS11Slot::VerifySignature: Called\n");

    CK_MECHANISM mechanism;
    CK_RV result;

    Log::debug("PKCS11Slot::VerifySignature: Mechanism is CKM_RSA_PKCS\n");
    mechanism.mechanism = CKM_RSA_PKCS;
    mechanism.pParameter = NULL;
    mechanism.ulParameterLen = 0;

    result = m_pPKCS11->C_VerifyInit(m_SessionHandle, &mechanism, key);
    Utility::ThrowOnError(result, "PKCS11Slot::VerifySignature", "C_VerifyInit");

    result = m_pPKCS11->C_Verify(m_SessionHandle, (CK_BYTE_PTR)in, inLength, (CK_BYTE_PTR)signature, signatureLength);
    Utility::ThrowOnError(result, "PKCS11Slot::VerifySignature", "C_Verify");

    // Check for the specific invalid signature response
    if (CKR_SIGNATURE_INVALID == result) {
        return false;
    }

    // We must have succeeded!
    return true;
}

void PKCS11Slot::GenerateRandom(char * buffer, int length) {
    Log::debug("PKCS11Slot::GenerateRandom: Called\n");

    if (!this->isTokenPresent) {
        Log::error("PKCS11Slot::GenerateRandom: No token is present");
        throw;
    }

    if (NULL == this->m_SessionHandle) {
        Log::warn("PKCS11Slot::GenerateRandom: Session must be opened first.");
        return;
    }

    CK_RV result;

    // Generate the random data
    result = this->m_pPKCS11->C_GenerateRandom(this->m_SessionHandle, (CK_BYTE_PTR)buffer, length);
    Utility::ThrowOnError(result, "PKCS11Slot::GenerateRandom", "C_GenerateRandom");
}

void PKCS11Slot::QueryObject(CK_OBJECT_HANDLE handle, CK_ATTRIBUTE * attributes, CK_ULONG count) {

    CK_RV result;
    result = this->m_pPKCS11->C_GetAttributeValue(this->m_SessionHandle, handle, attributes, count);
    Utility::ThrowOnError(result, "PKCS11Slot::QueryObject", "C_GetAttributeValue");

}

void PKCS11Slot::QueryObjects(vector<CK_OBJECT_HANDLE> * handles) {
    // This is just a wrapper overload with no attributes specified
    this->QueryObjects(handles, NULL_PTR, 0);
}

void PKCS11Slot::QueryObjects(vector<CK_OBJECT_HANDLE> * handles, CK_ATTRIBUTE * attributes, CK_ULONG attrCount) {

    if (!this->isTokenPresent) {
        Log::error("PKCS11Slot::QueryObjects: No token is present");
        throw;
    }

    if (NULL == this->m_SessionHandle) {
        Log::warn("PKCS11Slot::QueryObjects: Session must be opened first.");
        return;
    }

    CK_OBJECT_HANDLE hObject;
    CK_ULONG count;
    CK_RV result;

    // Find all objects with the template specified
    result = this->m_pPKCS11->C_FindObjectsInit(this->m_SessionHandle, attributes, attrCount);
    Utility::ThrowOnError(result, "PKCS11Slot::QueryObjects", "C_FindObjectsInit");

    do {

        // Find the next object
        result = this->m_pPKCS11->C_FindObjects(this->m_SessionHandle, &hObject, 1, &count);
        Utility::ThrowOnError(result, "PKCS11Slot::QueryObjects", "C_FindObjects");

        if (count != 0) handles->push_back(hObject);

    } while (count != 0);

    result = this->m_pPKCS11->C_FindObjectsFinal(this->m_SessionHandle);
    Utility::ThrowOnError(result, "PKCS11Slot::QueryObjects", "C_FindObjectsFinal");
}
