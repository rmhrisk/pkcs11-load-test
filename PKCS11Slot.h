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
#include "stdafx.h"

#include <string>
#include <vector>

#include "include/cryptoki.h"

using namespace std;

typedef struct {

    // Basic info
    string label;
    string manufacturer;
    string model;
    string serial;
    string hardwareVersion;
    string firmwareVersion;

    // Capabilities
    bool hasRNG;
    bool isLoginRequired;

} PKCS11Token;


class PKCS11Slot
{
public:
    PKCS11Slot(CK_FUNCTION_LIST * pPKCS11);
    ~PKCS11Slot(void);

    // List all objects on a token
    void QueryObjects(vector<CK_OBJECT_HANDLE> * handles);

    // List all objects on a token having the supplied attributes
    void QueryObjects(vector<CK_OBJECT_HANDLE> * handles, CK_ATTRIBUTE * attributes, CK_ULONG count);

    // Return a set of defined attributes for a particular object 
    void QueryObject(CK_OBJECT_HANDLE handle, CK_ATTRIBUTE * attributes, CK_ULONG count);

    // Interrogate basic information from the associated token.
    void QueryToken(PKCS11Token * token);

    // Open a session to the token
    void OpenSession(bool rw);

    // Close a session to the token
    void CloseSession();

    // Log into the token using the USER pin
    void Login(string * pin);

    // Log out of the token
    void Logout();

    // UNUSED - Generate an RSA key-pair
    void GenerateKeyPair();

    // Generate [length] bytes of random data from the token
    void GenerateRandom(char * buffer, int length);

    // Generate a SHA-1 message digest for supplied data
    void GenerateDigest(const char * in, int inLength, char * out, int * outLength);

    // Generate a signature for the supplied data using the specified key handle
    void GenerateSignature(int key, const char * in, int inLength, char * out, int * outLength);

    // Verify a supplied signature for the given data using the specified key
    bool VerifySignature(int key, const char * in, int inLength, char * signature, int signatureLength);

    // Encrypt data using the specified public key
    void EncryptData(int key, const char * in, int inLength, char * out, int * outLength);

    // Decrypt data using the specified private key
    void DecryptData(int key, const char * in, int inLength, char * out, int * outLength);

public:
    unsigned long id;
    string description;
    string manufacturer;
    bool isTokenPresent;
    bool isTokenRemovable;
    bool isHardware;
    string hardwareVersion;
    string firmwareVersion;

private:
    CK_FUNCTION_LIST * m_pPKCS11;
    CK_SESSION_HANDLE m_SessionHandle;

};

