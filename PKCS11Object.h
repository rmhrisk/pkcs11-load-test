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

#include "Utility.h"
#include "PKCS11Slot.h"
#include "include\cryptoki.h"

using namespace std;

class PKCS11Object
{

public:
    PKCS11Object(void);
    ~PKCS11Object(void);

    // Static factory method to interrogate a token for a particular object handle and return an appropriate instance.
    static PKCS11Object* Create(PKCS11Slot * slot, CK_OBJECT_HANDLE handle);

public:

    // Returns the CKA_CLASS object value
    CK_OBJECT_CLASS getClass();

    // Returns the CKA_CLASS object value as a string
    string getClassString();

    // Returns the object handle
    CK_OBJECT_HANDLE getHandle();

    // Diagnostic method to dump all related attributes to this object
    virtual void DumpAttributes();

protected:

    // Causes the instance to read its related attributes from the token.
    virtual void QueryAttributes(PKCS11Slot * slot);

protected:
    CK_OBJECT_CLASS m_Class;
    CK_OBJECT_HANDLE m_Handle;
};

class PKCS11StorageObject : public PKCS11Object
{
public:
    PKCS11StorageObject(void);
    ~PKCS11StorageObject(void);

    // Returns the CKA_TOKEN object value
    bool getIsToken();

    // Returns the CKA_PRIVATE object value
    bool getIsPrivate();

    // Returns the CKA_MODIFIABLE object value
    bool getIsModifiable();

    // Returns the CKA_LABEL object value
    string getLabel();


protected:
    virtual void QueryAttributes(PKCS11Slot * slot);
    virtual void DumpAttributes();

protected:
    CK_BBOOL m_Token;
    CK_BBOOL m_Private;
    CK_BBOOL m_Modifiable;
    string m_Label;
};


class PKCS11DataObject : public PKCS11StorageObject
{

public:
    PKCS11DataObject(void);
    ~PKCS11DataObject(void);

    // Returns the CKA_APPLICATION object value
    string getApplication();

    // Returns the CKA_OBJECT_ID object value
    char* getObjectId();

    // Returns the CKA_VALUE object value
    char* getValue();

    string getObjectIdString();
    string getValueString();

protected:
    void QueryAttributes(PKCS11Slot * slot);
    void DumpAttributes();

protected:
    string m_Application;

    char* m_ObjectId;
    int m_ObjectIdLength;
    char* m_Value;
    int m_ValueLength;
};


class PKCS11KeyObject : public PKCS11StorageObject
{
public:
    PKCS11KeyObject(void);
    ~PKCS11KeyObject(void);

    // Returns the CKA_KEY_TYPE object value
    CK_KEY_TYPE getKeyType();

    // Returns the CKA_KEY_TYPE object value as a string
    string getKeyTypeString();

    // Returns the CKA_ID object value
    char * getId();

    // Returns the CKA_ID object value as a string
    string getIdString();

protected:
    void QueryAttributes(PKCS11Slot * slot);
    void DumpAttributes();

protected:
    CK_KEY_TYPE m_KeyType;
    char * m_Id;
    int m_IdLength;
    // Start Date
    // End Date
};

class PKCS11X509CertificateObject : public PKCS11StorageObject
{
public:
    PKCS11X509CertificateObject(void);
    ~PKCS11X509CertificateObject(void);

    // Returns the CKA_SERIAL_NUMBER object value
    char* getSerial();

    // Returns the CKA_SERIAL_NUMBER object value as a string
    string getSerialString();

protected:
    void QueryAttributes(PKCS11Slot * slot);
    void DumpAttributes();

protected:
    char * m_Serial;
    int m_SerialLength;
};

