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
    static PKCS11Object* Create(PKCS11Slot * slot, CK_OBJECT_HANDLE handle);

public:
    CK_OBJECT_CLASS getClass();
    string getClassString();
    CK_OBJECT_HANDLE getHandle();

    virtual void DumpAttributes();

protected:
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

    bool getIsToken();
    bool getIsPrivate();
    bool getIsModifiable();
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

    string getApplication();
    char* getObjectId();
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

    CK_KEY_TYPE getKeyType();
    string getKeyTypeString();
    char * getId();
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

    char* getSerial();
    string getSerialString();

protected:
    void QueryAttributes(PKCS11Slot * slot);
    void DumpAttributes();

protected:
    char * m_Serial;
    int m_SerialLength;
};


/*
class PKCS11PublicKeyObject : PKCS11Object
{


};

class PKCS11PrivateKeyObject : PKCS11Object
{


};

class PKCS11SecretKeyObject : PKCS11Object
{


};

class PKCS11HWFeatureObject : PKCS11Object
{
  //CK_HW_FEATURE_TYPE m_Type;
};

class PKCS11DomainParametersObject : PKCS11Object
{


};


class PKCS11MechanismObject : PKCS11Object
{


};
*/