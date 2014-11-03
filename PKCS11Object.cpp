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

#include "StdAfx.h"
#include "PKCS11Object.h"
#include "Log.h"

PKCS11Object::PKCS11Object(void)
{
    m_Class = NULL;
    m_Handle = NULL;
}


PKCS11Object::~PKCS11Object(void)
{
}


PKCS11Object* PKCS11Object::Create(PKCS11Slot * slot, CK_OBJECT_HANDLE handle) {

    CK_OBJECT_CLASS classObject;
    PKCS11Object* result;

    // Attribute Definitions
    CK_ATTRIBUTE attributes[] = {
        { CKA_CLASS, &classObject, sizeof(CK_OBJECT_CLASS) }
    };

    // Query Attributes
    slot->QueryObject(handle, attributes, 1);

    switch (classObject) {

    case CKO_DATA:
        result = new PKCS11DataObject();
        break;
    case CKO_CERTIFICATE:
        result = new PKCS11X509CertificateObject();
        break;
    case CKO_PUBLIC_KEY:
        result = new PKCS11KeyObject();
        break;
    case CKO_PRIVATE_KEY:
        result = new PKCS11KeyObject();
        break;
    case CKO_SECRET_KEY:
        result = new PKCS11KeyObject();
        break;
    case CKO_HW_FEATURE:
        result = new PKCS11Object();
        break;
    case CKO_DOMAIN_PARAMETERS:
        result = new PKCS11StorageObject();
        break;
    case CKO_MECHANISM:
        result = new PKCS11Object();
        break;

    default:
        Log::error("PKCS11Object::Create: Invalid classObject specified (%u)\n", classObject);
        throw;
    }

    // Query the object
    result->m_Handle = handle;
    result->QueryAttributes(slot);

    return result;
}


CK_OBJECT_CLASS PKCS11Object::getClass() {
    return m_Class;
}

string PKCS11Object::getClassString() {

    switch (m_Class) {

    case CKO_DATA:
        return string("Data");
    case CKO_CERTIFICATE:
        return string("Certificate");
    case CKO_PUBLIC_KEY:
        return string("PublicKey");
    case CKO_PRIVATE_KEY:
        return string("PrivateKey");
    case CKO_SECRET_KEY:
        return string("Secret");
    case CKO_HW_FEATURE:
        return string("HWFeature");
    case CKO_DOMAIN_PARAMETERS:
        return string("DomainParameters");
    case CKO_MECHANISM:
        return string("Mechanism");

    default:
        Log::error("PKCS11Object::Create: Invalid classObject specified (%u)\n", m_Class);
        throw;
    }

}

CK_OBJECT_HANDLE PKCS11Object::getHandle() {
    return m_Handle;
}

void PKCS11Object::DumpAttributes() {
    Log::debug("CKA_CLASS\t\t%s\n", getClassString().c_str());
}

void PKCS11Object::QueryAttributes(PKCS11Slot * slot) {

    // Attribute Definitions
    CK_ATTRIBUTE attributes[] = {
        { CKA_CLASS, &m_Class, sizeof(CK_OBJECT_CLASS) }
    };

    // Query Attributes
    slot->QueryObject(this->m_Handle, attributes, 1);
}


// STORAGE OBJECT

PKCS11StorageObject::PKCS11StorageObject(void) {
    m_Token = CK_FALSE;
    m_Private = CK_FALSE;
    m_Modifiable = CK_FALSE;
}

PKCS11StorageObject::~PKCS11StorageObject(void) {
}

bool PKCS11StorageObject::getIsToken() {
    return (m_Token == CK_TRUE) ? true : false;
}

bool PKCS11StorageObject::getIsPrivate() {
    return (m_Private == CK_TRUE) ? true : false;
}

bool PKCS11StorageObject::getIsModifiable() {
    return (m_Modifiable == CK_TRUE) ? true : false;
}

string PKCS11StorageObject::getLabel() {
    return m_Label;
}

void PKCS11StorageObject::QueryAttributes(PKCS11Slot * slot) {

    // Call the base class function
    PKCS11Object::QueryAttributes(slot);

    // Label Attribute
    {
        CK_ATTRIBUTE attributes[] = {
            { CKA_LABEL, NULL_PTR, 0 }
        };

        // Query 1 (To retrieve length of label)
        slot->QueryObject(this->m_Handle, attributes, 1);

        CK_UTF8CHAR_PTR label;
        CK_ULONG length;

        // Re-query with correct label length
        length = attributes[0].ulValueLen;
        label = (CK_UTF8CHAR_PTR)malloc(length);

        attributes[0].pValue = label;
        attributes[0].ulValueLen = length;
        slot->QueryObject(this->m_Handle, attributes, 1);

        m_Label = Utility::CK_UTF8CHARtoString(label, length);

        free(label);
    }

    // Other Attributes
    {
        CK_ATTRIBUTE attributes[] = {
            { CKA_TOKEN, &m_Token, sizeof(CK_BBOOL) },
            { CKA_PRIVATE, &m_Private, sizeof(CK_BBOOL) },
            { CKA_MODIFIABLE, &m_Modifiable, sizeof(CK_BBOOL) }
        };

        // Query Attributes
        slot->QueryObject(this->m_Handle, attributes, 3);
    }
}


void PKCS11StorageObject::DumpAttributes() {

    // Call the base class function
    PKCS11Object::DumpAttributes();

    Log::debug("CKA_TOKEN\t\t%s\n", getIsToken() ? "True" : "False" );
    Log::debug("CKA_PRIVATE\t\t%s\n", getIsToken() ? "True" : "False" );
    Log::debug("CKA_MODIFIABLE\t\t%s\n", getIsToken() ? "True" : "False" );
    Log::debug("CKA_LABEL\t\t\"%s\"\n", getLabel().c_str());
}




// DATA OBJECT

PKCS11DataObject::PKCS11DataObject(void) {

    m_ObjectId = NULL;
    m_ObjectIdLength = 0;

    m_Value = NULL;
    m_ValueLength = 0;

}


PKCS11DataObject::~PKCS11DataObject(void) {

    if (NULL == m_ObjectId) {
        free(m_ObjectId);
        m_ObjectId = NULL;
    }

    if (NULL == m_Value) {
        free(m_Value);
        m_Value = NULL;
    }

}

string PKCS11DataObject::getApplication() {
    return m_Application;
}

char* PKCS11DataObject::getObjectId() {
    return m_ObjectId;
}

char* PKCS11DataObject::getValue() {
    return m_Value;
}

string PKCS11DataObject::getObjectIdString() {
    return Utility::ArraytoHexString(m_ObjectId, m_ObjectIdLength);
}

string PKCS11DataObject::getValueString() {
    return Utility::ArraytoHexString(m_Value, m_ValueLength);
}

void PKCS11DataObject::QueryAttributes(PKCS11Slot * slot) {

    // Call the base class function
    PKCS11StorageObject::QueryAttributes(slot);

    // APPLICATION Attribute
    // OBJECT_ID Attribute
    // VALUE Attribute
    CK_ATTRIBUTE attributes[] = {
        { CKA_APPLICATION, NULL_PTR, 0 },
        { CKA_OBJECT_ID, NULL_PTR, 0 },
        { CKA_VALUE, NULL_PTR, 0 }
    };

    // Query 1 (To retrieve length)
    slot->QueryObject(this->m_Handle, attributes, 3);

    CK_UTF8CHAR_PTR application = NULL;
    CK_ULONG applicationLen = 0;

    // Re-query with correct label length
    if (attributes[0].ulValueLen > 0) {
        applicationLen = attributes[0].ulValueLen;
        application = (CK_UTF8CHAR_PTR)malloc(applicationLen);
        attributes[0].pValue = &application;
    }

    if (attributes[1].ulValueLen > 0) {
        m_ObjectIdLength = attributes[1].ulValueLen;
        m_ObjectId = (char*)malloc(m_ObjectIdLength);
        attributes[1].pValue = &m_ObjectId;
    }
    if (attributes[2].ulValueLen > 0) {
        m_ValueLength = attributes[2].ulValueLen;
        m_Value = (char*)malloc(m_ValueLength);
        attributes[2].pValue = &m_Value;
    }

    slot->QueryObject(this->m_Handle, attributes, 3);

    if (application != NULL) {
        m_Application = Utility::CK_UTF8CHARtoString(application, applicationLen);
        free(application);
    }

}

void PKCS11DataObject::DumpAttributes() {

    // Call the base class function
    PKCS11StorageObject::DumpAttributes();

    if (!m_Application.empty()) Log::debug("CKA_APPLICATION\t\t\"%s\"\n", getApplication().c_str());
    if (m_ObjectId != NULL) Log::debug("CKA_OBJECTID\t\t\"%s\"\n", getObjectIdString().c_str());
    if (m_Value != NULL) Log::debug("CKA_VALUE\t\t\"%s\"\n", getValueString().c_str());

}




PKCS11KeyObject::PKCS11KeyObject(void) {

    m_KeyType = -1; // CKK_RSA is 0, so this is to specifically set it to an undefined value;
    m_Id = NULL;
    m_IdLength = 0;
}

PKCS11KeyObject::~PKCS11KeyObject(void) {
    if (NULL != m_Id) {
        free( m_Id );
        m_Id = NULL;
    }
}

CK_KEY_TYPE PKCS11KeyObject::getKeyType() {
    return m_KeyType;
}

string PKCS11KeyObject::getKeyTypeString() {

    switch (m_KeyType) {

    case CKK_RSA:
        return "RSA";
    case CKK_DSA:
        return "DSA";
    case CKK_DH:
        return "DH";

    /* CKK_ECDSA and CKK_KEA are new for v2.0 */
    /* CKK_ECDSA is deprecated in v2.11, CKK_EC is preferred. */
    case CKK_EC:
        return "EC";
    case CKK_X9_42_DH:
        return "X9_42_DH";
    case CKK_KEA:
        return "KEA";

    case CKK_GENERIC_SECRET:
        return "GENERIC";
    case CKK_RC2:
        return "RC2";
    case CKK_RC4:
        return "RC4";
    case CKK_DES:
        return "DES";
    case CKK_DES2:
        return "DES2";
    case CKK_DES3:
        return "DES3";

    /* all these key types are new for v2.0 */
    case CKK_CAST:
        return "CAST";
    case CKK_CAST3:
        return "CAST3";
    /* CKK_CAST5 is deprecated in v2.11, CKK_CAST128 is preferred. */
    case CKK_CAST128:
        return "CAST128";
    case CKK_RC5:
        return "RC5";
    case CKK_IDEA:
        return "IDEA";
    case CKK_SKIPJACK:
        return "SKIPJACK";
    case CKK_BATON:
        return "BATON";
    case CKK_JUNIPER:
        return "JUNIPER";
    case CKK_CDMF:
        return "CDMF";
    case CKK_AES:
        return "AES";

    /* BlowFish and TwoFish are new for v2.20 */
    case CKK_BLOWFISH:
        return "BLOWFISH";
    case CKK_TWOFISH:
        return "TWOFISH";

    /* SecurID, HOTP, and ACTI are new for PKCS #11 v2.20 amendment 1 */
    case CKK_SECURID:
        return "SECURID";
    case CKK_HOTP:
        return "HOTP";
    case CKK_ACTI:
        return "ACTI";

    /* Camellia is new for PKCS #11 v2.20 amendment 3 */
    case CKK_CAMELLIA:
        return "CAMELLIA";
    /* ARIA is new for PKCS #11 v2.20 amendment 3 */
    case CKK_ARIA:
        return "ARIA";

    case CKK_VENDOR_DEFINED:
        return "VENDOR";
    default:
        return "UNDEFINED";

    }

}

char * PKCS11KeyObject::getId() {
    return m_Id;
}


string PKCS11KeyObject::getIdString() {
    return Utility::ArraytoHexString(m_Id, m_IdLength);
}

void PKCS11KeyObject::QueryAttributes(PKCS11Slot * slot) {

    // Call the base class function
    PKCS11StorageObject::QueryAttributes(slot);

    // KEY_TYPE Attribute
    CK_ATTRIBUTE attributes[] = {
        { CKA_KEY_TYPE, &m_KeyType, sizeof(CK_KEY_TYPE) },
        { CKA_ID, NULL_PTR, 0 }
    };

    // Query 1 (To retrieve length)
    slot->QueryObject(this->m_Handle, attributes, 2);

    // Re-query with correct label length
    if (attributes[1].ulValueLen > 0) {
        m_IdLength = attributes[1].ulValueLen;
        m_Id = (char*)malloc(m_IdLength);
        attributes[1].pValue = m_Id;
    }

    slot->QueryObject(this->m_Handle, attributes, 2);

}

void PKCS11KeyObject::DumpAttributes() {

    // Call the base class function
    PKCS11StorageObject::DumpAttributes();

    Log::debug("CKA_KEY_TYPE\t\t\"%s\"\n", getKeyTypeString().c_str());
    if (NULL != m_Id) Log::debug("CKA_ID\t\t\t\"%s\"\n", getIdString().c_str());

}


PKCS11X509CertificateObject::PKCS11X509CertificateObject(void) {
    m_Serial = NULL;
    m_SerialLength = 0;
}

PKCS11X509CertificateObject::~PKCS11X509CertificateObject(void) {
    if (NULL != m_Serial) {
        delete m_Serial;
        m_Serial = NULL;
    }
}

void PKCS11X509CertificateObject::QueryAttributes(PKCS11Slot * slot) {

    // Call the base class function
    PKCS11StorageObject::QueryAttributes(slot);

    // KEY_TYPE Attribute
    CK_ATTRIBUTE attributes[] = {
        { CKA_SERIAL_NUMBER, NULL_PTR, 0 }
    };

    // Query 1 (To retrieve length)
    slot->QueryObject(this->m_Handle, attributes, 1);

    // Re-query with correct label length
    if (attributes[0].ulValueLen > 0) {
        m_SerialLength = attributes[0].ulValueLen;
        m_Serial = (char*)malloc(m_SerialLength);
        attributes[0].pValue = m_Serial;
    }

    slot->QueryObject(this->m_Handle, attributes, 1);

}

void PKCS11X509CertificateObject::DumpAttributes() {

    // Call the base class function
    PKCS11StorageObject::DumpAttributes();

    if (NULL != m_Serial) Log::debug("CKA_SERIAL\t\t\"%s\"\n", getSerialString().c_str());

}

char * PKCS11X509CertificateObject::getSerial() {
    return m_Serial;
}


string PKCS11X509CertificateObject::getSerialString() {
    return Utility::ArraytoHexString(m_Serial, m_SerialLength);
}
