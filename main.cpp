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

#include <windows.h>
#include <iostream>
#include <sstream>
#include <string>
#include <ios>
#include <fstream>
#include <iomanip>
#include <map>

#include "PCSC.h"
#include "PKCS11Manager.h"
#include "PKCS11Object.h"
#include "Options.h"
#include "Utility.h"
#include "Log.h"


/*
 * Application Variables
 */

// The PKCS11 Object
PKCS11Manager * m_PKCS11 = NULL;

// Holds a list of GlobalPlatform CPLC ICC Serial Numbers associated with the token in each slot
map<CK_ULONG, string> m_SlotSerials;

// Global - The number of iterations performed so far
int _iterations = 0;

// Global - A flag set by the Control Handler to indicate the application should cancel after the next processing cycle.
bool _shutdown = false;

// Options instance
Options _options;

/*
 * Function Prototypes
 */

void Startup(vector<PKCS11Slot> * slots);
void Process(vector<PKCS11Slot> * slots);
void Shutdown();
void Shutdown_AtExit();
void AppendLogEntry();
void DisplayVersion();
void DisplayUsage();
void AppendJournal( string serial, char * operation, bool outcome, char * data, int len);
static BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType);

string Process_FindSerial(PKCS11Slot * slot);
CK_OBJECT_HANDLE Process_FindPublicKey(PKCS11Slot * slot);
CK_OBJECT_HANDLE Process_FindPrivateKey(PKCS11Slot * slot);


/*
 * Global application definitions
 */
#define APP_NAME        "PKCS11 Load Test Tool"
#define APP_VERSION     "V1.0.0"


int _tmain(int argc, _TCHAR* argv[])
{
    /*
     * APPLICATION MAIN
     */

    // Handle CTRL-C + CTRL-BRK
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    // Set the locale for string conversion
    setlocale(LC_CTYPE, "");

    // Set the logging level
    Log::setLevel(LOG_INFO);

    // Define the at-exit function
    atexit(Shutdown_AtExit);

    // Process command-line arguments

    if (!_options.Parse(argc, argv)) {
        DisplayUsage();
        return (EXIT_FAILURE);
    }

    // Validate Arguments

    // MANDATORY - PKCS11 Libary
    if (_options.PKCS11Library.empty()) {
        Log::error("A PKCS11 library must be supplied using the -L argument.\n");
        exit(EXIT_FAILURE);
    }

    // MANDATORY - PIN
    if (_options.PIN.empty()) {
        Log::error("A valid, numeric PIN must be supplied using the -P argument.\n");
        exit(EXIT_FAILURE);
    }

    // MANDATORY - KEY ID
    if (0 == _options.KeyIdLength) {
        Log::error("A valid, hexidecimal key identifier must supplied using the -K argument.\n");
        exit(EXIT_FAILURE);
    }

    
    // Holds the list of detected PKCS11 Slots
    vector<PKCS11Slot> slots;

    // Call Startup
    Startup(&slots);

    // Loop
    _iterations = 0;

    while (_iterations < _options.MaxIterations) {

        // Increment the iteration count
        _iterations++;

        // Call Process
        Log::info ("ITERATION %d of %d:\n", _iterations, _options.MaxIterations);

        try
        {
            Process(&slots);
        }
        catch (...) {
            Log::error("Unhandled exception during processing ...\n");
        }

        // Wait for the next round

        if (_shutdown) {
            Log::info("Skipping further load test iterations\n");
            break;
        }

        if (_iterations < _options.MaxIterations) {
            Log::info ("Iteration complete, waiting for %dms.\n", _options.Interval);
            Sleep(_options.Interval);
        }
    }

    Log::info("LOAD TEST COMPLETE\n");

    // Call Shutdown
    Shutdown();
}



void Startup(vector<PKCS11Slot> * slots)
{

    // Create the PKCS11 manager object
    try {
        m_PKCS11 = PKCS11Manager::Create(_options.PKCS11Library.c_str());
    }
    catch (...) {
        Log::error("Unable to connect to the PKCS11 library, aborting ...\n");
        exit(EXIT_FAILURE);
    }

    // Print PKCS11 Module Info
    // TODO:

    // Enumerate all slots WITH tokens
    try {
        m_PKCS11->QuerySlots(true, slots);
    }
    catch (...) {
        Log::error("Unable to list the available slots, aborting ...\n");
        exit(EXIT_FAILURE);
    }

    // If there are not slots with a token, shut down
    if (slots->size() == 0) {
        Log::error("You must have at least one slot available with a token present.\n");
        exit(EXIT_FAILURE);
    }

    // Print slot info
    for(vector<PKCS11Slot>::iterator slot = slots->begin();
            slot != slots->end();
            ++slot)
    {
        PKCS11Token token;
        slot->QueryToken(&token);

        // Print slot / token information
        Log::info("FOUND SLOT ID = %u, DESCRIPTION = '%s', TOKEN = '%s' \n", slot->id, slot->description.c_str(), token.label.c_str());


        try {
            slot->OpenSession(false);
            string serial = Process_FindSerial(&(*slot));

            try {
                string csn = PCSC::QueryCPLC(slot->description);
                m_SlotSerials[slot->id] = csn;
                Log::info("Matched serial %s to CPLC ICC CSN %u. Using CSN\n", serial.c_str(), csn);
            }
            catch (...) {
                Log::error("Unable to retrieve CPLC, using certificate serial number %s\n", serial.c_str());
                m_SlotSerials[slot->id] = serial;
            }


        } catch ( ... ) {
            Log::error("Unable to retrieve serial number for slot %u\n", slot->id);
            slot->CloseSession();
            exit(EXIT_FAILURE);
        }

        slot->CloseSession();
    }
}


string Process_FindSerial(PKCS11Slot * slot) {

    try {

        // Create the search template
        CK_OBJECT_CLASS classValue = CKO_CERTIFICATE;
        CK_ATTRIBUTE attributes[] = {
            { CKA_CLASS, &classValue, sizeof(CK_OBJECT_CLASS) }
            ,{ CKA_ID, &_options.KeyId, _options.KeyIdLength }
        };

        // Search
        vector<CK_OBJECT_HANDLE> handles;
        slot->QueryObjects(&handles, attributes, 2);
        if (handles.size() == 0) {

            // Try again with only the CKO_CERTIFICATE
            slot->QueryObjects(&handles, attributes, 1);

            if (handles.size() == 0) {
                throw "Certificate was not found, please check Key Id.";
            }

            else {
                Log::warn("Certificate with supplied Key Identifier not found, defaulting to first available.\n");
                slot->QueryObject(handles[0], attributes, 2);
                Log::warn("Found first certificate using Key Identifier %s\n", Utility::ArraytoHexString(_options.KeyId, _options.KeyIdLength).c_str());
            }

        }

        // Get the data for the certificate
        // NOTE: Currently assuming it is X.509!
        PKCS11X509CertificateObject * cert = dynamic_cast<PKCS11X509CertificateObject*>(PKCS11Object::Create(slot, handles[0]));

        string result = cert->getSerialString();

        delete cert;

        return result;

    }
    catch (...) {
        throw "Exception thrown whilst trying to query the private key handle.";
    }

}

CK_OBJECT_HANDLE Process_FindPrivateKey(PKCS11Slot * slot) {

    try {

        // Create the search template
        CK_OBJECT_CLASS classValue = CKO_PRIVATE_KEY;
        CK_ATTRIBUTE attributes[] = {
            { CKA_CLASS, &classValue, sizeof(CK_OBJECT_CLASS) }
            ,{ CKA_ID, &_options.KeyId, _options.KeyIdLength }
        };

        // Search
        vector<CK_OBJECT_HANDLE> handles;
        slot->QueryObjects(&handles, attributes, 2);

        if (handles.size() == 0) {
            throw "Private key was not found";
        } else {
            // Return the first one
            return handles[0];
        }

    }
    catch (...) {
        throw "Exception thrown whilst trying to query the private key handle.";
    }

}

CK_OBJECT_HANDLE Process_FindPublicKey(PKCS11Slot * slot) {

    try {

        // Create the search template
        CK_OBJECT_CLASS classValue = CKO_PUBLIC_KEY;
        CK_ATTRIBUTE attributes[] = {
            { CKA_CLASS, &classValue, sizeof(CK_OBJECT_CLASS) },
            { CKA_ID, &_options.KeyId, _options.KeyIdLength }
        };

        // Search
        vector<CK_OBJECT_HANDLE> handles;
        slot->QueryObjects(&handles, attributes, 2);

        if (handles.size() == 0) {
            throw "Public key was not found";
        } else {
            // Return the first one
            return handles[0];
        }
    }
    catch (...) {
        throw "Exception thrown whilst trying to query the private key handle.";
    }
}

void Process(vector<PKCS11Slot> * slots) {

    // Loop through each slot with a token
    for(vector<PKCS11Slot>::iterator slot = slots->begin();
            slot != slots->end();
            ++slot)
    {
        // Retrieve the serial number associated with this slot
        string serial = m_SlotSerials[slot->id];

        Log::info("SERIAL: %s\n", serial.c_str());

        // Open Session
        slot->OpenSession(false);

        CK_OBJECT_HANDLE privateKey, publicKey;

        int dataLength = 128;
        char * data = new char[dataLength];

        int cipherTextLength = 256;
        char * cipherText = new char[cipherTextLength];

        int digestLength = 20;
        char * digest = new char[digestLength];

        int signatureLength = 512;
        char * signature = new char[signatureLength];

        // Login
        try {
            Log::info(" - Login ...");
            string pin(_options.PIN.begin(), _options.PIN.end());
            slot->Login(&pin);
            AppendJournal(serial, "LOGIN", true, NULL, 0);
            Log::info("Success\n");
        } catch (...) {
            Log::info("Failed\n");
            AppendJournal(serial, "LOGIN", false, NULL, 0);
            slot->CloseSession();
            continue;
        }

        /*
         * UNUSED
         */

        //try {
        //  Log::info(" - Generate KeyPair ...");
        //  slot->GenerateKeyPair();
        //  AppendJournal(serial, "GENERATEKEYPAIR", true, NULL, 0);
        //  Log::info("Success\n");
        //} catch (...) {
        //  Log::info("Failed\n");
        //  AppendJournal(serial, "GENERATEKEYPAIR", false, NULL, 0);
        //  slot->CloseSession();
        //  continue;
        //}

        // Find Private Key [x]
        try {
            Log::info(" - Find Private key ...");
            privateKey = Process_FindPrivateKey((&(*slot)));
            AppendJournal(serial, "FIND_KEY_PRIVATE", true, NULL, 0);
            Log::info("Success\n");
        } catch (...) {
            Log::info("Failed\n");
            AppendJournal(serial, "FIND_KEY_PRIVATE", false, NULL, 0);
            slot->CloseSession();
            continue;
        }

        // Find Public Key [x]
        try {
            Log::info(" - Find Public key ...");
            publicKey = Process_FindPublicKey((&(*slot)));
            AppendJournal(serial, "FIND_KEY_PUBLIC", true, NULL, 0);
            Log::info("Success\n");
        } catch (...) {
            Log::info("Failed\n");
            AppendJournal(serial, "FIND_KEY_PUBLIC", false, NULL, 0);
            slot->CloseSession();
            continue;
        }

        // Generate Random Data
        try {
            Log::info(" - Generate Random Data (%d bytes) ...", dataLength);
            slot->GenerateRandom(data, dataLength);
            AppendJournal(serial, "RANDOM", true, data, dataLength);
            Log::info("Success\n");
        } catch (...) {
            Log::info("Failed\n");
            AppendJournal(serial, "RANDOM", false, NULL, 0);
            slot->CloseSession();
            continue;
        }

        // Encrypt (with Public Key)
        try {
            Log::info(" - Encrypt (%d bytes) ...", dataLength);
            slot->EncryptData(publicKey, data, dataLength, cipherText, &cipherTextLength);
            AppendJournal(serial, "ENCRYPT", true, cipherText, cipherTextLength);
            Log::info("Success\n");
        } catch (...) {
            Log::info("Failed\n");
            AppendJournal(serial, "ENCRYPT", false, NULL, 0);
            slot->CloseSession();
            continue;
        }

        // Digest
        try {
            Log::info(" - Digest (%d bytes) ...", dataLength);
            slot->GenerateDigest(cipherText, cipherTextLength, digest, &digestLength);
            AppendJournal(serial, "DIGEST", true, NULL, 0);
            Log::info("Success\n");
        } catch (...) {
            Log::info("Failed\n");
            AppendJournal(serial, "DIGEST", false, NULL, 0);
            slot->CloseSession();
            continue;
        }

        // Sign
        try {
            Log::info(" - Sign (%d bytes) ...", digestLength);
            slot->GenerateSignature(privateKey, digest, digestLength, signature, &signatureLength);
            AppendJournal(serial, "SIGN", true, signature, signatureLength);
            Log::info("Success\n");
        } catch (...) {
            Log::info("Failed\n");
            AppendJournal(serial, "SIGN", false, NULL, 0);
            slot->CloseSession();
            continue;
        }

        // Verify
        try {
            Log::info(" - Verify Signature (%d bytes) ...", signatureLength);
            slot->VerifySignature(publicKey, digest, digestLength, signature, signatureLength);
            AppendJournal(serial, "VERIFY", true, NULL, NULL);
            Log::info("Success\n");
        } catch (...) {
            Log::info("Failed\n");
            AppendJournal(serial, "VERIFY", false, NULL, 0);
            slot->CloseSession();
            continue;
        }

        // Decrypt (with Private Key)
        try {
            Log::info(" - Decrypt (%d bytes) ...", cipherTextLength);
            slot->DecryptData(privateKey, cipherText, cipherTextLength, data, &dataLength);
            AppendJournal(serial, "DECRYPT", true, data, dataLength);
            Log::info("Success\n");
        } catch (...) {
            Log::info("Failed\n");
            AppendJournal(serial, "DECRYPT", false, NULL, 0);
            slot->CloseSession();
            continue;
        }

        // Logout
        try {
            Log::info(" - Logout ...", cipherTextLength);
            slot->Logout();
            AppendJournal(serial, "LOGOUT", true, NULL, 0);
            Log::info("Success\n");
        } catch (...) {
            Log::info("Failed\n");
            AppendJournal(serial, "LOGOUT", false, NULL, 0);
        }

        // Close Session
        slot->CloseSession();
    }
}

void Shutdown() {
    Log::debug("Shutdown: Complete\n");
}

void Shutdown_AtExit() {

    if (m_PKCS11 != NULL) {
        delete m_PKCS11;
    }

    Log::debug("Shutdown_AtExit: Complete\n");
}



void DisplayVersion()
{
    Log::info("%s - %s\n", APP_NAME, APP_VERSION);
}

void DisplayUsage()
{
    DisplayVersion();

    cout << "Usage: " << _options.EXEName << " <-L library_path> <-P pin> [-C count] [-I interval] [-HD]" << endl << endl;
    cout << "   L : Sets the library path" << endl;
    cout << "   P : Sets the USER pin used for the PKCS#11 Login" << endl;
    cout << "   C : Sets the maximum iteration count (defaults to 9999999)" << endl;
    cout << "   I : Set the load testing interval in milliseconds (defaults to 1000)" << endl;
    cout << "   H : Show this usage description and exits" << endl;
    cout << "   D : Enabled debugging output" << endl << endl;
}



void AppendJournal( string serial, char * operation, bool outcome, char * data, int len ) {

    // Generate the file path
    string path = serial + ".log";

    // Check if the file exists
    ofstream o(path, ios_base::app | ios_base::out);

    // Get the date/time

    o << Utility::CurrentDateTime() << ",";

    o << serial << "," << _iterations << "," << string(operation) << ",";

    if (outcome) {
        o << "SUCCESS";
    } else {
        o << "FAIL";
    }

    if (len != 0) {
        o << "," << Utility::ArraytoHexString(data, len);
    }

    o << endl;

    o.close();
}

static BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType)
{
    switch (dwCtrlType)
    {
    case CTRL_C_EVENT: // Ctrl+C
        Log::info("\nCTRL-C - Will shut down after this operation completes\n");
        _shutdown = true;
        return TRUE;

    case CTRL_BREAK_EVENT: // Ctrl+Break
        Log::info("\nCTRL-BRK - Will shut down after this operation completes\n");
        _shutdown = true;
        return TRUE;

    case CTRL_CLOSE_EVENT: // Closing the console window
        break;
    }

    // Return TRUE if handled this message, further handler functions won't be called.
    // Return FALSE to pass this message to further handlers until default handler calls ExitProcess().
    return FALSE;
}

