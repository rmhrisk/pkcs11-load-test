#pragma once

#include "stdafx.h"
#include <strstream>
#include <string>

#include "include/cryptoki.h"

using namespace std;

class Utility
{
public:

    // Converts a PKCS#11 CK_UTF8Char to a string
    static string CK_UTF8CHARtoString(CK_UTF8CHAR * value, int len);

    // Converts a PKCS#11 CK_VERSION to a string
    static string CK_VERSIONtoString(CK_VERSION value);

    // Takes a PKCS#11 CK_RV result and throws an error if it is considered a failure.
    static void ThrowOnError(CK_RV result, char * source, char * call);

    // Parses a hexadecimal numeric string to produce a byte array.
    static void HexStringToArray(char * data, const char *hexstring, unsigned int len);

    // Converts a byte array to a hexadecimal string
    static string ArraytoHexString(char * value, int len);

    // Returns a formatted string with the current local date and time.
    static string CurrentDateTime();
};

