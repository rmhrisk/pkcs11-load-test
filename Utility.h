#pragma once

#include "stdafx.h"
#include <strstream>
#include <string>

#include "include/cryptoki.h"

using namespace std;

class Utility
{
public:

    static string CK_UTF8CHARtoString(CK_UTF8CHAR * value, int len);
    static string CK_VERSIONtoString(CK_VERSION value);
    static void ThrowOnError(CK_RV result, char * source, char * call);

    static void HexStringToArray(char *data, const char *hexstring, unsigned int len);
    static string ArraytoHexString(char * value, int len);
    static string CurrentDateTime();
};

