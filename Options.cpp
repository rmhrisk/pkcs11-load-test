#include "StdAfx.h"
#include "Options.h"

#include "Log.h"
#include "Utility.h"

/*
  Default Values
 */
#define DEFAULT_KEYIDLENGTH     0;
#define DEFAULT_MAX_ITERATIONS  9999999;
#define DEFAULT_INTERVAL        1000;


Options::Options()
{
    // Set the default values
    KeyIdLength = DEFAULT_KEYIDLENGTH;
    MaxIterations = DEFAULT_MAX_ITERATIONS;
    Interval = DEFAULT_INTERVAL;
}


Options::~Options(void)
{
}


bool Options::Parse(int argc, _TCHAR* argv[])
{
    // Get the EXE name
    wstring exe = argv[0];
    EXEName = string(exe.begin(), exe.end());

    for (int i = 1; i < argc; i++) {

        // Check for the starting '-'
        if (argv[i][0] != '-') {
            Log::error("Invalid start character in argument %d, expected '-', got '%c'\n", i, argv[i][0]);
            return false;
        }

        switch ( argv[i][1] )
        {
        case 'H': // Library Path
        case 'h': // Library Path
            return false;

        case 'l': // Library Path
        case 'L': // Library Path
            if (argc <= i + 1) return false;
            PKCS11Library = wstring(argv[++i]);
            Log::debug("Setting the Library Path to %S\n", PKCS11Library.c_str());
            break;

        case 'p': // PIN
        case 'P': // PIN
            if (argc <= i + 1) return false;
            PIN = wstring(argv[++i]);
            Log::debug("Setting the PIN to %S (length %d)\n", PIN.c_str(), PIN.size());
            break;

        case 'K': // Key Identifier
        {
            if (argc <= i + 1) return false;
            wstring buffer = wstring(argv[++i]);
            string key = string(buffer.begin(), buffer.end());
            KeyIdLength = key.length() / 2;

            try {
                Utility::HexStringToArray(KeyId, key.c_str(), KeyIdLength);
                Log::debug("Setting the Key Identifier to %s\n", KeyId);
            }
            catch (...) {
                Log::error("Invalid Key Identifier specified. aborting ...\n");
                exit(EXIT_FAILURE);
            }
            break;
        }

        case 'c': // Count
        case 'C': // Count
            if (argc <= i + 1) return false;
            MaxIterations = _wtoi(argv[++i]);
            Log::debug("Setting the Maximum Iteration Count to %d\n", MaxIterations);
            break;

        case 'i': // Interval
        case 'I': // Interval
            if (argc <= i + 1) return false;
            Interval = _wtoi(argv[++i]);
            Log::debug("Setting the Interval to %d milliseconds\n", Interval);
            break;

        case 'd': // Debug
        case 'D': // Debug
            Log::setLevel(LOG_DEBUG);
            Log::debug("Enabling DEBUG output\n");
            break;
        }
    }

    return true;
}
