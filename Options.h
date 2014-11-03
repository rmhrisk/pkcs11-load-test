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

#include <windows.h>
#include <iostream>
#include <sstream>
#include <string>

using namespace std;

class Options
{

public:
    Options();
    ~Options(void);

    // Parse the command-line arguments into the Options instance
    bool Parse(int argc, _TCHAR* argv[]);

public:
    // Argument - The name of this executable (passed through as argv[0])
    string EXEName;

    // Argument - The path to the PKCS11 library
    wstring PKCS11Library;

    // Argument - The PIN to be used for the PKCS11 Login (Normal User)
    wstring PIN;

    // Argument - The ID value of the RSA key pair to be used for the crypto operations
    char KeyId[255];

    // Argument - The length of the supplied Key ID
    int KeyIdLength;

    // Argument - The number of process iterations to perform before shutting down.
    int MaxIterations;

    // Argument - The period of time to wait between each process
    int Interval;
};

