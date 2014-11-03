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
#include "Log.h"

#include <stdarg.h>


// Static member definitions
int Log::m_LogLevel = LOG_DEFAULT_LEVEL;

void Log::debug(const char * format, ...)
{
    if (m_LogLevel < LOG_DEBUG) return;

    va_list args;
    va_start(args, format);

    printf("DEBUG - ");
    vprintf(format, args);

#ifdef LOG_FORCE_LF
    printf("\n");
#endif

    va_end(args);
}

void Log::warn(const char * format, ...)
{
    if (m_LogLevel < LOG_WARNING) return;

    va_list args;
    va_start(args, format);

    printf("WARN - ");
    vprintf(format, args);
#ifdef LOG_FORCE_LF
    printf("\n");
#endif

    va_end(args);
}

void Log::error(const char * format, ...)
{
    if (m_LogLevel < LOG_ERR) return;

    va_list args;
    va_start(args, format);

    printf("ERR - ");
    vprintf(format, args);
#ifdef LOG_FORCE_LF
    printf("\n");
#endif

    va_end(args);
}

void Log::info(const char * format, ...)
{
    if (m_LogLevel < LOG_INFO) return;

    va_list args;
    va_start(args, format);

    vprintf(format, args);
#ifdef LOG_FORCE_LF
    printf("\n");
#endif

    va_end(args);
}

void Log::notice(const char * format, ...)
{
    if (m_LogLevel < LOG_NOTICE) return;

    va_list args;
    va_start(args, format);

    printf("NOTICE - ");
    vprintf(format, args);
#ifdef LOG_FORCE_LF
    printf("\n");
#endif

    va_end(args);
}

void Log::setLevel(int level)
{
    // Quick sanity check
    if (level < LOG_EMERG || level > LOG_DEBUG) {
        return;
    }

    m_LogLevel = level;

}

int Log::getLevel()
{
    return m_LogLevel;
}
