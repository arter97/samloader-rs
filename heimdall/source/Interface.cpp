/* Copyright (c) 2010-2017 Benjamin Dobell, Glass Echidna

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
 THE SOFTWARE.*/

// C/C++ Standard Library
#include <cstdarg>
#include <cstdlib>
#include <stdio.h>

// Heimdall
#include "Heimdall.h"
#include "Interface.h"

using namespace std;
using namespace libpit;
using namespace Heimdall;

const char *version = "v2.2.2";

const char *releaseInfo = "Heimdall %s\n\n\
Copyright (c) 2010-2017 Benjamin Dobell, Glass Echidna https://glassechidna.com.au\n\
Copyright (c) 2021-2024 Henrik Grimler\n\
This software is provided free of charge. Copying and redistribution is encouraged.\n\n";

static const char *extraInfo = "Heimdall utilises libusb for all USB communication:\n\
    https://www.libusb.info/\n\
\n\
libusb is licensed under the LGPL-2.1:\n\
    https://www.gnu.org/licenses/licenses.html#LGPL\n\n";

void Interface::PrintError(const char *format, ...)
{
        va_list stderrArgs;
        va_start(stderrArgs, format);

        fprintf(stderr, "ERROR: ");
        vfprintf(stderr, format, stderrArgs);
        fflush(stderr);

        va_end(stderrArgs);
}

void Interface::PrintVersion(void)
{
        printf("%s\n", version);
}

void Interface::PrintReleaseInfo(void)
{
        printf(releaseInfo, version);
}

void Interface::PrintFullInfo(void)
{
        printf(releaseInfo, version);
        printf("%s", extraInfo);
}
