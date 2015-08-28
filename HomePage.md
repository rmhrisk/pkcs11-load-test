# PKCS11 Load Test Tool #


---


## Overview ##

Many Government agencies and commercial organizations use PKI security tokens or
smartcards that utilize various proprietary token or smartcard PKI implementations and/or
openly accredited standards such as FIPS-201 (PIV).
For US Government agencies FIPS-201 is normally mandatory.  Both FIPS-201 and virtually
all proprietary and standards based PKI implementations implement PKCS#11 at the operating
system or middleware API level.  This is essential for interoperability.  This API is more
commonly called Cryptoki, pronounced crypto-key and short for cryptographic token interface

There has been little work done on tools to load test the entire PKI channel, which seems
to be a missing test tool given the complexity of the channel, which typically looks like;

Calling Application > Middleware or Windows Cryptoki > OS > PC/SC > USB > Reader > Token
Interface > JavaCard VM > FIPS-201 JC Applet > Hardware Crypto Engine and memory > Applet
> JCVM > Token Interface > Reader > USB > PC/SC > OS > Cryptoki > Calling Application

There are clearly many areas for issues in the channel above, and historically it has been
difficult to find problems such as memory leaks at the various software and hardware
levels. There is also the potential that some smartcards or tokens may have issues that
may reduce the useful life of the tokens well below the stated MTBF. It is also possible
that the security tokens may fail due to ‘false positives’ in their tamper prevention
mechanisms. Finally, it is useful to be able to test PKCS#11 implementations under
simulated load for performance purposes (i.e. against a HSM or Remote Desktop instance
via a LAN/WAN network).

This simple test tool has therefore been developed to perform a common PKI cryptographic
use-case using the Cryptoki PKCS#11 API many times in quick succession, providing a
‘load test’ environment that will validate or assist in identifying both integrity and
performance issues by inducing failures quickly.

The test sits at the application level and as such exercises the entire channel other
than the "Calling Application" in conjunction with PKCS#11 middleware. It exercises
authentication, encryption and digital signature functionality.  Other testing would be
necessary to exercise the various possible applications (email, acrobat, word) that would
call Cryptoki.

The test tool can support multiple USB connected smartcard readers and cards/tokens in a
"round robin". With a round robin of two (2), 20,000 transactions can be reached with
most cards in 3 days of continuous testing. The tool is tested with up to 8 cards/readers
in the round robin.


## Scope ##

The scope of this test tool is as follows:
1)	Performs load testing against a PKCS#11 token to provide support in validating
reliability and integrity problems with existing implementations. The PKCS#11 commands
are a simple subset of the total PKCS#11 functionality.

**a. Initialise a PKCS#11 library (using a configurable module path)**

**b. Detect the presence of all PKCS#11 slots and list the available tokens.**

**c. Read the GlobalPlatform CPLC Issuer Serial Number**

**d. Perform a series of typical transactions against all available tokens, [n](n.md) number of times.**


One transaction consists of the following PKCS#11 operations:
> i.	Open Session (Read-only session)<br>
<blockquote>ii.	Login (Normal User)<br>
iii.	Query Objects (Find Private Key)<br>
iv.	Query Objects (Find Public Key)<br>
v.	Generate Random Data<br>
vi.	Encrypt Block (RSA PKCS)<br>
vii.	Digest (SHA-1)<br>
viii.	Generate Signature (RSA PKCS)<br>
ix.	Verify Signature (RSA PKCS)<br>
x.	Decrypt (RSA PKCS)<br>
xi.	Logout<br>
xii.	Close Session<br></blockquote>

2)	Generate a simple set of reporting outputs in CSV format that record the IC Serial Number, the output status and data of the above operations. Failures will be logged and the operator prompted to proceed.<br>
<br>
<br>
<h2>Scope Exclusions</h2>
<blockquote>a.	The initialisation and personalization of PKCS11/PIV tokens<br>
b.	Broad testing of all PKCS11 functionality on a token<br>
c.	Broad testing of support for compatibility with commercially available PKCS11<br>
<blockquote>tokens or library modules (Currently, the Charismatics Middleware 1.1 and several<br>
FIPS-201 compliant cards have been provided).</blockquote></blockquote>


<h2>Installation</h2>

This test tool is a self-contained Windows executable, and as such does not need installation as such. However, it requires the following dependent components to be installed and working:<br>
<br>
a.	Microsoft Windows 7 or above (64-bit)<br>
<blockquote><a href='http://www.microsoft.com/windows'>http://www.microsoft.com/windows</a></blockquote>

<blockquote>b.	Microsoft Visual C++ 2010 SP1 Redistributable Package (X64)<br>
<a href='http://www.microsoft.com/en-au/download/details.aspx?id=13523'>http://www.microsoft.com/en-au/download/details.aspx?id=13523</a></blockquote>

<blockquote>c.	A PC-SC compliant smart-card reader</blockquote>

<blockquote>d.	A suitable PKCS#11 Library</blockquote>


<h2>Operation</h2>

The test tool operates as a command-line executable, so familiarity with the DOS-style<br>
command-prompt is recommended. By default, the test tool is named ‘PKCS11LoadTest.exe’.<br>
The application has several command-line arguments that configure the behaviour of its<br>
operation. To see a listing of these command-line parameters from within the application, including a description of each, run the executable with the ‘-H’ parameter (for help).<br>
<br>
The command-line parameters are as follow:<br>
PKCS11LoadTest  [-D] -L LibraryPath -P Pin [-C Count] [-I Interval] [-H]<br>
<br>
<table><thead><th> <b>Parameter</b> </th><th> <b>Description</b> </th></thead><tbody>
<tr><td> -L               </td><td> REQUIRED - The full or relative path to the PKCS#11 Library Module (See the PKCS#11 standard for more information).  <br>Example: ‘-L C:\Windows\System32\cmp11.dll’ </td></tr>
<tr><td> -P               </td><td> REQUIRED - The ASCII/Numeric PIN number for the active tokens. <br>Example: ‘-P 11111111’ </td></tr>
<tr><td> -C	              </td><td> The number of simulated transactions to perform in this session. <br>Example: ‘-C 10’ <br> Default: 10 </td></tr>
<tr><td> -I               </td><td> The amount of time to wait between transactions in milliseconds’<br>Example: ‘-I 1000’. <br> 				Default: 1000 (1 second) </td></tr>
<tr><td> -D               </td><td> If specified, the application will produce verbose debug information  to assist in diagnosing issues.<br><br>NOTE: If you want to use this flag, it is recommended that you pass it first so that it takes effect immediately, even before further options processing. </td></tr>
<tr><td> -H               </td><td> Displays the help message and exits. </td></tr></tbody></table>

At a minimum, the PKCS11 module path, User PIN and Key identifier must be supplied, for<br>
example: X:\PKCS11LoadTest.EXE –L cmp11.dll –P 11111111 –K 9C07<br>
<br>
NOTES:<br>
a.	When running multiple cards in a "round robin" the PIN for all cards must be the same.<br>
b.	A separate ‘.log’ file will be created for each card, using the CPLC IC Serial Number<br>
<blockquote>as the name. These will always be appended to so you will need to delete previous<br>
files manually if you wish to start from a clean file.</blockquote>

c.	The log file format is an ASCII Comma-Separated Value (CSV) file and has the following<br>
<blockquote>format:</blockquote>

<blockquote>TIMESTAMP,SERIAL,ITERATION,OPERATION,OUTCOME[,DATA] #CRLF#</blockquote>


WARNING! 	Because this test tool cycles transactions very fast, if an incorrect PIN is  used it is likely that the token will be locked before the operator has time to respond.  In some scenarios this may make the token un-recoverable due to excess failed PIN attempts or if the System Operator (SO) PIN cannot be  obtained.<br>
<br>
<br>
<br>
<h2>Development</h2>

The test tool is written in C++, using Microsoft Visual Studio 2010 Professional Edition<br>
- SP1 as the development environment. Aside from the runtime requirements above, there are<br>
no special installation steps necessary.<br>
<br>
To open the project, simply click on the PKCS11LoadTest.vcxproj file or PKCS11LoadTest<br>
solution.<br>
<br>
This project is hosted using Google Code at the following repository location:<br>
<a href='https://code.google.com/p/pkcs11-load-test/'>https://code.google.com/p/pkcs11-load-test/</a>

This project can be checked out anonymously, using the following subversion command:<br>
svn checkout <a href='http://pkcs11-load-test.googlecode.com/svn/'>http://pkcs11-load-test.googlecode.com/svn/</a> pkcs11-load-test-read-only<br>
<br>
<br>
<h2>License</h2>

This application is licensed under the MIT License, a copy of which is provided below:<br>
<br>
The MIT License (MIT)<br>
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:<br>
<br>
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.<br>
<br>
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR<br>
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.<br>
<br>
<br>
<h2>References / Standards</h2>

PKCS#11		<a href='http://www.emc.com/emc-plus/rsa-labs/standards-initiatives/pkcs-11-cryptograph'>http://www.emc.com/emc-plus/rsa-labs/standards-initiatives/pkcs-11-cryptograph</a>
<blockquote>ic-token-interface-standard.htm<br>
NOTE: This has been tested against library modules implementing PKCS#11 v2.11<br>
and v2.20 only.</blockquote>

PCSC		<a href='http://pcscworkgroup.com/'>http://pcscworkgroup.com/</a>

