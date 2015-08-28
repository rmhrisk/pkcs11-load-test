Many Government agencies and commercial organizations use PKI security tokens or smartcards that utilize various proprietary token or smartcard PKI implementations and/or openly accredited standards such as FIPS-201 (PIV).

For US Government agencies FIPS-201 is normally mandatory.  Both FIPS-201 and virtually all proprietary and standards based PKI implementations implement PKCS#11 at the operating system or middleware API level.  This is essential for interoperability.  This API is more commonly called Cryptoki, pronounced crypto-key and short for cryptographic token interface

There has been little work done on tools to load test the entire PKI channel, which seems to be a missing test tool given the complexity of the channel, which typically looks like;

Calling Application > Middleware or Windows Cryptoki > OS > PC/SC > USB > Reader > Token Interface > JavaCard VM > FIPS-201 JC Applet > Hardware Crypto Engine and memory > Applet > JCVM > Token Interface > Reader > USB > PC/SC > OS > Cryptoki > Calling Application

There are clearly many areas for issues in the channel above, and historically it has been difficult to find problems such as memory leaks at the various software and hardware levels. There is also the potential that some smartcards or tokens may have issues that may reduce the useful life of the tokens well below the stated MTBF. It is also possible that the security tokens may fail due to ‘false positives’ in their tamper prevention mechanisms. Finally, it is useful to be able to test PKCS#11 implementations under simulated load for performance purposes (i.e. against a HSM or Remote Desktop instance via a LAN/WAN network).

This simple test tool has therefore been developed to perform a common PKI cryptographic use-case using the Cryptoki PKCS#11 API many times in quick succession, providing a ‘load test’ environment that will validate or assist in identifying both integrity and performance issues by inducing failures quickly.

The test sits at the application level and as such exercises the entire channel other than the "Calling Application" in conjunction with PKCS#11 middleware. It exercises authentication, encryption and digital signature functionality.  Other testing would be necessary to exercise the various possible applications (email, acrobat, word) that would call Cryptoki.

The test tool can support multiple USB connected smartcard readers and cards/tokens in a "round robin". With a round robin of two (2), 20,000 transactions can be reached with most cards in 3 days of continuous testing. The tool is tested with up to 8 cards/readers in the round robin.