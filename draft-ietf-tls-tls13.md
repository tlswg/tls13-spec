---
title: The Transport Layer Security (TLS) Protocol Version 1.3
abbrev: TLS
docname: draft-ietf-tls-tls13-latest
category: std
updates: 4492, 6066, 6961
obsoletes: 5077, 5246, 5746, 6347

ipr: pre5378Trust200902
area: General
workgroup:
keyword: Internet-Draft

stand_alone: yes
pi:
  rfcedstyle: yes
  toc: yes
  tocindent: yes
  sortrefs: yes
  symrefs: yes
  strict: yes
  comments: yes
  inline: yes
  text-list-symbols: -o*+
  docmapping: yes
author:
 -
       ins: E. Rescorla
       name: Eric Rescorla
       organization: RTFM, Inc.
       email: ekr@rtfm.com

normative:
  RFC2104:
  RFC2119:
  RFC2434:
  RFC3447:
  RFC5280:
  RFC5288:
  RFC5289:
  RFC5487:
  RFC5869:
  RFC6066:



  RFC6655:
  RFC7748:
  I-D.mattsson-tls-ecdhe-psk-aead:
  I-D.ietf-tls-chacha20-poly1305:
  I-D.irtf-cfrg-eddsa:
  
  RFC4443:
  RFC4821: 
  RFC6298: 
  RFC1191: 
  RFC6347: 

  TCP: 
       title: Transmission Control Protocol (TCP)
       date: 1981-09
       author:
          - ins: J. Postel
       seriesinfo:
         IETF: RFC 793
  AES:
       title: Specification for the Advanced Encryption Standard (AES)
       date: 2001-11-26
       author:
         org: National Institute of Standards and Technology
       seriesinfo:
         NIST: FIPS 197
  SHS:
       title: Secure Hash Standard
       date: 2012-03
       author:
         org: National Institute of Standards and Technology, U.S. Department of Commerce
       seriesinfo:
         NIST: FIPS PUB 180-4
  X690:
       title: "Information technology - ASN.1 encoding Rules: Specification of Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)"
       date: 2002
       author:
         org: ITU-T
       seriesinfo:
         ISO/IEC: 8825-1:2002
  X962:
       title: "Public Key Cryptography For The Financial Services Industry: The Elliptic Curve Digital Signature Algorithm (ECDSA)"
       date: 1998
       author:
         org: ANSI
       seriesinfo:
         ANSI: X9.62
  DH:
        title: "New Directions in Cryptography"
        author:
          - ins: W. Diffie
          - ins: M. Hellman
        date: 1977-06
        seriesinfo: IEEE Transactions on Information Theory, V.IT-22 n.6


informative:
  RFC0793:
  RFC1948:
  RFC4086:
  RFC4279:
  RFC4302:
  RFC4303:
  RFC4346:
  RFC4366:
  RFC4492:
  RFC4506:
  RFC4507:
  RFC4681:
  RFC5054:
  RFC5077:
  RFC5081:
  RFC5116:
  RFC5246:
  RFC5746:
  RFC5764:
  RFC5878:
  RFC5929:
  RFC6176:
  RFC6091:
  RFC6520:
  RFC7301:
  RFC7230:
  RFC7250:
  RFC7366:
  RFC7465:
  RFC7568:
  RFC7627:
  RFC7685:
  
  RFC4303:
  RFC5996:
  RFC2522:
  RFC4340:
  RFC5238:
  I-D.ietf-tls-negotiated-ff-dhe:

  DSS:
       title: "Digital Signature Standard, version 4"
       date: 2013
       author:
         org: National Institute of Standards and Technology, U.S. Department of Commerce
       seriesinfo:
         NIST: FIPS PUB 186-4
  ECDSA:
       title: "Public Key Cryptography for the Financial Services Industry: The Elliptic Curve Digital Signature Algorithm (ECDSA)"
       author:
         org: American National Standards Institute
       date: 2005-11
       seriesinfo:
         ANSI: ANS X9.62-2005
  FI06:
       title: "Bleichenbacher's RSA signature forgery based on implementation error"
       author:
         - name: Hal Finney
       date: 2006-08-27
       target: https://www.ietf.org/mail-archive/web/openpgp/current/msg00999.html

  GCM:
       title: "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC"
       date: 2007-11
       author:
         ins: M. Dworkin
       seriesinfo:
         NIST: Special Publication 800-38D
  PKCS6:
       title: "PKCS #6: RSA Extended Certificate Syntax Standard, version 1.5"
       author:
         org: RSA Laboratories
       date: 1993-11
  PKCS7:
       title: "PKCS #7: RSA Cryptographic Message Syntax Standard, version 1.5"
       author:
         org: RSA Laboratories
       date: 1993-11
  RSA:
       title: "A Method for Obtaining Digital Signatures and Public-Key Cryptosystems"
       author:
         -
           ins: R. Rivest
         -
           ins: A. Shamir
         -
           ins: L. M. Adleman
       date: 1978-02
       seriesinfo:
         Communications of the ACM: v. 21, n. 2, pp. 120-126.
  SSL2:
       title: "The SSL Protocol"
       author:
         name: Kipp Hickman
         org: Netscape Communications Corp.
       date: 1995-02-09
  SSL3:
       title: The SSL 3.0 Protocol
       author:
         -
           ins: A. Freier
           org: Netscape Communications Corp.
         -
           ins: P. Karlton
           org: Netscape Communications Corp.
         -
           ins: P. Kocher
           org: Netscape Communications Corp.
       date: 1996-11-18
  TIMING:
       title: "Remote timing attacks are practical"
       author:
         -
           ins: D. Boneh
         -
           ins: D. Brumley
       seriesinfo:
         USENIX: Security Symposium
       date: 2003
  X501:
       title: "Information Technology - Open Systems Interconnection - The Directory: Models"
       date: 1993
       seriesinfo:
         ITU-T: X.501
  IEEE1363:
       title: "Standard Specifications for Public Key Cryptography"
       date: 2000
       author:
         org: IEEE
       seriesinfo:
         IEEE 1363
  PSK-FINISHED:
       title: "Revision 10: possible attack if client authentication is allowed during PSK"
       date: 2015
       target: https://www.ietf.org/mail-archive/web/tls/current/msg18215.html
       author:
       -
         ins: C. Cremers
       -
         ins: M. Horvat
       -
         ins: T. van der Merwe
       -
         ins: S. Scott
  SLOTH:
       title: "Transcript Collision Attacks: Breaking Authentication in TLS, IKE, and SSH"
       author:
       -
         ins: K. Bhargavan
       -
         ins: G. Leurent
       seriesinfo: Network and Distributed System Security Symposium (NDSS 2016)
       date: 2016

--- abstract

This document specifies Version 1.3 of the Transport Layer Security
(TLS) and Datagram Transport Layer Security (DTLS) protocols.  These two protocols allows client/server applications to
communicate over the Internet in a way that is designed to prevent eavesdropping,
tampering, and message forgery.
--- middle


#  Introduction

DISCLAIMER: This is a WIP draft of TLS 1.3 and has not yet seen significant security analysis.

RFC EDITOR: PLEASE REMOVE THE FOLLOWING PARAGRAPH
The source for this draft is maintained in GitHub. Suggested changes
should be submitted as pull requests at
https://github.com/tlswg/tls13-spec. Instructions are on that page as
well. Editorial changes can be managed in GitHub, but any substantive
change should be discussed on the TLS mailing list.

The primary goal of the TLS protocol is to provide privacy and data integrity
between two communicating peers. The TLS protocol is composed of two layers:
the TLS Record Protocol and the TLS Handshake Protocol. At the lowest level,
layered on top of some reliable transport protocol (e.g., TCP {{RFC0793}}), is
the TLS Record Protocol. The TLS Record Protocol provides connection security
that has two basic properties:

- The connection is private.  Symmetric cryptography is used for
  data encryption (e.g., AES {{AES}}).  The keys for
  this symmetric encryption are generated uniquely for each
  connection and are based on a secret negotiated by another
  the TLS Handshake Protocol.

- The connection is reliable.  Messages include an authentication
  tag which protects them against modification.

Note: The TLS Record Protocol can operate in an insecure mode but is generally
only used in this mode while another protocol is using the TLS Record
Protocol as a transport for negotiating security parameters.

The TLS Record Protocol is used for encapsulation of various higher-level
protocols. One such encapsulated protocol, the TLS Handshake Protocol, allows
the server and client to authenticate each other and to negotiate an encryption
algorithm and cryptographic keys before the application protocol transmits or
receives its first byte of data. The TLS Handshake Protocol provides connection
security that has three basic properties:


- The peer's identity can be authenticated using asymmetric (public key)
  cryptography (e.g., RSA {{RSA}}, ECDSA {{ECDSA}}) or a pre-shared
  symmetric key. The TLS server is always authenticated; client authentication
  is optional.

- The negotiation of a shared secret is secure: the negotiated
  secret is unavailable to eavesdroppers, and for any authenticated
  connection the secret cannot be obtained, even by an attacker who
  can place himself in the middle of the connection.

- The negotiation is reliable: no attacker can modify the
  negotiation communication without being detected by the parties to
  the communication.


One advantage of TLS is that it is application protocol independent.
Higher-level protocols can layer on top of the TLS protocol transparently. The
TLS standard, however, does not specify how protocols add security with TLS;
the decisions on how to initiate TLS handshaking and how to interpret the
authentication certificates exchanged are left to the judgment of the designers
and implementors of protocols that run on top of TLS.

##  Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119 {{RFC2119}}.

The following terms are used:

client: The endpoint initiating the TLS connection.

connection: A transport-layer connection between two endpoints.

endpoint: Either the client or server of the connection.

handshake: An initial negotiation between client and server that establishes the parameters of their transactions.

peer: An endpoint. When discussing a particular endpoint, "peer" refers to the endpoint that is remote to the primary subject of discussion.

receiver: An endpoint that is receiving records.

sender: An endpoint that is transmitting records.

session: An association between a client and a server resulting from a handshake.

server: The endpoint which did not initiate the TLS connection.


##  Major Differences from TLS 1.2

draft-14

- Allow cookies to be longer.

- Included description of DTLS 1.3 in TLS 1.3 spec.  


draft-13

- Allow server to send SupportedGroups.

- Remove 0-RTT client authentication

- Remove (EC)DHE 0-RTT.

- Flesh out 0-RTT PSK mode and shrink EarlyDataIndiation

- Turn PSK-resumption response into an index to save room

- Move CertificateStatus to an extension

- Extra fields in NewSessionTicket.

- Restructure key schedule and add a resumption_context value.

- Require DH public keys and secrets to be zero-padded to the size
  of the group.

- Remove the redundant length fields in KeyShareEntry.

- Define a cookie field for HRR.


draft-12

- Provide a list of the PSK cipher suites.

- Remove the ability for the ServerHello to have no extensions
  (this aligns the syntax with the text).

- Clarify that the server can send application data after its first
  flight (0.5 RTT data)

- Revise signature algorithm negotiation to group hash, signature
  algorithm, and curve together. This is backwards compatible.

- Make ticket lifetime mandatory and limit it to a week.

- Make the purpose strings lower-case. This matches how people
  are implementing for interop.

- Define exporters.

- Editorial cleanup

draft-11

- Port the CFRG curves & signatures work from RFC4492bis.

- Remove sequence number and version from additional_data, which
  is now empty.

- Reorder values in HkdfLabel.

- Add support for version anti-downgrade mechanism.

- Update IANA considerations section and relax some of the policies.

- Unify authentication modes. Add post-handshake client authentication.

- Remove early_handshake content type. Terminate 0-RTT data with
  an alert.

- Reset sequence number upon key change (as proposed by Fournet et al.)

draft-10

- Remove ClientCertificateTypes field from CertificateRequest
  and add extensions.

- Merge client and server key shares into a single extension.


draft-09

- Change to RSA-PSS signatures for handshake messages.

- Remove support for DSA.

- Update key schedule per suggestions by Hugo, Hoeteck, and Bjoern Tackmann.

- Add support for per-record padding.

- Switch to encrypted record ContentType.

- Change HKDF labeling to include protocol version and value lengths.

- Shift the final decision to abort a handshake due to incompatible
  certificates to the client rather than having servers abort early.

- Deprecate SHA-1 with signatures.

- Add MTI algorithms.


draft-08

- Remove support for weak and lesser used named curves.

- Remove support for MD5 and SHA-224 hashes with signatures.

- Update lists of available AEAD cipher suites and error alerts.

- Reduce maximum permitted record expansion for AEAD from 2048 to 256 octets.

- Require digital signatures even when a previous configuration is used.

- Merge EarlyDataIndication and KnownConfiguration.

- Change code point for server_configuration to avoid collision with
  server_hello_done.

- Relax certificate_list ordering requirement to match current practice.


draft-07

- Integration of semi-ephemeral DH proposal.

- Add initial 0-RTT support.

- Remove resumption and replace with PSK + tickets.

- Move ClientKeyShare into an extension.

- Move to HKDF.


draft-06

- Prohibit RC4 negotiation for backwards compatibility.

- Freeze & deprecate record layer version field.

- Update format of signatures with context.

- Remove explicit IV.


draft-05

- Prohibit SSL negotiation for backwards compatibility.

- Fix which MS is used for exporters.


draft-04

- Modify key computations to include session hash.

- Remove ChangeCipherSpec.

- Renumber the new handshake messages to be somewhat more
  consistent with existing convention and to remove a duplicate
  registration.

- Remove renegotiation.

- Remove point format negotiation.


draft-03

- Remove GMT time.

- Merge in support for ECC from RFC 4492 but without explicit
  curves.

- Remove the unnecessary length field from the AD input to AEAD
  ciphers.

- Rename {Client,Server}KeyExchange to {Client,Server}KeyShare.

- Add an explicit HelloRetryRequest to reject the client's.


draft-02

-  Increment version number.

-  Rework handshake to provide 1-RTT mode.

-  Remove custom DHE groups.

-  Remove support for compression.

-  Remove support for static RSA and DH key exchange.

-  Remove support for non-AEAD ciphers.


#  Goals

The goals of the TLS protocol, in order of priority, are as follows:

1. Cryptographic security: TLS should be used to establish a secure connection
between two parties.

2. Interoperability: Independent programmers should be able to develop
applications utilizing TLS that can successfully exchange cryptographic
parameters without knowledge of one another's code.

3. Extensibility: TLS seeks to provide a framework into which new public key
and record protection methods can be incorporated as necessary. This will also
accomplish two sub-goals\: preventing the need to create a new protocol (and
risking the introduction of possible new weaknesses) and avoiding the need to
implement an entire new security library.

4. Relative efficiency: Cryptographic operations tend to be highly CPU
intensive, particularly public key operations. For this reason, the TLS
protocol has incorporated an optional session caching scheme to reduce the
number of connections that need to be established from scratch. Additionally,
care has been taken to reduce network activity.

In addition to the goals stated above, this specification also introduces DTLS 1.3
and thereby harmonizes
previously separate specifications for TLS and DTLS into a single document. 
Throughout the document any reference to TLS also refers to DTLS unless explicitly
indicated otherwise. {{dtls-rational}} provides a design rational for DTLS. 

#  Goals of This Document

This document and the TLS protocol itself have evolved from the SSL 3.0 Protocol
Specification as published by Netscape. The differences between this version
and previous versions are significant enough that the various
versions of TLS and SSL 3.0 do not interoperate (although each protocol
incorporates a mechanism by which an implementation can back down to prior
versions). This document is intended primarily for readers who will be
implementing the protocol and for those doing cryptographic analysis of it. The
specification has been written with this in mind, and it is intended to reflect
the needs of those two groups. For that reason, many of the algorithm-dependent
data structures and rules are included in the body of the text (as opposed to
in an appendix), providing easier access to them.

This document is not intended to supply any details of service definition or of
interface definition, although it does cover select areas of policy as they are
required for the maintenance of solid security.


#  Presentation Language

This document deals with the formatting of data in an external representation.
The following very basic and somewhat casually defined presentation syntax will
be used. The syntax draws from several sources in its structure. Although it
resembles the programming language "C" in its syntax and XDR {{RFC4506}} in
both its syntax and intent, it would be risky to draw too many parallels. The
purpose of this presentation language is to document TLS only; it has no
general application beyond that particular goal.


##  Basic Block Size

The representation of all data items is explicitly specified. The basic data
block size is one byte (i.e., 8 bits). Multiple byte data items are
concatenations of bytes, from left to right, from top to bottom. From the byte
stream, a multi-byte item (a numeric in the example) is formed (using C
notation) by:

       value = (byte[0] << 8*(n-1)) | (byte[1] << 8*(n-2)) |
               ... | byte[n-1];

This byte ordering for multi-byte values is the commonplace network byte order
or big-endian format.


##  Miscellaneous

Comments begin with "/\*" and end with "\*/".

Optional components are denoted by enclosing them in "\[\[ \]\]" double
brackets.

Single-byte entities containing uninterpreted data are of type
opaque.


##  Vectors

A vector (single-dimensioned array) is a stream of homogeneous data elements.
The size of the vector may be specified at documentation time or left
unspecified until runtime. In either case, the length declares the number of
bytes, not the number of elements, in the vector. The syntax for specifying a
new type, T', that is a fixed- length vector of type T is

       T T'[n];

Here, T' occupies n bytes in the data stream, where n is a multiple of the size
of T.  The length of the vector is not included in the encoded stream.

In the following example, Datum is defined to be three consecutive bytes that
the protocol does not interpret, while Data is three consecutive Datum,
consuming a total of nine bytes.

       opaque Datum[3];      /* three uninterpreted bytes */
       Datum Data[9];        /* 3 consecutive 3 byte vectors */

Variable-length vectors are defined by specifying a subrange of legal lengths,
inclusively, using the notation \<floor..ceiling\>. When these are encoded, the
actual length precedes the vector's contents in the byte stream. The length
will be in the form of a number consuming as many bytes as required to hold the
vector's specified maximum (ceiling) length. A variable-length vector with an
actual length field of zero is referred to as an empty vector.

       T T'<floor..ceiling>;

In the following example, mandatory is a vector that must contain between 300
and 400 bytes of type opaque. It can never be empty. The actual length field
consumes two bytes, a uint16, which is sufficient to represent the value 400
(see {{numbers}}). On the other hand, longer can represent up to 800 bytes of
data, or 400 uint16 elements, and it may be empty. Its encoding will include a
two-byte actual length field prepended to the vector. The length of an encoded
vector must be an even multiple of the length of a single element (for example,
a 17-byte vector of uint16 would be illegal).

       opaque mandatory<300..400>;
             /* length field is 2 bytes, cannot be empty */
       uint16 longer<0..800>;
             /* zero to 400 16-bit unsigned integers */


##  Numbers

The basic numeric data type is an unsigned byte (uint8). All larger numeric
data types are formed from fixed-length series of bytes concatenated as
described in {{basic-block-size}} and are also unsigned. The following numeric
types are predefined.

       uint8 uint16[2];
       uint8 uint24[3];
       uint8 uint32[4];
       uint8 uint64[8];

All values, here and elsewhere in the specification, are stored in network byte
(big-endian) order; the uint32 represented by the hex bytes 01 02 03 04 is
equivalent to the decimal value 16909060.

Note that in some cases (e.g., DH parameters) it is necessary to represent
integers as opaque vectors. In such cases, they are represented as unsigned
integers (i.e., additional leading zero octets are not used even if the most
significant bit is set).


##  Enumerateds

An additional sparse data type is available called enum. A field of type enum
can only assume the values declared in the definition. Each definition is a
different type. Only enumerateds of the same type may be assigned or compared.
Every element of an enumerated must be assigned a value, as demonstrated in the
following example. Since the elements of the enumerated are not ordered, they
can be assigned any unique value, in any order.

       enum { e1(v1), e2(v2), ... , en(vn) [[, (n)]] } Te;

An enumerated occupies as much space in the byte stream as would its maximal
defined ordinal value. The following definition would cause one byte to be used
to carry fields of type Color.

       enum { red(3), blue(5), white(7) } Color;

One may optionally specify a value without its associated tag to force the
width definition without defining a superfluous element.

In the following example, Taste will consume two bytes in the data stream but
can only assume the values 1, 2, or 4.

       enum { sweet(1), sour(2), bitter(4), (32000) } Taste;

The names of the elements of an enumeration are scoped within the defined type.
In the first example, a fully qualified reference to the second element of the
enumeration would be Color.blue. Such qualification is not required if the
target of the assignment is well specified.

       Color color = Color.blue;     /* overspecified, legal */
       Color color = blue;           /* correct, type implicit */

For enumerateds that are never converted to external representation, the
numerical information may be omitted.

       enum { low, medium, high } Amount;


##  Constructed Types

Structure types may be constructed from primitive types for convenience. Each
specification declares a new, unique type. The syntax for definition is much
like that of C.

       struct {
           T1 f1;
           T2 f2;
           ...
           Tn fn;
       } [[T]];

The fields within a structure may be qualified using the type's name, with a
syntax much like that available for enumerateds. For example, T.f2 refers to
the second field of the previous declaration. Structure definitions may be
embedded.

###  Variants

Defined structures may have variants based on some knowledge that is available
within the environment. The selector must be an enumerated type that defines
the possible variants the structure defines. There must be a case arm for every
element of the enumeration declared in the select. Case arms have limited
fall-through: if two case arms follow in immediate succession with no fields in
between, then they both contain the same fields. Thus, in the example below,
"orange" and "banana" both contain V2. Note that this is a new piece of syntax
in TLS 1.2.

The body of the variant structure may be given a label for reference. The
mechanism by which the variant is selected at runtime is not prescribed by the
presentation language.

       struct {
           T1 f1;
           T2 f2;
           ....
           Tn fn;
            select (E) {
                case e1: Te1;
                case e2: Te2;
                case e3: case e4: Te3;
                ....
                case en: Ten;
            } [[fv]];
       } [[Tv]];

For example:

       enum { apple, orange, banana } VariantTag;

       struct {
           uint16 number;
           opaque string<0..10>; /* variable length */
       } V1;

       struct {
           uint32 number;
           opaque string[10];    /* fixed length */
       } V2;

       struct {
           select (VariantTag) { /* value of selector is implicit */
               case apple:
                 V1;   /* VariantBody, tag = apple */
               case orange:
               case banana:
                 V2;   /* VariantBody, tag = orange or banana */
           } variant_body;       /* optional label on variant */
       } VariantRecord;


##  Constants

Typed constants can be defined for purposes of specification by declaring a
symbol of the desired type and assigning values to it.

Under-specified types (opaque, variable-length vectors, and structures that
contain opaque) cannot be assigned values. No fields of a multi-element
structure or vector may be elided.

For example:

       struct {
           uint8 f1;
           uint8 f2;
       } Example1;

       Example1 ex1 = {1, 4};  /* assigns f1 = 1, f2 = 4 */

##  Cryptographic Attributes

The two cryptographic operations --- digital signing, and authenticated
encryption with additional data (AEAD) --- are designated digitally-signed,
and aead-ciphered, respectively. A field's cryptographic processing
is specified by prepending an appropriate key word designation before
the field's type specification.  Cryptographic keys are implied by the
current session state (see {{connection-states}}).

### Digital Signing

A digitally-signed element is encoded as a struct DigitallySigned:

       struct {
          SignatureScheme algorithm;
          opaque signature<0..2^16-1>;
       } DigitallySigned;

The algorithm field specifies the algorithm used (see {{signature-algorithms}}
for the definition of this field). The signature is a digital signature
using those algorithms over the contents of the element. The contents
themselves do not appear on the wire but are simply calculated. The length of
the signature is specified by the signing algorithm and key.

In previous versions of TLS, the ServerKeyExchange format meant that attackers
can obtain a signature of a message with a chosen, 32-byte prefix. Because TLS
1.3 servers are likely to also implement prior versions, the contents of the
element always start with 64 bytes of octet 32 in order to clear that
chosen-prefix.

Following that padding is a context string used to disambiguate
signatures for different purposes. The context string will be
specified whenever a digitally-signed element is used. A single 0 byte
is appended to the context to act as a separator.

Finally, the specified contents of the digitally-signed structure follow the
0 byte after the context string. (See the example at the end of this
section.)

The combined input is then fed into the corresponding signature algorithm
to produce the signature value on the wire. See {{signature-algorithms}} for
algorithms defined in this specification.

In the following example

       struct {
           uint8 field1;
           uint8 field2;
           digitally-signed opaque {
             uint8 field3<0..255>;
             uint8 field4;
           };
       } UserType;

Assume that the context string for the signature was specified as "Example".
The input for the signature/hash algorithm would be:

       2020202020202020202020202020202020202020202020202020202020202020
       2020202020202020202020202020202020202020202020202020202020202020
       4578616d706c6500

followed by the encoding of the inner struct (field3 and field4).

The length of the structure, in bytes, would be equal to two
bytes for field1 and field2, plus two bytes for the signature
algorithm, plus two bytes for the length of the signature, plus the length of
the output of the signing algorithm. The length of the signature is known
because the algorithm and key used for the signing are known prior to encoding
or decoding this structure.


### Authenticated Encryption with Additional Data (AEAD)

In AEAD encryption, the plaintext is simultaneously encrypted and integrity
protected. The input may be of any length, and aead-ciphered output is
generally larger than the input in order to accommodate the integrity check
value.


#  The TLS Record Protocol

The TLS Record Protocol takes messages to be transmitted, fragments
the data into manageable blocks, protects the records, and transmits
the result. Received data is decrypted and verified, reassembled, and
then delivered to higher-level clients.

Three protocols that use the TLS Record Protocol are described in this document: the TLS
Handshake Protocol, the Alert Protocol, and
the application data protocol. In order to allow extension of the TLS protocol,
additional record content types can be supported by the TLS Record Protocol. New
record content type values are assigned by IANA in the TLS Content Type
Registry as described in {{iana-considerations}}.

Implementations MUST NOT send record types not defined in this document unless
negotiated by some extension. If a TLS implementation receives an unexpected
record type, it MUST send an "unexpected_message" alert.

Any protocol designed for use over TLS must be carefully designed to deal with
all possible attacks against it. As a practical matter, this means that the
protocol designer must be aware of what security properties TLS does and does
not provide and cannot safely rely on the latter.

Note in particular that the length of a record or absence of traffic
itself is not protected by encryption unless the sender uses the
supplied padding mechanism -- see {{record-padding}} for more details.


##  Connection States

[[TODO: I plan to totally rewrite or remove this. IT seems like just cruft.]]

A TLS connection state is the operating environment of the TLS Record
Protocol.  It specifies a record protection algorithm and its
parameters as well as the record protection keys and IVs for the
connection in both the read and the write directions. The security
parameters are set by the TLS Handshake Protocol, which also determines
when new cryptographic keys are installed and used for record
protection.
The initial current state always specifies that records are
not protected.

The security parameters for a TLS Connection read and write state are set by
providing the following values:

{:br: vspace="0"}

connection end

: Whether this entity is considered the "client" or the "server" in
  this connection.

Hash algorithm

: An algorithm used to generate keys from the appropriate secret (see
  {{key-schedule}} and {{traffic-key-calculation}}).

record protection algorithm

: The algorithm to be used for record protection. This algorithm must
  be of the AEAD type and thus provides integrity and confidentiality
  as a single primitive. This specification
  includes the key size of this algorithm and of the nonce for
  the AEAD algorithm.

master secret

: A 48-byte secret shared between the two peers in the connection
  and used to generate keys for protecting data.


client random

: A 32-byte value provided by the client.

server random

: A 32-byte value provided by the server.
{: br}

These parameters are defined in the presentation language as:

%%% Security Parameters
       enum { server, client } ConnectionEnd;

       enum { tls_kdf_sha256, tls_kdf_sha384 } KDFAlgorithm;

       enum { aes_gcm } RecordProtAlgorithm;

       /* The algorithms specified in KDFAlgorithm and
          RecordProtAlgorithm may be added to. */

       struct {
           ConnectionEnd          entity;
           KDFAlgorithm           kdf_algorithm;
           RecordProtAlgorithm    record_prot_algorithm;
           uint8                  enc_key_length;
           uint8                  iv_length;
           opaque                 hs_master_secret[48];
           opaque                 master_secret[48];
           opaque                 client_random[32];
           opaque                 server_random[32];
       } SecurityParameters;

[TODO: update this to handle new key hierarchy.]

The connection state will use the security parameters to generate the following four
items:

       client_write_key
       server_write_key
       client_write_iv
       server_write_iv

The client write parameters are used by the server when receiving and
processing records and vice versa. The algorithm used for generating these
items from the security parameters is described in {{traffic-key-calculation}}.

Once the security parameters have been set and the keys have been generated,
the connection states can be instantiated by making them the current states.
These current states MUST be updated for each record processed. Each connection
state includes the following elements:

cipher state
: The current state of the encryption algorithm.  This will consist
  of the scheduled key for that connection.

sequence number
: Each connection state contains a sequence number, which is
  maintained separately for read and write states.  The sequence
  number is set to zero at the beginning of a connection, and whenever
  the key is changed.

  The sequence number is incremented after each record: specifically,
  the first record transmitted under a particular connection state and
  record key MUST use sequence number 0.

  Sequence numbers are of type uint64 and MUST NOT exceed 2^64-1.
  Sequence numbers do not wrap.  If a TLS implementation would need to
  wrap a sequence number, it MUST either rekey ({{key-update}}) or
  terminate the connection.
{:br }


##  TLS Record Layer

The TLS record layer receives uninterpreted data from higher layers in
non-empty blocks of arbitrary size.

###  Fragmentation

The record layer fragments information blocks into TLSPlaintext records
carrying data in chunks of 2^14 bytes or less. Message boundaries are
not preserved in the record layer (i.e., multiple messages of the same
ContentType MAY be coalesced into a single TLSPlaintext record, or a single
message MAY be fragmented across several records).
Alert messages ({{alert-protocol}}) MUST NOT be fragmented across records.

%%% Record Layer
       struct {
           uint8 major;
           uint8 minor;
       } ProtocolVersion;

       enum {
           invalid_RESERVED(0),
           change_cipher_spec_RESERVED(20),
           alert(21),
           handshake(22),
           application_data(23)
           (255)
       } ContentType;

       struct {
           ContentType type;
           ProtocolVersion record_version = { 3, 1 };    /* TLS v1.x */
           uint16 length;
           opaque fragment[TLSPlaintext.length];
       } TLSPlaintext;

type
: The higher-level protocol used to process the enclosed fragment.

record_version
: The protocol version the current record is compatible with.
  This value MUST be set to { 3, 1 } for all records.
  This field is deprecated and MUST be ignored for all purposes.

length
: The length (in bytes) of the following TLSPlaintext.fragment.  The
  length MUST NOT exceed 2^14.

fragment
: The application data.  This data is transparent and treated as an
  independent block to be dealt with by the higher-level protocol
  specified by the type field.
{:br }

This document describes TLS Version 1.3, which uses the version { 3, 4 }.
The version value 3.4 is historical, deriving from the use of { 3, 1 }
for TLS 1.0 and { 3, 0 } for SSL 3.0. In order to maximize backwards
compatibility, the record layer version identifies as simply TLS 1.0.
Endpoints supporting other versions negotiate the version to use
by following the procedure and requirements in {{backward-compatibility}}.

Implementations MUST NOT send zero-length fragments of Handshake or
Alert types, even if those fragments contain padding. Zero-length
fragments of Application data MAY be sent as they are potentially
useful as a traffic analysis countermeasure.

When record protection has not yet been engaged, TLSPlaintext
structures are written directly onto the wire. Once record protection
has started, TLSPlaintext records are protected and sent as
described in the following section.

###  Record Payload Protection

The record protection functions translate a TLSPlaintext structure into a
TLSCiphertext. The deprotection functions reverse the process. In TLS 1.3
as opposed to previous versions of TLS, all ciphers are modeled as
"Authenticated Encryption with Additional Data" (AEAD) {{RFC5116}}.
AEAD functions provide a unified encryption and authentication
operation which turns plaintext into authenticated ciphertext and
back again.

AEAD ciphers take as input a single key, a nonce, a plaintext, and "additional
data" to be included in the authentication check, as described in Section 2.1
of {{RFC5116}}. The key is either the client_write_key or the server_write_key
and in TLS 1.3 the additional data input is empty (zero length).

%%% Record Layer
       struct {
           ContentType opaque_type = application_data(23); /* see fragment.type */
           ProtocolVersion record_version = { 3, 1 };    /* TLS v1.x */
           uint16 length;
           aead-ciphered struct {
              opaque content[TLSPlaintext.length];
              ContentType type;
              uint8 zeros[length_of_padding];
           } fragment;
       } TLSCiphertext;

opaque_type
: The outer opaque_type field of a TLSCiphertext record is always set to the
  value 23 (application_data) for outward compatibility with
  middleboxes accustomed to parsing previous versions of TLS.  The
  actual content type of the record is found in fragment.type after
  decryption.

record_version
: The record_version field is identical to TLSPlaintext.record_version and is always { 3, 1 }.
  Note that the handshake protocol including the ClientHello and ServerHello messages authenticates
  the protocol version, so this value is redundant.

length
: The length (in bytes) of the following TLSCiphertext.fragment.  The length
  MUST NOT exceed 2^14 + 256.  An endpoint that receives a record that exceeds
  this length MUST generate a fatal "record_overflow" alert.

fragment.content
: The cleartext of TLSPlaintext.fragment.

fragment.type
: The actual content type of the record.

fragment.zeros
: An arbitrary-length run of zero-valued bytes may
  appear in the cleartext after the type field.  This provides an
  opportunity for senders to pad any TLS record by a chosen amount as
  long as the total stays within record size limits.  See
  {{record-padding}} for more details.

fragment
: The AEAD encrypted form of TLSPlaintext.fragment + TLSPlaintext.type + zeros,
  where "+" denotes concatenation.
{:br }


The length of the per-record nonce (iv_length) is set to max(8 bytes,
N_MIN) for the AEAD algorithm (see {{RFC5116}} Section 4). An AEAD
algorithm where N_MAX is less than 8 bytes MUST NOT be used with TLS.
The per-record nonce for the AEAD construction is formed as follows:

  1. The 64-bit record sequence number is padded to the left with zeroes
     to iv_length.

  2. The padded sequence number is XORed with the static client_write_iv
     or server_write_iv, depending on the role.

The resulting quantity (of length iv_length) is used as the per-record
nonce.

Note: This is a different construction from that in TLS 1.2, which
specified a partially explicit nonce.

The plaintext is the concatenation of TLSPlaintext.fragment and TLSPlaintext.type.

The AEAD output consists of the ciphertext output by the AEAD
encryption operation. The length of the plaintext is greater than
TLSPlaintext.length due to the inclusion of TLSPlaintext.type and
however much padding is supplied by the sender.  The length of
aead_output will generally be larger than the plaintext, but by an
amount that varies with the AEAD cipher. Since the ciphers might
incorporate padding, the amount of overhead could vary with different
lengths of plaintext. Symbolically,

       AEADEncrypted =
           AEAD-Encrypt(write_key, nonce, plaintext of fragment)

In order to decrypt and verify, the cipher takes as input the key,
nonce, and the AEADEncrypted value. The output is either the plaintext
or an error indicating that the decryption failed. There is no
separate integrity check. That is:

       plaintext of fragment =
           AEAD-Decrypt(write_key, nonce, AEADEncrypted)

If the decryption fails, a fatal "bad_record_mac" alert MUST be generated.

An AEAD cipher MUST NOT produce an expansion of greater than 255
bytes.  An endpoint that receives a record from its peer with
TLSCipherText.length larger than 2^14 + 256 octets MUST generate a
fatal "record_overflow" alert.  This limit is derived from the maximum
TLSPlaintext length of 2^14 octets + 1 octet for ContentType + the
maximum AEAD expansion of 255 octets.

### Record Padding

All encrypted TLS records can be padded to inflate the size of the
TLSCipherText.  This allows the sender to hide the size of the
traffic from an observer.

When generating a TLSCiphertext record, implementations MAY choose to
pad.  An unpadded record is just a record with a padding length of
zero.  Padding is a string of zero-valued bytes appended
to the ContentType field before encryption.  Implementations MUST set
the padding octets to all zeros before encrypting.

Application Data records may contain a zero-length fragment.content if
the sender desires.  This permits generation of plausibly-sized cover
traffic in contexts where the presence or absence of activity may be
sensitive.  Implementations MUST NOT send Handshake or Alert records
that have a zero-length fragment.content.

The padding sent is automatically verified by the record protection
mechanism: Upon successful decryption of a TLSCiphertext.fragment,
the receiving implementation scans the field from the end toward the
beginning until it finds a non-zero octet. This non-zero octet is the
content type of the message.
This padding scheme was selected because it allows padding of any encrypted
TLS record by an arbitrary size (from zero up to TLS record size
limits) without introducing new content types.  The design also
enforces all-zero padding octets, which allows for quick detection of
padding errors.

Implementations MUST limit their scanning to the cleartext returned
from the AEAD decryption.  If a receiving implementation does not find
a non-zero octet in the cleartext, it should treat the record as
having an unexpected ContentType, sending an "unexpected_message"
alert.

The presence of padding does not change the overall record size
limitations -- the full fragment plaintext may not exceed 2^14 octets.

Selecting a padding policy that suggests when and how much to pad is a
complex topic, and is beyond the scope of this specification. If the
application layer protocol atop TLS permits padding, it may be
preferable to pad application_data TLS records within the application
layer.  Padding for encrypted handshake and alert TLS records must
still be handled at the TLS layer, though.  Later documents may define
padding selection algorithms, or define a padding policy request
mechanism through TLS extensions or some other means.

# The DTLS Record Layer

The DTLS record layer is extremely similar to that of TLS 1.3.  The
only change is the inclusion of an explicit epoch and sequence number 
in the record.  This sequence number allows the recipient to correctly
verify the TLS MAC.  The DTLS record format is shown below:

      struct {
           ContentType type;
           ProtocolVersion version = { 254, 253 };
           uint16 epoch;                         // DTLS-related field
           uint48 sequence_number;               // DTLS-related field
           uint16 length;
           opaque fragment[DTLSPlaintext.length];
         } DTLSPlaintext;

type
: Identical to the type field in a TLS 1.3 record.

version
: This specification re-uses the DTLS version 1.2 version number, namely
{ 254, 253 }. This field is deprecated and MUST be ignored for all purposes.

epoch
: A counter value that is incremented on every cipher state change.

sequence_number
: The sequence number for this record.

length
: Identical to the length field in a TLS 1.3 record.

fragment
: Identical to the fragment field in a TLS 1.3 record.

   DTLS uses an explicit sequence number, rather than an implicit one,
   carried in the sequence_number field of the record.  Sequence numbers
   are maintained separately for each epoch, with each sequence_number
   initially being 0 for each epoch.  For instance, if a handshake
   message from epoch 0 is retransmitted, it might have a sequence
   number after a message from epoch 1, even if the message from epoch 1
   was transmitted first.  Note that some care needs to be taken during
   the handshake to ensure that retransmitted messages use the right
   epoch and keying material.

   If several handshakes are performed in close succession, there might
   be multiple records on the wire with the same sequence number but
   from different cipher states.  The epoch field allows recipients to
   distinguish such packets.  The epoch number is initially zero and is
   incremented each time a KeyUpdate message is sent.  In order
   to ensure that any given sequence/epoch pair is unique,
   implementations MUST NOT allow the same epoch value to be reused
   within two times the TCP maximum segment lifetime. 

   Note that because DTLS records may be reordered, a record from epoch
   1 may be received after epoch 2 has begun.  In general,
   implementations SHOULD discard packets from earlier epochs, but if
   packet loss causes noticeable problems they MAY choose to retain
   keying material from previous epochs for up to the default MSL
   specified for TCP {{TCP}} to allow for packet reordering.  (Note that
   the intention here is that implementors use the current guidance from
   the IETF for MSL, not that they attempt to interrogate the MSL that
   the system TCP stack is using.)  Until the handshake has completed,
   implementations MUST accept packets from the old epoch.

   Conversely, it is possible for records that are protected by the
   newly negotiated context to be received prior to the completion of a
   handshake.  For instance, the server may send its Finished message
   and then start transmitting data.  Implementations MAY either buffer
   or discard such packets, though when DTLS is used over reliable
   transports (e.g., SCTP), they SHOULD be buffered and processed once
   the handshake completes.  Note that TLS's restrictions on when
   packets may be sent still apply, and the receiver treats the packets
   as if they were sent in the right order.  In particular, it is still
   impermissible to send data prior to completion of the first
   handshake.

   As in TLS, implementations MUST either abandon an association or
   re-key using a KeyUpdate message prior to allowing the sequence number to wrap.

   Implementations MUST NOT allow the epoch to wrap, but
   instead MUST establish a new association, terminating the old
   association.

##  Transport Layer Mapping

   Each DTLS record MUST fit within a single datagram.  In order to
   avoid IP fragmentation, clients of the DTLS record layer SHOULD
   attempt to size records so that they fit within any PMTU estimates
   obtained from the record layer.

   Note that unlike IPsec, DTLS records do not contain any association
   identifiers.  Applications must arrange to multiplex between
   associations.  With UDP, this is presumably done with the host/port
   number.

   Multiple DTLS records may be placed in a single datagram.  They are
   simply encoded consecutively.  The DTLS record framing is sufficient
   to determine the boundaries.  Note, however, that the first byte of
   the datagram payload must be the beginning of a record.  Records may
   not span datagrams.

   Some transports, such as DCCP {{RFC4340}} provide their own sequence
   numbers.  When carried over those transports, both the DTLS and the
   transport sequence numbers will be present.  Although this introduces
   a small amount of inefficiency, the transport layer and DTLS sequence
   numbers serve different purposes; therefore, for conceptual
   simplicity, it is superior to use both sequence numbers.

   Some transports, such as DCCP, provide congestion control for traffic
   carried over them.  If the congestion window is sufficiently narrow,
   DTLS handshake retransmissions may be held rather than transmitted
   immediately, potentially leading to timeouts and spurious
   retransmission.  When DTLS is used over such transports, care should
   be taken not to overrun the likely congestion window. {{RFC5238}}
   defines a mapping of DTLS to DCCP that takes these issues into
   account.

##  PMTU Issues

   In general, DTLS's philosophy is to leave PMTU discovery to the
   application.  However, DTLS cannot completely ignore PMTU for three
   reasons:

-  The DTLS record framing expands the datagram size, thus lowering
      the effective PMTU from the application's perspective.

-  In some implementations, the application may not directly talk to
      the network, in which case the DTLS stack may absorb ICMP
      {{RFC1191}} "Datagram Too Big" indications or ICMPv6 {{RFC4443}}
      "Packet Too Big" indications.

-  The DTLS handshake messages can exceed the PMTU.

   In order to deal with the first two issues, the DTLS record layer
   SHOULD behave as described below.

   If PMTU estimates are available from the underlying transport
   protocol, they should be made available to upper layer protocols.  In
   particular:

-  For DTLS over UDP, the upper layer protocol SHOULD be allowed to
      obtain the PMTU estimate maintained in the IP layer.

-  For DTLS over DCCP, the upper layer protocol SHOULD be allowed to
      obtain the current estimate of the PMTU.

-  For DTLS over TCP or SCTP, which automatically fragment and
      reassemble datagrams, there is no PMTU limitation.  However, the
      upper layer protocol MUST NOT write any record that exceeds the
      maximum record size of 2^14 bytes.

   The DTLS record layer SHOULD allow the upper layer protocol to
   discover the amount of record expansion expected by the DTLS
   processing.

   If there is a transport protocol indication (either via ICMP or via a
   refusal to send the datagram as in Section 14 of {{RFC4340}}), then the
   DTLS record layer MUST inform the upper layer protocol of the error.

   The DTLS record layer SHOULD NOT interfere with upper layer protocols
   performing PMTU discovery, whether via {{RFC1191}} or {{RFC4821}}
   mechanisms.  In particular:

-  Where allowed by the underlying transport protocol, the upper
      layer protocol SHOULD be allowed to set the state of the DF bit
      (in IPv4) or prohibit local fragmentation (in IPv6).

-  If the underlying transport protocol allows the application to
      request PMTU probing (e.g., DCCP), the DTLS record layer should
      honor this request.

   The final issue is the DTLS handshake protocol.  From the perspective
   of the DTLS record layer, this is merely another upper layer
   protocol.  However, DTLS handshakes occur infrequently and involve
   only a few round trips; therefore, the handshake protocol PMTU
   handling places a premium on rapid completion over accurate PMTU
   discovery.  In order to allow connections under these circumstances,
   DTLS implementations SHOULD follow the following rules:

-  If the DTLS record layer informs the DTLS handshake layer that a
      message is too big, it SHOULD immediately attempt to fragment it,
      using any existing information about the PMTU.

-  If repeated retransmissions do not result in a response, and the
      PMTU is unknown, subsequent retransmissions SHOULD back off to a
      smaller record size, fragmenting the handshake message as
      appropriate.  This standard does not specify an exact number of
      retransmits to attempt before backing off, but 2-3 seems
      appropriate.

##  Record Payload Protection

   Like TLS, DTLS transmits data as a series of protected records.  The
   rest of this section describes the details of that format.



###  Anti-Replay

   DTLS records contain a sequence number to provide replay protection.
   Sequence number verification SHOULD be performed using the following
   sliding window procedure, borrowed from Section 3.4.3 of {{RFC4303}}.

   The receiver packet counter for this session MUST be initialized to
   zero when the session is established.  For each received record, the
   receiver MUST verify that the record contains a sequence number that
   does not duplicate the sequence number of any other record received
   during the life of this session.  This SHOULD be the first check
   applied to a packet after it has been matched to a session, to speed
   rejection of duplicate records.

   Duplicates are rejected through the use of a sliding receive window.
   (How the window is implemented is a local matter, but the following
   text describes the functionality that the implementation must
   exhibit.)  A minimum window size of 32 MUST be supported, but a
   window size of 64 is preferred and SHOULD be employed as the default.
   Another window size (larger than the minimum) MAY be chosen by the
   receiver.  (The receiver does not notify the sender of the window
   size.)

   The "right" edge of the window represents the highest validated
   sequence number value received on this session.  Records that contain
   sequence numbers lower than the "left" edge of the window are
   rejected.  Packets falling within the window are checked against a
   list of received packets within the window.  An efficient means for
   performing this check, based on the use of a bit mask, is described
   in Section 3.4.3 of {{RFC4303}}.

   If the received record falls within the window and is new, or if the
   packet is to the right of the window, then the receiver proceeds to
   MAC verification.  If the MAC validation fails, the receiver MUST
   discard the received record as invalid.  The receive window is
   updated only if the MAC verification succeeds.

### Handling Invalid Records

   Unlike TLS, DTLS is resilient in the face of invalid records (e.g.,
   invalid formatting, length, MAC, etc.).  In general, invalid records
   SHOULD be silently discarded, thus preserving the association;
   however, an error MAY be logged for diagnostic purposes.
   Implementations which choose to generate an alert instead, MUST
   generate fatal level alerts to avoid attacks where the attacker
   repeatedly probes the implementation to see how it responds to
   various types of error.  Note that if DTLS is run over UDP, then any
   implementation which does this will be extremely susceptible to
   denial-of-service (DoS) attacks because UDP forgery is so easy.
   Thus, this practice is NOT RECOMMENDED for such transports.

   If DTLS is being carried over a transport that is resistant to
   forgery (e.g., SCTP with SCTP-AUTH), then it is safer to send alerts
   because an attacker will have difficulty forging a datagram that will
   not be rejected by the transport layer.

#  The TLS Handshaking Protocols

TLS has two subprotocols that are used to allow peers to agree upon security
parameters for the record layer, to authenticate themselves, to instantiate
negotiated security parameters, and to report error conditions to each other.

The TLS Handshake Protocol is responsible for negotiating a session, which consists
of the following items:

peer certificate
: X509v3 {{RFC5280}} certificate of the peer.  This element of the state
  may be null.

cipher spec
: Specifies the authentication and key establishment algorithms,
  the hash for use with HKDF to generate keying
  material, and the record protection algorithm (See
  {{the-security-parameters}} for formal definition.)

resumption master secret
: a secret shared between the client and server that can be used
  as a pre-shared symmetric key (PSK) in future connections.
{:br }

These items are then used to create security parameters for use by the record
layer when protecting application data. Many connections can be instantiated
using the same session using a PSK established in an initial handshake.


##  Alert Protocol

One of the content types supported by the TLS record layer is the alert type.
Alert messages convey the severity of the message (warning or fatal) and a
description of the alert. Alert messages with a level of fatal result in the
immediate termination of the connection. In this case, other connections
corresponding to the session may continue, but the session identifier MUST be
invalidated, preventing the failed session from being used to establish new
connections. Like other messages, alert messages are encrypted
as specified by the current connection state.

%%% Alert Messages
       enum { warning(1), fatal(2), (255) } AlertLevel;

       enum {
           close_notify(0),
           end_of_early_data(1),
           unexpected_message(10),               /* fatal */
           bad_record_mac(20),                   /* fatal */
           decryption_failed_RESERVED(21),       /* fatal */
           record_overflow(22),                  /* fatal */
           decompression_failure_RESERVED(30),   /* fatal */
           handshake_failure(40),                /* fatal */
           no_certificate_RESERVED(41),          /* fatal */
           bad_certificate(42),
           unsupported_certificate(43),
           certificate_revoked(44),
           certificate_expired(45),
           certificate_unknown(46),
           illegal_parameter(47),                /* fatal */
           unknown_ca(48),                       /* fatal */
           access_denied(49),                    /* fatal */
           decode_error(50),                     /* fatal */
           decrypt_error(51),                    /* fatal */
           export_restriction_RESERVED(60),      /* fatal */
           protocol_version(70),                 /* fatal */
           insufficient_security(71),            /* fatal */
           internal_error(80),                   /* fatal */
           inappropriate_fallback(86),           /* fatal */
           user_canceled(90),
           no_renegotiation_RESERVED(100),       /* fatal */
           missing_extension(109),               /* fatal */
           unsupported_extension(110),           /* fatal */
           certificate_unobtainable(111),
           unrecognized_name(112),
           bad_certificate_status_response(113), /* fatal */
           bad_certificate_hash_value(114),      /* fatal */
           unknown_psk_identity(115),
           (255)
       } AlertDescription;

       struct {
           AlertLevel level;
           AlertDescription description;
       } Alert;

###  Closure Alerts

The client and the server must share knowledge that the connection is ending in
order to avoid a truncation attack. Failure to properly close a connection does
not prohibit a session from being resumed.

close_notify
: This alert notifies the recipient that the sender will not send
  any more messages on this connection. Any data received after a
  closure MUST be ignored.

end_of_early_data
: This alert is sent by the client to indicate that all 0-RTT
  application_data messages have been transmitted (or none will
  be sent at all) and that this is the end of the flight. This
  alert MUST be at the warning level. Servers MUST NOT send this
  alert and clients receiving it MUST terminate the connection
  with an "unexpected_message" alert.

user_canceled
: This alert notifies the recipient that the sender is canceling the
  handshake for some reason unrelated to a protocol failure. If a user
  cancels an operation after the handshake is complete, just closing the
  connection by sending a "close_notify" is more appropriate. This alert
  SHOULD be followed by a "close_notify". This alert is generally a warning.
{:br }

Either party MAY initiate a close by sending a "close_notify" alert. Any data
received after a closure alert is ignored. If a transport-level close is
received prior to a "close_notify", the receiver cannot know that all the
data that was sent has been received.

Each party MUST send a "close_notify" alert before closing the write side
of the connection, unless some other fatal alert has been transmitted. The
other party MUST respond with a "close_notify" alert of its own and close down
the connection immediately, discarding any pending writes. The initiator of the
close need not wait for the responding "close_notify" alert before closing the
read side of the connection.

If the application protocol using TLS provides that any data may be carried
over the underlying transport after the TLS connection is closed, the TLS
implementation must receive the responding "close_notify" alert before indicating
to the application layer that the TLS connection has ended. If the application
protocol will not transfer any additional data, but will only close the
underlying transport connection, then the implementation MAY choose to close
the transport without waiting for the responding "close_notify". No part of this
standard should be taken to dictate the manner in which a usage profile for TLS
manages its data transport, including when connections are opened or closed.

Note: It is assumed that closing a connection reliably delivers pending data
before destroying the transport.

###  Error Alerts

Error handling in the TLS Handshake Protocol is very simple. When an error is
detected, the detecting party sends a message to its peer. Upon
transmission or receipt of a fatal alert message, both parties immediately
close the connection. Servers and clients MUST forget any session-identifiers,
keys, and secrets associated with a failed connection. Thus, any connection
terminated with a fatal alert MUST NOT be resumed.

Whenever an implementation encounters a condition which is defined as a fatal
alert, it MUST send the appropriate alert prior to closing the connection. For
all errors where an alert level is not explicitly specified, the sending party
MAY determine at its discretion whether to treat this as a fatal error or not.
If the implementation chooses to send an alert but intends to close the
connection immediately afterwards, it MUST send that alert at the fatal alert
level.

If an alert with a level of warning is sent and received, generally the
connection can continue normally. If the receiving party decides not to proceed
with the connection (e.g., after having received a "user_canceled" alert that
it is not willing to accept), it SHOULD send a fatal alert to terminate the
connection. Given this, the sending peer cannot, in general, know how the
receiving party will behave. Therefore, warning alerts are not very useful when
the sending party wants to continue the connection, and thus are sometimes
omitted. For example, if a party decides to accept an expired certificate
(perhaps after confirming this with the user) and wants to continue the
connection, it would not generally send a "certificate_expired" alert.

The following error alerts are defined:

unexpected_message
: An inappropriate message was received.  This alert is always fatal
  and should never be observed in communication between proper
  implementations.

bad_record_mac
: This alert is returned if a record is received which cannot be
  deprotected. Because AEAD algorithms combine decryption and
  verification, this alert is used for all deprotection failures.
  This alert is always fatal and should never be observed in
  communication between proper implementations (except when messages
  were corrupted in the network).

record_overflow
: A TLSCiphertext record was received that had a length more than
  2^14 + 256 bytes, or a record decrypted to a TLSPlaintext record
  with more than 2^14 bytes.  This alert is always fatal and
  should never be observed in communication between proper
  implementations (except when messages were corrupted in the
  network).

handshake_failure
: Reception of a "handshake_failure" alert message indicates that the
  sender was unable to negotiate an acceptable set of security
  parameters given the options available.
  This alert is always fatal.

bad_certificate
: A certificate was corrupt, contained signatures that did not
  verify correctly, etc.

unsupported_certificate
: A certificate was of an unsupported type.

certificate_revoked
: A certificate was revoked by its signer.

certificate_expired
: A certificate has expired or is not currently valid.

certificate_unknown
: Some other (unspecified) issue arose in processing the
  certificate, rendering it unacceptable.

illegal_parameter
: A field in the handshake was out of range or inconsistent with
  other fields.  This alert is always fatal.

unknown_ca
: A valid certificate chain or partial chain was received, but the
  certificate was not accepted because the CA certificate could not
  be located or couldn't be matched with a known, trusted CA.  This
  alert is always fatal.

access_denied
: A valid certificate or PSK was received, but when access control was
  applied, the sender decided not to proceed with negotiation.  This
  alert is always fatal.

decode_error
: A message could not be decoded because some field was out of the
  specified range or the length of the message was incorrect.  This
  alert is always fatal and should never be observed in
  communication between proper implementations (except when messages
  were corrupted in the network).

decrypt_error
: A handshake cryptographic operation failed, including being unable
  to correctly verify a signature or validate a Finished message.
  This alert is always fatal.

protocol_version
: The protocol version the peer has attempted to negotiate is
  recognized but not supported.  (For example, old protocol versions
  might be avoided for security reasons.)  This alert is always
  fatal.

insufficient_security
: Returned instead of "handshake_failure" when a negotiation has
  failed specifically because the server requires ciphers more
  secure than those supported by the client.  This alert is always
  fatal.

internal_error
: An internal error unrelated to the peer or the correctness of the
  protocol (such as a memory allocation failure) makes it impossible
  to continue.  This alert is always fatal.

inappropriate_fallback
: Sent by a server in response to an invalid connection retry attempt
  from a client. (see [RFC7507]) This alert is always fatal.

missing_extension
: Sent by endpoints that receive a hello message not containing an
  extension that is mandatory to send for the offered TLS version.
  This message is always fatal.
[[TODO: IANA Considerations.]]

unsupported_extension
: Sent by endpoints receiving any hello message containing an extension
  known to be prohibited for inclusion in the given hello message, including
  any extensions in a ServerHello not first offered in the corresponding
  ClientHello. This alert is always fatal.

certificate_unobtainable
: Sent by servers when unable to obtain a certificate from a URL
  provided by the client via the "client_certificate_url" extension
  [RFC6066].

unrecognized_name
: Sent by servers when no server exists identified by the name
  provided by the client via the "server_name" extension
  [RFC6066].

bad_certificate_status_response
: Sent by clients when an invalid or unacceptable OCSP response is
  provided by the server via the "status_request" extension
  [RFC6066]. This alert is always fatal.

bad_certificate_hash_value
: Sent by servers when a retrieved object does not have the correct hash
  provided by the client via the "client_certificate_url" extension
  [RFC6066]. This alert is always fatal.

unknown_psk_identity
: Sent by servers when a PSK cipher suite is selected but no
 acceptable PSK identity is provided by the client. Sending this alert
 is OPTIONAL; servers MAY instead choose to send a "decrypt_error"
 alert to merely indicate an invalid PSK identity.
{:br }

New Alert values are assigned by IANA as described in {{iana-considerations}}.


##  TLS Handshake Protocol Overview {#handshake-protocol-overview}

The cryptographic parameters of the session state are produced by the
TLS Handshake Protocol, which operates on top of the TLS record
layer. When a TLS client and server first start communicating, they
agree on a protocol version, select cryptographic algorithms,
optionally authenticate each other, and establish shared secret keying
material.

TLS supports three basic key exchange modes:

- Diffie-Hellman (of both the finite field and elliptic curve
  varieties).

- A pre-shared symmetric key (PSK)

- A combination of a symmetric key and Diffie-Hellman

Which mode is used depends on the negotiated cipher suite. Conceptually,
the handshake establishes three secrets which are used to derive all the
keys.


{{tls-full}} below shows the basic full TLS handshake.

~~~~
       Client                                           Server

Key  ^ ClientHello
Exch | + key_share*
     v + pre_shared_key*     -------->
                                                   ServerHello  ^ Key
                                                  + key_share*  | Exch
                                             + pre_shared_key*  v
                                         {EncryptedExtensions}  ^ Server
                                         {CertificateRequest*}  v Params
                                                {Certificate*}  ^
                                          {CertificateVerify*}  | Auth
                                                    {Finished}  v
                             <--------     [Application Data*]
     ^ {Certificate*}
Auth | {CertificateVerify*}
     v {Finished}            -------->
       [Application Data]    <------->      [Application Data]

              +  Indicates extensions sent in the
                 previously noted message.

              *  Indicates optional or situation-dependent
                 messages that are not always sent.

              {} Indicates messages protected using keys
                 derived from handshake_traffic_secret.

              [] Indicates messages protected using keys
                 derived from traffic_secret_N
~~~~
{: #tls-full title="Message flow for full TLS Handshake"}

The handshake can be thought of as having three phases, indicated
in the diagram above.

Key Exchange: establish shared keying material and select the
   cryptographic parameters. Everything after this phase is
   encrypted.

Server Parameters: establish other handshake parameters
(whether the client is authenticated, application layer protocol support, etc.)

Authentication: authenticate the server (and optionally the client)
   and provide key confirmation and handshake integrity.

In the Key Exchange phase, the client sends the ClientHello
({{client-hello}}) message, which contains a random nonce
(ClientHello.random), its offered protocol version, cipher suite, and
extensions, and in general either one or more Diffie-Hellman key shares (in the
"key_share" extension {{key-share}}), one or more pre-shared key labels (in the
"pre_shared_key" extension {{pre-shared-key-extension}}), or both.

The server processes the ClientHello and determines the appropriate
cryptographic parameters for the connection. It then responds with
its own ServerHello which indicates the negotiated connection parameters. [{{server-hello}}].
The combination of the ClientHello and the ServerHello determines
the values of ES and SS, as described above. If either a pure
(EC)DHE or (EC)DHE-PSK cipher suite is in use, then the ServerHello
will contain a "key_share" extension with the server's ephemeral
Diffie-Hellman share which MUST be in the same group.
If a pure PSK or an (EC)DHE-PSK cipher suite is negotiated, then the
ServerHello will contain a "pre_shared_key" extension indicating
which of the client's offered PSKs was selected.

The server then sends two messages to establish the Server Parameters:

EncryptedExtensions
: responses to any extensions which are not required in order to
  determine the cryptographic parameters. [{{encrypted-extensions}}]

CertificateRequest
: if certificate-based client authentication is desired, the
  desired parameters for that certificate. This message will
  be omitted if client authentication is not desired.

Finally, the client and server exchange Authentication messages. TLS
uses the same set of messages every time that authentication is needed.
Specifically:

Certificate
: the certificate of the endpoint. This message is omitted if the
  server is not authenticating with a certificate (i.e.,
  with PSK or (EC)DHE-PSK cipher suites). Note that if raw public keys
  {{RFC7250}} or the cached information extension
  {{?I-D.ietf-tls-cached-info}} are in use, then this message
  will not contain a certificate but rather some other value
  corresponding to the server's long-term key.
  [{{certificate}}]

CertificateVerify
: a signature over the entire handshake using the public key
  in the Certificate message. This message is omitted if the
  server is not authenticating via a certificate (i.e.,
  with PSK or (EC)DHE-PSK cipher suites). [{{certificate-verify}}]

Finished
: a MAC over the entire handshake. This message provides key confirmation, binds the endpoint's identity
  to the exchanged keys, and in PSK mode
  also authenticates the handshake. [{{finished}}]
{:br }

Upon receiving the server's messages, the client responds with its Authentication
messages, namely Certificate and CertificateVerify (if requested), and Finished.

At this point, the handshake is complete, and the client and server may exchange
application layer data. Application data MUST NOT be sent prior to sending the
Finished message. Note that while the server may send application data
prior to receiving the client's Authentication messages, any data sent at
that point is, of course, being sent to an unauthenticated peer.

[[TODO: Move this elsewhere?
Note that higher layers should not be overly reliant on whether TLS always
negotiates the strongest possible connection between two endpoints. There are a
number of ways in which a man-in-the-middle attacker can attempt to make two
entities drop down to the least secure method they support
(i.e., perform a downgrade attack). The TLS protocol has
been designed to minimize this risk, but there are still attacks available: for
example, an attacker could block access to the port a secure service runs on,
or attempt to get the peers to negotiate an unauthenticated connection. The
fundamental rule is that higher levels must be cognizant of what their security
requirements are and never transmit information over a channel less secure than
what they require. The TLS protocol is secure in that any cipher suite offers
its promised level of security: if you negotiate AES-GCM {{GCM}} with
a 255-bit ECDHE key exchange with a host whose certificate
chain you have verified, you can expect that to be reasonably "secure"
against algorithmic attacks, at least in the year 2015.]]

### Incorrect DHE Share

If the client has not provided an appropriate "key_share" extension (e.g. it
includes only DHE or ECDHE groups unacceptable or unsupported by the
server), the server corrects the mismatch with a HelloRetryRequest and
the client will need to restart the handshake with an appropriate
"key_share" extension, as shown in Figure 2.
If no common cryptographic parameters can be negotiated,
the server will send a "handshake_failure" or "insufficient_security"
fatal alert (see {{alert-protocol}}).

~~~~
         Client                                               Server

         ClientHello
           + key_share             -------->
                                   <--------       HelloRetryRequest

         ClientHello
           + key_share             -------->
                                                         ServerHello
                                                         + key_share
                                               {EncryptedExtensions}
                                               {CertificateRequest*}
                                                      {Certificate*}
                                                {CertificateVerify*}
                                                          {Finished}
                                   <--------     [Application Data*]
         {Certificate*}
         {CertificateVerify*}
         {Finished}                -------->
         [Application Data]        <------->     [Application Data]
~~~~
{: #tls-restart title="Message flow for a full handshake with mismatched parameters"}

Note: the handshake transcript includes the initial
ClientHello/HelloRetryRequest exchange. It is not reset with the new
ClientHello.

TLS also allows several optimized variants of the basic handshake, as
described below.

### Resumption and Pre-Shared Key (PSK) {#resumption-and-psk}

Although TLS PSKs can be established out of band,
PSKs can also be established in a previous session and
then reused ("session resumption"). Once a handshake has completed, the server can
send the client a PSK identity which corresponds to a key derived from
the initial handshake (See {{new-session-ticket-message}}). The client
can then use that PSK identity in future handshakes to negotiate use
of the PSK; if the server accepts it, then the security context of the
original connection is tied to the new connection. In TLS 1.2 and
below, this functionality was provided by "session resumption" and
"session tickets" {{RFC5077}}. Both mechanisms are obsoleted in TLS
1.3.

PSK cipher suites can either use PSK in combination with
an (EC)DHE exchange in order to provide forward secrecy in combination
with shared keys, or can use PSKs alone, at the cost of losing forward
secrecy.

{{tls-resumption-psk}} shows a pair of handshakes in which the first establishes
a PSK and the second uses it:

~~~~
       Client                                               Server

Initial Handshake:
       ClientHello
        + key_share              -------->
                                                       ServerHello
                                                       + key_share
                                             {EncryptedExtensions}
                                             {CertificateRequest*}
                                                    {Certificate*}
                                              {CertificateVerify*}
                                                        {Finished}
                                 <--------     [Application Data*]
       {Certificate*}
       {CertificateVerify*}
       {Finished}                -------->
                                 <--------      [NewSessionTicket]
       [Application Data]        <------->      [Application Data]


Subsequent Handshake:
       ClientHello
         + pre_shared_key
         + key_share*            -------->
                                                       ServerHello
                                                  + pre_shared_key
                                                      + key_share*
                                             {EncryptedExtensions}
                                                        {Finished}
                                 <--------     [Application Data*]
       {Finished}                -------->
       [Application Data]        <------->      [Application Data]
~~~~
{: #tls-resumption-psk title="Message flow for resumption and PSK"}

As the server is authenticating via a PSK, it does not send a
Certificate or a CertificateVerify. When a client offers resumption
via PSK it SHOULD also supply a "key_share" extension to the server as well; this
allows server to decline resumption and fall back to a full handshake.
A "key_share" extension MUST also be sent if the client is attempting to
negotiate an (EC)DHE-PSK cipher suite.


### Zero-RTT Data

When resuming via a PSK with an appropriate ticket (i.e., one with
the "allow_early_data" flag), clients can also send data on their first
flight ("early data"). This data is encrypted solely under keys
derived using the PSK as the static secret.  As shown in
{{tls-0-rtt}}, the Zero-RTT data is just added to the 1-RTT handshake
in the first flight, the rest of the handshake uses the same messages.

~~~~
         Client                                               Server

         ClientHello
           + early_data
           + pre_shared_key
           + key_share*
         (EncryptedExtensions)
         (Finished)
         (Application Data*)
         (end_of_early_data)        -------->
                                                         ServerHello
                                                        + early_data
                                                    + pre_shared_key
                                                        + key_share*
                                               {EncryptedExtensions}
                                               {CertificateRequest*}
                                                          {Finished}
                                   <--------     [Application Data*]
         {Certificate*}
         {CertificateVerify*}
         {Finished}                -------->

         [Application Data]        <------->      [Application Data]

               *  Indicates optional or situation-dependent
                  messages that are not always sent.

               () Indicates messages protected using keys
                  derived from early_traffic_secret.

               {} Indicates messages protected using keys
                  derived from handshake_traffic_secret.

               [] Indicates messages protected using keys
                  derived from traffic_secret_N
~~~~
{: #tls-0-rtt title="Message flow for a zero round trip handshake"}

[[OPEN ISSUE: Should it be possible to combine 0-RTT with the
server authenticating via a signature
https://github.com/tlswg/tls13-spec/issues/443]]


IMPORTANT NOTE: The security properties for 0-RTT data (regardless of
the cipher suite) are weaker than those for other kinds of TLS data.
Specifically:

1. This data is not forward secret, because it is encrypted solely
with the PSK.

2. There are no guarantees of non-replay between connections.
Unless the server takes special measures outside those provided by TLS (See
{{replay-time}}), the server has no guarantee that the same
0-RTT data was not transmitted on multiple 0-RTT connections.
This is especially relevant if the data is authenticated either
with TLS client authentication or inside the application layer
protocol. However, 0-RTT data cannot be duplicated within a connection (i.e., the server
will not process the same data twice for the same connection) and
an attacker will not be able to make 0-RTT data appear to be
1-RTT data (because it is protected with different keys.)

The contents and significance of each message will be presented in detail in
the following sections.


##  Handshake Protocol

The TLS Handshake Protocol is one of the defined higher-level clients of the
TLS Record Protocol. This protocol is used to negotiate the secure attributes
of a session. Handshake messages are supplied to the TLS record layer, where
they are encapsulated within one or more TLSPlaintext or TLSCiphertext structures, which are
processed and transmitted as specified by the current active session state.

%%% Handshake Protocol
       enum {
           hello_request_RESERVED(0),
           client_hello(1),
           server_hello(2),
           new_session_ticket(4),
           hello_retry_request(6),
           encrypted_extensions(8),
           certificate(11),
           server_key_exchange_RESERVED(12),
           certificate_request(13),
           server_hello_done_RESERVED(14),
           certificate_verify(15),
           client_key_exchange_RESERVED(16),
           finished(20),
           key_update(24),
           (255)
       } HandshakeType;

       struct {
           HandshakeType msg_type;    /* handshake type */
           uint24 length;             /* bytes in message */
           select (HandshakeType) {
               case client_hello:          ClientHello;
               case server_hello:          ServerHello;
               case hello_retry_request:   HelloRetryRequest;
               case encrypted_extensions:  EncryptedExtensions;
               case certificate_request:   CertificateRequest;
               case certificate:           Certificate;
               case certificate_verify:    CertificateVerify;
               case finished:              Finished;
               case new_session_ticket:    NewSessionTicket;
               case key_update:            KeyUpdate;
           } body;
       } Handshake;

The TLS Handshake Protocol messages are presented below in the order they
MUST be sent; sending handshake messages in an unexpected order
results in an "unexpected_message" fatal error. Unneeded handshake
messages can be omitted, however.

New handshake message types are assigned by IANA as described in
{{iana-considerations}}.

### Key Exchange Messages

The key exchange messages are used to exchange security capabilities
between the client and server and to establish the traffic keys used to protect
the handshake and the data.

####  Client Hello

When this message will be sent:

> When a client first connects to a server, it is required to send the
ClientHello as its first message. The client will also send a
ClientHello when the server has responded to its ClientHello with a
ServerHello that selects cryptographic parameters that don't match the
client's "key_share" extension. In that case, the client MUST send the same
ClientHello (without modification) except including a new KeyShareEntry
as the lowest priority share (i.e., appended to the list of shares in
the "key_share" extension). If a server receives a ClientHello at any other time, it MUST send
a fatal "unexpected_message" alert and close the connection.

Structure of this message:

> The ClientHello message includes a random structure, which is used later in
the protocol.

%%% Key Exchange Messages

The cipher suite list, passed from the client to the server in the ClientHello
message, contains the combinations of cryptographic algorithms supported by the
client in order of the client's preference (favorite choice first). Each cipher
suite defines a key exchange algorithm, a record protection algorithm (including
secret key length) and a hash to be used with HKDF. The server will select a cipher
suite or, if no acceptable choices are presented, return a "handshake_failure"
alert and close the connection. If the list contains cipher suites the server
does not recognize, support, or wish to use, the server MUST ignore those
cipher suites, and process the remaining ones as usual.

%%% Key Exchange Messages
       struct {
           opaque random_bytes[32];
       } Random;

       uint8 CipherSuite[2];    /* Cryptographic suite selector */

       struct {
           ProtocolVersion client_version = { 3, 4 };    /* TLS v1.3 */
           Random random;
           opaque legacy_session_id<0..32>;
           CipherSuite cipher_suites<2..2^16-2>;
           opaque legacy_compression_methods<1..2^8-1>;
           Extension extensions<0..2^16-1>;
       } ClientHello;

TLS allows extensions to follow the compression_methods field in an extensions
block. The presence of extensions can be detected by determining whether there
are bytes following the compression_methods at the end of the ClientHello. Note
that this method of detecting optional data differs from the normal TLS method
of having a variable-length field, but it is used for compatibility with TLS
before extensions were defined.
As of TLS 1.3, all clients and servers will send at least
one extension (at least "key_share" or "pre_shared_key").

client_version
: The version of the TLS protocol by which the client wishes to
  communicate during this session.  This SHOULD be the latest
  (highest valued) version supported by the client.  For this
  version of the specification, the version will be { 3, 4 }. (See
  {{backward-compatibility}} for details about backward compatibility.)

random
: 32 bytes generated by a secure random number generator.
  See {{implementation-notes}} for additional information.

legacy_session_id
: Versions of TLS before TLS 1.3 supported a session resumption
  feature which has been merged with Pre-Shared Keys in this version
  (see {{resumption-and-psk}}).
  This field MUST be ignored by a server negotiating TLS 1.3 and
  SHOULD be set as a zero length vector (i.e., a single zero byte
  length field) by clients which do not have a cached session ID
  set by a pre-TLS 1.3 server.

cipher_suites
: This is a list of the cryptographic options supported by the
  client, with the client's first preference first.
  Values are defined in {{cipher-suites}}.

legacy_compression_methods
: Versions of TLS before 1.3 supported compression and the list of
  compression methods was supplied in this field. For any TLS 1.3
  ClientHello, this vector MUST contain exactly one byte set to
  zero, which corresponds to the "null" compression method in
  prior versions of TLS. If a TLS 1.3 ClientHello is
  received with any other value in this field, the server MUST
  generate a fatal "illegal_parameter" alert. Note that TLS 1.3
  servers might receive TLS 1.2 or prior ClientHellos which contain
  other compression methods and MUST follow the procedures for
  the appropriate prior version of TLS.

extensions
: Clients request extended functionality from servers by sending
  data in the extensions field.  The actual "Extension" format is
  defined in {{hello-extensions}}.
{:br }

In the event that a client requests additional functionality using
extensions, and this functionality is not supplied by the server, the
client MAY abort the handshake. Note: TLS 1.3 ClientHello messages
MUST always contain extensions, and a TLS 1.3 server MUST respond to
any TLS 1.3 ClientHello without extensions with a fatal "decode_error"
alert. TLS 1.3 servers may receive TLS 1.2 ClientHello messages
without extensions. If negotiating TLS 1.2, a server MUST check that
the amount of data in the message precisely matches one of these
formats; if not, then it MUST send a fatal "decode_error" alert.

After sending the ClientHello message, the client waits for a ServerHello
or HelloRetryRequest message.

####  Server Hello {#server-hello}

When this message will be sent:

> The server will send this message in response to a ClientHello message when
it was able to find an acceptable set of algorithms and the client's
"key_share" extension was acceptable. If the client proposed groups are not
acceptable by the server, it will respond with a "handshake_failure" fatal alert.

Structure of this message:

%%% Key Exchange Messages
       struct {
           ProtocolVersion server_version;
           Random random;
           CipherSuite cipher_suite;
           Extension extensions<0..2^16-1>;
       } ServerHello;

In prior versions of TLS, the extensions field could be omitted entirely
if not needed, similar to ClientHello.
As of TLS 1.3, all clients and servers will send at least
one extension (at least "key_share" or "pre_shared_key").

server_version
: This field will contain the lower of that suggested by the client
  in the ClientHello and the highest supported by the server.  For
  this version of the specification, the version is { 3, 4 }.  (See
  {{backward-compatibility}} for details about backward compatibility.)

random
: This structure is generated by the server and MUST be
  generated independently of the ClientHello.random.

cipher_suite
: The single cipher suite selected by the server from the list in
  ClientHello.cipher_suites.  For resumed sessions, this field is
  the value from the state of the session being resumed.
  [[TODO: interaction with PSK.]]

extensions
: A list of extensions.  Note that only extensions offered by the
  client can appear in the server's list. In TLS 1.3 as opposed to
  previous versions of TLS, the server's extensions are split between
  the ServerHello and the EncryptedExtensions {{encrypted-extensions}}
  message. The ServerHello MUST only include extensions which are
  required to establish the cryptographic context. Currently the only
  such extensions are "key_share", "pre_shared_key", and "early_data".
  Clients MUST check the ServerHello for the presence of any forbidden
  extensions and if any are found MUST terminate the handshake with a
  "illegal_parameter" alert.
{:br }

TLS 1.3 server implementations which respond to a ClientHello with a
client_version indicating TLS 1.2 or below MUST set the first eight
bytes of their Random value to the bytes:

      44 4F 57 4E 47 52 44 01

TLS 1.2 server implementations which respond to a ClientHello with a
client_version indicating TLS 1.1 or below SHOULD set the first eight
bytes of their Random value to the bytes:

      44 4F 57 4E 47 52 44 00


TLS 1.3 clients receiving a TLS 1.2 or below ServerHello MUST check
that the top eight octets are not equal to either of these values. TLS
1.2 clients SHOULD also perform this check if the ServerHello
indicates TLS 1.1 or below. If a match is found, the client MUST abort
the handshake with a fatal "illegal_parameter" alert. This mechanism
provides limited protection against downgrade attacks over and above
that provided by the Finished exchange: because the ServerKeyExchange
includes a signature over both random values, it is not possible for
an active attacker to modify the randoms without detection as long as
ephemeral ciphers are used. It does not provide downgrade protection
when static RSA is used.

Note: This is an update to TLS 1.2 so in practice many TLS 1.2 clients
and servers will not behave as specified above.

Note: Versions of TLS prior to TLS 1.3 used the top 32 bits of
the Random value to encode the time since the UNIX epoch. The
sentinel value above was selected to avoid conflicting with any
valid TLS 1.2 Random value and to have a low (2^{-64})
probability of colliding with randomly selected Random
values.


####  Hello Retry Request {#hello-retry-request}

When this message will be sent:

> Servers send this message in response to a ClientHello
message when it was able to find an acceptable set of algorithms and
groups that are mutually supported, but
the client's KeyShare did not contain an acceptable
offer. If it cannot find such a match, it will respond with a
fatal "handshake_failure" alert.

Structure of this message:

%%% Key Exchange Messages
       struct {
           ProtocolVersion server_version;
           CipherSuite cipher_suite;
           NamedGroup selected_group;
           Extension extensions<0..2^16-1>;
       } HelloRetryRequest;

selected_group
: The mutually supported group the server intends to negotiate and
  is requesting a retried ClientHello/KeyShare for.
{:br }

The server_version, cipher_suite, and extensions fields have the
same meanings as their corresponding values in the ServerHello. The
server SHOULD send only the extensions necessary for the client to
generate a correct ClientHello pair. As with ServerHello, a
HelloRetryRequest MUST NOT contain any extensions that were not first
offered by the client in its ClientHello.

Upon receipt of a HelloRetryRequest, the client MUST first verify that
the selected_group field corresponds to a group which was provided
in the "supported_groups" extension in the original ClientHello.  It
MUST then verify that the selected_group field does not correspond
to a group which was provided in the "key_share" extension in the
original ClientHello. If either of these checks fails, then the client
MUST abort the handshake with a fatal "handshake_failure"
alert. Clients SHOULD also abort with "handshake_failure" in response
to any second HelloRetryRequest which was sent in the same connection
(i.e., where the ClientHello was itself in response to a
HelloRetryRequest).

Otherwise, the client MUST send a ClientHello with an updated KeyShare
extension to the server. The client MUST append a new KeyShareEntry
for the group indicated in the selected_group field to the groups
in its original KeyShare.

Upon re-sending the ClientHello and receiving the
server's ServerHello/KeyShare, the client MUST verify that
the selected CipherSuite and NamedGroup match that supplied in
the HelloRetryRequest. If either of these values differ, the client
MUST abort the connection with a fatal "handshake_failure" alert.

###  Hello Extensions

The extension format is:

%%% Key Exchange Messages
       struct {
           ExtensionType extension_type;
           opaque extension_data<0..2^16-1>;
       } Extension;

       enum {
           supported_groups(10),
           signature_algorithms(13),
           key_share(40),
           pre_shared_key(41),
           early_data(42),
           ticket_age(43),
           cookie(44),
           (65535)
       } ExtensionType;

Here:

-  "extension_type" identifies the particular extension type.

-  "extension_data" contains information specific to the particular
  extension type.

The initial set of extensions is defined in {{RFC6066}}.
The list of extension types is maintained by IANA as described in
{{iana-considerations}}.

An extension type MUST NOT appear in the ServerHello or HelloRetryRequest
unless the same extension type appeared in the corresponding ClientHello.
If a client receives an extension type in ServerHello or HelloRetryRequest
that it did not request in the associated ClientHello, it MUST abort the
handshake with an "unsupported_extension" fatal alert.

Nonetheless, "server-oriented" extensions may be provided in the future within
this framework. Such an extension (say, of type x) would require the client to
first send an extension of type x in a ClientHello with empty extension_data to
indicate that it supports the extension type. In this case, the client is
offering the capability to understand the extension type, and the server is
taking the client up on its offer.

When multiple extensions of different types are present in the ClientHello or
ServerHello messages, the extensions MAY appear in any order. There MUST NOT be
more than one extension of the same type.

Finally, note that extensions can be sent both when starting a new session and
when requesting session resumption or 0-RTT mode. Indeed, a client that requests session
resumption does not in general know whether the server will accept this
request, and therefore it SHOULD send the same extensions as it would send if
it were not attempting resumption.

In general, the specification of each extension type needs to describe the
effect of the extension both during full handshake and session resumption. Most
current TLS extensions are relevant only when a session is initiated: when an
older session is resumed, the server does not process these extensions in
ClientHello, and does not include them in ServerHello. However, some
extensions may specify different behavior during session resumption.
[[TODO: update this and the previous paragraph to cover PSK-based resumption.]]

There are subtle (and not so subtle) interactions that may occur in this
protocol between new features and existing features which may result in a
significant reduction in overall security. The following considerations should
be taken into account when designing new extensions:

- Some cases where a server does not agree to an extension are error
  conditions, and some are simply refusals to support particular features. In
  general, error alerts should be used for the former, and a field in the
  server extension response for the latter.

- Extensions should, as far as possible, be designed to prevent any attack that
  forces use (or non-use) of a particular feature by manipulation of handshake
  messages. This principle should be followed regardless of whether the feature
  is believed to cause a security problem.
  Often the fact that the extension fields are included in the inputs to the
  Finished message hashes will be sufficient, but extreme care is needed when
  the extension changes the meaning of messages sent in the handshake phase.
  Designers and implementors should be aware of the fact that until the
  handshake has been authenticated, active attackers can modify messages and
  insert, remove, or replace extensions.

- It would be technically possible to use extensions to change major aspects
  of the design of TLS; for example, the design of cipher suite negotiation.
  This is not recommended; it would be more appropriate to define a new version
  of TLS --- particularly since the TLS handshake algorithms have specific
  protection against version rollback attacks based on the version number, and
  the possibility of version rollback should be a significant consideration in
  any major design change.


####  Cookie {#cookie}

%%% Cookie Extension
       struct {
           opaque cookie<0..2^16-1>;
       } Cookie;

Cookies serve two primary purposes:

- Allowing the server to force the client to demonstrate reachability
  at their apparent network address (thus providing a measure of DoS
  protection). This is primarily useful for non-connection-oriented
  transports (see {{dtls}}).

- Allowing the server to offload state to the client, thus allowing it to send
  a HelloRetryRequest without storing any state. The server does this by
  pickling that post-ClientHello hash state into the cookie (protected
  with some suitable integrity algorithm).

When sending a HelloRetryRequest, the server MAY provide a "cookie" extension to the
client (this is an exception to the usual rule that the only extensions that
may be sent are those that appear in the ClientHello). When sending the
new ClientHello, the client MUST echo the value of the extension.
Clients MUST NOT use cookies in subsequent connections.


####  Signature Algorithms

The client uses the "signature_algorithms" extension to indicate to the server
which signature algorithms may be used in digital signatures.

Clients which offer one or more cipher suites which use certificate authentication
(i.e., any non-PSK cipher suite) MUST send the "signature_algorithms" extension.
If this extension is not provided and no alternative cipher suite is available,
the server MUST close the connection with a fatal "missing_extension" alert.
(see {{mti-extensions}})

The "extension_data" field of this extension contains a
"supported_signature_algorithms" value:

%%% Signature Algorithm Extension
       enum {
           /* RSASSA-PKCS-v1_5 algorithms */
           rsa_pkcs1_sha1 (0x0201),
           rsa_pkcs1_sha256 (0x0401),
           rsa_pkcs1_sha384 (0x0501),
           rsa_pkcs1_sha512 (0x0601),

           /* ECDSA algorithms */
           ecdsa_secp256r1_sha256 (0x0403),
           ecdsa_secp384r1_sha384 (0x0503),
           ecdsa_secp521r1_sha512 (0x0603),

           /* RSASSA-PSS algorithms */
           rsa_pss_sha256 (0x0700),
           rsa_pss_sha384 (0x0701),
           rsa_pss_sha512 (0x0702),

           /* EdDSA algorithms */
           ed25519 (0x0703),
           ed448 (0x0704),

           /* Reserved Code Points */
           dsa_sha1_RESERVED (0x0202),
           dsa_sha256_RESERVED (0x0402),
           dsa_sha384_RESERVED (0x0502),
           dsa_sha512_RESERVED (0x0602),
           obsolete_RESERVED (0x0000..0x0200),
           obsolete_RESERVED (0x0203..0x0400),
           obsolete_RESERVED (0x0404..0x0500),
           obsolete_RESERVED (0x0504..0x0600),
           obsolete_RESERVED (0x0604..0x06FF),
           private_use (0xFE00..0xFFFF),
           (0xFFFF)
       } SignatureScheme;

       SignatureScheme supported_signature_algorithms<2..2^16-2>;

Note: This production is named "SignatureScheme" because there is already
a SignatureAlgorithm type in TLS 1.2. We use the term "signature algorithm"
throughout the text.

Each SignatureScheme value lists a single signature algorithm that the
client is willing to verify. The values are indicated in descending order
of preference. Note that a signature algorithm takes as input an
arbitrary-length message, rather than a digest. Algorithms which
traditionally act on a digest should be defined in TLS to first
hash the input with a specified hash function and then proceed as usual.
The code point groups listed above have the following meanings:

RSASSA-PKCS-v1_5 algorithms
: Indicates a signature algorithm using RSASSA-PKCS1-v1_5 {{RFC3447}}
  with the corresponding hash algorithm as defined in {{SHS}}. These values
  refer solely to signatures which appear in certificates (see
  {{server-certificate-selection}}) and are not defined for use in signed
  TLS handshake messages (see {{digital-signing}}).

ECDSA algorithms
: Indicates a signature algorithm using ECDSA {{ECDSA}}, the corresponding
  curve as defined in ANSI X9.62 {{X962}} and FIPS 186-4 {{DSS}}, and the
  corresponding hash algorithm as defined in {{SHS}}. The signature is
  represented as a DER-encoded {{X690}} ECDSA-Sig-Value structure.

RSASSA-PSS algorithms
: Indicates a signature algorithm using RSASSA-PSS {{RFC3447}} with
  MGF1. The digest used in the mask generation function and the digest
  being signed are both the corresponding hash algorithm as defined in
  {{SHS}}. When used in signed TLS handshake messages (see
  {{digital-signing}}), the length of the salt MUST be equal to the length
  of the digest output.

EdDSA algorithms
: Indicates a signature algorithm using EdDSA as defined in
  {{I-D.irtf-cfrg-eddsa}} or its successors. Note that these correspond to
  the "PureEdDSA" algorithms and not the "prehash" variants.
{:br }

The semantics of this extension are somewhat complicated because the cipher
suite adds additional constraints on signature algorithms.
{{server-certificate-selection}} describes the appropriate rules.

rsa_pkcs1_sha1 and dsa_sha1 SHOULD NOT be offered. Clients offering these
values for backwards compatibility MUST list them as the lowest priority
(listed after all other algorithms in the supported_signature_algorithms
vector). TLS 1.3 servers MUST NOT offer a SHA-1 signed certificate unless no
valid certificate chain can be produced without it (see
{{server-certificate-selection}}).

The signatures on certificates that are self-signed or certificates that are
trust anchors are not validated since they begin a certification path (see
{{RFC5280}}, Section 3.2).  A certificate that begins a certification
path MAY use a signature algorithm that is not advertised as being supported
in the "signature_algorithms" extension.

Note that TLS 1.2 defines this extension differently. TLS 1.3 implementations
willing to negotiate TLS 1.2 MUST behave in accordance with the requirements of
{{RFC5246}} when negotiating that version. In particular:

* TLS 1.2 ClientHellos may omit this extension.

* In TLS 1.2, the extension contained hash/signature pairs. The pairs are
  encoded in two octets, so SignatureScheme values have been allocated to
  align with TLS 1.2's encoding. Some legacy pairs are left unallocated. These
  algorithms are deprecated as of TLS 1.3. They MUST NOT be offered or
  negotiated by any implementation. In particular, MD5 {{SLOTH}} and SHA-224
  MUST NOT be used.

* ecdsa_secp256r1_sha256, etc., align with TLS 1.2's ECDSA hash/signature pairs.
  However, the old semantics did not constrain the signing curve.

#### Negotiated Groups

When sent by the client, the "supported_groups" extension indicates
the named groups which the client supports, ordered from most preferred
to least preferred.

Note: In versions of TLS prior to TLS 1.3, this extension was named
"elliptic_curves" and only contained elliptic curve groups. See {{RFC4492}} and
{{I-D.ietf-tls-negotiated-ff-dhe}}. This extension was also used to negotiate
ECDSA curves. Signature algorithms are now negotiated independently (see
{{signature-algorithms}}).

Clients which offer one or more (EC)DHE cipher suites MUST send at least one
supported NamedGroup value and servers MUST NOT negotiate any of these
cipher suites unless a supported value was provided.
If this extension is not provided and no alternative cipher suite is available,
the server MUST close the connection with a fatal "missing_extension" alert.
(see {{mti-extensions}})
If the extension is provided, but no compatible group is offered, the
server MUST NOT negotiate a cipher suite of the relevant type. For
instance, if a client supplies only ECDHE groups, the server MUST NOT
negotiate finite field Diffie-Hellman. If no acceptable group can be
selected across all cipher suites, then the server MUST generate a
fatal "handshake_failure" alert.

The "extension_data" field of this extension contains a
"NamedGroupList" value:

%%% Named Group Extension
       enum {
           /* Elliptic Curve Groups (ECDHE) */
           obsolete_RESERVED (1..22),
           secp256r1 (23), secp384r1 (24), secp521r1 (25),
           obsolete_RESERVED (26..28),
           x25519 (29), x448 (30),

           /* Finite Field Groups (DHE) */
           ffdhe2048 (256), ffdhe3072 (257), ffdhe4096 (258),
           ffdhe6144 (259), ffdhe8192 (260),

           /* Reserved Code Points */
           ffdhe_private_use (0x01FC..0x01FF),
           ecdhe_private_use (0xFE00..0xFEFF),
           obsolete_RESERVED (0xFF01..0xFF02),
           (0xFFFF)
       } NamedGroup;

       struct {
           NamedGroup named_group_list<1..2^16-1>;
       } NamedGroupList;

Elliptic Curve Groups (ECDHE)
: Indicates support of the corresponding named curve.
  Note that some curves are also recommended in ANSI
  X9.62 {{X962}} and FIPS 186-4 {{DSS}}. Others are recommended
  in {{RFC7748}}.
  Values 0xFE00 through 0xFEFF are reserved for private use.

Finite Field Groups (DHE)
: Indicates support of the corresponding finite field
  group, defined in {{I-D.ietf-tls-negotiated-ff-dhe}}.
  Values 0x01FC through 0x01FF are reserved for private use.
{:br }

Items in named_group_list are ordered according to the client's
preferences (most preferred choice first).

As of TLS 1.3, servers are permitted to send the "supported_groups"
extension to the client.  If the server has a group it prefers to the
ones in the "key_share" extension but is still willing to accept the
ClientHello, it SHOULD send "supported_groups" to update the client's
view of its preferences.  Clients MUST NOT act upon any information
found in "supported_groups" prior to successful completion of the
handshake, but MAY use the information learned from a successfully
completed handshake to change what groups they offer to a server in
subsequent connections.


[[TODO: IANA Considerations.]]



#### Key Share

The "key_share" extension contains the endpoint's cryptographic parameters
for non-PSK key establishment methods (currently DHE or ECDHE).

Clients which offer one or more (EC)DHE cipher suites MUST send this
extension and SHOULD send at least one supported KeyShareEntry value.
Servers MUST NOT negotiate any of these cipher suites unless a supported
value was provided.
If this extension is not provided in a ServerHello or ClientHello,
and the peer is offering (EC)DHE cipher suites, then the endpoint MUST close
the connection with a fatal "missing_extension" alert.
(see {{mti-extensions}})
Clients MAY send an empty client_shares vector in order to request
group selection from the server at the cost of an additional round trip.
(see {{hello-retry-request}})

%%% Key Exchange Messages
       struct {
           NamedGroup group;
           opaque key_exchange<1..2^16-1>;
       } KeyShareEntry;

group
: The named group for the key being exchanged.
  Finite Field Diffie-Hellman {{DH}} parameters are described in
  {{ffdhe-param}}; Elliptic Curve Diffie-Hellman parameters are
  described in {{ecdhe-param}}.

key_exchange
: Key exchange information.  The contents of this field are
  determined by the specified group and its corresponding
  definition.  Endpoints MUST NOT send empty or otherwise
  invalid key_exchange values for any reason.
{:br }

The "extension_data" field of this extension contains a
"KeyShare" value:

%%% Key Exchange Messages
       struct {
           select (role) {
               case client:
                   KeyShareEntry client_shares<0..2^16-1>;

               case server:
                   KeyShareEntry server_share;
           }
       } KeyShare;

client_shares
: A list of offered KeyShareEntry values in descending order of client preference.
  This vector MAY be empty if the client is requesting a HelloRetryRequest.
  The ordering of values here SHOULD match that of the ordering of offered support
  in the "supported_groups" extension.

server_share
: A single KeyShareEntry value for the negotiated cipher suite.
{:br }

Servers offer exactly one KeyShareEntry value, which corresponds to the
key exchange used for the negotiated cipher suite.

Clients offer an arbitrary number of KeyShareEntry values, each representing
a single set of key exchange parameters. For instance, a client might
offer shares for several elliptic curves or multiple FFDHE groups.
The key_exchange values for each KeyShareEntry MUST by generated independently.
Clients MUST NOT offer multiple KeyShareEntry values for the same group
and servers receiving multiple KeyShareEntry values for the same group
MUST abort the connection with a fatal "illegal_parameter" alert.
Clients and servers MUST NOT offer or accept any KeyShareEntry values for
groups not listed in the client's "supported_groups" extension.
Servers MUST NOT offer a KeyShareEntry value for a group not offered by the
client in its corresponding KeyShare.

If the server selects an (EC)DHE cipher suite and no mutually
supported group is available between the two endpoints' KeyShare
offers, yet there is a mutually supported group that can be found via
the "supported_groups" extension, then the server MUST reply with a
HelloRetryRequest.  If there is no mutually supported group at all,
the server MUST NOT negotiate an (EC)DHE cipher suite.

[[TODO: Recommendation about what the client offers.
Presumably which integer DH groups and which curves.]]

#####  Diffie-Hellman Parameters {#ffdhe-param}

Diffie-Hellman {{DH}} parameters for both clients and servers are encoded in
the opaque key_exchange field of a KeyShareEntry in a KeyShare structure.
The opaque value contains the
Diffie-Hellman public value (Y = g^X mod p),
encoded as a big-endian integer, padded with zeros to the size of p.

Note: For a given Diffie-Hellman group, the padding results in all public keys
having the same length.

##### ECDHE Parameters {#ecdhe-param}

ECDHE parameters for both clients and servers are encoded in the
the opaque key_exchange field of a KeyShareEntry in a KeyShare structure.

For secp256r1, secp384r1 and secp521r1, the contents are the byte string
representation of an elliptic curve public value following the conversion
routine in Section 4.3.6 of ANSI X9.62 {{X962}}.

Although X9.62 supports multiple point formats, any given curve
MUST specify only a single point format. All curves currently
specified in this document MUST only be used with the uncompressed
point format (the format for all ECDH functions is considered
uncompressed).

For x25519 and x448, the contents are the byte string inputs and outputs of the
corresponding functions defined in {{RFC7748}}, 32 bytes for x25519 and 56
bytes for x448.

Note: Versions of TLS prior to 1.3 permitted point negotiation;
TLS 1.3 removes this feature in favor of a single point format
for each curve.

#### Pre-Shared Key Extension

The "pre_shared_key" extension is used to indicate the identity of the
pre-shared key to be used with a given handshake in association
with a PSK or (EC)DHE-PSK cipher suite (see {{RFC4279}} for background).

Clients which offer one or more PSK cipher suites
MUST send at least one supported psk_identity value and
servers MUST NOT negotiate any of these cipher suites unless a supported
value was provided.
If this extension is not provided and no alternative cipher suite is available,
the server MUST close the connection with a fatal "missing_extension" alert.
(see {{mti-extensions}})

The "extension_data" field of this extension contains a
"PreSharedKeyExtension" value:

%%% Key Exchange Messages

       opaque psk_identity<0..2^16-1>;

       struct {
           select (Role) {
               case client:
                   psk_identity identities<2..2^16-1>;

               case server:
                   uint16 selected_identity;
           }
       } PreSharedKeyExtension;

identities
: A list of the identities (labels for keys) that the client is willing
  to negotiate with the server.

selected_identity
: The server's chosen identity expressed as a (0-based) index into
  the identies in the client's list.
{: br}

If no suitable identity is provided, the server MUST NOT negotiate
a PSK cipher suite and MAY respond with an "unknown_psk_identity"
alert message. Sending this alert is OPTIONAL; servers MAY instead
choose to send a "decrypt_error" alert to merely indicate an
invalid PSK identity or instead negotiate use of a non-PSK cipher
suite, if available.

If the server selects a PSK cipher suite, it MUST send a
"pre_shared_key" extension with the identity that it selected.
The client MUST verify that the server's selected_identity
is within the range supplied by the client. If any other value
is returned, the client MUST generate a fatal
"unknown_psk_identity" alert and close the connection.


#### OCSP Status Extensions

{{!RFC6066}} and {{!RFC6961}} provide extensions to negotiate the server
sending OCSP responses to the client. In TLS 1.2 and below, the
server sends an empty extension to indicate negotiation of this
extension and the OCSP information is carried in a CertificateStatus
message. In TLS 1.3, the server's OCSP information is
carried in an extension in EncryptedExtensions. Specifically:
The body of the "status_request" or "status_request_v2" extension
from the server MUST be a CertificateStatus structure as defined
in {{RFC6066}} and {{RFC6961}} respectively.

Note: this means that the certificate status appears prior to the
certificates it applies to. This is slightly anomalous but matches
the existing behavior for SignedCertificateTimestamps {{?RFC6962}},
and is more easily extensible in the handshake state machine.


#### Early Data Indication

When PSK resumption is used, the client can send application data
in its first flight of messages. If the client opts to do so, it MUST
supply an "early_data" extension as well as the "pre_shared_key"
extension.

The "extension_data" field of this extension contains an
"EarlyDataIndication" value:

%%% Key Exchange Messages
       struct {
           select (Role) {
               case client:
                   opaque context<0..255>;

               case server:
                  struct {};
           }
       } EarlyDataIndication;

context
: An optional context value that can be used for anti-replay
  (see below).
{:br }

All of the parameters for the 0-RTT data (symmetric cipher suite,
ALPN, etc.) MUST be those which were negotiated in the connection
which established the PSK.  The PSK used to encrypt the early data
MUST be the first PSK listed in the client's "pre_shared_key" extension.

0-RTT messages sent in the first flight have the same content types
as their corresponding messages sent in other flights (handshake,
application_data, and alert respectively) but are protected under
different keys. After all the 0-RTT application data messages (if
any) have been sent, a "end_of_early_data" alert of type
"warning" is sent to indicate the end of the flight.
0-RTT MUST always be followed by an "end_of_early_data" alert.

A server which receives an "early_data" extension
can behave in one of two ways:

- Ignore the extension and return no response. This indicates that the
  server has ignored any early data and an ordinary 1-RTT handshake is
  required.

- Return an empty extension, indicating that it intends to
  process the early data. It is not possible for the server
  to accept only a subset of the early data messages.

[[OPEN ISSUE: are the rules below correct? https://github.com/tlswg/tls13-spec/issues/451]]
Prior to accepting the "early_data" extension, the server MUST
validate that the session ticket parameters are consistent with its
current configuration. It MUST also validate that the extensions
negotiated in the previous connection are identical to those being
negotiated in the ServerHello, with the exception of the
following extensions:

- The use of "signed_certificate_timestamp" {{!RFC6962}} MUST
  be identical but the server's SCT extension value may differ.

- The "padding" extension {{RFC7685}} MUST be ignored for this purpose.

- The values of "key_share", "pre_shared_key", and "early_data", which MUST
  be as defined in this document.

In addition, it MUST validate that the ticket_age is within a small
tolerance of the time since the ticket was issued (see {{replay-time}}).

If any of these checks fail, the server MUST NOT respond
with the extension and must discard all the remaining first
flight data (thus falling back to 1-RTT). If the client attempts
a 0-RTT handshake but the server rejects it, it will generally
not have the 0-RTT record protection keys and must instead
trial decrypt each record with the 1-RTT handshake keys
until it finds one that decrypts properly, and then pick up
the handshake from that point.

If the server chooses to accept the "early_data" extension,
then it MUST comply with the same error handling requirements
specified for all records when processing early data records.
Specifically, decryption failure of any 0-RTT record following
an accepted "early_data" extension MUST produce a fatal
"bad_record_mac" alert as per {{record-payload-protection}}.
Implementations SHOULD determine the security parameters for the
1-RTT phase of the connection entirely before processing the EncryptedExtensions
and Finished, using those values solely to determine whether to
accept or reject 0-RTT data.

[[TODO: How does the client behave if the indication is rejected.]]

##### Processing Order

Clients are permitted to "stream" 0-RTT data until they
receive the server's Finished, only then sending the "end_of_early_data"
alert. In order to avoid deadlock, when accepting "early_data",
servers MUST process the client's Finished and then immediately
send the ServerHello, rather than waiting for the client's
"end_of_early_data" alert.

##### Replay Properties {#replay-time}

As noted in {{zero-rtt-data}}, TLS provides only a limited
inter-connection mechanism for replay protection for data sent by the
client in the first flight.

The "ticket_age" extension sent by the client SHOULD be used by
servers to limit the time over which the first flight might be
replayed.  A server can store the time at which it sends a server
configuration to a client, or encode the time in a ticket.  Then, each
time it receives an early_data extension, it can check to see if the
value used by the client matches its expectations.

The "ticket_age" value provided by the client will be shorter than the
actual time elapsed on the server by a single round trip time.  This
difference is comprised of the delay in sending the NewSessionTicket
message to the client, plus the time taken to send the ClientHello to
the server.  For this reason, a server SHOULD measure the round trip
time prior to sending the NewSessionTicket message and account for
that in the value it saves.

There are several potential sources of error that make an exact
measurement of time difficult.  Variations in client and server clocks
are likely to be minimal, outside of gross time corrections.  Network
propagation delays are most likely causes of a mismatch in legitimate
values for elapsed time.  Both the NewSessionTicket and ClientHello
messages might be retransmitted and therefore delayed, which might be
hidden by TCP.

A small allowance for errors in clocks and variations in measurements
is advisable.  However, any allowance also increases the opportunity
for replay.  In this case, it is better to reject early data than to
risk greater exposure to replay attacks.

#### Ticket Age

%%% Key Exchange Messages
       struct {
           uint32 ticket_age;
       } TicketAge;

When the client sends the "early_data" extension, it MUST also send
a "ticket_age" extension in its EncryptedExtensions block. This value
contains the time elapsed since the client learned about the server
configuration that it is using, in milliseconds.  This value can
be used by the server to limit the time over which early data can
be replayed. Note: because ticket lifetimes are restricted to a week,
32 bits is enough to represent any plausible age, even in milliseconds.


### Server Parameters

####  Encrypted Extensions {#encrypted-extensions}

When this message will be sent:

> In all handshakes, the server MUST send the
EncryptedExtensions message immediately after the
ServerHello message. This is the first message that is encrypted
under keys derived from handshake_traffic_secret. If the client indicates "early_data"
in its ClientHello, it MUST also send EncryptedExtensions immediately
following the ClientHello and immediately prior to the Finished.

Meaning of this message:

> The EncryptedExtensions message contains any extensions
which should be protected, i.e., any which are not needed to
establish the cryptographic context.

The same extension types MUST NOT appear in both the ServerHello and
EncryptedExtensions.  If the same extension appears in both locations,
the client MUST rely only on the value in the EncryptedExtensions
block.  All server-sent extensions other than those explicitly listed
in {{server-hello}} or designated in the IANA registry MUST only
appear in EncryptedExtensions. Extensions which are designated to
appear in ServerHello MUST NOT appear in EncryptedExtensions. Clients
MUST check EncryptedExtensions for the presence of any forbidden
extensions and if any are found MUST terminate the handshake with an
"illegal_parameter" alert.

The client's EncryptedExtensions apply only to the early data
with which they appear. Servers MUST NOT use them to negotiate
the rest of the handshake. Only those extensions explicitly
designated as being included in 0-RTT Encrypted Extensions
in the IANA registry can be sent in the client's EncryptedExtensions.

Structure of this message:

%%% Server Parameters Messages
       struct {
           Extension extensions<0..2^16-1>;
       } EncryptedExtensions;

extensions
: A list of extensions.
{:br }

####  Certificate Request {#certificate-request}

When this message will be sent:

> A non-anonymous server can optionally request a certificate from the client,
if appropriate for the selected cipher suite. This message, if sent, will
follow EncryptedExtensions.

Structure of this message:

%%% Server Parameters Messages
       opaque DistinguishedName<1..2^16-1>;

       struct {
           opaque certificate_extension_oid<1..2^8-1>;
           opaque certificate_extension_values<0..2^16-1>;
       } CertificateExtension;

       struct {
           opaque certificate_request_context<0..2^8-1>;
           SignatureScheme
             supported_signature_algorithms<2..2^16-2>;
           DistinguishedName certificate_authorities<0..2^16-1>;
           CertificateExtension certificate_extensions<0..2^16-1>;
       } CertificateRequest;

certificate_request_context
: An opaque string which identifies the certificate request and
  which will be echoed in the client's Certificate message. The
  certificate_request_context MUST be unique within the scope
  of this connection (thus preventing replay of client
  CertificateVerify messages).

supported_signature_algorithms
: A list of the signature algorithms that the server is
  able to verify, listed in descending order of preference. Any
  certificates provided by the client MUST be signed using a
  signature algorithm found in supported_signature_algorithms.

certificate_authorities
: A list of the distinguished names {{X501}} of acceptable
  certificate_authorities, represented in DER-encoded {{X690}} format.  These
  distinguished names may specify a desired distinguished name for a
  root CA or for a subordinate CA; thus, this message can be used to
  describe known roots as well as a desired authorization space.  If
  the certificate_authorities list is empty, then the client MAY
  send any certificate that meets the rest of the selection criteria
  in the CertificateRequest, unless there is some external arrangement
  to the contrary.

certificate_extensions
: A list of certificate extension OIDs {{RFC5280}} with their allowed
  values, represented in DER-encoded {{X690}} format. Some certificate
  extension OIDs allow multiple values (e.g. Extended Key Usage).
  If the server has included a non-empty certificate_extensions list,
  the client certificate MUST contain all of the specified extension
  OIDs that the client recognizes. For each extension OID recognized
  by the client, all of the specified values MUST be present in the
  client certificate (but the certificate MAY have other values as
  well). However, the client MUST ignore and skip any unrecognized
  certificate extension OIDs. If the client has ignored some of the
  required certificate extension OIDs, and supplied a certificate
  that does not satisfy the request, the server MAY at its discretion
  either continue the session without client authentication, or
  terminate the session with a fatal unsupported_certificate alert.

  PKIX RFCs define a variety of certificate extension OIDs and their
  corresponding value types. Depending on the type, matching
  certificate extension values are not necessarily bitwise-equal. It
  is expected that TLS implementations will rely on their PKI
  libraries to perform certificate selection using certificate
  extension OIDs.

  This document defines matching rules for two standard certificate
  extensions defined in {{RFC5280}}:

  - The Key Usage extension in a certificate matches the request when
  all key usage bits asserted in the request are also asserted in the
  Key Usage certificate extension.

  - The Extended Key Usage extension in a certificate matches the
  request when all key purpose OIDs present in the request are also
  found in the Extended Key Usage certificate extension. The special
  anyExtendedKeyUsage OID MUST NOT be used in the request.

  Separate specifications may define matching rules for other certificate
  extensions.
{:br }

Note: It is a fatal "handshake_failure" alert for an anonymous server to request
client authentication.

### Authentication Messages

As discussed in {{handshake-protocol-overview}}, TLS uses a common
set of messages for authentication, key confirmation, and handshake
integrity: Certificate, CertificateVerify, and Finished. These
messages are always sent as the last messages in their handshake
flight. The Certificate and CertificateVerify messages are only
sent under certain circumstances, as defined below. The Finished
message is always sent as part of the Authentication block.

The computations for the Authentication messages all uniformly
take the following inputs:

- The certificate and signing key to be used.
- A Handshake Context based on the hash of the handshake messages
- A base key to be used to compute a MAC key.

Based on these inputs, the messages then contain:

Certificate
: The certificate to be used for authentication and any
supporting certificates in the chain. Note that certificate-based
client authentication is not available in the 0-RTT case.

CertificateVerify
: A signature over the value Hash(Handshake Context + Certificate) + Hash(resumption_context)
See {{new-session-ticket-message}} for the definition of resumption_context.

Finished
: A MAC over the value Hash(Handshake Context + Certificate + CertificateVerify) +
  Hash(resumption_context) using  a MAC key derived from the base key.
{:br}

Because the CertificateVerify signs the Handshake Context +
Certificate and the Finished MACs the Handshake Context + Certificate
+ CertificateVerify, this is mostly equivalent to keeping a running hash
of the handshake messages (exactly so in the pure 1-RTT cases). Note,
however, that subsequent post-handshake authentications do not include
each other, just the messages through the end of the main handshake.

The following table defines the Handshake Context and MAC Base Key
for each scenario:

| Mode | Handshake Context | Base Key |
|------|-------------------|----------|
| 0-RTT | ClientHello | early_traffic_secret|
| 1-RTT (Server) | ClientHello ... later of EncryptedExtensions/CertificateRequest | handshake_traffic_secret |
| 1-RTT (Client) | ClientHello ... ServerFinished     | handshake_traffic_secret |
| Post-Handshake | ClientHello ... ClientFinished + CertificateRequest | traffic_secret_0 |

Note: The Handshake Context for the last three rows does not include any 0-RTT
  handshake messages, regardless of whether 0-RTT is used.

####  Certificate {#certificate}

When this message will be sent:

> The server MUST send a Certificate message whenever the agreed-upon
key exchange method uses certificates for authentication (this
includes all key exchange methods defined in this document except PSK).

> The client MUST send a Certificate message if and only if server has
requested client authentication via a CertificateRequest message
({{certificate-request}}). If the server requests client authentication
but no suitable certificate is available, the client
MUST send a Certificate message containing no certificates (i.e., with
the "certificate_list" field having length 0).

Meaning of this message:

> This message conveys the endpoint's certificate chain to the peer.

> The certificate MUST be appropriate for the negotiated cipher suite's key
exchange algorithm and any negotiated extensions.

Structure of this message:

%%% Authentication Messages
       opaque ASN1Cert<1..2^24-1>;

       struct {
           opaque certificate_request_context<0..2^8-1>;
           ASN1Cert certificate_list<0..2^24-1>;
       } Certificate;

certificate_request_context:
: If this message is in response to a CertificateRequest, the
  value of certificate_request_context in that message. Otherwise,
  in the case of server authentication or client authentication
  in 0-RTT, this field SHALL be zero length.

certificate_list
: This is a sequence (chain) of certificates. The sender's
  certificate MUST come first in the list. Each following
  certificate SHOULD directly certify one preceding it. Because
  certificate validation requires that trust anchors be distributed
  independently, a certificate that specifies a
  trust anchor MAY be omitted from the chain, provided that
  supported peers are known to possess any omitted certificates.
{:br }

Note: Prior to TLS 1.3, "certificate_list" ordering required each certificate
to certify the one immediately preceding it,
however some implementations allowed some flexibility. Servers sometimes send
both a current and deprecated intermediate for transitional purposes, and others
are simply configured incorrectly, but these cases can nonetheless be validated
properly. For maximum compatibility, all implementations SHOULD be prepared to
handle potentially extraneous certificates and arbitrary orderings from any TLS
version, with the exception of the end-entity certificate which MUST be first.

The server's certificate list MUST always be non-empty. A client will
send an empty certificate list if it does not have an appropriate
certificate to send in response to the server's authentication
request.

##### Server Certificate Selection

The following rules apply to the certificates sent by the server:

- The certificate type MUST be X.509v3 {{RFC5280}}, unless explicitly negotiated
  otherwise (e.g., {{RFC5081}}).

- The server's end-entity certificate's public key (and associated
  restrictions) MUST be compatible with the selected key exchange
  algorithm.

| Key Exchange Alg.    | Certificate Key Type       |
|----------------------|----------------------------|
| DHE_RSA or ECDHE_RSA | RSA public key             |
| ECDHE_ECDSA          | ECDSA or EdDSA public key  |

- The certificate MUST allow the key to be used for signing (i.e., the
  digitalSignature bit MUST be set if the Key Usage extension is present) with
  a signature scheme indicated in the client's "signature_algorithms" extension.

- The "server_name" and "trusted_ca_keys" extensions {{RFC6066}} are used to
  guide certificate selection. As servers MAY require the presence of the "server_name"
  extension, clients SHOULD send this extension.

All certificates provided by the server MUST be signed by a
signature algorithm that appears in the "signature_algorithms"
extension provided by the client, if they are able to provide such
a chain (see {{signature-algorithms}}).
Certificates that are self-signed
or certificates that are expected to be trust anchors are not validated as
part of the chain and therefore MAY be signed with any algorithm.

If the server cannot produce a certificate chain that is signed only via the
indicated supported algorithms, then it SHOULD continue the handshake by sending
the client a certificate chain of its choice that may include algorithms
that are not known to be supported by the client. This fallback chain MAY
use the deprecated SHA-1 hash algorithm only if the "signature_algorithms"
extension provided by the client permits it.
If the client cannot construct an acceptable chain using the provided
certificates and decides to abort the handshake, then it MUST send an
"unsupported_certificate" alert message and close the connection.

If the server has multiple certificates, it chooses one of them based on the
above-mentioned criteria (in addition to other criteria, such as transport
layer endpoint, local configuration and preferences).

As cipher suites that specify new key exchange methods are specified for the
TLS protocol, they will imply the certificate format and the required encoded
keying information.


##### Client Certificate Selection

The following rules apply to certificates sent by the client:

In particular:

- The certificate type MUST be X.509v3 {{RFC5280}}, unless explicitly negotiated
  otherwise (e.g., {{RFC5081}}).

- If the certificate_authorities list in the certificate request
  message was non-empty, one of the certificates in the certificate
  chain SHOULD be issued by one of the listed CAs.

- The certificates MUST be signed using an acceptable hash/
  signature algorithm pair, as described in {{certificate-request}}.  Note
  that this relaxes the constraints on certificate-signing
  algorithms found in prior versions of TLS.

- If the certificate_extensions list in the certificate request message
  was non-empty, the end-entity certificate MUST match the extension OIDs
  recognized by the client, as described in {{certificate-request}}.

Note that, as with the server certificate, there are certificates that use
algorithm combinations that cannot be currently used with TLS.


##### Receiving a Certificate Message

In general, detailed certificate validation procedures are out of scope for
TLS (see {{RFC5280}}). This section provides TLS-specific requirements.

If the server supplies an empty Certificate message, the client MUST terminate
the handshake with a fatal "decode_error" alert.

If the client does not send any certificates,
the server MAY at its discretion either continue the handshake without client
authentication, or respond with a fatal "handshake_failure" alert. Also, if some
aspect of the certificate chain was unacceptable (e.g., it was not signed by a
known, trusted CA), the server MAY at its discretion either continue the
handshake (considering the client unauthenticated) or send a fatal alert.

Any endpoint receiving any certificate signed using any signature algorithm
using an MD5 hash MUST send a "bad_certificate" alert message and close
the connection.

SHA-1 is deprecated and therefore NOT RECOMMENDED.
Endpoints that reject certification paths due to use of a deprecated hash MUST send
a fatal "bad_certificate" alert message before closing the connection.
All endpoints are RECOMMENDED to transition to SHA-256 or better as soon
as possible to maintain interoperability with implementations
currently in the process of phasing out SHA-1 support.

Note that a certificate containing a key for one signature algorithm
MAY be signed using a different signature algorithm (for instance,
an RSA key signed with an ECDSA key).


####  Certificate Verify {#certificate-verify}

When this message will be sent:

> This message is used to provide explicit proof that an endpoint
possesses the private key corresponding to its certificate
and also provides integrity for the handshake up
to this point. Servers MUST send this message when using
a cipher suite which is authenticated via a certificate.
Clients MUST send this
message whenever authenticating via a Certificate (i.e., when
the Certificate message is non-empty). When sent, this message MUST appear immediately
after the Certificate Message and immediately prior to the Finished
message.

Structure of this message:

%%% Authentication Messages
       struct {
            digitally-signed struct {
               opaque hashed_data[hash_length];
            };
       } CertificateVerify;

> Where hashed_data is the hash output described in
{{authentication-messages}}, namely Hash(Handshake Context +
Certificate) + Hash(resumption_context). For concreteness, this means that the value that is
signed is:

~~~~
       padding + context_string + 00 + hashed_data
~~~~
> The context string for a server signature is "TLS 1.3, server CertificateVerify"
and for a client signature is "TLS 1.3, client CertificateVerify". A
hash of the handshake messages is signed rather than the messages themselves
because the digitally-signed format requires padding and context bytes at the
beginning of the input. Thus, by signing a digest of the messages, an
implementation only needs to maintain a single running hash per hash type for
CertificateVerify, Finished and other messages.

> If sent by a server, the signature algorithm MUST be one offered in the
client's "signature_algorithms" extension unless no valid certificate chain can be
produced without unsupported algorithms (see {{signature-algorithms}}). Note that
there is a possibility for inconsistencies here. For instance, the client might
offer ECDHE_ECDSA key exchange but omit any ECDSA and EdDSA values from its
"signature_algorithms" extension. In order to negotiate correctly, the server
MUST check any candidate cipher suites against the "signature_algorithms"
extension before selecting them. This is somewhat inelegant but is a compromise
designed to minimize changes to the original cipher suite design.

> If sent by a client, the signature algorithm used in the
signature MUST be one of those present in the
supported_signature_algorithms field of the CertificateRequest
message.

> In addition, the signature algorithm MUST be compatible with the key
in the sender's end-entity certificate. RSA signatures MUST use an
RSASSA-PSS algorithm, regardless of whether RSASSA-PKCS-v1_5 algorithms
appear in "signature_algorithms". SHA-1 MUST NOT be used in any signatures in
CertificateVerify. (Note that rsa_pkcs1_sha1 and dsa_sha1, the only defined
SHA-1 signature algorithms, are undefined for CertificateVerify signatures.)

Note: When used with non-certificate-based handshakes (e.g., PSK), the
client's signature does not cover the server's certificate directly,
although it does cover the server's Finished message, which
transitively includes the server's certificate when the PSK derives
from a certificate-authenticated handshake.  {{PSK-FINISHED}}
describes a concrete attack on this mode if the Finished is omitted
from the signature. It is unsafe to use certificate-based client
authentication when the client might potentially share the same
PSK/key-id pair with two different endpoints. In order to ensure
this, implementations MUST NOT mix certificate-based client
authentication with pure PSK modes (i.e., those where the
PSK was not derived from a previous non-PSK handshake).


####  Finished {#finished}

When this message will be sent:

> The Finished message is the final message in the authentication
block. It is essential for providing authentication of the handshake
and of the computed keys.

Meaning of this message:

> Recipients of Finished messages MUST verify that the contents are
correct. Once a side has sent its Finished message and received and
validated the Finished message from its peer, it may begin to send and
receive application data over the connection.

The key used to compute the finished message is computed from the
Base key defined in {{authentication-messages}} using HKDF (see
{{key-schedule}}). Specifically:

~~~~
client_finished_key =
    HKDF-Expand-Label(BaseKey, "client finished", "", L)

server_finished_key =
    HKDF-Expand-Label(BaseKey, "server finished", "", L)
~~~~

Structure of this message:

%%% Authentication Messages

       struct {
           opaque verify_data[verify_data_length];
       } Finished;


The verify_data value is computed as follows:

       verify_data =
           HMAC(finished_key, Hash(
                  Handshake Context + Certificate* + CertificateVerify*
               ) + Hash(resumption_context)
               )

       * Only included if present.

Where HMAC {{RFC2104}} uses the Hash algorithm for the handshake.
As noted above: the HMAC input can generally be implemented by a running
hash, i.e., just the handshake hash at this point.

In previous versions of TLS, the verify_data was always 12 octets long. In
the current version of TLS, it is the size of the HMAC output for the
Hash used for the handshake.

Note: Alerts and any other record types are not handshake messages
and are not included in the hash computations.

### Post-Handshake Messages

TLS also allows other messages to be sent after the main handshake.
These messages use a handshake content type and are encrypted under the application
traffic key.

#### New Session Ticket Message

At any time after the server has received the client Finished message, it MAY send
a NewSessionTicket message. This message creates a pre-shared key
(PSK) binding between the ticket value and the following two values derived
from the resumption master secret:

~~~~
   resumption_psk = HKDF-Expand-Label(resumption_secret,
                                      "resumption psk", "", L)

   resumption_context = HKDF-Expand-Label(resumption_secret,
                                          "resumption context", "", L)
~~~~

The client MAY use this PSK for future handshakes by including
the ticket value in the "pre_shared_key" extension in its ClientHello
({{pre-shared-key-extension}}) and supplying a suitable PSK cipher
suite. Servers may send multiple tickets on a single connection, for
instance after post-handshake authentication. For handshakes that
do not use a resumption_psk, the resumption_context is a string of
L zeroes.

%%% Ticket Establishment

     enum { (65535) } TicketExtensionType;

     struct {
         TicketExtensionType extension_type;
         opaque extension_data<0..2^16-1>;
     } TicketExtension;

     enum {
       allow_early_data(1),
       allow_dhe_resumption(2),
       allow_psk_resumption(4)
     } TicketFlags;

     struct {
         uint32 ticket_lifetime;
         uint32 flags;
         TicketExtension extensions<2..2^16-2>;
         opaque ticket<0..2^16-1>;
     } NewSessionTicket;


flags
: A 32-bit value indicating the ways in which this ticket may
  be used (as an OR of the flags values).

ticket_lifetime
: Indicates the lifetime in seconds as a 32-bit unsigned integer in
  network byte order from the time of ticket issuance.
  Servers MUST NOT use any value more than 604800 seconds (7 days).
  The value of zero indicates that the ticket should be discarded
  immediately. Clients MUST NOT cache session tickets for longer than
  7 days, regardless of the ticket_lifetime. It MAY delete the ticket
  earlier based on local policy. A server MAY treat a ticket as valid
  for a shorter period of time than what is stated in the
  ticket_lifetime.

ticket_extensions
: A placeholder for extensions in the ticket. Clients MUST ignore
  unrecognized extensions.

ticket
: The value of the ticket to be used as the PSK identifier.
The ticket itself is an opaque label. It MAY either be a database
lookup key or a self-encrypted and self-authenticated value. Section
4 of {{RFC5077}} describes a recommended ticket construction mechanism.
{:br }

The meanings of the flags are as follows:

allow_early_data
: When resuming with this ticket, the client MAY send data in its
first flight (early data) encrypted under a key derived from
this PSK.

allow_dhe_resumption
: This ticket MAY be used with (EC)DHE-PSK cipher
  suite

allow_psk_resumption
: This ticket MAY be used with a pure PSK cipher
  suite.
{:br }

In all cases, the PSK or (EC)DHE-PSK cipher suites that the client
offers/uses MUST have the same symmetric parameters (cipher/hash) as
the cipher suite negotiated for this connection. If no flags are set
that the client recognizes, it MUST ignore the ticket.


#### Post-Handshake Authentication

The server is permitted to request client authentication at any time
after the handshake has completed by sending a CertificateRequest
message. The client SHOULD respond with the appropriate Authentication
messages. If the client chooses to authenticate, it MUST send
Certificate, CertificateVerify, and Finished. If it declines, it
MUST send a Certificate message containing no certificates followed by Finished.

Note: Because client authentication may require prompting the user,
servers MUST be prepared for some delay, including receiving an
arbitrary number of other messages between sending the
CertificateRequest and receiving a response. In addition, clients which receive multiple
CertificateRequests in close succession MAY respond to them in a
different order than they were received (the
certificate_request_context value allows the server to disambiguate
the responses).


#### Key and IV Update {#key-update}

struct {} KeyUpdate;

The KeyUpdate handshake message is used to indicate that the sender is
updating its sending cryptographic keys. This message can be sent by
the server after sending its first flight and the client after sending
its second flight. Implementations that receive a KeyUpdate message
prior to receiving a Finished message as part of the 1-RTT handshake
MUST generate a fatal "unexpected_message" alert.  After sending a
KeyUpdate message, the sender SHALL send all its traffic using the
next generation of keys, computed as described in
{{updating-traffic-keys}}. Upon receiving a KeyUpdate, the receiver
MUST update their receiving keys and if they have not already updated
their sending state up to or past the then current receiving
generation MUST send their own KeyUpdate prior to sending any other
messages.  This mechanism allows either side to force an update to the
entire connection. Note that implementations may receive an arbitrary
number of messages between sending a KeyUpdate and receiving the
peer's KeyUpdate because those messages may already be in flight.

Note that if implementations independently send their own
KeyUpdates and they cross in flight, this only results in an
update of one generation; when each side receives the other
side's update it just updates its receive keys and notes that
the generations match and thus no send update is needed.

Note that the side which sends its KeyUpdate first needs to retain
the traffic keys (though not the traffic secret) for the previous
generation of keys until it receives the KeyUpdate from the other
side.

Both sender and receiver MUST encrypt their KeyUpdate
messages with the old keys. Additionally, both sides MUST enforce that
a KeyUpdate with the old key is received before accepting any messages
encrypted with the new key. Failure to do so may allow message truncation
attacks.


# The DTLS Handshake Protocol {#dtls}

DTLS 1.3 re-uses the TLS 1.3 handshake messages and flows, with
the following changes:

1. Modifications to the handshake header to handle message loss,
   reordering, and DTLS message fragmentation (in order to avoid
   IP fragmentation). Additionally, a new ACK message is introduced. 

2. Retransmission timers to handle message loss.

3. The TLS 1.3 KeyUpdate message is not used in DTLS 1.3


Note that TLS 1.3 already supports a cookie extension, which used to 
prevent denial-of-service attacks. This DoS prevention mechanism is
described in more detail below since it is more dangerous than with 
a connection-oriented transport like TCP that performs return-routability
checks as part of the connection establishment. 

With these exceptions, the DTLS message formats, flows, and logic are
   the same as those of TLS 1.3.

## Denial-of-Service Countermeasures

Datagram security protocols are extremely susceptible to a variety of
   DoS attacks.  Two attacks are of particular concern:

1. An attacker can consume excessive resources on the server by
         transmitting a series of handshake initiation requests, causing
         the server to allocate state and potentially to perform
         expensive cryptographic operations.

2. An attacker can use the server as an amplifier by sending
         connection initiation messages with a forged source of the
         victim.  The server then sends its next message (in DTLS, a
         Certificate message, which can be quite large) to the victim
         machine, thus flooding it.

   In order to counter both of these attacks, DTLS borrows the stateless
   cookie technique used by Photuris {{RFC2522}} and IKE {{RFC5996}}.  When
   the client sends its ClientHello message to the server, the server
   MAY respond with a HelloRetryRequest message.  This message contains
   a stateless cookie generated using the technique of {{RFC2522}}.  The
   client MUST retransmit the ClientHello with the cookie added.  The
   server then verifies the cookie and proceeds with the handshake only
   if it is valid.  This mechanism forces the attacker/client to be able
   to receive the cookie, which makes DoS attacks with spoofed IP
   addresses difficult.  This mechanism does not provide any defense
   against DoS attacks mounted from valid IP addresses.

   The exchange is shown in {{dtls-cookie-exchange}}. Note that 
   the figure focuses on the cookie exchange; other extensions 
   are omitted. 

~~~~
      Client                                   Server
      ------                                   ------
      ClientHello           ------>

                            <----- HelloRetryRequest
                                    + cookie

      ClientHello           ------>
       + cookie

      [Rest of handshake]
~~~~
{: #dtls-cookie-exchange title="DTLS Exchange with HelloRetryRequest contain the Cookie Extension"}

The cookie extension is defined in {{cookie}}. When sending the 
first ClientHello, the client does not have a cookie yet. In this case, 
the cookie extension is omitted and the legacy_cookie field in the ClientHello 
message SHOULD be set as a zero length vector (i.e., a single zero byte length field) 
and MUST be ignored by a server negotiating DTLS 1.3. 

   When responding to a HelloRetryRequest, the client MUST use the same
   parameter values (version, random, cipher_suites) as it 
   did in the original ClientHello.  The
   server SHOULD use those values to generate its cookie and verify that
   they are correct upon cookie receipt.  The server MUST use the same
   version number in the HelloRetryRequest that it would use when
   sending a ServerHello.  Upon receipt of the ServerHello, the client
   MUST verify that the server version values match.  In order to avoid
   sequence number duplication in case of multiple HelloRetryRequests,
   the server MUST use the record sequence number in the ClientHello as
   the record sequence number in the HelloRetryRequest.

   When the second ClientHello is received, the server can verify that
   the Cookie is valid and that the client can receive packets at the
   given IP address.  In order to avoid sequence number duplication in
   case of multiple cookie exchanges, the server MUST use the record
   sequence number in the ClientHello as the record sequence number in
   its initial ServerHello.  Subsequent ServerHellos will only be sent
   after the server has created state and MUST increment normally.

   One potential attack on this scheme is for the attacker to collect a
   number of cookies from different addresses and then reuse them to
   attack the server.  The server can defend against this attack by
   changing the Secret value frequently, thus invalidating those
   cookies.  If the server wishes that legitimate clients be able to
   handshake through the transition (e.g., they received a cookie with
   Secret 1 and then sent the second ClientHello after the server has
   changed to Secret 2), the server can have a limited window during
   which it accepts both secrets.  {{RFC5996}} suggests adding a version
   number to cookies to detect this case.  An alternative approach is
   simply to try verifying with both secrets.

   DTLS servers SHOULD perform a cookie exchange whenever a new
   handshake is being performed.  If the server is being operated in an
   environment where amplification is not a problem, the server MAY be
   configured not to perform a cookie exchange.  The default SHOULD be
   that the exchange is performed, however.  In addition, the server MAY
   choose not to do a cookie exchange when a session is resumed.
   Clients MUST be prepared to do a cookie exchange with every
   handshake.

   If HelloRetryRequest is used, the initial ClientHello and
   HelloRetryRequest are included in the calculation of the
   handshake_messages (for the CertificateVerify message) and
   verify_data (for the Finished message).

   If a server receives a ClientHello with an invalid cookie, it SHOULD
   treat it the same as a ClientHello with no cookie.  This avoids
   race/deadlock conditions if the client somehow gets a bad cookie
   (e.g., because the server changes its cookie signing key).

   Note to implementors: This may result in clients receiving multiple
   HelloRetryRequest messages with different cookies.  Clients SHOULD
   handle this by sending a new ClientHello with a cookie in response to
   the new HelloRetryRequest.

##  DTLS Handshake Message Format

   In order to support message loss, reordering, and message
   fragmentation, DTLS modifies the TLS 1.3 handshake header:

~~~~
       enum {
           hello_request_RESERVED(0),
           client_hello(1),
           server_hello(2),
           hello_verify_request_RESERVED(3),
           new_session_ticket(4),
           hello_retry_request(6),
           encrypted_extensions(8),
           certificate(11),
           server_key_exchange_RESERVED(12),
           certificate_request(13),
           server_hello_done_RESERVED(14),
           certificate_verify(15),
           client_key_exchange_RESERVED(16),
           finished(20),
           key_update_RESERVED(24),
           (255)
       } HandshakeType;

       struct {
           HandshakeType msg_type;    /* handshake type */
           uint24 length;             /* bytes in message */
           uint16 message_seq;        // DTLS-required field
           uint24 fragment_offset;    // DTLS-required field
           uint24 fragment_length;    // DTLS-required field           
           select (HandshakeType) {
               case client_hello:          ClientHello;
               case server_hello:          ServerHello;
               case hello_retry_request:   HelloRetryRequest;
               case encrypted_extensions:  EncryptedExtensions;
               case certificate_request:   CertificateRequest;
               case certificate:           Certificate;
               case certificate_verify:    CertificateVerify;
               case finished:              Finished;
               case new_session_ticket:    NewSessionTicket;
               case key_update:            KeyUpdate;
           } body;
       } Handshake;
~~~~

In addition to the handshake messages that are depricated by the TLS 1.3
specification DTLS 1.3 furthermore depricates the HelloVerifyRequest message
originally defined in DTLS 1.0. DTLS 1.3-compliant implements MUST NOT 
use the HelloVerifyRequest to execute a return-routability check. A 
dual-stack DTLS 1.2/DTLS 1.3 client must, however, be prepared to 
interact with a DTLS 1.2 ser

Furthermore, a DTLS 1.3 MUST NOT use the KeyUpdate message to update 
keying material. Instead the epoch field is re-used, which is explained 
in {{dtls-rekying}}. 

The format of the ClientHello used by a DTLS 1.3 client differs from the 
TLS 1.3 ClientHello format. 
 
~~~~
  struct {
       ProtocolVersion client_version = { 254,252 };    /* DTLS v1.3 */
       Random random;
       opaque legacy_session_id<0..32>;
       opaque legacy_cookie<0..2^8-1>;                  // DTLS       
       CipherSuite cipher_suites<2..2^16-2>;
       opaque legacy_compression_methods<1..2^8-1>;
       Extension extensions<0..2^16-1>;
   } ClientHello;
~~~~

client_version
: The version of the DTLS protocol by which the client wishes to 
communicate during this session. This SHOULD be the latest (highest 
valued) version supported by the client. For the DTLS 1.3 version of the 
specification, the version will be { 254,252 }.

random
: Same as for TLS 1.3

legacy_session_id
: Same as for TLS 1.3

legacy_cookie
: A DTLS 1.3 client MUST set the legacy_cookie field to zero length.

cipher_suites
: Same as for TLS 1.3

legacy_compression_methods
: Same as for TLS 1.3

extensions
: Same as for TLS 1.3
{:br } 



   The first message each side transmits in each handshake always has
   message_seq = 0.  Whenever each new message is generated, the
   message_seq value is incremented by one.  Note that in the case of a
   rehandshake, this implies that the HelloRequest will have message_seq
   = 0 and the ServerHello will have message_seq = 1.  When a message is
   retransmitted, the same message_seq value is used.  For example:

~~~~
         Client                             Server
         ------                             ------
         ClientHello (seq=0)  ------>

                                 X<-- HelloRetryRequest (seq=0)
                                                 (lost)

         [Timer Expires]

         ClientHello (seq=0)  ------>
         (retransmit)

                              <------ HelloRetryRequest (seq=0)

         ClientHello (seq=1)  ------>
         (with cookie)

                              <------        ServerHello (seq=1)

                          [Rest of handshake]
~~~~
{: #dtls-msg-loss title="Example DTLS Exchange with Message Loss"}

   Note, however, that from the perspective of the DTLS record layer,
   the retransmission is a new record.  This record will have a new
   DTLSPlaintext.sequence_number value.

   DTLS implementations maintain (at least notionally) a
   next_receive_seq counter.  This counter is initially set to zero.
   When a message is received, if its sequence number matches
   next_receive_seq, next_receive_seq is incremented and the message is
   processed.  If the sequence number is less than next_receive_seq, the
   message MUST be discarded.  If the sequence number is greater than
   next_receive_seq, the implementation SHOULD queue the message but MAY
   discard it.  (This is a simple space/bandwidth tradeoff).

##  Handshake Message Fragmentation and Reassembly

   Each DTLS message MUST fit within a single
   transport layer datagram.  However, handshake messages are
   potentially bigger than the maximum record size.  Therefore, DTLS
   provides a mechanism for fragmenting a handshake message over a
   number of records, each of which can be transmitted separately, thus
   avoiding IP fragmentation.
   
   When transmitting the handshake message, the sender divides the
   message into a series of N contiguous data ranges.  These ranges MUST
   NOT be larger than the maximum handshake fragment size and MUST
   jointly contain the entire handshake message.  The ranges SHOULD NOT
   overlap.  The sender then creates N handshake messages, all with the
   same message_seq value as the original handshake message.  Each new
   message is labeled with the fragment_offset (the number of bytes
   contained in previous fragments) and the fragment_length (the length
   of this fragment).  The length field in all messages is the same as
   the length field of the original message.  An unfragmented message is
   a degenerate case with fragment_offset=0 and fragment_length=length.

   When a DTLS implementation receives a handshake message fragment, it
   MUST buffer it until it has the entire handshake message.  DTLS
   implementations MUST be able to handle overlapping fragment ranges.
   This allows senders to retransmit handshake messages with smaller
   fragment sizes if the PMTU estimate changes.

   Note that as with TLS, multiple handshake messages may be placed in
   the same DTLS record, provided that there is room and that they are
   part of the same flight.  Thus, there are two acceptable ways to pack
   two DTLS messages into the same datagram: in the same record or in
   separate records.

##  Timeout and Retransmission

   DTLS messages are grouped into a series of message flights, according
   to the diagrams below.  Although each flight of messages may consist
   of a number of messages, they should be viewed as monolithic for the
   purpose of timeout and retransmission.

~~~~
Client                                             Server

ClientHello                                                 +----------+
 + key_share*                                               | Flight 1 |
 + pre_shared_key*      -------->                           +----------+

                                                            +----------+
                        <--------        HelloRetryRequest  | Flight 2 |
                                          + cookie          +----------+


ClientHello                                                 +----------+
 + key_share*                                               | Flight 3 |
 + pre_shared_key*      -------->                           +----------+
 + cookie

                                               ServerHello
                                              + key_share*
                                         + pre_shared_key*  +----------+
                                     {EncryptedExtensions}  | Flight 4 |
                                     {CertificateRequest*}  +----------+
                                            {Certificate*}
                                      {CertificateVerify*}
                        <--------               {Finished}


 {Certificate*}                                             +----------+
 {CertificateVerify*}                                       | Flight 5 |
 {Finished}             -------->                           +----------+
~~~~
{: #dtls-full title="Message Flights for full DTLS Handshake (With Cookie Exchange)"}

~~~~
ClientHello                                               +----------+
  + pre_shared_key                                        | Flight 1 |
  + key_share*         -------->                          +----------+


                                             ServerHello
                                        + pre_shared_key  +----------+
                                            + key_share*  | Flight 2 |
                                   {EncryptedExtensions}  +----------+
                       <--------              {Finished}

                                                          +----------+
{Finished}             -------->                          | Flight 3 |
                                                          +----------+
~~~~
{: #dtls-psk title="Message Flights for resumption and PSK Handshake (No Cookie Exchange)"}

~~~~
Client                                            Server

ClientHello
  + early_data
  + pre_shared_key                                        +----------+
  + key_share*                                            | Flight 1 |
(EncryptedExtensions)                                     +----------+
(Finished)
(Application Data*)
(end_of_early_data)     -------->

                                             ServerHello
                                            + early_data
                                        + pre_shared_key  +----------+
                                            + key_share*  | Flight 2 |
                                   {EncryptedExtensions}  +----------+
                                   {CertificateRequest*}
                       <--------              {Finished}

{Certificate*}                                            +----------+
{CertificateVerify*}                                      | Flight 3 |
{Finished}             -------->                          +----------+
~~~~
{: #dtls-zero-rtt title="Message Flights for a zero round trip handshake"}

Note: The application data sent by the client is not included in the 
timeout and retransmission calculation. 

[[TBD: More description for the use with Post-Handshake messages, such as 
CertificateRequest, NewSessionTicket.]]

### State Machine
         
   DTLS uses a simple timeout and retransmission scheme with the
   state machine shown in {{dtls-timeout-state-machine}. 
   Because DTLS clients send the first message
   (ClientHello), they start in the PREPARING state.  DTLS servers start
   in the WAITING state, but with empty buffers and no retransmit timer.

~~~~
                      +-----------+
                      | PREPARING |
                +---> |           | <--------------------+
                |     |           |                      |
                |     +-----------+                      |
                |           |                            |
                |           | Buffer next flight         |
                |           |                            |
                |          \|/                           |
                |     +-----------+                      |
                |     |           |                      |
                |     |  SENDING  |<------------------+  |
                |     |           |                   |  | Send
                |     +-----------+                   |  | HelloRequest
        Receive |           |                         |  |
           next |           | Send flight             |  | or
         flight |  +--------+                         |  |
                |  |        | Set retransmit timer    |  | Receive
                |  |       \|/                        |  | HelloRequest
                |  |  +-----------+                   |  | Send
                |  |  |           |                   |  | ClientHello
                +--)--|  WAITING  |-------------------+  |
                |  |  |           |   Timer expires   |  |
                |  |  +-----------+                   |  |
                |  |         |                        |  |
                |  |         |                        |  |
                |  |         +------------------------+  |
                |  |                Read retransmit      |
        Receive |  |                                     |
           last |  |                                     |
         flight |  |                                     |
                |  |                                     |
               \|/\|/                                    |
                                                         |
            +-----------+                                |
            |           |                                |
            | FINISHED  | -------------------------------+
            |           |
            +-----------+
                 |  /|\
                 |   |
                 |   |
                 +---+

              Read retransmit
           Retransmit last flight
~~~~
{: #dtls-timeout-state-machine title="DTLS Timeout and Retransmission State Machine"}

   The state machine has three basic states.

   In the PREPARING state, the implementation does whatever computations
   are necessary to prepare the next flight of messages.  It then
   buffers them up for transmission (emptying the buffer first) and
   enters the SENDING state.

   In the SENDING state, the implementation transmits the buffered
   flight of messages.  Once the messages have been sent, the
   implementation then enters the FINISHED state if this is the last
   flight in the handshake.  Or, if the implementation expects to
   receive more messages, it sets a retransmit timer and then enters the
   WAITING state.

   There are three ways to exit the WAITING state:

1. The retransmit timer expires: the implementation transitions to
      the SENDING state, where it retransmits the flight, resets the
      retransmit timer, and returns to the WAITING state.

2. The implementation reads a retransmitted flight from the peer: the
      implementation transitions to the SENDING state, where it
      retransmits the flight, resets the retransmit timer, and returns
      to the WAITING state.  The rationale here is that the receipt of a
      duplicate message is the likely result of timer expiry on the peer
      and therefore suggests that part of one's previous flight was
      lost.

3. The implementation receives the next flight of messages: if this
      is the final flight of messages, the implementation transitions to
      FINISHED.  If the implementation needs to send a new flight, it
      transitions to the PREPARING state.  Partial reads (whether
      partial messages or only some of the messages in the flight) do
      not cause state transitions or timer resets.

   Because DTLS clients send the first message (ClientHello), they start
   in the PREPARING state.  DTLS servers start in the WAITING state, but
   with empty buffers and no retransmit timer.

   When the server desires a rehandshake, it transitions from the
   FINISHED state to the PREPARING state to transmit the HelloRequest.
   When the client receives a HelloRequest, it transitions from FINISHED
   to PREPARING to transmit the ClientHello.

   In addition, for at least twice the default MSL defined for {{TCP}},
   when in the FINISHED state, the node that transmits the last flight
   (the server in an ordinary handshake or the client in a resumed
   handshake) MUST respond to a retransmit of the peer's last flight
   with a retransmit of the last flight.  This avoids deadlock
   conditions if the last flight gets lost.  To see why
   this is necessary, consider what happens in an ordinary handshake if
   the server's Finished message is lost: the server believes the
   handshake is complete but it actually is not.  As the client is
   waiting for the Finished message, the client's retransmit timer will
   fire and it will retransmit the client's Finished message.  This will
   cause the server to respond with its own Finished message, completing
   the handshake.  The same logic applies on the server side for the
   resumed handshake.

   Note that because of packet loss, it is possible for one side to be
   sending application data even though the other side has not received
   the first side's Finished message.  Implementations MUST either
   discard or buffer all application data packets for the new epoch
   until they have received the Finished message for that epoch.
   Implementations MAY treat receipt of application data with a new
   epoch prior to receipt of the corresponding Finished message as
   evidence of reordering or packet loss and retransmit their final
   flight immediately, shortcutting the retransmission timer.

### Timer Values

   Though timer values are the choice of the implementation, mishandling
   of the timer can lead to serious congestion problems; for example, if
   many instances of a DTLS time out early and retransmit too quickly on
   a congested link.  Implementations SHOULD use an initial timer value
   of 1 second (the minimum defined in RFC 6298 {{RFC6298}}) and double
   the value at each retransmission, up to no less than the RFC 6298
   maximum of 60 seconds.  Note that we recommend a 1-second timer
   rather than the 3-second RFC 6298 default in order to improve latency
   for time-sensitive applications.  Because DTLS only uses
   retransmission for handshake and not dataflow, the effect on
   congestion should be minimal.

   Implementations SHOULD retain the current timer value until a
   transmission without loss occurs, at which time the value may be
   reset to the initial value.  After a long period of idleness, no less
   than 10 times the current timer value, implementations may reset the
   timer to the initial value.  One situation where this might occur is
   when a rehandshake is used after substantial data transfer.

##  CertificateVerify and Finished Messages

   CertificateVerify and Finished messages have the same format as in
   TLS.  Hash calculations include entire handshake messages, including
   DTLS-specific fields: message_seq, fragment_offset, and
   fragment_length.  However, in order to remove sensitivity to
   handshake message fragmentation, the Finished MAC MUST be computed as
   if each handshake message had been sent as a single fragment.  Note
   that in cases where the cookie exchange is used, the initial
   ClientHello and HelloRetryRequest MUST NOT be included in the
   CertificateVerify or Finished MAC computations.

##  Alert Messages

   Note that Alert messages are not retransmitted at all, even when they
   occur in the context of a handshake.  However, a DTLS implementation
   which would ordinarily issue an alert SHOULD generate a new alert
   message if the offending record is received again (e.g., as a
   retransmitted handshake message).  Implementations SHOULD detect when
   a peer is persistently sending bad messages and terminate the local
   connection state after such misbehavior is detected.

##  Establishing New Associations with Existing Parameters

   If a DTLS client-server pair is configured in such a way that
   repeated connections happen on the same host/port quartet, then it is
   possible that a client will silently abandon one connection and then
   initiate another with the same parameters (e.g., after a reboot).
   This will appear to the server as a new handshake with epoch=0.  In
   cases where a server believes it has an existing association on a
   given host/port quartet and it receives an epoch=0 ClientHello, it
   SHOULD proceed with a new handshake but MUST NOT destroy the existing
   association until the client has demonstrated reachability either by
   completing a cookie exchange or by completing a complete handshake
   including delivering a verifiable Finished message.  After a correct
   Finished message is received, the server MUST abandon the previous
   association to avoid confusion between two valid associations with
   overlapping epochs.  The reachability requirement prevents
   off-path/blind attackers from destroying associations merely by
   sending forged ClientHellos.

## Rekeying {#dtls-rekying}

TBD: Add text about the absent KeyUpdate message and the use of epoch. 

#  Cryptographic Computations

In order to begin connection protection, the TLS Record Protocol
requires specification of a suite of algorithms, a master secret, and
the client and server random values. The authentication, key
exchange, and record protection algorithms are determined by the
cipher_suite selected by the server and revealed in the ServerHello
message. The random values are exchanged in the hello messages. All
that remains is to calculate the key schedule.

## Key Schedule

The TLS handshake establishes one or more input secrets which
are combined to create the actual working keying material, as detailed
below. The key derivation process makes use of the following functions,
based on HKDF {{RFC5869}}:

~~~~
  HKDF-Extract(Salt, IKM) as defined in {{RFC5869}}.

  HKDF-Expand-Label(Secret, Label, Messages, Length) =
       HKDF-Expand(Secret, HkdfLabel, Length)

  Where HkdfLabel is specified as:

  struct HkdfLabel {
    uint16 length;
    opaque label<9..255>;
    opaque hash_value<0..255>;
  };

  - HkdfLabel.length is Length
  - HkdfLabel.label is "TLS 1.3, " + Label
  - HkdfLabel.hash_value is HashValue.

  Derive-Secret(Secret, Label, Messages) =
       HKDF-Expand-Label(Secret, Label,
                         Hash(Messages) + Hash(resumption_context), L))
~~~~

Given a set of n InputSecrets, the final "master secret" is computed
by iteratively invoking HKDF-Extract with InputSecret_1, InputSecret_2,
etc.  The initial secret is simply a string of 0s as long as the size
of the Hash that is the basis for the HKDF. Concretely, for the
present version of TLS 1.3, secrets are added in the following order:

- PSK
- (EC)DHE shared secret

This produces a full key derivation schedule shown in the diagram below.
In this diagram, the following formatting conventions apply:

- HKDF-Extract is drawn as taking the Salt argument from the top and the IKM argument
  from the left.
- Derive-Secret's Secret argument is indicated by the arrow coming in
  from the left. For instance, the Early Secret is the Secret for
  generating the early_traffic-secret.

~~~~
                 0
                 |
                 v
   PSK ->  HKDF-Extract
                 |
                 v
               Early
               Secret --> Derive-Secret(., "early traffic secret",
                 |                      ClientHello)
                 |                      = early_traffic_secret
                 v
(EC)DHE -> HKDF-Extract
                 |
                 v
              Handshake
               Secret --> Derive-Secret(., "handshake traffic secret",
                 |                      ClientHello + ServerHello)
                 |                      = handshake_traffic_secret
                 v
      0 -> HKDF-Extract
                 |
                 v
              Master
              Secret
                 |
                 +------> Derive-Secret(., "application traffic secret",
                 |                      ClientHello...Server Finished)
                 |                      = traffic_secret_0
                 |
                 +------> Derive-Secret(., "exporter master secret",
                 |                      ClientHello...Client Finished)
                 |                      = exporter_secret
                 |
                 +------> Derive-Secret(., "resumption master secret",
                                        ClientHello...Client Finished)
                                        = resumption_secret
~~~~

The general pattern here is that the secrets shown down the left side
of the diagram are just raw entropy without context, whereas the
secrets down the right side include handshake context and therefore
can be used to derive working keys without additional context.
Note that the different
calls to Derive-Secret may take different Messages arguments,
even with the same secret. In a 0-RTT exchange, Derive-Secret is
called with four distinct transcripts; in a 1-RTT only exchange
with three distinct transcripts.

If a given secret is not available, then the 0-value consisting of
a string of L zeroes is used.


## Updating Traffic Keys and IVs {#updating-traffic-keys}

Once the handshake is complete, it is possible for either side to
update its sending traffic keys using the KeyUpdate handshake message
{{key-update}}.  The next generation of traffic keys is computed by
generating traffic_secret_N+1 from traffic_secret_N as described in
this section then re-deriving the traffic keys as described in
{{traffic-key-calculation}}.

The next-generation traffic_secret is computed as:

  traffic_secret_N+1 = HKDF-Expand-Label(traffic_secret_N,
                                         "application traffic secret", "", L)

Once traffic_secret_N+1 and its associated traffic keys have been computed,
implementations SHOULD delete traffic_secret_N. Once the directional
keys are no longer needed, they SHOULD be deleted as well.


## Traffic Key Calculation

The traffic keying material is generated from the following input values:

* A secret value
* A phase value indicating the phase of the protocol the keys are
  being generated for.
* A purpose value indicating the specific value being generated
* The length of the key.

The keying material is computed using:

       key = HKDF-Expand-Label(Secret,
                               phase + ", " + purpose, "",
                               key_length)

The following table describes the inputs to the key calculation for
each class of traffic keys:

| Record Type | Secret | Phase |
|:------------|--------|-------|
| 0-RTT Handshake   | early_traffic_secret | "early handshake key expansion" |
| 0-RTT Application | early_traffic_secret | "early application data key expansion" |
| Handshake         | handshake_traffic_secret | "handshake key expansion" |
| Application Data  | traffic_secret_N | "application data key expansion" |

The following table indicates the purpose values for each type of key:

| Key Type         | Purpose            |
|:-----------------|:-------------------|
| client_write_key | "client write key" |
| server_write_key | "server write key" |
| client_write_iv  | "client write iv"  |
| server_write_iv  | "server write iv"  |

All the traffic keying material is recomputed whenever the
underlying Secret changes (e.g., when changing from the handshake to
application data keys or upon a key update).


###  Diffie-Hellman

A conventional Diffie-Hellman computation is performed. The negotiated key (Z)
is converted to byte string by encoding in big-endian, padded with zeros up to
the size of the prime. This byte string is used as the shared secret, and is
used in the key schedule as specified above.

Note that this construction differs from previous versions of TLS which remove
leading zeros.

### Elliptic Curve Diffie-Hellman

For secp256r1, secp384r1 and secp521r1, ECDH calculations (including parameter
and key generation as well as the shared secret calculation) are
performed according to {{IEEE1363}} using the ECKAS-DH1 scheme with the identity
map as key derivation function (KDF), so that the shared secret is the
x-coordinate of the ECDH shared secret elliptic curve point represented
as an octet string.  Note that this octet string (Z in IEEE 1363 terminology)
as output by FE2OSP, the Field Element to Octet String Conversion
Primitive, has constant length for any given field; leading zeros
found in this octet string MUST NOT be truncated.

(Note that this use of the identity KDF is a technicality.  The
complete picture is that ECDH is employed with a non-trivial KDF
because TLS does not directly use this secret for anything
other than for computing other secrets.)

ECDH functions are used as follows:

* The public key to put into the KeyShareEntry.key_exchange structure is the
  result of applying the ECDH function to the secret key of appropriate length
  (into scalar input) and the standard public basepoint (into u-coordinate point
  input).
* The ECDH shared secret is the result of applying ECDH function to the secret
  key (into scalar input) and the peer's public key (into u-coordinate point
  input). The output is used raw, with no processing.

For X25519 and X448, see {{RFC7748}}.

### Exporters

{{!RFC5705}} defines keying material exporters for TLS in terms of
the TLS PRF. This document replaces the PRF with HKDF, thus requiring
a new construction. The exporter interface remains the same, however
the value is computed as:

    HKDF-Expand-Label(exporter_secret,
                      label, context_value, key_length)

#  Mandatory Algorithms

##  MTI Cipher Suites

In the absence of an application profile standard specifying otherwise, a
TLS-compliant application MUST implement the following cipher suites:

~~~~
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
~~~~

These cipher suites MUST support both digital signatures and key exchange
with secp256r1 (NIST P-256) and SHOULD support key exchange with X25519
{{RFC7748}}.

A TLS-compliant application SHOULD implement the following cipher suites:

~~~~
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
~~~~

##  MTI Extensions

In the absence of an application profile standard specifying otherwise, a
TLS-compliant application MUST implement the following TLS extensions:

  * Signature Algorithms ("signature_algorithms"; {{signature-algorithms}})
  * Negotiated Groups ("supported_groups"; {{negotiated-groups}})
  * Key Share ("key_share"; {{key-share}})
  * Pre-Shared Key ("pre_shared_key"; {{pre-shared-key-extension}})
  * Server Name Indication ("server_name"; Section 3 of {{RFC6066}})
  * Cookie ("cookie"; {{cookie}})

All implementations MUST send and use these extensions when offering
applicable cipher suites:

  * "signature_algorithms" is REQUIRED for certificate authenticated cipher suites
  * "supported_groups" and "key_share" are REQUIRED for DHE or ECDHE cipher suites
  * "pre_shared_key" is REQUIRED for PSK cipher suites
  * "cookie" is REQUIRED for all cipher suites.

When negotiating use of applicable cipher suites, endpoints MUST abort the
connection with a "missing_extension" alert if the required extension was
not provided. Any endpoint that receives any invalid combination of cipher
suites and extensions MAY abort the connection with a "missing_extension"
alert, regardless of negotiated parameters.

Additionally, all implementations MUST support use of the "server_name"
extension with applications capable of using it.
Servers MAY require clients to send a valid "server_name" extension.
Servers requiring this extension SHOULD respond to a ClientHello
lacking a "server_name" extension with a fatal "missing_extension" alert.

Servers MUST NOT send the "signature_algorithms" extension; if a client
receives this extension it MUST respond with a fatal "unsupported_extension" alert
and close the connection.


#  Application Data Protocol

Application data messages are carried by the record layer and are fragmented
and encrypted based on the current connection state. The messages
are treated as transparent data to the record layer.


#  Security Considerations

Security issues are discussed throughout this memo, especially in Appendices B,
C, and D.


#  IANA Considerations

This document uses several registries that were originally created in
{{RFC4346}}. IANA has updated these to reference this document. The registries
and their allocation policies are below:

- TLS Cipher Suite Registry: Values with the first byte in the range
  0-254 (decimal) are assigned via Specification Required {{RFC2434}}.
  Values with the first byte 255 (decimal) are reserved for Private
  Use {{RFC2434}}. IANA [SHALL add/has added] a "Recommended" column
  to the cipher suite registry. All cipher suites listed in
  {{cipher-suites}} are marked as "Yes". All other cipher suites are
  marked as "No". IANA [SHALL add/has added] add a note to this column
  reading:

  > Cipher suites marked as "Yes" are those allocated via
    Standards Track RFCs. Cipher suites marked as "No" are not;
    cipher suites marked "No" range from "good" to "bad" from a
    cryptographic standpoint.

  > Note that RFC 6347 (DTLS) required that authors mark ciphersuites 
    according to their suitable use with DTLS. With DTLS 1.3 no such 
    distinction is necessary and all TLS 1.3 are also fit for use with 
    DTLS 1.3 since only AEAD-based ciphers are supported
    by TLS 1.3. 
     
-  TLS ContentType Registry: Future values are allocated via
  Standards Action {{RFC2434}}.

-  TLS Alert Registry: Future values are allocated via Standards
  Action {{RFC2434}}.

-  TLS HandshakeType Registry: Future values are allocated via
  Standards Action {{RFC2434}}. IANA [SHALL update/has updated] this registry
  to rename item 4 from "NewSessionTicket" to "new_session_ticket".

This document also uses a registry originally created in {{RFC4366}}. IANA has
updated it to reference this document. The registry and its allocation policy
is listed below:

- TLS ExtensionType Registry: Values with the first byte in the range
   0-254 (decimal) are assigned via Specification Required {{RFC2434}}.
   Values with the first byte 255 (decimal) are reserved for Private
   Use {{RFC2434}}. IANA [SHALL update/has updated]
   this registry to include the "key_share", "pre_shared_key", and
   "early_data" extensions as defined in this document.

   IANA [shall update/has updated] this registry to include a "TLS
   1.3" column with the following four values: "Client", indicating
   that the server shall not send them. "Clear", indicating
   that they shall be in the ServerHello. "Encrypted", indicating that
   they shall be in the EncryptedExtensions block, "Early", indicating
   that they shall be only in the client's 0-RTT EncryptedExtensions block,
   and "No" indicating
   that they are not used in TLS 1.3. This column [shall be/has been]
   initially populated with the values in this document.
   IANA [shall update/has updated] this registry to add a
   "Recommended" column. IANA [shall/has] initially populated this
   column with the values in the table below. This table has been generated
   by marking Standards Track RFCs as "Yes" and all others as
   "No".

| Extension                                | Recommended |  TLS 1.3  |
|:-----------------------------------------|------------:|----------:|
| server_name [RFC6066]                    |         Yes | Encrypted |
| max_fragment_length [RFC6066]            |         Yes | Encrypted |
| client_certificate_url [RFC6066]         |         Yes | Encrypted |
| trusted_ca_keys [RFC6066]                |         Yes | Encrypted |
| truncated_hmac [RFC6066]                 |         Yes |        No |
| status_request [RFC6066]                 |         Yes |        No |
| user_mapping [RFC4681]                   |         Yes | Encrypted |
| client_authz [RFC5878]                   |          No | Encrypted |
| server_authz [RFC5878]                   |          No | Encrypted |
| cert_type [RFC6091]                      |         Yes | Encrypted |
| supported_groups [RFC-ietf-tls-negotiated-ff-dhe] | Yes | Encrypted |
| ec_point_formats [RFC4492]               |         Yes |        No |
| srp [RFC5054]                            |          No |        No |
| signature_algorithms [RFC5246]           |         Yes |    Client |
| use_srtp [RFC5764]                       |         Yes | Encrypted |
| heartbeat [RFC6520]                      |         Yes | Encrypted |
| application_layer_protocol_negotiation [RFC7301] | Yes | Encrypted |
| status_request_v2 [RFC6961]              |         Yes | Encrypted |
| signed_certificate_timestamp [RFC6962]   |          No | Encrypted |
| client_certificate_type [RFC7250]        |         Yes | Encrypted |
| server_certificate_type [RFC7250]        |         Yes | Encrypted |
| padding [RFC7685]                        |         Yes |    Client |
| encrypt_then_mac [RFC7366]               |         Yes |        No |
| extended_master_secret [RFC7627]         |         Yes |        No |
| SessionTicket TLS [RFC4507]              |         Yes |        No |
| renegotiation_info [RFC5746]             |         Yes |        No |
| key_share [[this document]]              |         Yes |     Clear |
| pre_shared_key [[this document]]         |         Yes |     Clear |
| early_data [[this document]]             |         Yes |     Clear |
| ticket_age [[this document]]             |         Yes |     Early |
| cookie [[this document]]                 |         Yes | Encrypted/HelloRetryRequest |
| cookie [[this document]]                 |         Yes | Clear/ClientHello |


In addition, this document defines two new registries to be maintained
by IANA

-  TLS SignatureScheme Registry: Values with the first byte in the range
  0-254 (decimal) are assigned via Specification Required {{RFC2434}}.
  Values with the first byte 255 (decimal) are reserved for Private
  Use {{RFC2434}}. This registry SHALL have a "Recommended" column.
  The registry [shall be/ has been] initially populated with the values described in
  {{signature-algorithms}}. The following values SHALL be marked as
  "Recommended": ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384,
  rsa_pss_sha256, rsa_pss_sha384, rsa_pss_sha512, ed25519.
--- back

# DTLS Design Rational and Overview {#dtls-rational}

The basic design philosophy of DTLS is to construct "TLS over
   datagram transport". Datagram transport does not require or provide 
   reliable or in-order delivery of data.  The DTLS protocol preserves this property for
   application data.  Applications such as media streaming, Internet
   telephony, and online gaming use datagram transport for communication
   due to the delay-sensitive nature of transported data.  The behavior
   of such applications is unchanged when the DTLS protocol is used to
   secure communication, since the DTLS protocol does not compensate for
   lost or re-ordered data traffic.

The reason that TLS cannot be used directly in
   datagram environments is simply that payloads may be lost or
   reordered.  Unreliability and reordering creates problems for TLS 
   at three levels:

1. TLS does not allow independent decryption of individual
         records.  Because the integrity check depends on the sequence
         number, if record N is not received, then the integrity check
         on record N+1 will be based on the wrong sequence number and
         thus will fail. DTLS solves this problem by adding explicit 
         sequence numbers.

2. The TLS handshake is a lockstep cryptographic handshake. 
   Messages must be transmitted and received in a defined order; any other order
   is an error.  Clearly, this is incompatible with reordering and
   message loss.  In addition, TLS handshake messages are potentially
   larger than any given datagram, thus creating the problem of IP
   fragmentation.  DTLS provides fixes for both of these problems, 
   as described in the subsections below. 

3. Not all TLS 1.3 handshake messages (such as the NewSessionTicket meesage ) 
are acknowledged. Hence, a new acknowledgement message has to be integrated 
to detect message loss. 

The DTLS 1.3 specification changes the way how cookies are exchanged
   compared to DTLS 1.2. DTLS 1.3 re-uses the HelloRetryRequest message
   and conveys the cookie to the client via an extension. The client 
   then uses the same extension to place the cookie into a ClientHello message. 
   DTLS 1.2 on the other hand used a separate message, namely the HelloVerifyRequest, 
   to pass a cookie to the client and did not utlize the extension mechanism. 
   For backwards compatibility reason the cookie field in the ClientHello
   is present in DTLS 1.3 but is ignored by a DTLS 1.3 compliant server 
   implementation. 
   
###  Packet Loss

DTLS uses a simple retransmission timer to handle packet loss. 
{{dtls-retransmission} demonstrates the basic concept, using the first
phase of the DTLS handshake:

~~~~
         Client                                   Server
         ------                                   ------
         ClientHello           ------>

                                 X<-- HelloRetryRequest
                                                  (lost)

         [Timer Expires]

         ClientHello           ------>
         (retransmit)
~~~~
{: #dtls-retransmission title="DTLS Retransmission Example."}

   Once the client has transmitted the ClientHello message, it expects
   to see a HelloRetryRequest from the server.  However, if the
   server's message is lost, the client knows that either the
   ClientHello or the HelloRetryRequest has been lost and retransmits.
   When the server receives the retransmission, it knows to retransmit.

   The server also maintains a retransmission timer and retransmits when
   that timer expires.

   Note that timeout and retransmission do not apply to the
   HelloVRetryRequest, because this would require creating state on the
   server.  The HelloRetryRequest is designed to be small enough that
   it will not itself be fragmented, thus avoiding concerns about
   interleaving multiple HelloRetryRequests.

###  Reordering

In DTLS, each handshake message is assigned a specific sequence
   number within that handshake.  When a peer receives a handshake
   message, it can quickly determine whether that message is the next
   message it expects.  If it is, then it processes it.  If not, it
   queues it for future handling once all previous messages have been
   received.

###  Message Size

TLS and DTLS handshake messages can be quite large (in theory up to
   2^24-1 bytes, in practice many kilobytes).  By contrast, UDP
   datagrams are often limited to <1500 bytes if IP fragmentation is not
   desired.  In order to compensate for this limitation, each DTLS
   handshake message may be fragmented over several DTLS records, each
   of which is intended to fit in a single IP datagram.  Each DTLS
   handshake message contains both a fragment offset and a fragment
   length.  Thus, a recipient in possession of all bytes of a handshake
   message can reassemble the original unfragmented message.

##  Replay Detection

DTLS optionally supports record replay detection.  The technique used
   is the same as in IPsec AH/ESP, by maintaining a bitmap window of
   received records.  Records that are too old to fit in the window and
   records that have previously been received are silently discarded.
   The replay detection feature is optional, since packet duplication is
   not always malicious, but can also occur due to routing errors.
   Applications may conceivably detect duplicate packets and accordingly
   modify their data transmission strategy.


# Protocol Data Structures and Constant Values

This section describes protocol types and constants. Values listed as
_RESERVED were used in previous versions of TLS and are listed here
for completeness. TLS 1.3 implementations MUST NOT send them but
might receive them from older TLS implementations.

%%## Record Layer
%%## Alert Messages
%%## Handshake Protocol
%%### Key Exchange Messages
%%#### Cookie Extension
%%#### Signature Algorithm Extension
%%#### Named Group Extension

Values within "obsolete_RESERVED" ranges were used in previous versions
of TLS and MUST NOT be offered or negotiated by TLS 1.3 implementations.
The obsolete curves have various known/theoretical weaknesses or have
had very little usage, in some cases only due to unintentional
server configuration issues. They are no longer considered appropriate
for general use and should be assumed to be potentially unsafe. The set
of curves specified here is sufficient for interoperability with all
currently deployed and properly configured TLS implementations.

#### Deprecated Extensions

The following extensions are no longer applicable to TLS 1.3, although
TLS 1.3 clients MAY send them if they are willing to negotiate them
with prior versions of TLS. TLS 1.3 servers MUST ignore these
extensions if they are negotiating TLS 1.3:
truncated_hmac {{RFC6066}},
srp {{RFC5054}},
encrypt_then_mac {{RFC7366}},
extended_master_secret {{RFC7627}},
SessionTicket {{RFC5077}},
and renegotiation_info {{RFC5746}}.

%%### Server Parameters Messages
%%### Authentication Messages
%%### Ticket Establishment

## Cipher Suites

A cipher suite defines a cipher specification supported in TLS and negotiated
via hello messages in the TLS handshake.
Cipher suite names follow a general naming convention composed of a series
of component algorithm names separated by underscores:

~~~~
   CipherSuite TLS_KEA_AUTH_WITH_CIPHER_HASH = VALUE;
~~~~

| Component | Contents |
|:----------|:---------|
| TLS       | The string "TLS" |
| KEA       | The key exchange algorithm (e.g. ECDHE, DHE) |
| AUTH      | The authentication algorithm (e.g. certificates, PSK) |
| WITH      | The string "WITH" |
| CIPHER    | The symmetric cipher used for record protection |
| HASH      | The hash algorithm used with HKDF |
| VALUE     | The two byte ID assigned for this cipher suite |

The "CIPHER" component commonly has sub-components used to designate
the cipher name, bits, and mode, if applicable. For example, "AES_256_GCM"
represents 256-bit AES in the GCM mode of operation. Cipher suite names that
lack a "HASH" value that are defined for use with TLS 1.2 or later use the
SHA-256 hash algorithm by default.

The primary key exchange algorithm used in TLS is Ephemeral Diffie-Hellman
{{DH}}. The finite field based version is denoted "DHE" and the elliptic
curve based version is denoted "ECDHE". Prior versions of TLS supported
non-ephemeral key exchanges, however these are not supported by TLS 1.3.

See the definitions of each cipher suite in its specification document for
the full details of each combination of algorithms that is specified.

The following is a list of standards track server-authenticated (and optionally
client-authenticated) cipher suites which are currently available in TLS 1.3:

|              Cipher Suite Name                |    Value    | Specification |
|:----------------------------------------------|:------------|:--------------|
| TLS_DHE_RSA_WITH_AES_128_GCM_SHA256           | {0x00,0x9E} | [RFC5288]     |
| TLS_DHE_RSA_WITH_AES_256_GCM_SHA384           | {0x00,0x9F} | [RFC5288]     |
| TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       | {0xC0,0x2B} | [RFC5289]     |
| TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       | {0xC0,0x2C} | [RFC5289]     |
| TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         | {0xC0,0x2F} | [RFC5289]     |
| TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         | {0xC0,0x30} | [RFC5289]     |
| TLS_DHE_RSA_WITH_AES_128_CCM                  | {0xC0,0x9E} | [RFC6655]     |
| TLS_DHE_RSA_WITH_AES_256_CCM                  | {0xC0,0x9F} | [RFC6655]     |
| TLS_DHE_RSA_WITH_AES_128_CCM_8                | {0xC0,0xA2} | [RFC6655]     |
| TLS_DHE_RSA_WITH_AES_256_CCM_8                | {0xC0,0xA3} | [RFC6655]     |
| TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   | {0xCC,0xA8}   | [I-D.ietf-tls-chacha20-poly1305] |
| TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 | {0xCC,0xA9}   | [I-D.ietf-tls-chacha20-poly1305] |
| TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256     | {0xCC,0xAA}   | [I-D.ietf-tls-chacha20-poly1305] |

Note: The values listed for ChaCha/Poly are preliminary but are being
or will be used for interop testing and therefore are likely to be
assigned.

Note: ECDHE AES GCM was not yet standards track prior to the publication of
this specification. This document promotes the above-listed ciphers to
standards track.

The following is a list of standards track ephemeral pre-shared key cipher
suites which are currently available in TLS 1.3:

|              Cipher Suite Name                |    Value    | Specification |
|:----------------------------------------------|:------------|:--------------|
| TLS_DHE_PSK_WITH_AES_128_GCM_SHA256           | {0x00,0xAA} | [RFC5487]     |
| TLS_DHE_PSK_WITH_AES_256_GCM_SHA384           | {0x00,0xAB} | [RFC5487]     |
| TLS_DHE_PSK_WITH_AES_128_CCM                  | {0xC0,0xA6} | [RFC6655]     |
| TLS_DHE_PSK_WITH_AES_256_CCM                  | {0xC0,0xA7} | [RFC6655]     |
| TLS_PSK_DHE_WITH_AES_128_CCM_8                | {0xC0,0xAA} | [RFC6655]     |
| TLS_PSK_DHE_WITH_AES_256_CCM_8                | {0xC0,0xAB} | [RFC6655]     |
| TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256         | {0xD0,0x01}   | [I-D.mattsson-tls-ecdhe-psk-aead] |
| TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384         | {0xD0,0x02}   | [I-D.mattsson-tls-ecdhe-psk-aead] |
| TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256       | {0xD0,0x03}   | [I-D.mattsson-tls-ecdhe-psk-aead] |
| TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256         | {0xD0,0x04}   | [I-D.mattsson-tls-ecdhe-psk-aead] |
| TLS_ECDHE_PSK_WITH_AES_256_CCM_SHA384         | {0xD0,0x05}   | [I-D.mattsson-tls-ecdhe-psk-aead] |
| TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256   | {0xCC,0xAC}   | [I-D.ietf-tls-chacha20-poly1305] |
| TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256     | {0xCC,0xAD}   | [I-D.ietf-tls-chacha20-poly1305] |

Note: The values listed for ECDHE and ChaCha/Poly are preliminary but
are being or will be used for interop testing and therefore are likely to be
assigned.

Note: [RFC6655] is inconsistent with respect to the ordering of components
within PSK AES CCM cipher suite names. The names above are as defined.

All cipher suites in this section are specified for use with both TLS 1.2
and TLS 1.3, as well as the corresponding versions of DTLS.
(see {{backward-compatibility}})

New cipher suite values are assigned by IANA as described in
{{iana-considerations}}.

### Unauthenticated Operation

Previous versions of TLS offered explicitly unauthenticated cipher suites
based on anonymous Diffie-Hellman. These cipher suites have been deprecated
in TLS 1.3. However, it is still possible to negotiate cipher suites
that do not provide verifiable server authentication by several methods,
including:

- Raw public keys {{RFC7250}}.
- Using a public key contained in a certificate but without
  validation of the certificate chain or any of its contents.

Either technique used alone is are vulnerable to man-in-the-middle attacks
and therefore unsafe for general use. However, it is also possible to
bind such connections to an external authentication mechanism via
out-of-band validation of the server's public key, trust on first
use, or channel bindings {{RFC5929}}. [[NOTE: TLS 1.3 needs a new
channel binding definition that has not yet been defined.]]
If no such mechanism is used, then the connection has no protection
against active man-in-the-middle attack; applications MUST NOT use TLS
in such a way absent explicit configuration or a specific application
profile.

## The Security Parameters

These security parameters are determined by the TLS Handshake Protocol and
provided as parameters to the TLS record layer in order to initialize a
connection state. SecurityParameters includes:

%%! Security Parameters


## Changes to RFC 4492

RFC 4492 {{RFC4492}} adds Elliptic Curve cipher suites to TLS. This document
changes some of the structures used in that document. This section details the
required changes for implementors of both RFC 4492 and TLS 1.2. Implementors of
TLS 1.2 who are not implementing RFC 4492 do not need to read this section.

This document adds an "algorithm" field to the digitally-signed
element in order to identify the signature and digest algorithms used to create
a signature. This change applies to digital signatures formed using ECDSA as
well, thus allowing ECDSA signatures to be used with digest algorithms other
than SHA-1, provided such use is compatible with the certificate and any
restrictions imposed by future revisions of {{RFC5280}}.

As described in {{server-certificate-selection}}, the restrictions on the signature
algorithms used to sign certificates are no longer tied to the cipher suite.
Thus, the restrictions on the algorithm used to sign certificates specified in
Sections 2 and 3 of RFC 4492 are also relaxed. As in this document, the
restrictions on the keys in the end-entity certificate remain.


# Implementation Notes

The TLS protocol cannot prevent many common security mistakes. This section
provides several recommendations to assist implementors.


## Random Number Generation and Seeding

TLS requires a cryptographically secure pseudorandom number generator (PRNG).
Care must be taken in designing and seeding PRNGs. PRNGs based on secure hash
operations, most notably SHA-256, are acceptable, but cannot provide more
security than the size of the random number generator state.

To estimate the amount of seed material being produced, add the number of bits
of unpredictable information in each seed byte. For example, keystroke timing
values taken from a PC compatible 18.2 Hz timer provide 1 or 2 secure bits
each, even though the total size of the counter value is 16 bits or more.
Seeding a 128-bit PRNG would thus require approximately 100 such timer values.

{{RFC4086}} provides guidance on the generation of random values.


## Certificates and Authentication

Implementations are responsible for verifying the integrity of certificates and
should generally support certificate revocation messages. Certificates should
always be verified to ensure proper signing by a trusted Certificate Authority
(CA). The selection and addition of trusted CAs should be done very carefully.
Users should be able to view information about the certificate and root CA.


## Cipher Suite Support

TLS supports a range of key sizes and security levels, including some that
provide no or minimal security. A proper implementation will probably not
support many cipher suites. Applications SHOULD also enforce minimum and
maximum key sizes. For example, certification paths containing keys or
signatures weaker than 2048-bit RSA or 224-bit ECDSA are not appropriate
for secure applications.
See also {{backwards-compatibility-security-restrictions}}.


## Implementation Pitfalls

Implementation experience has shown that certain parts of earlier TLS
specifications are not easy to understand, and have been a source of
interoperability and security problems. Many of these areas have been clarified
in this document, but this appendix contains a short list of the most important
things that require special attention from implementors.

TLS protocol issues:

-  Do you correctly handle handshake messages that are fragmented to
  multiple TLS records (see {{fragmentation}})? Including corner cases
  like a ClientHello that is split to several small fragments? Do
  you fragment handshake messages that exceed the maximum fragment
  size? In particular, the certificate and certificate request
  handshake messages can be large enough to require fragmentation.

-  Do you ignore the TLS record layer version number in all TLS
  records? (see {{backward-compatibility}})

-  Have you ensured that all support for SSL, RC4, EXPORT ciphers, and
  MD5 (via the "signature_algorithm" extension) is completely removed from
  all possible configurations that support TLS 1.3 or later, and that
  attempts to use these obsolete capabilities fail correctly?
  (see {{backward-compatibility}})

-  Do you handle TLS extensions in ClientHello correctly, including
  unknown extensions or omitting the extensions field completely?

-  When the server has requested a client certificate, but no
  suitable certificate is available, do you correctly send an empty
  Certificate message, instead of omitting the whole message (see
  {{client-certificate-selection}})?

- When processing the plaintext fragment produced by AEAD-Decrypt and
  scanning from the end for the ContentType, do you avoid scanning
  past the start of the cleartext in the event that the peer has sent
  a malformed plaintext of all-zeros?

- When processing a ClientHello containing a version of { 3, 5 } or higher, do
  you respond with the highest common version of TLS rather than requiring an
  exact match?

- Do you ignore unrecognized cipher suites (see {{client-hello}}), named groups
  (see {{negotiated-groups}}), and signature algorithms (see
  {{signature-algorithms}})?

Cryptographic details:

-  What countermeasures do you use to prevent timing attacks against
  RSA signing operations {{TIMING}}?

- When verifying RSA signatures, do you accept both NULL and missing parameters
  (see {{cryptographic-attributes}})? Do you verify that the RSA padding
  doesn't have additional data after the hash value? {{FI06}}

-  When using Diffie-Hellman key exchange, do you correctly preserve
  leading zero bytes in the negotiated key (see {{diffie-hellman}})?

-  Does your TLS client check that the Diffie-Hellman parameters sent
  by the server are acceptable (see
  {{diffie-hellman-key-exchange-with-authentication}})?

- Do you use a strong and, most importantly, properly seeded random number
  generator (see {{random-number-generation-and-seeding}}) Diffie-Hellman
  private values, the ECDSA "k" parameter, and other security-critical values?

- Do you zero-pad Diffie-Hellman public key values to the group size (see
  {{ffdhe-param}})?


## Client Tracking Prevention

Clients SHOULD NOT reuse a session ticket for multiple connections. Reuse
of a session ticket allows passive observers to correlate different connections.
Servers that issue session tickets SHOULD offer at least as many session tickets
as the number of connections that a client might use; for example, a web browser
using HTTP/1.1 {{RFC7230}} might open six connections to a server. Servers SHOULD
issue new session tickets with every connection. This ensures that clients are
always able to use a new session ticket when creating a new connection.


# Backward Compatibility

The TLS protocol provides a built-in mechanism for version negotiation between
endpoints potentially supporting different versions of TLS.

TLS 1.x and SSL 3.0 use compatible ClientHello messages. Servers can also handle
clients trying to use future versions of TLS as long as the ClientHello format
remains compatible and the client supports the highest protocol version available
in the server.

Prior versions of TLS used the record layer version number for various
purposes. (TLSPlaintext.record_version & TLSCiphertext.record_version)
As of TLS 1.3, this field is deprecated and its value MUST be ignored by all
implementations. Version negotiation is performed using only the handshake versions.
(ClientHello.client_version & ServerHello.server_version)
In order to maximize interoperability with older endpoints, implementations
that negotiate the use of TLS 1.0-1.2 SHOULD set the record layer
version number to the negotiated version for the ServerHello and all
records thereafter.

For maximum compatibility with previously non-standard behavior and misconfigured
deployments, all implementations SHOULD support validation of certification paths
based on the expectations in this document, even when handling prior TLS versions'
handshakes. (see {{server-certificate-selection}})

TLS 1.2 and prior supported an "Extended Master Secret" {{?RFC7627}} extension
which digested large parts of the handshake transcript into the master secret.
Because TLS 1.3 always hashes in the transcript up to the server CertificateVerify,
implementations which support both TLS 1.3 and earlier versions SHOULD
indicate the use of the Extended Master Secret extension in their APIs
whenever TLS 1.3 is used.

## Negotiating with an older server

A TLS 1.3 client who wishes to negotiate with such older servers will send a
normal TLS 1.3 ClientHello containing { 3, 4 } (TLS 1.3) in
ClientHello.client_version. If the server does not support this version it
will respond with a ServerHello containing an older version number. If the
client agrees to use this version, the negotiation will proceed as appropriate
for the negotiated protocol. A client resuming a session SHOULD initiate the
connection using the version that was previously negotiated.

Note that 0-RTT data is not compatible with older servers.
See {{zero-rtt-backwards-compatibility}}.

If the version chosen by the server is not supported by the client (or not
acceptable), the client MUST send a "protocol_version" alert message and close
the connection.

If a TLS server receives a ClientHello containing a version number greater than
the highest version supported by the server, it MUST reply according to the
highest version supported by the server.

Some legacy server implementations are known to not implement the TLS
specification properly and might abort connections upon encountering
TLS extensions or versions which it is not aware of. Interoperability
with buggy servers is a complex topic beyond the scope of this document.
Multiple connection attempts may be required in order to negotiate
a backwards compatible connection, however this practice is vulnerable
to downgrade attacks and is NOT RECOMMENDED.


## Negotiating with an older client

A TLS server can also receive a ClientHello containing a version number smaller
than the highest supported version. If the server wishes to negotiate with old
clients, it will proceed as appropriate for the highest version supported by
the server that is not greater than ClientHello.client_version. For example, if
the server supports TLS 1.0, 1.1, and 1.2, and client_version is TLS 1.0, the
server will proceed with a TLS 1.0 ServerHello. If the server only supports
versions greater than client_version, it MUST send a "protocol_version"
alert message and close the connection.

Note that earlier versions of TLS did not clearly specify the record layer
version number value in all cases (TLSPlaintext.record_version). Servers
will receive various TLS 1.x versions in this field, however its value
MUST always be ignored.


## Zero-RTT backwards compatibility

0-RTT data is not compatible with older servers. An older server will respond
to the ClientHello with an older ServerHello, but it will not correctly skip
the 0-RTT data and fail to complete the handshake. This can cause issues when
a client offers 0-RTT, particularly against multi-server deployments. For
example, a deployment may deploy TLS 1.3 gradually with some servers
implementing TLS 1.3 and some implementing TLS 1.2, or a TLS 1.3 deployment
may be downgraded to TLS 1.2.

If a client accepts older versions of TLS and receives an older ServerHello
after sending a ClientHello with 0-RTT data, it MAY retry the connection
without 0-RTT. It is NOT RECOMMENDED to retry the connection in response to a
more generic error or advertise lower versions of TLS.

Multi-server deployments are RECOMMENDED to ensure a stable deployment of TLS
1.3 without 0-RTT prior to enabling 0-RTT.

## Backwards Compatibility Security Restrictions

If an implementation negotiates use of TLS 1.2, then negotiation of cipher
suites also supported by TLS 1.3 SHOULD be preferred, if available.

The security of RC4 cipher suites is considered insufficient for the reasons
cited in {{RFC7465}}. Implementations MUST NOT offer or negotiate RC4 cipher suites
for any version of TLS for any reason.

Old versions of TLS permitted the use of very low strength ciphers.
Ciphers with a strength less than 112 bits MUST NOT be offered or
negotiated for any version of TLS for any reason.

The security of SSL 2.0 {{SSL2}} is considered insufficient for the reasons enumerated
in {{RFC6176}}, and MUST NOT be negotiated for any reason.

Implementations MUST NOT send an SSL version 2.0 compatible CLIENT-HELLO.
Implementations MUST NOT negotiate TLS 1.3 or later using an SSL version 2.0 compatible
CLIENT-HELLO. Implementations are NOT RECOMMENDED to accept an SSL version 2.0 compatible
CLIENT-HELLO in order to negotiate older versions of TLS.

Implementations MUST NOT send or accept any records with a version less than { 3, 0 }.

The security of SSL 3.0 {{SSL3}} is considered insufficient for the reasons enumerated
in {{RFC7568}}, and MUST NOT be negotiated for any reason.

Implementations MUST NOT send a ClientHello.client_version or ServerHello.server_version
set to { 3, 0 } or less. Any endpoint receiving a Hello message with
ClientHello.client_version or ServerHello.server_version set to { 3, 0 } MUST respond
with a "protocol_version" alert message and close the connection.

Implementations MUST NOT use the Truncated HMAC extension, defined in
Section 7 of [RFC6066], as it is not applicable to AEAD ciphers and has
been shown to be insecure in some scenarios.


#  Security Analysis

## TLS-specific Security Considerations

[[TODO: The entire security analysis needs a rewrite.]]

The TLS protocol is designed to establish a secure connection between a client
and a server communicating over an insecure channel. This document makes
several traditional assumptions, including that attackers have substantial
computational resources and cannot obtain secret information from sources
outside the protocol. Attackers are assumed to have the ability to capture,
modify, delete, replay, and otherwise tamper with messages sent over the
communication channel. This appendix outlines how TLS has been designed to
resist a variety of attacks.

## DTLS-specific Security Considerations

   The primary additional security consideration raised by DTLS is that
   of denial of service.  DTLS includes a cookie exchange designed to
   protect against denial of service.  However, implementations that do
   not use this cookie exchange are still vulnerable to DoS.  In
   particular, DTLS servers that do not use the cookie exchange may be
   used as attack amplifiers even if they themselves are not
   experiencing DoS.  Therefore, DTLS servers SHOULD use the cookie
   exchange unless there is good reason to believe that amplification is
   not a threat in their environment.  Clients MUST be prepared to do a
   cookie exchange with every handshake.

   Unlike TLS implementations, DTLS implementations SHOULD NOT respond
   to invalid records by terminating the connection.
   

## TLS Handshake Protocol

The TLS Handshake Protocol is responsible for selecting a cipher spec and
generating a master secret, which together comprise the primary cryptographic
parameters associated with a secure session. The TLS Handshake Protocol can also
optionally authenticate parties who have certificates signed by a trusted
certificate authority.

###  Authentication and Key Exchange

TLS supports three authentication modes: authentication of both parties, server
authentication with an unauthenticated client, and total anonymity. Whenever
the server is authenticated, the channel is secure against man-in-the-middle
attacks, but completely anonymous sessions are inherently vulnerable to such
attacks. Anonymous servers cannot authenticate clients. If the server is
authenticated, its certificate message must provide a valid certificate chain
leading to an acceptable certificate authority. Similarly, authenticated
clients must supply an acceptable certificate to the server. Each party is
responsible for verifying that the other's certificate is valid and has not
expired or been revoked.

[[TODO: Rewrite this because the master_secret is not used this way any
more after Hugo's changes.]]
The general goal of the key exchange process is to create a master_secret
known to the communicating parties and not to attackers (see
{{key-schedule}}). The master_secret is required to generate the
Finished messages and record protection keys (see {{finished}} and
{{traffic-key-calculation}}). By sending a correct Finished message, parties thus prove
that they know the correct master_secret.

####  Diffie-Hellman Key Exchange with Authentication

When Diffie-Hellman key exchange is used, the client and server use
the "key_share" extension to send
temporary Diffie-Hellman parameters. The signature in the certificate
verify message (if present) covers the entire handshake up to that
point and thus attests the certificate holder's desire to use
the ephemeral DHE keys.

Peers SHOULD validate each other's public key Y by ensuring that
1 < Y < p-1.  This simple check ensures that the remote peer is properly
behaved and isn't forcing the local system into a small subgroup.

Additionally, using a fresh key for each handshake provides Perfect
Forward Secrecy. Implementations SHOULD generate a new X for each
handshake when using DHE cipher suites.

###  Version Rollback Attacks

Because TLS includes substantial improvements over SSL Version 2.0, attackers
may try to make TLS-capable clients and servers fall back to Version 2.0. This
attack can occur if (and only if) two TLS-capable parties use an SSL 2.0
handshake. (See also {{backwards-compatibility-security-restrictions}}.)

Although the solution using non-random PKCS #1 block type 2 message padding is
inelegant, it provides a reasonably secure way for Version 3.0 servers to
detect the attack. This solution is not secure against attackers who can
brute-force the key and substitute a new ENCRYPTED-KEY-DATA message containing
the same key (but with normal padding) before the application-specified wait
threshold has expired. Altering the padding of the least-significant 8 bytes of
the PKCS padding does not impact security for the size of the signed hashes and
RSA key lengths used in the protocol, since this is essentially equivalent to
increasing the input block size by 8 bytes.

###  Detecting Attacks Against the Handshake Protocol

An attacker might try to influence the handshake exchange to make the parties
select different encryption algorithms than they would normally choose.

For this attack, an attacker must actively change one or more handshake
messages. If this occurs, the client and server will compute different values
for the handshake message hashes. As a result, the parties will not accept each
others' Finished messages. Without the static secret, the attacker cannot
repair the Finished messages, so the attack will be discovered.


## Protecting Application Data

The shared secrets are hashed with the handshake transcript
to produce unique record protection secrets for each connection.

Outgoing data is protected using an AEAD algorithm before transmission. The
authentication data includes the sequence number, message type, message length,
and the message contents. The message type field is necessary to ensure that messages
intended for one TLS record layer client are not redirected to another. The
sequence number ensures that attempts to delete or reorder messages will be
detected. Since sequence numbers are 64 bits long, they should never overflow.
Messages from one party cannot be inserted into the other's output, since they
use independent keys.


## Denial of Service against TLS 

TLS is susceptible to a number of denial-of-service (DoS) attacks. In
particular, an attacker who initiates a large number of TCP connections can
cause a server to consume large amounts of CPU doing asymmetric crypto
operations. However, because TLS is generally used over TCP, it is difficult for the
attacker to hide their point of origin if proper TCP SYN randomization is used
{{RFC1948}} by the TCP stack.

Because TLS runs over TCP, it is also susceptible to a number of DoS attacks on
individual connections. In particular, attackers can forge RSTs, thereby
terminating connections, or forge partial TLS records, thereby causing the
connection to stall. These attacks cannot in general be defended against by a
TCP-using protocol. Implementors or users who are concerned with this class of
attack should use IPsec AH {{RFC4302}} or ESP {{RFC4303}}.


## Final Notes

For TLS to be able to provide a secure connection, both the client and server
systems, keys, and applications must be secure. In addition, the implementation
must be free of security errors.

The system is only as strong as the weakest key exchange and authentication
algorithm supported, and only trustworthy cryptographic functions should be
used. Short public keys and anonymous servers should be used with great
caution. Implementations and users must be careful when deciding which
certificates and certificate authorities are acceptable; a dishonest
certificate authority can do tremendous damage.


# Working Group Information

The discussion list for the IETF TLS working group is located at the e-mail
address <tls@ietf.org>. Information on the group and information on how to
subscribe to the list is at <https://www1.ietf.org/mailman/listinfo/tls>

Archives of the list can be found at:
<https://www.ietf.org/mail-archive/web/tls/current/index.html>


# Contributors

* Martin Abadi \\
  University of California, Santa Cruz \\
  abadi@cs.ucsc.edu

* Christopher Allen (co-editor of TLS 1.0) \\
  Alacrity Ventures \\
  ChristopherA@AlacrityManagement.com

* Steven M. Bellovin \\
  Columbia University \\
  smb@cs.columbia.edu

* David Benjamin \\
  Google \\
  davidben@google.com

* Benjamin Beurdouche

* Karthikeyan Bhargavan (co-author of [RFC7627]) \\
  INRIA \\
  karthikeyan.bhargavan@inria.fr

* Simon Blake-Wilson (co-author of [RFC4492]) \\
  BCI \\
  sblakewilson@bcisse.com

* Nelson Bolyard (co-author of [RFC4492]) \\
  Sun Microsystems, Inc. \\
  nelson@bolyard.com

* Ran Canetti \\
  IBM \\
  canetti@watson.ibm.com

* Pete Chown \\
  Skygate Technology Ltd \\
  pc@skygate.co.uk

* Antoine Delignat-Lavaud (co-author of [RFC7627]) \\
  INRIA \\
  antoine.delignat-lavaud@inria.fr

* Tim Dierks (co-editor of TLS 1.0, 1.1, and 1.2) \\
  Independent \\
  tim@dierks.org

* Taher Elgamal \\
  Securify \\
  taher@securify.com

* Pasi Eronen \\
  Nokia \\
  pasi.eronen@nokia.com

* Cedric Fournet \\
  Microsoft \\
  fournet@microsoft.com

* Anil Gangolli \\
  anil@busybuddha.org

* David M. Garrett

* Vipul Gupta (co-author of [RFC4492]) \\
  Sun Microsystems Laboratories \\
  vipul.gupta@sun.com

* Chris Hawk (co-author of [RFC4492]) \\
  Corriente Networks LLC \\
  chris@corriente.net

* Kipp Hickman

* Alfred Hoenes

* David Hopwood \\
  Independent Consultant \\
  david.hopwood@blueyonder.co.uk


* Subodh Iyengar \\
  Facebook \\
  subodh@fb.com

* Daniel Kahn Gillmor \\
  ACLU \\
  dkg@fifthhorseman.net

* Phil Karlton (co-author of SSL 3.0)

* Paul Kocher (co-author of SSL 3.0) \\
  Cryptography Research \\
  paul@cryptography.com

* Hugo Krawczyk \\
  IBM \\
  hugo@ee.technion.ac.il

* Adam Langley (co-author of [RFC7627]) \\
  Google \\
  agl@google.com

* Ilari Liusvaara \\
  Independent \\
  ilariliusvaara@welho.com

* Jan Mikkelsen \\
  Transactionware \\
  janm@transactionware.com

* Bodo Moeller (co-author of [RFC4492]) \\
  Google \\
  bodo@openssl.org

* Erik Nygren \\
  Akamai Technologies \\
  erik+ietf@nygren.org

* Magnus Nystrom \\
  RSA Security \\
  magnus@rsasecurity.com

* Alfredo Pironti (co-author of [RFC7627]) \\
  INRIA \\
  alfredo.pironti@inria.fr

* Andrei Popov \\
  Microsoft \\
  andrei.popov@microsoft.com

* Marsh Ray (co-author of [RFC7627]) \\
  Microsoft \\
  maray@microsoft.com

* Robert Relyea \\
  Netscape Communications \\
  relyea@netscape.com

* Kyle Rose \\
  Akamai Technologies \\
  krose@krose.org

* Jim Roskind \\
  Netscape Communications \\
  jar@netscape.com

* Michael Sabin

* Dan Simon \\
  Microsoft, Inc. \\
  dansimon@microsoft.com

* Nick Sullivan \\
  CloudFlare Inc. \\
  nick@cloudflare.com

* Bjoern Tackmann \\
  University of California, San Diego \\
  btackmann@eng.ucsd.edu

* Martin Thomson \\
  Mozilla \\
  mt@mozilla.com

* Tom Weinstein

* Hoeteck Wee \\
  Ecole Normale Superieure, Paris \\
  hoeteck@alum.mit.edu

* Tim Wright \\
  Vodafone \\
  timothy.wright@vodafone.com

* Nagendra Modadugu (co-author of {{RFC6347}})\\
   Google, Inc.\\
   nagendra@cs.stanford.edu
