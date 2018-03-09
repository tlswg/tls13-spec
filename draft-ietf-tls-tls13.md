---
title: The Transport Layer Security (TLS) Protocol Version 1.3
abbrev: TLS
docname: draft-ietf-tls-tls13-latest
category: std
updates: 4492, 5705, 6066
obsoletes: 5077, 5246, 6961

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
  RFC5280:
  RFC5869:
  RFC6066:
  RFC6655:
  RFC7539:
  RFC7748:
  RFC7919:
  RFC8032:
  RFC8017:
  RFC8126:
  RFC8174:
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
  GCM:
        title: "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC"
        date: 2007-11
        author:
          - ins: M. Dworkin
        seriesinfo:
          NIST: Special Publication 800-38D

informative:
  RFC4086:
  RFC4346:
  RFC4366:
  RFC4492:
  RFC5077:
  RFC5116:
  RFC5246:
  RFC5764:
  RFC5929:
  RFC6176:
  RFC6091:
  RFC6520:
  RFC8305:
  RFC7230:
  RFC7250:
  RFC7465:
  RFC7568:
  RFC7627:
  RFC7685:

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
  CHHSV17:
       title: "Awkward Handshake: Possible mismatch of client/server view on client authentication in post-handshake mode in Revision 18"
       date: 2017
       target: https://www.ietf.org/mail-archive/web/tls/current/msg22382.html
       author:
       -
         ins: C. Cremers
       -
         ins: M. Horvat
       -
         ins: J. Hoyland
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
  AEAD-LIMITS:
       title: "Limits on Authenticated Encryption Use in TLS"
       author:
       -
         ins: A. Luykx
       -
         ins: K. Paterson
       target: http://www.isg.rhul.ac.uk/~kp/TLS-AEbounds.pdf
       date: 2016
  CK01:
       title: "Analysis of Key-Exchange Protocols and Their Use for Building Secure Channels"
       author:
       -
         ins: R. Canetti
       -
         ins: H. Krawczyk
       seriesinfo: Proceedings of Eurocrypt 2001
       date: 2001
  CCG16:
       title: "On Post-Compromise Security"
       author:
       -
         ins: K. Cohn-Gordon
       -
         ins: C. Cremers
       -
         ins: L. Garratt
       seriesinfo: IEEE Computer Security Foundations Symposium
       date: 2015
  BBFKZG16:
       title: "Downgrade Resilience in Key-Exchange Protocols"
       author:
       -
         ins: K. Bhargavan
       -
         ins: C. Brzuska
       -
         ins: C. Fournet
       -
         ins: M. Kohlweiss
       -
         ins: S. Zanella-Beguelin
       -
         ins: M. Green
       seriesinfo: Proceedings of IEEE Symposium on Security and Privacy (Oakland) 2016
       date: 2016
  DOW92:
       title: "Authentication and authenticated key exchanges"
       author:
       -
         ins: W. Diffie
       -
         ins: P. van Oorschot
       -
         ins: M. Wiener
       seriesinfo: Designs, Codes and Cryptography
       date: 1992
  HGFS15:
       title: "Prying Open Pandora's Box: KCI Attacks against TLS"
       author:
       -
         ins: C. Hlauschek
       -
         ins: M. Gruber
       -
         ins: F. Fankhauser
       -
         ins: C. Schanes
       seriesinfo: Proceedings of USENIX Workshop on Offensive Technologies
       date: 2015
  SIGMA:
       title: "SIGMA: the 'SIGn-and-MAc' approach to authenticated Diffie-Hellman and its use in the IKE protocols"
       author:
       -
         ins: H. Krawczyk
       seriesinfo: Proceedings of CRYPTO 2003
       date: 2003
  CHSV16:
       title: "Automated Analysis and Verification of TLS 1.3: 0-RTT, Resumption and Delayed Authentication"
       author:
       -
         ins: C. Cremers
       -
         ins: M. Horvat
       -
         ins: S. Scott
       -
         ins: T. van der Merwe
       seriesinfo: Proceedings of IEEE Symposium on Security and Privacy (Oakland) 2016
       target: http://ieeexplore.ieee.org/document/7546518/
       date: 2016
  FGSW16:
       title: "Key Confirmation in Key Exchange: A Formal Treatment and Implications for TLS 1.3"
       author:
       -
         ins: M. Fischlin
       -
         ins: F. Guenther
       -
         ins: B. Schmidt
       -
         ins: B. Warinschi
       seriesinfo: Proceedings of IEEE Symposium on Security and Privacy (Oakland) 2016
       target: http://ieeexplore.ieee.org/document/7546517/
       date: 2016
  LXZFH16:
       title: "Multiple Handshakes Security of TLS 1.3 Candidates"
       author:
       -
         ins: X. Li
       -
         ins: J. Xu
       -
         ins: D. Feng
       -
         ins: Z. Zhang
       -
         ins: H. Hu
       seriesinfo: Proceedings of IEEE Symposium on Security and Privacy (Oakland) 2016
       target: http://ieeexplore.ieee.org/document/7546519/
       date: 2016
  FW15:
       title: "Factoring RSA Keys With TLS Perfect Forward Secrecy"
       author:
       -
         ins: Florian Weimer
         org: Red Hat Product Security
       date: 2015-09
  REKEY:
      title: "Increasing the Lifetime of a Key: A Comparative Analysis of the Security of Re-keying Techniques"
      author:
      -
        ins: M. Abdalla
      -
        ins: M. Bellare
      seriesinfo: ASIACRYPT2000
      date: 2000-10
  BDFKPPRSZZ16:
      title: "Implementing and Proving the TLS 1.3 Record Layer"
      author:
      -
        ins: K. Bhargavan
      -
        ins: A. Delignat-Lavaud
      -
        ins: C. Fournet
      -
        ins: M. Kohlweiss
      -
        ins: J. Pan
      -
        ins: J. Protzenko
      -
        ins: A. Rastogi
      -
        ins: N. Swamy
      -
        ins: S. Zanella-Beguelin
      -
        ins: J.K. Zinzindohoue
      seriesinfo: Proceedings of IEEE Symposium on Security and Privacy (Oakland) 2017
      date: 2016-12
      target: https://eprint.iacr.org/2016/1178

  BMMT15:
      title: "Augmented Secure Channels and the Goal of the TLS 1.3 Record Layer"
      author:
      -
        ins: C. Badertscher
      -
        ins: C. Matt
      -
        ins: U. Maurer
      -
        ins: B. Tackmann
      seriesinfo: ProvSec 2015
      date: 2015-09
      target: https://eprint.iacr.org/2015/394

  BT16:
      title: "The Multi-User Security of Authenticated Encryption: AES-GCM in TLS 1.3"
      author:
      -
        ins: M. Bellare
      -
        ins: B. Tackmann
      seriesinfo: Proceedings of CRYPTO 2016
      date: 2016
      target: https://eprint.iacr.org/2016/564

  Kraw16:
       title: "A Unilateral-to-Mutual Authentication Compiler for Key Exchange (with Applications to Client Authentication in TLS 1.3"
       date: 2016
       seriesinfo: Proceedings of ACM CCS 2016
       target: https://eprint.iacr.org/2016/711
       author:
       -
         ins: H. Krawczyk

  KW16:
       title: "The OPTLS Protocol and TLS 1.3"
       date: 2016
       seriesinfo: Proceedings of Euro S&quot;P 2016
       target: https://eprint.iacr.org/2015/978
       author:
       -
         ins: H. Krawczyk
       -
         ins: H. Wee

  DFGS15:
       title: "A Cryptographic Analysis of the TLS 1.3 draft-10 Full and Pre-shared Key Handshake Protocol"
       date: 2015
       seriesinfo: Proceedings of ACM CCS 2015
       target: https://eprint.iacr.org/2015/914
       author:
       -
         ins: B. Dowling
       -
         ins: M. Fischlin
       -
         ins: F. Guenther
       -
         ins: D. Stebila

  DFGS16:
       title: "A Cryptographic Analysis of the TLS 1.3 draft-10 Full and Pre-shared Key Handshake Protocol"
       date: 2016
       seriesinfo: TRON 2016
       target: https://eprint.iacr.org/2016/081
       author:
       -
         ins: B. Dowling
       -
         ins: M. Fischlin
       -
         ins: F. Guenther
       -
         ins: D. Stebila

  FG17:
       title: "Replay Attacks on Zero Round-Trip Time: The Case of the TLS 1.3 Handshake Candidates"
       date: 2017
       seriesinfo: Proceedings of Euro S&quot;P 2017
       target: https://eprint.iacr.org/2017/082
       author:
       -
         ins: M. Fischlin
       -
         ins: F. Guenther

  BBK17:
       title: "Verified Models and Reference Implementations for the TLS 1.3 Standard Candidate"
       date: 2017
       seriesinfo: Proceedings of IEEE Symposium on Security and Privacy (Oakland) 2017
       author:
       -
         ins: K. Bhargavan
       -
         ins: B. Blanchet
       -
         ins: N. Kobeissi
  Kraw10:
       title: "Cryptographic Extraction and Key Derivation: The HKDF Scheme"
       date: 2010
       seriesinfo: Proceedings of CRYPTO 2010
       target: https://eprint.iacr.org/2010/264
       author:
       -
         ins: H. Krawczyk
  Mac17:
       title: "Security Review of TLS1.3 0-RTT"
       date: 2017
       target: https://github.com/tlswg/tls13-spec/issues/1001
       author:
       -
         ins: C. MacCarthaigh

  Res17a:
       title: Preliminary data on Firefox TLS 1.3 Middlebox experiment
       date: 2017
       target: https://www.ietf.org/mail-archive/web/tls/current/msg25091.html
       author:
       -
         ins: E. Rescorla

  Res17b:
       title: More compatibility measurement results
       date: 2017
       target: https://www.ietf.org/mail-archive/web/tls/current/msg25179.html
       author:
       -
         ins: E. Rescorla

  Ben17a:
       title: Presentation before the TLS WG at IETF 100
       date: 2017
       target: https://datatracker.ietf.org/meeting/100/materials/slides-100-tls-sessa-tls13/
       author:
       -
         ins: D. Benjamin

  Ben17b:
       title: Additional TLS 1.3 results from Chrome
       date: 2017
       target: https://www.ietf.org/mail-archive/web/tls/current/msg25168.html
       author:
       -
         ins: D. Benjamin

  JSS15:
       title: On the Security of TLS 1.3 and QUIC Against Weaknesses in PKCS#1 v1.5 Encryption
       date: 2015
       seriesinfo: Proceedings of ACM CCS 2015
       target: https://www.nds.rub.de/media/nds/veroeffentlichungen/2015/08/21/Tls13QuicAttacks.pdf
       author:
       -
         ins: T. Jager
       -
         ins: J. Schwenk
       -
         ins: J. Somorovsky

  Anon18:
       title: "Secure Channels for Multiplexed Data Streams: Analyzing the TLS 1.3 Record Layer Without Elision"
       date: 2018
       seriesinfo: "In submission to CRYPTO 2018. RFC EDITOR: PLEASE UPDATE THIS
       REFERENCE AFTER FINAL NOTIFICATION (2018-4-29)."
       author:
       -
         ins: A. Anonymous

--- abstract

This document specifies version 1.3 of the Transport Layer Security
(TLS) protocol.  TLS allows client/server applications to
communicate over the Internet in a way that is designed to prevent eavesdropping,
tampering, and message forgery.

This document updates RFCs 4492, 5705, and 6066 and it obsoletes
RFCs 5077, 5246, and 6961.
--- middle


#  Introduction

RFC EDITOR: PLEASE REMOVE THE FOLLOWING PARAGRAPH
The source for this draft is maintained in GitHub. Suggested changes
should be submitted as pull requests at
https://github.com/tlswg/tls13-spec. Instructions are on that page as
well. Editorial changes can be managed in GitHub, but any substantive
change should be discussed on the TLS mailing list.

The primary goal of TLS is to provide a secure channel between two
communicating peers; the only requirement from the underlying
transport is a reliable, in-order, data stream. Specifically, the
secure channel should provide the following properties:

- Authentication: The server side of the channel is always
  authenticated; the client side is optionally
  authenticated. Authentication can happen via asymmetric cryptography
  (e.g., RSA {{RSA}}, ECDSA {{ECDSA}}, EdDSA {{RFC8032}}) or a pre-shared key (PSK).

- Confidentiality: Data sent over the channel after establishment
  is only visible to the
  endpoints. TLS does not hide the length of the data it transmits,
  though endpoints are able to pad TLS records in order to obscure lengths
  and improve protection against traffic analysis techniques.

- Integrity: Data sent over the channel after establishment cannot be
  modified by attackers.

These properties should be true even in the face of an attacker who has complete
control of the network, as described in {{?RFC3552}}.
See {{security-analysis}} for a more complete statement of the relevant security
properties.

TLS consists of two primary components:

- A handshake protocol ({{handshake-protocol}}) that authenticates the communicating parties,
  negotiates cryptographic modes and parameters, and establishes
  shared keying material. The handshake protocol is designed to
  resist tampering; an active attacker should not be able to force
  the peers to negotiate different parameters than they would
  if the connection were not under attack.

- A record protocol ({{record-protocol}}) that uses the parameters established by the
  handshake protocol to protect traffic between the communicating
  peers. The record protocol divides traffic up into a series of
  records, each of which is independently protected using the
  traffic keys.

TLS is application protocol independent; higher-level protocols can
layer on top of TLS transparently. The TLS standard, however, does not
specify how protocols add security with TLS; how to
initiate TLS handshaking and how to interpret the authentication
certificates exchanged are left to the judgment of the designers and
implementors of protocols that run on top of TLS.

This document defines TLS version 1.3. While TLS 1.3 is not directly
compatible with previous versions, all versions of TLS incorporate a
versioning mechanism which allows clients and servers to interoperably
negotiate a common version if one is supported by both peers.

This document supersedes and obsoletes previous versions of TLS
including version 1.2 {{RFC5246}}.  It also obsoletes the TLS ticket
mechanism defined in {{RFC5077}} and replaces it with the mechanism
defined in {{resumption-and-psk}}. {{negotiated-groups}} updates
{{RFC4492}} by modifying the protocol attributes used to negotiate
Elliptic Curves.  Because TLS 1.3 changes the way keys are derived, it
updates {{RFC5705}} as described in {{exporters}}.  It also changes
how OCSP messages are carried and therefore updates {{RFC6066}}
and obsoletes {{RFC6961}} as described in section {{ocsp-and-sct}}.


##  Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}}
when, and only when, they appear in all capitals, as shown here.

The following terms are used:

client: The endpoint initiating the TLS connection.

connection: A transport-layer connection between two endpoints.

endpoint: Either the client or server of the connection.

handshake: An initial negotiation between client and server that establishes the parameters of their subsequent interactions within TLS.

peer: An endpoint. When discussing a particular endpoint, "peer" refers to the endpoint that is not the primary subject of discussion.

receiver: An endpoint that is receiving records.

sender: An endpoint that is transmitting records.

server: The endpoint which did not initiate the TLS connection.


##  Change Log

RFC EDITOR PLEASE DELETE THIS SECTION.


(*) indicates changes to the wire protocol which may require implementations
    to update.

draft-26

- Clarify that you can't negotiate pre-TLS 1.3 with supported_versions.

draft-25

- Add the header to additional data (*)

- Minor clarifications.

- IANA cleanup.

draft-24

- Require that CH2 have version 0303 (*)

- Some clarifications

draft-23

- Renumber key_share (*)

- Add a new extension and new code points to allow negotiating PSS
  separately for certificates and CertificateVerify (*)

- Slightly restrict when CCS must be accepted to make implementation
  easier.

- Document protocol invariants

- Add some text on the security of static RSA.

draft-22

- Implement changes for improved middlebox penetration (*)

- Move server_certificate_type to encrypted extensions (*)

- Allow resumption with a different SNI (*)

- Padding extension can change on HRR (*)

- Allow an empty ticket_nonce (*)

- Remove requirement to immediately respond to close_notify with
  close_notify (allowing half-close)

draft-21

- Add a per-ticket nonce so that each ticket is associated with a
  different PSK (*).

- Clarify that clients should send alerts with the handshake key
  if possible.

- Update state machine to show rekeying events

- Add discussion of 0-RTT and replay. Recommend that implementations
  implement some anti-replay mechanism.

draft-20

- Add "post_handshake_auth" extension to negotiate post-handshake authentication
  (*).

- Shorten labels for HKDF-Expand-Label so that we can fit within one
  compression block (*).

- Define how RFC 7250 works (*).

- Re-enable post-handshake client authentication even when you do PSK.
  The previous prohibition was editorial error.

- Remove cert_type and user_mapping, which don't work on TLS 1.3 anyway.

- Added the no_application_protocol alert from {{!RFC7301}} to the list
  of extensions.

- Added discussion of traffic analysis and side channel attacks.

draft-19

- Hash context_value input to Exporters (*)

- Add an additional Derive-Secret stage to Exporters (*).

- Hash ClientHello1 in the transcript when HRR is used. This
  reduces the state that needs to be carried in cookies. (*)

- Restructure CertificateRequest to have the selectors
  in extensions. This also allowed defining a "certificate_authorities"
  extension which can be used by the client instead of trusted_ca_keys (*).

- Tighten record framing requirements and require checking of them (*).

- Consolidate "ticket_early_data_info" and "early_data" into a single
  extension (*).

- Change end_of_early_data to be a handshake message (*).

- Add pre-extract Derive-Secret stages to key schedule (*).

- Remove spurious requirement to implement "pre_shared_key".

- Clarify location of "early_data" from server (it goes in EE,
  as indicated by the table in S 10).

- Require peer public key validation

- Add state machine diagram.


draft-18

- Remove unnecessary resumption_psk which is the only thing expanded from
  the resumption master secret. (*).

- Fix signature_algorithms entry in extensions table.

- Restate rule from RFC 6066 that you can't resume unless SNI is the same.


draft-17

- Remove 0-RTT Finished and resumption_context, and replace with a
  psk_binder field in the PSK itself (*)

- Restructure PSK key exchange negotiation modes (*)

- Add max_early_data_size field to TicketEarlyDataInfo (*)

- Add a 0-RTT exporter and change the transcript for the regular exporter (*)

- Merge TicketExtensions and Extensions registry. Changes
  ticket_early_data_info code point (*)

- Replace Client.key_shares in response to HRR (*)

- Remove redundant labels for traffic key derivation (*)

- Harmonize requirements about cipher suite matching: for resumption you
  need to match KDF but for 0-RTT you need whole cipher suite. This
  allows PSKs to actually negotiate cipher suites. (*)

- Move SCT and OCSP into Certificate.extensions (*)

- Explicitly allow non-offered extensions in NewSessionTicket

- Explicitly allow predicting client Finished for NST

- Clarify conditions for allowing 0-RTT with PSK


draft-16

- Revise version negotiation (*)

- Change RSASSA-PSS and EdDSA SignatureScheme codepoints for better backwards compatibility (*)

- Move HelloRetryRequest.selected_group to an extension (*)

- Clarify the behavior of no exporter context and make it the same
  as an empty context.(*)

- New KeyUpdate format that allows for requesting/not-requesting an
  answer. This also means changes to the key schedule to support
  independent updates (*)

- New certificate_required alert (*)

- Forbid CertificateRequest with 0-RTT and PSK.

- Relax requirement to check SNI for 0-RTT.


draft-15

- New negotiation syntax as discussed in Berlin (*)

- Require CertificateRequest.context to be empty during handshake (*)

- Forbid empty tickets (*)

- Forbid application data messages in between post-handshake messages
  from the same flight (*)

- Clean up alert guidance (*)

- Clearer guidance on what is needed for TLS 1.2.

- Guidance on 0-RTT time windows.

- Rename a bunch of fields.

- Remove old PRNG text.

- Explicitly require checking that handshake records not span
  key changes.



draft-14

- Allow cookies to be longer (*)

- Remove the "context" from EarlyDataIndication as it was undefined
  and nobody used it (*)

- Remove 0-RTT EncryptedExtensions and replace the ticket_age extension
  with an obfuscated version. Also necessitates a change to
  NewSessionTicket (*).

- Move the downgrade sentinel to the end of ServerHello.Random
  to accommodate tlsdate (*).

- Define ecdsa_sha1 (*).

- Allow resumption even after fatal alerts. This matches current
  practice.

- Remove non-closure warning alerts. Require treating unknown alerts as
  fatal.

- Make the rules for accepting 0-RTT less restrictive.

- Clarify 0-RTT backward-compatibility rules.

- Clarify how 0-RTT and PSK identities interact.

- Add a section describing the data limits for each cipher.

- Major editorial restructuring.

- Replace the Security Analysis section with a WIP draft.


draft-13

- Allow server to send SupportedGroups.

- Remove 0-RTT client authentication

- Remove (EC)DHE 0-RTT.

- Flesh out 0-RTT PSK mode and shrink EarlyDataIndication

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

- Increment version number.

- Rework handshake to provide 1-RTT mode.

- Remove custom DHE groups.

- Remove support for compression.

- Remove support for static RSA and DH key exchange.

- Remove support for non-AEAD ciphers.


##  Major Differences from TLS 1.2

The following is a list of the major functional differences between
TLS 1.2 and TLS 1.3. It is not intended to be exhaustive and there
are many minor differences.

- The list of supported symmetric algorithms has been pruned of all algorithms that
  are considered legacy. Those that remain all use Authenticated Encryption
  with Associated Data (AEAD) algorithms. The ciphersuite concept has been
  changed to separate the authentication and key exchange mechanisms from
  the record protection algorithm (including secret key length) and a hash
  to be used with the key derivation function and HMAC.

- A 0-RTT mode was added, saving a round-trip at connection setup for
  some application data, at the cost of certain security properties.

- Static RSA and Diffie-Hellman cipher suites have been removed;
  all public-key based key exchange mechanisms now provide forward secrecy.

- All handshake messages after the ServerHello are now encrypted. The
  newly introduced EncryptedExtension message allows various extensions
  previously sent in clear in the ServerHello to also enjoy
  confidentiality protection from active attackers.

- The key derivation functions have been re-designed. The new design allows
  easier analysis by cryptographers due to their improved key separation
  properties. The HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
  is used as an underlying primitive.

- The handshake state machine has been significantly restructured to
  be more consistent and to remove superfluous messages such as
  ChangeCipherSpec (except when needed for middlebox compatibility).

- Elliptic curve algorithms are now in the base spec and new signature
  algorithms, such as ed25519 and ed448, are included. TLS 1.3 removed point format
  negotiation in favor of a single point format for each curve.

- Other cryptographic improvements including the removal of compression and
  custom DHE groups, changing the RSA padding to use RSASSA-PSS, and the removal of
  DSA.

- The TLS 1.2 version negotiation mechanism has been deprecated in favor
  of a version list in an extension. This increases compatibility with
  existing servers that incorrectly implemented version negotiation.

- Session resumption with and without server-side state as well as the
  PSK-based ciphersuites of earlier TLS versions have been replaced by a
  single new PSK exchange.

- Updated references to point to the updated versions of RFCs, as
  appropriate (e.g., RFC 5280 rather than RFC 3280).


## Updates Affecting TLS 1.2

This document defines several changes that optionally affect implementations of
TLS 1.2:

* A version downgrade protection mechanism is described in {{server-hello}}.

* RSASSA-PSS signature schemes are defined in {{signature-algorithms}}.

* The "supported_versions" ClientHello extension can be used to negotiate
  the version of TLS to use, in preference to the legacy_version field of
  the ClientHello.

* The "signature_algorithms_cert" extension allows a client to indicate
  which signature algorithms it can validate in X.509 certificates

An implementation of TLS 1.3 that also supports TLS 1.2 might need to include
changes to support these changes even when TLS 1.3 is not in use.  See the
referenced sections for more details.

Additionally, this document clarifies some compliance requirements for earlier
versions of TLS; see {{protocol-invariants}}.


# Protocol Overview

The cryptographic parameters used by the secure channel are produced by the
TLS handshake protocol. This sub-protocol of TLS is used by the client
and server when first communicating with each other.
The handshake protocol allows peers to negotiate a protocol version,
select cryptographic algorithms, optionally authenticate each other,
and establish shared secret keying material.
Once the handshake is complete, the peers use the established keys
to protect the application layer traffic.

A failure of the handshake or other protocol error triggers the
termination of the connection, optionally preceded by an alert message
({{alert-protocol}}).

TLS supports three basic key exchange modes:

- (EC)DHE (Diffie-Hellman over either finite fields or elliptic curves)

- PSK-only

- PSK with (EC)DHE

{{tls-full}} below shows the basic full TLS handshake:

~~~
       Client                                               Server

Key  ^ ClientHello
Exch | + key_share*
     | + signature_algorithms*
     | + psk_key_exchange_modes*
     v + pre_shared_key*         -------->
                                                       ServerHello  ^ Key
                                                      + key_share*  | Exch
                                                 + pre_shared_key*  v
                                             {EncryptedExtensions}  ^  Server
                                             {CertificateRequest*}  v  Params
                                                    {Certificate*}  ^
                                              {CertificateVerify*}  | Auth
                                                        {Finished}  v
                                 <--------     [Application Data*]
     ^ {Certificate*}
Auth | {CertificateVerify*}
     v {Finished}                -------->
       [Application Data]        <------->      [Application Data]

              +  Indicates noteworthy extensions sent in the
                 previously noted message.

              *  Indicates optional or situation-dependent
                 messages/extensions that are not always sent.

              {} Indicates messages protected using keys
                 derived from a [sender]_handshake_traffic_secret.

              [] Indicates messages protected using keys
                 derived from [sender]_application_traffic_secret_N
~~~
{: #tls-full title="Message flow for full TLS Handshake"}

The handshake can be thought of as having three phases (indicated
in the diagram above):

- Key Exchange: Establish shared keying material and select the
   cryptographic parameters. Everything after this phase is
   encrypted.

- Server Parameters: Establish other handshake parameters
   (whether the client is authenticated, application layer protocol support, etc.).

- Authentication: Authenticate the server (and optionally the client)
   and provide key confirmation and handshake integrity.

In the Key Exchange phase, the client sends the ClientHello
({{client-hello}}) message, which contains a random nonce
(ClientHello.random); its offered protocol versions; a list of
symmetric cipher/HKDF hash pairs; either a set of Diffie-Hellman key shares (in the
"key_share" extension {{key-share}}), a set of pre-shared key labels (in the
"pre_shared_key" extension {{pre-shared-key-extension}}) or both; and
potentially additional extensions.  Additional fields and/or messages
may also be present for middlebox compatibility.

The server processes the ClientHello and determines the appropriate
cryptographic parameters for the connection. It then responds with its
own ServerHello ({{server-hello}}), which indicates the negotiated connection
parameters. The combination of the ClientHello
and the ServerHello determines the shared keys. If (EC)DHE
key establishment is in use, then the ServerHello
contains a "key_share" extension with the server's ephemeral
Diffie-Hellman share which MUST be in the same group as one of the
client's shares. If PSK key establishment is
in use, then the ServerHello contains a "pre_shared_key"
extension indicating which of the client's offered PSKs was selected.
Note that implementations can use (EC)DHE and PSK together, in which
case both extensions will be supplied.

The server then sends two messages to establish the Server Parameters:

EncryptedExtensions:
: responses to ClientHello extensions that are not required to
  determine the cryptographic parameters, other than those
  that are specific to individual certificates. \[{{encrypted-extensions}}]

CertificateRequest:
: if certificate-based client authentication is desired, the
  desired parameters for that certificate. This message is
  omitted if client authentication is not desired. \[{{certificate-request}}]

Finally, the client and server exchange Authentication messages. TLS
uses the same set of messages every time that certificate-based
authentication is needed.  (PSK-based authentication happens as a side
effect of key exchange.)
Specifically:

Certificate:
: the certificate of the endpoint and any per-certificate extensions.
  This message is omitted by the server if not authenticating with a
  certificate and by the client if the server did not send
  CertificateRequest (thus indicating that the client should not
  authenticate with a certificate). Note that if raw
  public keys {{RFC7250}} or the cached information extension
  {{?RFC7924}} are in use, then this message will not
  contain a certificate but rather some other value corresponding to
  the server's long-term key.  \[{{certificate}}]

CertificateVerify:
: a signature over the entire handshake using the private key
  corresponding to the public key in the Certificate message. This
  message is omitted if the endpoint is not authenticating via a
  certificate. \[{{certificate-verify}}]

Finished:
: a MAC (Message Authentication Code) over the entire handshake.
  This message provides key confirmation, binds the endpoint's identity
  to the exchanged keys, and in PSK mode
  also authenticates the handshake. \[{{finished}}]
{:br }

Upon receiving the server's messages, the client responds with its Authentication
messages, namely Certificate and CertificateVerify (if requested), and Finished.

At this point, the handshake is complete, and the client and server
derive the keying material required by the record layer to exchange
application-layer data protected through authenticated encryption.
Application data MUST NOT be sent prior to sending the Finished message,
except as specified
in \[{{zero-rtt-data}}].
Note that while the server may send application data prior to receiving
the client's Authentication messages, any data sent at that point is,
of course, being sent to an unauthenticated peer.


## Incorrect DHE Share

If the client has not provided a sufficient "key_share" extension (e.g., it
includes only DHE or ECDHE groups unacceptable to or unsupported by the
server), the server corrects the mismatch with a HelloRetryRequest and
the client needs to restart the handshake with an appropriate
"key_share" extension, as shown in Figure 2.
If no common cryptographic parameters can be negotiated,
the server MUST abort the handshake with an appropriate alert.

~~~
         Client                                               Server

         ClientHello
         + key_share             -------->
                                 <--------         HelloRetryRequest
                                                         + key_share

         ClientHello
         + key_share             -------->
                                                         ServerHello
                                                         + key_share
                                               {EncryptedExtensions}
                                               {CertificateRequest*}
                                                      {Certificate*}
                                                {CertificateVerify*}
                                                          {Finished}
                                 <--------       [Application Data*]
         {Certificate*}
         {CertificateVerify*}
         {Finished}              -------->
         [Application Data]      <------->        [Application Data]
~~~
{: #tls-restart title="Message flow for a full handshake with mismatched parameters"}

Note: The handshake transcript incorporates the initial
ClientHello/HelloRetryRequest exchange; it is not reset with the new
ClientHello.

TLS also allows several optimized variants of the basic handshake, as
described in the following sections.


## Resumption and Pre-Shared Key (PSK) {#resumption-and-psk}

Although TLS PSKs can be established out of band,
PSKs can also be established in a previous connection and
then used to establish a new session ("session resumption"). Once a handshake has completed, the server can
send to the client a PSK identity that corresponds to a unique key derived from
the initial handshake (see {{NSTMessage}}). The client
can then use that PSK identity in future handshakes to negotiate the use
of the associated PSK. If the server accepts the PSK, then the security context of the
new connection is cryptographically tied to the original connection and the key derived
from the initial handshake is used to bootstrap the cryptographic state
instead of a full handshake.
In TLS 1.2 and below, this functionality was provided by "session IDs" and
"session tickets" {{RFC5077}}. Both mechanisms are obsoleted in TLS 1.3.

PSKs can be used with (EC)DHE key exchange in order to provide forward
secrecy in combination with shared keys, or can be used alone, at the
cost of losing forward secrecy for the application data.

{{tls-resumption-psk}} shows a pair of handshakes in which the first establishes
a PSK and the second uses it:

~~~
       Client                                               Server

Initial Handshake:
       ClientHello
       + key_share               -------->
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
       + key_share*
       + pre_shared_key          -------->
                                                       ServerHello
                                                  + pre_shared_key
                                                      + key_share*
                                             {EncryptedExtensions}
                                                        {Finished}
                                 <--------     [Application Data*]
       {Finished}                -------->
       [Application Data]        <------->      [Application Data]
~~~
{: #tls-resumption-psk title="Message flow for resumption and PSK"}

As the server is authenticating via a PSK, it does not send a
Certificate or a CertificateVerify message. When a client offers resumption
via PSK, it SHOULD also supply a "key_share" extension to the server to
allow the server to decline resumption and fall back
to a full handshake, if needed. The server responds with a "pre_shared_key"
extension to negotiate use of PSK key establishment and can (as shown here)
respond with a "key_share" extension to do (EC)DHE key establishment, thus
providing forward secrecy.

When PSKs are provisioned out of band, the PSK identity and the KDF hash
algorithm to
be used with the PSK MUST also be provisioned.

Note:
: When using an out-of-band provisioned pre-shared secret, a critical
  consideration is using sufficient entropy during the key generation, as
  discussed in [RFC4086]. Deriving a shared secret from a password or other
  low-entropy sources is not secure. A low-entropy secret, or password, is
  subject to dictionary attacks based on the PSK binder.  The specified PSK
  authentication is not a strong password-based authenticated key exchange even
  when used with Diffie-Hellman key establishment.  Specifically, it does not
  prevent an attacker that can observe the handshake from performing
  a brute-force attack on the password/pre-shared key.


## 0-RTT Data {#zero-rtt-data}

When clients and servers share a PSK (either obtained externally or
via a previous handshake), TLS 1.3 allows clients to send data on the
first flight ("early data"). The client uses the PSK to authenticate
the server and to encrypt the early data.

As shown in {{tls-0-rtt}}, the 0-RTT data is just added to the 1-RTT
handshake in the first flight. The rest of the handshake uses the same messages
as for a 1-RTT handshake with PSK resumption.

~~~
         Client                                               Server

         ClientHello
         + early_data
         + key_share*
         + psk_key_exchange_modes
         + pre_shared_key
         (Application Data*)     -------->
                                                         ServerHello
                                                    + pre_shared_key
                                                        + key_share*
                                               {EncryptedExtensions}
                                                       + early_data*
                                                          {Finished}
                                 <--------       [Application Data*]
         (EndOfEarlyData)
         {Finished}              -------->

         [Application Data]      <------->        [Application Data]

               +  Indicates noteworthy extensions sent in the
                  previously noted message.

               *  Indicates optional or situation-dependent
                  messages/extensions that are not always sent.

               () Indicates messages protected using keys
                  derived from client_early_traffic_secret.

               {} Indicates messages protected using keys
                  derived from a [sender]_handshake_traffic_secret.

               [] Indicates messages protected using keys
                  derived from [sender]_application_traffic_secret_N
~~~
{: #tls-0-rtt title="Message flow for a zero round trip handshake"}


IMPORTANT NOTE: The security properties for 0-RTT data are weaker than
those for other kinds of TLS data.  Specifically:

1. This data is not forward secret, as it is encrypted solely under
keys derived using the offered PSK.

2. There are no guarantees of non-replay between connections.
Protection against replay for ordinary TLS 1.3 1-RTT data is
provided via the server's Random value, but 0-RTT data does not depend
on the ServerHello and therefore has weaker guarantees.  This is especially
relevant if the data is authenticated either with TLS client
authentication or inside the application protocol. The same warnings
apply to any use of the early_exporter_master_secret.

0-RTT data cannot be duplicated within a connection (i.e., the server will
not process the same data twice for the same connection) and an
attacker will not be able to make 0-RTT data appear to be 1-RTT data
(because it is protected with different keys.) {{replay-0rtt}}
contains a description of potential attacks and {{anti-replay}}
describes mechanisms which the server can use to limit the impact of
replay.


#  Presentation Language

This document deals with the formatting of data in an external representation.
The following very basic and somewhat casually defined presentation syntax will
be used.


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

A type alias T' for an existing type T is defined by:

       T T';

##  Vectors

A vector (single-dimensioned array) is a stream of homogeneous data elements.
The size of the vector may be specified at documentation time or left
unspecified until runtime. In either case, the length declares the number of
bytes, not the number of elements, in the vector. The syntax for specifying a
new type, T', that is a fixed-length vector of type T is

       T T'[n];

Here, T' occupies n bytes in the data stream, where n is a multiple of the size
of T.  The length of the vector is not included in the encoded stream.

In the following example, Datum is defined to be three consecutive bytes that
the protocol does not interpret, while Data is three consecutive Datum,
consuming a total of nine bytes.

       opaque Datum[3];      /* three uninterpreted bytes */
       Datum Data[9];        /* 3 consecutive 3-byte vectors */

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
(see {{numbers}}). Similarly, longer can represent up to 800 bytes of
data, or 400 uint16 elements, and it may be empty. Its encoding will include a
two-byte actual length field prepended to the vector. The length of an encoded
vector must be an exact multiple of the length of a single element (e.g.,
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

All values, here and elsewhere in the specification, are transmitted in network byte
(big-endian) order; the uint32 represented by the hex bytes 01 02 03 04 is
equivalent to the decimal value 16909060.


##  Enumerateds

An additional sparse data type is available called enum. Each definition is a
different type. Only enumerateds of the same type may be assigned or compared.
Every element of an enumerated must be assigned a value, as demonstrated in the
following example. Since the elements of the enumerated are not ordered, they
can be assigned any unique value, in any order.

       enum { e1(v1), e2(v2), ... , en(vn) [[, (n)]] } Te;

Future extensions or additions to the protocol may define new values.
Implementations need to be able to parse and ignore unknown values unless the
definition of the field states otherwise.

An enumerated occupies as much space in the byte stream as would its maximal
defined ordinal value. The following definition would cause one byte to be used
to carry fields of type Color.

       enum { red(3), blue(5), white(7) } Color;

One may optionally specify a value without its associated tag to force the
width definition without defining a superfluous element.

In the following example, Taste will consume two bytes in the data stream but
can only assume the values 1, 2, or 4 in the current version of the protocol.

       enum { sweet(1), sour(2), bitter(4), (32000) } Taste;

The names of the elements of an enumeration are scoped within the defined type.
In the first example, a fully qualified reference to the second element of the
enumeration would be Color.blue. Such qualification is not required if the
target of the assignment is well specified.

       Color color = Color.blue;     /* overspecified, legal */
       Color color = blue;           /* correct, type implicit */

The names assigned to enumerateds do not need to be unique.  The numerical value
can describe a range over which the same name applies.  The value includes the
minimum and maximum inclusive values in that range, separated by two period
characters. This is principally useful for reserving regions of the space.

       enum { sad(0), meh(1..254), happy(255) } Mood;


##  Constructed Types

Structure types may be constructed from primitive types for convenience. Each
specification declares a new, unique type. The syntax for definition is much
like that of C.

       struct {
           T1 f1;
           T2 f2;
           ...
           Tn fn;
       } T;

Fixed- and variable-length vector fields are allowed using the standard vector
syntax. Structures V1 and V2 in the variants example below demonstrate this.

The fields within a structure may be qualified using the type's name, with a
syntax much like that available for enumerateds. For example, T.f2 refers to
the second field of the previous declaration.


## Constants

Fields and variables may be assigned a fixed value using "=", as in:

       struct {
           T1 f1 = 8;  /* T.f1 must always be 8 */
           T2 f2;
       } T;


##  Variants

Defined structures may have variants based on some knowledge that is
available within the environment. The selector must be an enumerated
type that defines the possible variants the structure defines. Each
arm of the select specifies the type of that variant's field and an
optional field label. The mechanism by which the variant is selected
at runtime is not prescribed by the presentation language.

       struct {
           T1 f1;
           T2 f2;
           ....
           Tn fn;
           select (E) {
               case e1: Te1 [[fe1]];
               case e2: Te2 [[fe2]];
               ....
               case en: Ten [[fen]];
           };
       } Tv;

For example:

       enum { apple(0), orange(1) } VariantTag;

       struct {
           uint16 number;
           opaque string<0..10>; /* variable length */
       } V1;

       struct {
           uint32 number;
           opaque string[10];    /* fixed length */
       } V2;

       struct {
           VariantTag type;
           select (VariantRecord.type) {
               case apple:  V1;
               case orange: V2;
           };
       } VariantRecord;


# Handshake Protocol

The handshake protocol is used to negotiate the security parameters
of a connection. Handshake messages are supplied to the TLS record layer, where
they are encapsulated within one or more TLSPlaintext or TLSCiphertext structures, which are
processed and transmitted as specified by the current active connection state.

%%% Handshake Protocol

       enum {
           hello_request_RESERVED(0),
           client_hello(1),
           server_hello(2),
           hello_verify_request_RESERVED(3),
           new_session_ticket(4),
           end_of_early_data(5),
           hello_retry_request_RESERVED(6),
           encrypted_extensions(8),
           certificate(11),
           server_key_exchange_RESERVED(12),
           certificate_request(13),
           server_hello_done_RESERVED(14),
           certificate_verify(15),
           client_key_exchange_RESERVED(16),
           finished(20),
           key_update(24),
           message_hash(254),
           (255)
       } HandshakeType;

       struct {
           HandshakeType msg_type;    /* handshake type */
           uint24 length;             /* bytes in message */
           select (Handshake.msg_type) {
               case client_hello:          ClientHello;
               case server_hello:          ServerHello;
               case end_of_early_data:     EndOfEarlyData;
               case encrypted_extensions:  EncryptedExtensions;
               case certificate_request:   CertificateRequest;
               case certificate:           Certificate;
               case certificate_verify:    CertificateVerify;
               case finished:              Finished;
               case new_session_ticket:    NewSessionTicket;
               case key_update:            KeyUpdate;
           };
       } Handshake;

Protocol messages MUST be sent in the order defined in
{{the-transcript-hash}} and shown in the diagrams in {{protocol-overview}}.
A peer which receives a handshake message in an unexpected order
MUST abort the handshake with an "unexpected_message" alert.

New handshake message types are assigned by IANA as described in
{{iana-considerations}}.


## Key Exchange Messages

The key exchange messages are used to determine the security capabilities
of the client and the server and to establish shared secrets including
the traffic keys used to protect the rest of the handshake and the data.

### Cryptographic Negotiation

In TLS, the cryptographic negotiation proceeds by the client offering the
following four sets of options in its ClientHello:

- A list of cipher suites which indicates the AEAD algorithm/HKDF hash
  pairs which the client supports.
- A "supported_groups" ({{negotiated-groups}}) extension which indicates the (EC)DHE groups
  which the client supports and a "key_share" ({{key-share}}) extension which contains
  (EC)DHE shares for some or all of these groups.
- A "signature_algorithms" ({{signature-algorithms}}) extension which indicates the signature
  algorithms which the client can accept.
- A "pre_shared_key" ({{pre-shared-key-extension}}) extension which
  contains a list of symmetric key identities known to the client and a
  "psk_key_exchange_modes" ({{pre-shared-key-exchange-modes}})
  extension which indicates the key exchange modes that may be used
  with PSKs.

If the server does not select a PSK, then the first three of these
options are entirely orthogonal: the server independently selects a
cipher suite, an (EC)DHE group and key share for key establishment,
and a signature algorithm/certificate pair to authenticate itself to
the client. If there is no overlap between the received "supported_groups"
and the groups supported by the server then the server MUST abort the
handshake with a "handshake_failure" or an "insufficient_security" alert.

If the server selects a PSK, then it MUST also select a key
establishment mode from the set indicated by client's
"psk_key_exchange_modes" extension (at present, PSK alone or with (EC)DHE). Note
that if the PSK can be used without (EC)DHE then non-overlap in the
"supported_groups" parameters need not be fatal, as it is in the
non-PSK case discussed in the previous paragraph.

If the server selects an (EC)DHE group and the client did not offer a
compatible "key_share" extension in the initial ClientHello, the server MUST
respond with a HelloRetryRequest ({{hello-retry-request}}) message.

If the server successfully selects parameters and does not require a
HelloRetryRequest, it indicates the selected parameters in the ServerHello as
follows:

- If PSK is being used, then the server will send a
  "pre_shared_key" extension indicating the selected key.

- If PSK is not being used, then (EC)DHE and certificate-based
  authentication are always used.

- When (EC)DHE is in use, the server will also provide a
  "key_share" extension.

- When authenticating via a certificate, the server will send
  the Certificate ({{certificate}}) and CertificateVerify
  ({{certificate-verify}}) messages. In TLS 1.3
  as defined by this document, either a PSK or a certificate
  is always used, but not both. Future documents may define how
  to use them together.

If the server is unable to negotiate a supported set of parameters
(i.e., there is no overlap between the client and server parameters),
it MUST abort the handshake with either
a "handshake_failure" or "insufficient_security" fatal alert
(see {{alert-protocol}}).

###  Client Hello

When a client first connects to a server, it is REQUIRED to send the
ClientHello as its first TLS message. The client will also send a
ClientHello when the server has responded to its ClientHello with a
HelloRetryRequest. In that case, the client MUST send the same
ClientHello (without modification) except:

- If a "key_share" extension was supplied in the HelloRetryRequest,
  replacing the list of shares with a list containing a single
  KeyShareEntry from the indicated group.

- Removing the "early_data" extension ({{early-data-indication}}) if one was
  present. Early data is not permitted after HelloRetryRequest.

- Including a "cookie" extension if one was provided in the
  HelloRetryRequest.

- Updating the "pre_shared_key" extension if present by
  recomputing the "obfuscated_ticket_age" and binder values
  and (optionally) removing
  any PSKs which are incompatible with the server's indicated
  cipher suite.

- Optionally adding, removing, or changing the length of the "padding"
  extension {{RFC7685}}.

- Other modifications that may be allowed by an extension defined in the
  future and present in the HelloRetryRequest.

Because TLS 1.3 forbids renegotiation, if a server has negotiated TLS
1.3 and receives a ClientHello at any other time, it MUST terminate
the connection with an "unexpected_message" alert.

If a server established a TLS connection with a previous version of TLS
and receives a TLS 1.3 ClientHello in a renegotiation, it MUST retain the
previous protocol version. In particular, it MUST NOT negotiate TLS 1.3.

Structure of this message:

%%% Key Exchange Messages

       uint16 ProtocolVersion;
       opaque Random[32];

       uint8 CipherSuite[2];    /* Cryptographic suite selector */

       struct {
           ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
           Random random;
           opaque legacy_session_id<0..32>;
           CipherSuite cipher_suites<2..2^16-2>;
           opaque legacy_compression_methods<1..2^8-1>;
           Extension extensions<8..2^16-1>;
       } ClientHello;

legacy_version
: In previous versions of TLS, this field was used for version negotiation
  and represented the highest version number supported by the client.
  Experience has shown that many servers do not properly implement
  version negotiation, leading to "version intolerance" in which
  the server rejects an otherwise acceptable ClientHello with a version
  number higher than it supports.
  In TLS 1.3, the client indicates its version preferences in the
  "supported_versions" extension ({{supported-versions}}) and the legacy_version field MUST
  be set to 0x0303, which is the version number for TLS 1.2.
  (See {{backward-compatibility}} for details about backward compatibility.)

random
: 32 bytes generated by a secure random number generator.
  See {{implementation-notes}} for additional information.

legacy_session_id
: Versions of TLS before TLS 1.3 supported a "session resumption"
  feature which has been merged with Pre-Shared Keys in this version
  (see {{resumption-and-psk}}). A client which has a cached session ID
  set by a pre-TLS 1.3 server SHOULD set this field to that value. In
  compatibility mode (see {{middlebox}}) this field MUST be non-empty,
  so a client not offering a pre-TLS 1.3 session MUST generate a
  new 32-byte value. This value need not be random but SHOULD be
  unpredictable to avoid implementations fixating on a specific value
  (also known as ossification).
  Otherwise, it MUST be set as a zero length vector (i.e., a single
  zero byte length field).

cipher_suites
: This is a list of the symmetric cipher options supported by the
  client, specifically the record protection algorithm (including
  secret key length) and a hash to be used with HKDF, in descending
  order of client preference. If the list contains cipher suites that
  the server does not recognize, support or wish to use, the server
  MUST ignore those cipher suites and process the remaining ones as
  usual. Values are defined in {{cipher-suites}}. If the client is
  attempting a PSK key establishment, it SHOULD advertise at least one
  cipher suite indicating a Hash associated with the PSK.

legacy_compression_methods
: Versions of TLS before 1.3 supported compression with the list of
  supported compression methods being sent in this field. For every TLS 1.3
  ClientHello, this vector MUST contain exactly one byte set to
  zero, which corresponds to the "null" compression method in
  prior versions of TLS. If a TLS 1.3 ClientHello is
  received with any other value in this field, the server MUST
  abort the handshake with an "illegal_parameter" alert. Note that TLS 1.3
  servers might receive TLS 1.2 or prior ClientHellos which contain
  other compression methods and (if negotiating such a prior version)
  MUST follow the procedures for
  the appropriate prior version of TLS.  TLS 1.3 ClientHellos are identified
  as having a legacy_version of 0x0303 and a supported_versions extension
  present with 0x0304 as the highest version indicated therein.

extensions
: Clients request extended functionality from servers by sending
  data in the extensions field.  The actual "Extension" format is
  defined in {{extensions}}.  In TLS 1.3, use
  of certain extensions is mandatory, as functionality is moved into
  extensions to preserve ClientHello compatibility with previous versions of TLS.
  Servers MUST ignore unrecognized extensions.
{:br }

All versions of TLS allow an extensions field to optionally follow the
compression_methods field. TLS 1.3 ClientHello
messages always contain extensions (minimally "supported_versions", otherwise
they will be interpreted as TLS 1.2 ClientHello messages).
However, TLS 1.3 servers might receive ClientHello messages without an
extensions field from prior versions of TLS.
The presence of extensions can be detected by determining whether there
are bytes following the compression_methods field at the end of the
ClientHello. Note that this method of detecting optional data differs
from the normal TLS method of having a variable-length field, but it
is used for compatibility with TLS before extensions were defined.
TLS 1.3 servers will need to perform this check first and only
attempt to negotiate TLS 1.3 if the "supported_versions" extension
is present.
If negotiating a version of TLS prior to 1.3, a server MUST check that
the message either contains no data after legacy_compression_methods
or that it contains a valid extensions block with no data following.
If not, then it MUST abort the handshake with a "decode_error" alert.

In the event that a client requests additional functionality using
extensions, and this functionality is not supplied by the server, the
client MAY abort the handshake.

After sending the ClientHello message, the client waits for a ServerHello
or HelloRetryRequest message. If early data
is in use, the client may transmit early application data
({{zero-rtt-data}}) while waiting for the next handshake message.

### Server Hello {#server-hello}

The server will send this message in response to a ClientHello message
to proceed with the handshake if it is able to negotiate an acceptable
set of handshake parameters based on the ClientHello.

Structure of this message:

%%% Key Exchange Messages

       struct {
           ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
           Random random;
           opaque legacy_session_id_echo<0..32>;
           CipherSuite cipher_suite;
           uint8 legacy_compression_method = 0;
           Extension extensions<6..2^16-1>;
       } ServerHello;

legacy_version
: In previous versions of TLS, this field was used for version negotiation
  and represented the selected version number for the connection. Unfortunately,
  some middleboxes fail when presented with new values.
  In TLS 1.3, the TLS server indicates its version using the
  "supported_versions" extension ({{supported-versions}}),
  and the legacy_version field MUST
  be set to 0x0303, which is the version number for TLS 1.2.
  (See {{backward-compatibility}} for details about backward compatibility.)

random
: 32 bytes generated by a secure random number generator.
  See {{implementation-notes}} for additional information.
  The last eight bytes MUST be overwritten as described
  below if negotiating TLS 1.2 or TLS 1.1, but the
  remaining bytes MUST be random.
  This structure is generated by the server and MUST be
  generated independently of the ClientHello.random.

legacy_session_id_echo
: The contents of the client's legacy_session_id field. Note that
  this field is echoed even if the client's value corresponded to
  a cached pre-TLS 1.3 session which the server has chosen not
  to resume. A client which receives a legacy_session_id_echo field
  that does not match what it sent in the ClientHello
  MUST abort the handshake with an "illegal_parameter"
  alert.

cipher_suite
: The single cipher suite selected by the server from the list in
  ClientHello.cipher_suites. A client which receives a cipher suite
  that was not offered MUST abort the handshake with an "illegal_parameter"
  alert.

legacy_compression_method
: A single byte which MUST have the value 0.

extensions
: A list of extensions.  The ServerHello MUST only include extensions
  which are required to establish the cryptographic context and negotiate
  the protocol version. All TLS 1.3 ServerHello messages MUST contain the
  "supported_versions" extension.  Current ServerHello messages additionally contain
  either the "pre_shared_key" or "key_share" extensions, or both when using
  a PSK with (EC)DHE key establishment. Other extensions are sent
  separately in the EncryptedExtensions message.
{:br }

For reasons of backward compatibility with middleboxes
(see {{middlebox}}) the HelloRetryRequest
message uses the same structure as the ServerHello, but with
Random set to the special value of the SHA-256 of
"HelloRetryRequest":

      CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
      C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C

Upon receiving a message with type server_hello, implementations
MUST first examine the Random value and if it matches
this value, process it as described in {{hello-retry-request}}).

TLS 1.3 has a downgrade protection mechanism embedded in the server's
random value. TLS 1.3 servers which negotiate TLS 1.2 or below in
response to a ClientHello MUST set the last eight bytes of their
Random value specially.

If negotiating TLS 1.2, TLS 1.3 servers MUST set the last eight bytes of their
Random value to the bytes:

      44 4F 57 4E 47 52 44 01

If negotiating TLS 1.1 or below, TLS 1.3 servers MUST and TLS 1.2
servers SHOULD set the last eight bytes of their Random value to the
bytes:

      44 4F 57 4E 47 52 44 00


TLS 1.3 clients receiving a ServerHello indicating TLS 1.2 or below
MUST check that the last eight bytes are not equal to either of these values.
TLS 1.2 clients SHOULD also check that the last eight bytes are not
equal to the second value if the ServerHello indicates TLS 1.1 or
below.  If a match is found, the client MUST abort the handshake
with an "illegal_parameter" alert.  This mechanism provides limited
protection against downgrade attacks over and above what is provided
by the Finished exchange: because the ServerKeyExchange, a message
present in TLS 1.2 and below, includes a signature over both random
values, it is not possible for an active attacker to modify the
random values without detection as long as ephemeral ciphers are used.
It does not provide downgrade protection when static RSA is used.

Note: This is a change from {{RFC5246}}, so in practice many TLS 1.2 clients
and servers will not behave as specified above.

A legacy TLS client performing renegotiation with TLS 1.2 or prior
and which receives a TLS 1.3 ServerHello during renegotiation
MUST abort the handshake with a "protocol_version" alert.
Note that renegotiation is not possible when TLS 1.3 has been
negotiated.

RFC EDITOR: PLEASE REMOVE THE FOLLOWING PARAGRAPH
Implementations of draft versions (see {{draft-version-indicator}}) of this
specification SHOULD NOT implement this mechanism on either client and server.
A pre-RFC client connecting to RFC servers, or vice versa, will appear to
downgrade to TLS 1.2. With the mechanism enabled, this will cause an
interoperability failure.

###  Hello Retry Request

The server will send this message in response to a ClientHello message
if it is able to find an acceptable set of parameters but the
ClientHello does not contain sufficient information to proceed with
the handshake. As discussed in {{server-hello}}, the HelloRetryRequest
has the same format as a ServerHello message, and the
legacy_version, legacy_session_id_echo, cipher_suite, and legacy_compression
methods fields have the same meaning. However, for convenience we
discuss HelloRetryRequest throughout this document as if it were
a distinct message.

The server's extensions MUST contain "supported_versions" and
otherwise the server SHOULD send only the extensions necessary for the
client to generate a correct ClientHello pair. As with ServerHello, a
HelloRetryRequest MUST NOT contain any extensions that were not first
offered by the client in its ClientHello, with the exception of
optionally the "cookie" (see {{cookie}}) extension.

Upon receipt of a HelloRetryRequest, the client MUST perform the
checks specified in {{server-hello}} and then process the
extensions, starting with determining the version using
"supported_versions". Clients MUST abort the handshake with
an "illegal_parameter" alert if the HelloRetryRequest would not result in
any change in the ClientHello. If a client receives a second
HelloRetryRequest in the same connection (i.e., where
the ClientHello was itself in response to a HelloRetryRequest), it
MUST abort the handshake with an "unexpected_message" alert.

Otherwise, the client MUST process all extensions in the
HelloRetryRequest and send a second updated ClientHello. The
HelloRetryRequest extensions defined in this specification are:

- supported_versions (see {{supported-versions}})

- cookie (see {{cookie}})

- key_share (see {{key-share}})

In addition, in its updated ClientHello, the client SHOULD NOT offer
any pre-shared keys associated with a hash other than that of the
selected cipher suite. This allows the client to avoid having to
compute partial hash transcripts for multiple hashes in the second
ClientHello.  A client which receives a cipher suite that was not
offered MUST abort the handshake.  Servers MUST ensure that they
negotiate the same cipher suite when receiving a conformant updated
ClientHello (if the server selects the cipher suite as the first step
in the negotiation, then this will happen automatically). Upon
receiving the ServerHello, clients MUST check that the cipher suite
supplied in the ServerHello is the same as that in the
HelloRetryRequest and otherwise abort the handshake with an
"illegal_parameter" alert.

The value of selected_version in the HelloRetryRequest "supported_versions"
extension MUST be retained in the ServerHello, and a client MUST abort the
handshake with an "illegal_parameter" alert if the value changes.

##  Extensions

A number of TLS messages contain tag-length-value encoded extensions structures.

%%% Key Exchange Messages

       struct {
           ExtensionType extension_type;
           opaque extension_data<0..2^16-1>;
       } Extension;

       enum {
           server_name(0),                             /* RFC 6066 */
           max_fragment_length(1),                     /* RFC 6066 */
           status_request(5),                          /* RFC 6066 */
           supported_groups(10),                       /* RFC 4492, 7919 */
           signature_algorithms(13),                   /* [[this document]] */
           use_srtp(14),                               /* RFC 5764 */
           heartbeat(15),                              /* RFC 6520 */
           application_layer_protocol_negotiation(16), /* RFC 7301 */
           signed_certificate_timestamp(18),           /* RFC 6962 */
           client_certificate_type(19),                /* RFC 7250 */
           server_certificate_type(20),                /* RFC 7250 */
           padding(21),                                /* RFC 7685 */
           RESERVED(40),                               /* Used but never assigned */
           pre_shared_key(41),                         /* [[this document]] */
           early_data(42),                             /* [[this document]] */
           supported_versions(43),                     /* [[this document]] */
           cookie(44),                                 /* [[this document]] */
           psk_key_exchange_modes(45),                 /* [[this document]] */
           RESERVED(46),                               /* Used but never assigned */
           certificate_authorities(47),                /* [[this document]] */
           oid_filters(48),                            /* [[this document]] */
           post_handshake_auth(49),                    /* [[this document]] */
           signature_algorithms_cert(50),              /* [[this document]] */
           key_share(51),                              /* [[this document]] */
           (65535)
       } ExtensionType;

Here:

- "extension_type" identifies the particular extension type.

- "extension_data" contains information specific to the particular
  extension type.

The list of extension types is maintained by IANA as described in
{{iana-considerations}}.

Extensions are generally structured in a request/response fashion, though
some extensions are just indications with no corresponding response. The client
sends its extension requests in the ClientHello message and the server sends
its extension responses in the ServerHello, EncryptedExtensions,
HelloRetryRequest and Certificate messages. The server sends extension requests
in the CertificateRequest message which a client MAY respond to with
a Certificate message. The server MAY also send unsolicited
extensions in the NewSessionTicket, though the client does not respond
directly to these.

Implementations MUST NOT send extension responses
if the remote endpoint did not send the corresponding extension requests,
with the exception of the "cookie" extension in HelloRetryRequest.
Upon receiving such an extension, an endpoint MUST abort the handshake with an
"unsupported_extension" alert.

The table below indicates the messages where a given extension may
appear, using the following notation: CH (ClientHello), SH
(ServerHello), EE (EncryptedExtensions), CT (Certificate), CR
(CertificateRequest), NST (NewSessionTicket) and HRR
(HelloRetryRequest). If an implementation receives an extension which
it recognizes and which is not specified for the message in which it
appears it MUST abort the handshake with an "illegal_parameter" alert.

| Extension                                |   TLS 1.3   |
|:-----------------------------------------|------------:|
| server_name [RFC6066]                    |      CH, EE |
| max_fragment_length [RFC6066]            |      CH, EE |
| status_request [RFC6066]                 |  CH, CR, CT |
| supported_groups [RFC7919]               |      CH, EE |
| signature_algorithms [RFC5246]           |      CH, CR |
| use_srtp [RFC5764]                       |      CH, EE |
| heartbeat [RFC6520]                      |      CH, EE |
| application_layer_protocol_negotiation [RFC7301]|      CH, EE |
| signed_certificate_timestamp [RFC6962]   |  CH, CR, CT |
| client_certificate_type [RFC7250]        |      CH, EE |
| server_certificate_type [RFC7250]        |      CH, EE |
| padding [RFC7685]                        |          CH |
| key_share \[\[this document]]            | CH, SH, HRR |
| pre_shared_key \[\[this document]]       |      CH, SH |
| psk_key_exchange_modes \[\[this document]]|          CH |
| early_data \[\[this document]]           | CH, EE, NST |
| cookie \[\[this document]]               |     CH, HRR |
| supported_versions \[\[this document]]   | CH, SH, HRR |
| certificate_authorities \[\[this document]]|      CH, CR |
| oid_filters \[\[this document]]          |          CR |
| post_handshake_auth \[\[this document]]  |          CH |
| signature_algorithms_cert \[\[this document]]|      CH, CR |

When multiple extensions of different types are present, the
extensions MAY appear in any order, with the exception of
"pre_shared_key" {{pre-shared-key-extension}} which MUST be
the last extension in the ClientHello.
There MUST NOT be more than one extension of the same type in a given
extension block.

In TLS 1.3, unlike TLS 1.2, extensions are negotiated for each
handshake even when in resumption-PSK mode. However, 0-RTT parameters are
those negotiated in the previous handshake; mismatches may require
rejecting 0-RTT (see {{early-data-indication}}).

There are subtle (and not so subtle) interactions that may occur in this
protocol between new features and existing features which may result in a
significant reduction in overall security. The following considerations should
be taken into account when designing new extensions:

- Some cases where a server does not agree to an extension are error
  conditions, and some are simply refusals to support particular features. In
  general, error alerts should be used for the former and a field in the
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

###  Supported Versions

%%% Version Extension

       struct {
           select (Handshake.msg_type) {
               case client_hello:
                    ProtocolVersion versions<2..254>;

               case server_hello: /* and HelloRetryRequest */
                    ProtocolVersion selected_version;
           };
       } SupportedVersions;

The "supported_versions" extension is used by the client to indicate
which versions of TLS it supports and by the server to indicate
which version it is using. The extension contains a list of
supported versions in preference order, with the most preferred
version first. Implementations of this specification MUST send this
extension in the ClientHello containing all versions of TLS which they are
prepared to negotiate (for this specification, that means minimally
0x0304, but if previous versions of TLS are allowed to be negotiated,
they MUST be present as well).

If this extension is not present, servers which are compliant with
this specification MUST negotiate TLS 1.2 or prior as specified in
{{RFC5246}}, even if ClientHello.legacy_version is 0x0304 or later.
Servers MAY abort the handshake upon receiving a ClientHello with
legacy_version 0x0304 or later.

If this extension is present in the ClientHello, servers MUST NOT use the
ClientHello.legacy_version value for version negotiation and MUST use only the
"supported_versions" extension to determine client
preferences. Servers MUST only select a version of TLS present in that
extension and MUST ignore any unknown versions that are present in that
extension. Note that this
mechanism makes it possible to negotiate a version prior to TLS 1.2 if
one side supports a sparse range. Implementations of TLS 1.3 which choose
to support prior versions of TLS SHOULD support TLS 1.2.
Servers MUST be prepared to receive ClientHellos that include this
extension but do not include 0x0304 in the list of versions.

A server which negotiates a version of TLS prior to TLS 1.3 MUST
set ServerHello.version and MUST NOT send the "supported_versions"
extension.
A server which negotiates TLS 1.3 MUST respond by sending a
"supported_versions" extension containing the selected version value
(0x0304). It MUST set the ServerHello.legacy_version field to 0x0303 (TLS
1.2). Clients MUST check for this extension prior to processing
the rest of the ServerHello (although they will have to parse the
ServerHello in order to read the extension).
If this extension is present, clients MUST ignore the
ServerHello.legacy_version value and MUST use only the
"supported_versions" extension to determine the selected version. If the
"supported_versions" extension in the ServerHello contains a version not offered by the
client or contains a version prior to TLS 1.3, the client MUST abort the handshake with an
"illegal_parameter" alert. 


#### Draft Version Indicator

RFC EDITOR: PLEASE REMOVE THIS SECTION

While the eventual version indicator for the RFC version of TLS 1.3 will
be 0x0304, implementations of draft versions of this specification SHOULD
instead advertise 0x7f00 | draft_version
in the ServerHello and HelloRetryRequest "supported_versions" extension.
For instance, draft-17 would be encoded as the 0x7f11.
This allows pre-RFC implementations to safely negotiate with each other,
even if they would otherwise be incompatible.

###  Cookie

%%% Cookie Extension

       struct {
           opaque cookie<1..2^16-1>;
       } Cookie;

Cookies serve two primary purposes:

- Allowing the server to force the client to demonstrate reachability
  at their apparent network address (thus providing a measure of DoS
  protection). This is primarily useful for non-connection-oriented
  transports (see {{?RFC6347}} for an example of this).

- Allowing the server to offload state to the client, thus allowing it to send
  a HelloRetryRequest without storing any state. The server can do this by
  storing the hash of the ClientHello in the HelloRetryRequest cookie
  (protected with some suitable integrity algorithm).

When sending a HelloRetryRequest, the server MAY provide a "cookie" extension to the
client (this is an exception to the usual rule that the only extensions that
may be sent are those that appear in the ClientHello). When sending the
new ClientHello, the client MUST copy the contents of the extension received in
the HelloRetryRequest into a "cookie" extension in the new ClientHello.
Clients MUST NOT use cookies in their initial ClientHello in subsequent connections.

When a server is operating statelessly it may receive an unprotected record of
type change_cipher_spec between the first and second ClientHello (see
{{record-protocol}}). Since the server is not storing any state this will appear
as if it were the first message to be received. Servers operating statelessly
MUST ignore these records.

###  Signature Algorithms

TLS 1.3 provides two extensions for indicating which signature
algorithms may be used in digital signatures. The
"signature_algorithms_cert" extension applies to signatures in
certificates and the "signature_algorithms" extension, which originally
appeared in TLS 1.2, applies to signatures in CertificateVerify
messages. The keys found in certificates MUST also be of
appropriate type for the signature algorithms they are used
with. This is a particular issue for RSA keys and PSS signatures,
as described below. If no "signature_algorithms_cert" extension is present,
then the "signature_algorithms" extension also applies to signatures
appearing in certificates. Clients which desire the server to authenticate
itself via a certificate MUST send "signature_algorithms". If a server
is authenticating via a certificate and the client has not sent a
"signature_algorithms" extension, then the server MUST abort the
handshake with a "missing_extension" alert (see {{mti-extensions}}).

The "signature_algorithms_cert" extension was added to allow implementations
which supported different sets of algorithms for certificates and in TLS itself
to clearly signal their capabilities. TLS 1.2 implementations SHOULD also process
this extension. Implementations which have the same policy in both cases
MAY omit the "signature_algorithms_cert" extension.

The "extension_data" field of these extension contains a
SignatureSchemeList value:

%%% Signature Algorithm Extension

       enum {
           /* RSASSA-PKCS1-v1_5 algorithms */
           rsa_pkcs1_sha256(0x0401),
           rsa_pkcs1_sha384(0x0501),
           rsa_pkcs1_sha512(0x0601),

           /* ECDSA algorithms */
           ecdsa_secp256r1_sha256(0x0403),
           ecdsa_secp384r1_sha384(0x0503),
           ecdsa_secp521r1_sha512(0x0603),

           /* RSASSA-PSS algorithms with public key OID rsaEncryption */
           rsa_pss_rsae_sha256(0x0804),
           rsa_pss_rsae_sha384(0x0805),
           rsa_pss_rsae_sha512(0x0806),

           /* EdDSA algorithms */
           ed25519(0x0807),
           ed448(0x0808),

           /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
           rsa_pss_pss_sha256(0x0809),
           rsa_pss_pss_sha384(0x080a),
           rsa_pss_pss_sha512(0x080b),

           /* Legacy algorithms */
           rsa_pkcs1_sha1(0x0201),
           ecdsa_sha1(0x0203),

           /* Reserved Code Points */
           obsolete_RESERVED(0x0000..0x0200),
           dsa_sha1_RESERVED(0x0202),
           obsolete_RESERVED(0x0204..0x0400),
           dsa_sha256_RESERVED(0x0402),
           obsolete_RESERVED(0x0404..0x0500),
           dsa_sha384_RESERVED(0x0502),
           obsolete_RESERVED(0x0504..0x0600),
           dsa_sha512_RESERVED(0x0602),
           obsolete_RESERVED(0x0604..0x06FF),
           private_use(0xFE00..0xFFFF),
           (0xFFFF)
       } SignatureScheme;

       struct {
           SignatureScheme supported_signature_algorithms<2..2^16-2>;
       } SignatureSchemeList;

Note: This enum is named "SignatureScheme" because there is already
a "SignatureAlgorithm" type in TLS 1.2, which this replaces.
We use the term "signature algorithm" throughout the text.

Each SignatureScheme value lists a single signature algorithm that the
client is willing to verify. The values are indicated in descending order
of preference. Note that a signature algorithm takes as input an
arbitrary-length message, rather than a digest. Algorithms which
traditionally act on a digest should be defined in TLS to first
hash the input with a specified hash algorithm and then proceed as usual.
The code point groups listed above have the following meanings:

RSASSA-PKCS1-v1_5 algorithms
: Indicates a signature algorithm using RSASSA-PKCS1-v1_5 {{RFC8017}}
  with the corresponding hash algorithm as defined in {{!SHS=DOI.10.6028/NIST.FIPS.180-4}}. These values
  refer solely to signatures which appear in certificates (see
  {{server-certificate-selection}}) and are not defined for use in signed
  TLS handshake messages, although they MAY appear in "signature_algorithms"
  and "signature_algorithms_cert" for backward compatibility with TLS 1.2,

ECDSA algorithms
: Indicates a signature algorithm using ECDSA {{ECDSA}}, the corresponding
  curve as defined in ANSI X9.62 {{X962}} and FIPS 186-4 {{DSS}}, and the
  corresponding hash algorithm as defined in {{!SHS}}. The signature is
  represented as a DER-encoded {{X690}} ECDSA-Sig-Value structure.

RSASSA-PSS RSAE algorithms
: Indicates a signature algorithm using RSASSA-PSS {{RFC8017}} with mask
  generation function 1. The
  digest used in the mask generation function and the digest being signed are
  both the corresponding hash algorithm as defined in {{!SHS}}.
  The length of the salt MUST be equal to the length of the digest
  algorithm. If the public key is carried
  in an X.509 certificate, it MUST use the rsaEncryption OID {{!RFC5280}}.

EdDSA algorithms
: Indicates a signature algorithm using EdDSA as defined in
  {{RFC8032}} or its successors. Note that these correspond to the
  "PureEdDSA" algorithms and not the "prehash" variants.

RSASSA-PSS PSS algorithms
: Indicates a signature algorithm using RSASSA-PSS {{RFC8017}} with mask
  generation function 1. The
  digest used in the mask generation function and the digest being signed are
  both the corresponding hash algorithm as defined in {{!SHS}}.
  The length of the salt MUST be equal to the length of the digest
  algorithm. If the public key is carried in an X.509 certificate,
  it MUST use the RSASSA-PSS OID  {{!RFC5756}}. When used in certificate signatures,
  the algorithm parameters MUST be DER encoded. If the corresponding
  public key's parameters are present, then the parameters in the signature
  MUST be identical to those in the public key.

Legacy algorithms
: Indicates algorithms which are being deprecated because they use
  algorithms with known weaknesses, specifically SHA-1 which is used
  in this context with either with RSA using RSASSA-PKCS1-v1_5 or ECDSA.  These values
  refer solely to signatures which appear in certificates (see
  {{server-certificate-selection}}) and are not defined for use in
  signed TLS handshake messages, although they MAY appear in "signature_algorithms"
  and "signature_algorithms_cert" for backward compatibility with TLS 1.2,
  Endpoints SHOULD NOT negotiate these algorithms
  but are permitted to do so solely for backward compatibility. Clients
  offering these values MUST list
  them as the lowest priority (listed after all other algorithms in
  SignatureSchemeList). TLS 1.3 servers MUST NOT offer a SHA-1 signed
  certificate unless no valid certificate chain can be produced
  without it (see {{server-certificate-selection}}).
{:br }


The signatures on certificates that are self-signed or certificates that are
trust anchors are not validated since they begin a certification path (see
{{RFC5280}}, Section 3.2).  A certificate that begins a certification
path MAY use a signature algorithm that is not advertised as being supported
in the "signature_algorithms" extension.

Note that TLS 1.2 defines this extension differently. TLS 1.3 implementations
willing to negotiate TLS 1.2 MUST behave in accordance with the requirements of
{{RFC5246}} when negotiating that version. In particular:

* TLS 1.2 ClientHellos MAY omit this extension.

* In TLS 1.2, the extension contained hash/signature pairs. The pairs are
  encoded in two octets, so SignatureScheme values have been allocated to
  align with TLS 1.2's encoding. Some legacy pairs are left unallocated. These
  algorithms are deprecated as of TLS 1.3. They MUST NOT be offered or
  negotiated by any implementation. In particular, MD5 {{SLOTH}}, SHA-224, and
  DSA MUST NOT be used.

* ECDSA signature schemes align with TLS 1.2's ECDSA hash/signature pairs.
  However, the old semantics did not constrain the signing curve.  If TLS 1.2 is
  negotiated, implementations MUST be prepared to accept a signature that uses
  any curve that they advertised in the "supported_groups" extension.

* Implementations that advertise support for RSASSA-PSS (which is mandatory in
  TLS 1.3), MUST be prepared to accept a signature using that scheme even when
  TLS 1.2 is negotiated. In TLS 1.2, RSASSA-PSS is used with RSA cipher suites.


### Certificate Authorities

The "certificate_authorities" extension is used to indicate the
certificate authorities which an endpoint supports and which SHOULD
be used by the receiving endpoint to guide certificate selection.

The body of the "certificate_authorities" extension consists of a
CertificateAuthoritiesExtension structure.

%%% Server Parameters Messages

       opaque DistinguishedName<1..2^16-1>;

       struct {
           DistinguishedName authorities<3..2^16-1>;
       } CertificateAuthoritiesExtension;

authorities
: A list of the distinguished names {{X501}} of acceptable
  certificate authorities, represented in DER-encoded {{X690}} format.  These
  distinguished names specify a desired distinguished name for trust anchor
  or subordinate CA; thus, this message can be used to
  describe known trust anchors as well as a desired authorization space.
{:br}

The client MAY send the "certificate_authorities" extension in the ClientHello
message. The server MAY send it in the CertificateRequest message.

The "trusted_ca_keys" extension, which serves a similar
purpose {{RFC6066}}, but is more complicated, is not used in TLS 1.3
(although it may appear in ClientHello messages from clients which are
offering prior versions of TLS).

### OID Filters

The "oid_filters" extension allows servers to provide a set of OID/value
pairs which it would like the client's certificate to match. This
extension, if provided by the server, MUST only be sent in the CertificateRequest message.

%%% Server Parameters Messages

       struct {
           opaque certificate_extension_oid<1..2^8-1>;
           opaque certificate_extension_values<0..2^16-1>;
       } OIDFilter;

       struct {
           OIDFilter filters<0..2^16-1>;
       } OIDFilterExtension;

filters

: A list of certificate extension OIDs {{RFC5280}} with their allowed value(s) and
  represented in DER-encoded {{X690}} format. Some certificate extension OIDs
  allow multiple values (e.g., Extended Key Usage).  If the server has included
  a non-empty filters list, the client certificate included in
  the response MUST contain all of the specified extension OIDs that the client
  recognizes. For each extension OID recognized by the client, all of the
  specified values MUST be present in the client certificate (but the
  certificate MAY have other values as well). However, the client MUST ignore
  and skip any unrecognized certificate extension OIDs. If the client ignored
  some of the required certificate extension OIDs and supplied a certificate
  that does not satisfy the request, the server MAY at its discretion either
  continue the connection without client authentication, or abort the handshake
  with an "unsupported_certificate" alert.

PKIX RFCs define a variety of certificate extension OIDs and their corresponding
value types. Depending on the type, matching certificate extension values are
not necessarily bitwise-equal. It is expected that TLS implementations will rely
on their PKI libraries to perform certificate selection using certificate
extension OIDs.

This document defines matching rules for two standard certificate extensions
defined in {{RFC5280}}:

- The Key Usage extension in a certificate matches the request when all key
  usage bits asserted in the request are also asserted in the Key Usage
  certificate extension.

- The Extended Key Usage extension in a certificate matches the request when all
  key purpose OIDs present in the request are also found in the Extended Key
  Usage certificate extension. The special anyExtendedKeyUsage OID MUST NOT be
  used in the request.

Separate specifications may define matching rules for other certificate
extensions.

### Post-Handshake Client Authentication {#post_handshake_auth}

The "post_handshake_auth" extension is used to indicate that a client is willing
to perform post-handshake authentication ({{post-handshake-authentication}}). Servers
MUST NOT send a post-handshake CertificateRequest to clients which do not
offer this extension. Servers MUST NOT send this extension.

%%% Server Parameters Messages

       struct {} PostHandshakeAuth;

The "extension_data" field of the "post_handshake_auth" extension is zero
length.

### Negotiated Groups

When sent by the client, the "supported_groups" extension indicates
the named groups which the client supports for key exchange, ordered
from most preferred to least preferred.

Note: In versions of TLS prior to TLS 1.3, this extension was named
"elliptic_curves" and only contained elliptic curve groups. See {{RFC4492}} and
{{RFC7919}}. This extension was also used to negotiate
ECDSA curves. Signature algorithms are now negotiated independently (see
{{signature-algorithms}}).

The "extension_data" field of this extension contains a
"NamedGroupList" value:

%%% Supported Groups Extension

       enum {
           unallocated_RESERVED(0x0000),

           /* Elliptic Curve Groups (ECDHE) */
           obsolete_RESERVED(0x0001..0x0016),
           secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),
           obsolete_RESERVED(0x001A..0x001C),
           x25519(0x001D), x448(0x001E),

           /* Finite Field Groups (DHE) */
           ffdhe2048(0x0100), ffdhe3072(0x0101), ffdhe4096(0x0102),
           ffdhe6144(0x0103), ffdhe8192(0x0104),

           /* Reserved Code Points */
           ffdhe_private_use(0x01FC..0x01FF),
           ecdhe_private_use(0xFE00..0xFEFF),
           obsolete_RESERVED(0xFF01..0xFF02),
           (0xFFFF)
       } NamedGroup;

       struct {
           NamedGroup named_group_list<2..2^16-1>;
       } NamedGroupList;

Elliptic Curve Groups (ECDHE)
: Indicates support for the corresponding named curve, defined
  either in FIPS 186-4 {{DSS}} or in {{RFC7748}}.
  Values 0xFE00 through 0xFEFF are reserved for private use.

Finite Field Groups (DHE)
: Indicates support of the corresponding finite field
  group, defined in {{RFC7919}}.
  Values 0x01FC through 0x01FF are reserved for private use.
{:br }

Items in named_group_list are ordered according to the client's
preferences (most preferred choice first).

As of TLS 1.3, servers are permitted to send the "supported_groups"
extension to the client. Clients MUST NOT act upon any information
found in "supported_groups" prior to successful completion of the
handshake but MAY use the information learned from a successfully
completed handshake to change what groups they use in their
"key_share" extension in subsequent connections.
If the server has a group it prefers to the
ones in the "key_share" extension but is still willing to accept the
ClientHello, it SHOULD send "supported_groups" to update the client's
view of its preferences; this extension SHOULD contain all groups
the server supports, regardless of whether they are currently
supported by the client.

### Key Share

The "key_share" extension contains the endpoint's cryptographic parameters.

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
  definition.
{:br }

In the ClientHello message, the "extension_data" field of this extension
contains a "KeyShareClientHello" value:

%%% Key Exchange Messages
       struct {
           KeyShareEntry client_shares<0..2^16-1>;
       } KeyShareClientHello;

client_shares
: A list of offered KeyShareEntry values in descending order of client preference.
{:br }

This vector MAY be empty if the client is requesting a HelloRetryRequest.
Each KeyShareEntry value MUST correspond to a group offered in the
"supported_groups" extension and MUST appear in the same order.  However, the
values MAY be a non-contiguous subset of the "supported_groups" extension and
MAY omit the most preferred groups. Such a situation could arise if the most
preferred groups are new and unlikely to be supported in enough places to
make pregenerating key shares for them efficient.

Clients can offer as many KeyShareEntry values as the number of supported
groups it is offering, each
representing a single set of key exchange parameters. For instance, a
client might offer shares for several elliptic curves or multiple
FFDHE groups.  The key_exchange values for each KeyShareEntry MUST be
generated independently.  Clients MUST NOT offer multiple
KeyShareEntry values for the same group.  Clients MUST NOT offer any
KeyShareEntry values for groups not listed in the client's
"supported_groups" extension.  Servers MAY check for violations of
these rules and abort the handshake with an "illegal_parameter" alert
if one is violated.

In a HelloRetryRequest message, the "extension_data" field of this
extension contains a KeyShareHelloRetryRequest value:

%%% Key Exchange Messages
       struct {
           NamedGroup selected_group;
       } KeyShareHelloRetryRequest;

selected_group
: The mutually supported group the server intends to negotiate and
  is requesting a retried ClientHello/KeyShare for.
{:br }

Upon receipt of this extension in a HelloRetryRequest, the client MUST
verify that (1) the selected_group field corresponds to a group which was provided
in the "supported_groups" extension in the original ClientHello; and (2)
the selected_group field does not correspond to a group which was
provided in the "key_share" extension in the original ClientHello. If either of
these checks fails, then the client MUST abort the handshake with an
"illegal_parameter" alert.  Otherwise, when sending the new ClientHello, the
client MUST replace the original "key_share" extension with one
containing only a new KeyShareEntry for the group indicated in the
selected_group field of the triggering HelloRetryRequest.

In a ServerHello message, the "extension_data" field of this
extension contains a KeyShareServerHello value:

%%% Key Exchange Messages
       struct {
           KeyShareEntry server_share;
       } KeyShareServerHello;

server_share
: A single KeyShareEntry value that is in the same group as one of the
  client's shares.
{:br}

If using (EC)DHE key establishment, servers offer exactly one
KeyShareEntry in the ServerHello. This value MUST be in the same group
as the KeyShareEntry value offered
by the client that the server has selected for the negotiated key exchange.
Servers MUST NOT send a KeyShareEntry for any group not
indicated in the "supported_groups" extension and
MUST NOT send a KeyShareEntry when using the "psk_ke" PskKeyExchangeMode.
If using (EC)DHE key establishment, and a HelloRetryRequest containing a
"key_share" extension was received by the client, the client MUST verify that the
selected NamedGroup in the ServerHello is the same as that in the HelloRetryRequest.
If this check fails, the client MUST abort the handshake with an "illegal_parameter"
alert.

####  Diffie-Hellman Parameters {#ffdhe-param}

Diffie-Hellman {{DH}} parameters for both clients and servers are encoded in
the opaque key_exchange field of a KeyShareEntry in a KeyShare structure.
The opaque value contains the
Diffie-Hellman public value (Y = g^X mod p) for the specified group
(see {{RFC7919}} for group definitions)
encoded as a big-endian integer and padded to the left with zeros to the size of p in
bytes.

Note: For a given Diffie-Hellman group, the padding results in all public keys
having the same length.

Peers MUST validate each other's public key Y by ensuring that 1 < Y
< p-1. This check ensures that the remote peer is properly behaved and
isn't forcing the local system into a small subgroup.

#### ECDHE Parameters {#ecdhe-param}

ECDHE parameters for both clients and servers are encoded in the
opaque key_exchange field of a KeyShareEntry in a KeyShare structure.

For secp256r1, secp384r1 and secp521r1, the contents are the serialized
value of the following struct:

%%% Key Exchange Messages

       struct {
           uint8 legacy_form = 4;
           opaque X[coordinate_length];
           opaque Y[coordinate_length];
       } UncompressedPointRepresentation;

X and Y respectively are the binary representations of the X and Y
values in network byte order.  There are no internal length markers,
so each number representation occupies as many octets as implied by
the curve parameters.  For P-256 this means that each of X and Y use
32 octets, padded on the left by zeros if necessary.  For P-384 they
take 48 octets each, and for P-521 they take 66 octets each.

For the curves secp256r1, secp384r1 and secp521r1,
peers MUST validate each other's public value Y by ensuring
that the point is a valid point on the elliptic curve.
The appropriate validation procedures are defined in Section 4.3.7 of {{X962}}
and alternatively in Section 5.6.2.3 of {{?KEYAGREEMENT=DOI.10.6028/NIST.SP.800-56Ar2}}.
This process consists of three steps: (1) verify that Y is not the point at
infinity (O), (2) verify that for Y = (x, y) both integers are in the correct
interval, (3) ensure that (x, y) is a correct solution to the elliptic curve equation.
For these curves, implementers do not need to verify membership in the correct subgroup.

For X25519 and X448, the contents of the public value are the byte string inputs and outputs of the
corresponding functions defined in {{RFC7748}}, 32 bytes for X25519 and 56
bytes for X448.

Note: Versions of TLS prior to 1.3 permitted point format negotiation;
TLS 1.3 removes this feature in favor of a single point format
for each curve.

### Pre-Shared Key Exchange Modes

In order to use PSKs, clients MUST also send a "psk_key_exchange_modes"
extension. The semantics of this extension are that the client only
supports the use of PSKs with these modes, which restricts both the
use of PSKs offered in this ClientHello and those which the server
might supply via NewSessionTicket.

A client MUST provide a "psk_key_exchange_modes" extension if it offers
a "pre_shared_key" extension. If clients offer "pre_shared_key" without
a "psk_key_exchange_modes" extension, servers MUST abort the handshake.
Servers MUST NOT select a key exchange mode that is not listed by the
client. This extension also restricts the modes for use with PSK resumption;
servers SHOULD NOT send NewSessionTicket with tickets that are not
compatible with the advertised modes; however, if a server does so, the impact
will just be that the client's attempts at resumption fail.

The server MUST NOT send a "psk_key_exchange_modes" extension.

%%% Key Exchange Messages

       enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;

       struct {
           PskKeyExchangeMode ke_modes<1..255>;
       } PskKeyExchangeModes;

psk_ke
: PSK-only key establishment. In this mode, the server MUST NOT
supply a "key_share" value.

psk_dhe_ke
: PSK with (EC)DHE key establishment. In this mode,
the client and servers MUST supply "key_share" values as described
in {{key-share}}.
{:br}

Any future values that are allocated must ensure that the transmitted
protocol messages unambiguously identify which mode was selected by
the server; at present, this is indicated by the presence of the "key_share"
in the ServerHello.

### Early Data Indication

When a PSK is used and early data is allowed for that PSK, the client can send application data
in its first flight of messages. If the client opts to do so, it MUST
supply both the "early_data" extension as well as the "pre_shared_key"
extension.

The "extension_data" field of this extension contains an
"EarlyDataIndication" value.

%%% Key Exchange Messages

       struct {} Empty;

       struct {
           select (Handshake.msg_type) {
               case new_session_ticket:   uint32 max_early_data_size;
               case client_hello:         Empty;
               case encrypted_extensions: Empty;
           };
       } EarlyDataIndication;

See {{NSTMessage}} for the use of the max_early_data_size field.

The parameters for the 0-RTT data (version, symmetric cipher suite, ALPN
protocol, etc.) are those associated with the PSK in use.
For externally established PSKs, the associated values are those
provisioned along with the key.  For PSKs established via a NewSessionTicket
message, the associated values are those which were negotiated in the connection
which established the PSK. The PSK used to encrypt the early data
MUST be the first PSK listed in the client's "pre_shared_key" extension.

For PSKs provisioned via NewSessionTicket, a server MUST validate that
the ticket age for the selected PSK identity (computed by subtracting
ticket_age_add from PskIdentity.obfuscated_ticket_age modulo 2^32)
is within a small tolerance of the
time since the ticket was issued (see {{anti-replay}}).  If it is not,
the server SHOULD proceed with the handshake but reject 0-RTT, and
SHOULD NOT take any other action that assumes that this ClientHello is
fresh.

0-RTT messages sent in the first flight have the same (encrypted) content types
as their corresponding messages sent in other flights (handshake and
application_data) but are protected under
different keys.  After receiving the server's Finished message, if the
server has accepted early data, an EndOfEarlyData message
will be sent to indicate the key change. This message will be encrypted
with the 0-RTT traffic keys.

A server which receives an "early_data" extension
MUST behave in one of three ways:

- Ignore the extension and return a regular 1-RTT response.  The server then
  ignores early data by attempting to decrypt received records in the handshake traffic
  keys until it is able to receive the
  client's second flight and complete an ordinary 1-RTT handshake, skipping
  records that fail to decrypt, up to the configured max_early_data_size.

- Request that the client send another ClientHello by responding with a
  HelloRetryRequest.  A client MUST NOT include the "early_data" extension in
  its followup ClientHello.  The server then ignores early data by skipping
  all records with external content type of "application_data" (indicating
  that they are encrypted), up to the configured max_early_data_size.

- Return its own extension in EncryptedExtensions,
  indicating that it intends to
  process the early data. It is not possible for the server
  to accept only a subset of the early data messages.
  Even though the server sends a message accepting early data, the actual early
  data itself may already be in flight by the time the server generates this message.

In order to accept early data, the server MUST have accepted a
PSK cipher suite and selected the first key offered in the
client's "pre_shared_key" extension. In addition, it MUST verify that
the following values are consistent with those associated with the selected
PSK:

- The TLS version number
- The selected cipher suite
- The selected ALPN {{RFC7301}} protocol, if any

These requirements are a superset of those needed to perform a 1-RTT
handshake using the PSK in question.  For externally established PSKs, the
associated values are those provisioned along with the key.  For PSKs
established via a NewSessionTicket message, the associated values are those
negotiated in the connection during which the ticket was established.

Future extensions MUST define their interaction with 0-RTT.

If any of these checks fail, the server MUST NOT respond
with the extension and must discard all the first
flight data using one of the first two mechanisms listed above
(thus falling back to 1-RTT or 2-RTT). If the client attempts
a 0-RTT handshake but the server rejects it, the server will generally
not have the 0-RTT record protection keys and must instead
use trial decryption (either with the 1-RTT handshake keys or
by looking for a cleartext ClientHello in the case of HelloRetryRequest) to
find the first non-0-RTT message.

If the server chooses to accept the "early_data" extension,
then it MUST comply with the same error handling requirements
specified for all records when processing early data records.
Specifically, if the server fails to decrypt any 0-RTT record following
an accepted "early_data" extension it MUST terminate the connection
with a "bad_record_mac" alert as per {{record-payload-protection}}.

If the server rejects the "early_data" extension, the client
application MAY opt to retransmit early data once the handshake has
been completed.  Note that automatic re-transmission of early data
could result in assumptions about the status of the connection being
incorrect. For instance, when the negotiated connection selects a
different ALPN protocol from what was used for the early data, an
application might need to construct different messages.  Similarly, if
early data assumes anything about the connection state, it might be
sent in error after the handshake completes.

A TLS implementation SHOULD NOT automatically re-send early data;
applications are in a better position to decide when re-transmission
is appropriate. A TLS implementation MUST NOT automatically re-send
early data unless the negotiated connection selects the same ALPN
protocol.

### Pre-Shared Key Extension

The "pre_shared_key" extension is used to indicate the identity of the
pre-shared key to be used with a given handshake in association
with PSK key establishment.

The "extension_data" field of this extension contains a
"PreSharedKeyExtension" value:

%%% Key Exchange Messages

       struct {
           opaque identity<1..2^16-1>;
           uint32 obfuscated_ticket_age;
       } PskIdentity;

       opaque PskBinderEntry<32..255>;

       struct {
           PskIdentity identities<7..2^16-1>;
           PskBinderEntry binders<33..2^16-1>;
       } OfferedPsks;

       struct {
           select (Handshake.msg_type) {
               case client_hello: OfferedPsks;
               case server_hello: uint16 selected_identity;
           };
       } PreSharedKeyExtension;

identity
: A label for a key. For instance, a ticket defined
  in {{ticket-establishment}} or a label for a pre-shared key
  established externally.

obfuscated_ticket_age
: An obfuscated version of the age of the key.
  {{ticket-age}} describes how to form this value
  for identities established via the NewSessionTicket message.
  For identities established externally an obfuscated_ticket_age of 0
  SHOULD be used, and servers MUST ignore the value.

identities
: A list of the identities that the client is willing
  to negotiate with the server. If sent alongside the "early_data"
  extension (see {{early-data-indication}}), the first identity is the
  one used for 0-RTT data.

binders
: A series of HMAC values, one for
  each PSK offered in the "pre_shared_keys" extension and in the same
  order, computed as described below.

selected_identity
: The server's chosen identity expressed as a (0-based) index into
  the identities in the client's list.
{: br}

Each PSK is associated with a single Hash algorithm. For PSKs established
via the ticket mechanism ({{NSTMessage}}), this is the KDF Hash algorithm
on the connection where the ticket was established.
For externally established PSKs, the Hash algorithm MUST be set when the
PSK is established, or default to SHA-256 if no such algorithm
is defined. The server MUST ensure that it selects a compatible
PSK (if any) and cipher suite.

In TLS versions prior to TLS 1.3, the Server Name Identification (SNI) value was
intended to be associated with the session (Section 3 of {{RFC6066}}), with the
server being required to enforce that the SNI value associated with the session
matches the one specified in the resumption handshake.  However, in reality the
implementations were not consistent on which of two supplied SNI values they
would use, leading to the consistency requirement being de-facto enforced by the
clients.  In TLS 1.3, the SNI value is always explicitly specified in the
resumption handshake, and there is no need for the server to associate an SNI value with the
ticket. Clients, however, SHOULD store the SNI with the PSK to fulfill
the requirements of {{NSTMessage}}.

Implementor's note: when session resumption is the primary use case of PSKs
the most straightforward way to implement the
PSK/cipher suite matching requirements is to negotiate the cipher
suite first and then exclude any incompatible PSKs. Any unknown PSKs
(e.g., they are not in the PSK database or are encrypted with an
unknown key) SHOULD simply be ignored. If no acceptable PSKs are
found, the server SHOULD perform a non-PSK handshake if possible.
If backwards compatibility is important, client provided, externally
established PSKs SHOULD influence cipher suite selection.

Prior to accepting PSK key establishment, the server MUST validate the
corresponding binder value (see {{psk-binder}} below). If this value is
not present or does not validate, the server MUST abort the handshake.
Servers SHOULD NOT attempt to validate multiple binders; rather they
SHOULD select a single PSK and validate solely the binder that
corresponds to that PSK.
See \[{{client-hello-recording}}] for the security rationale for this
requirement.
In order to accept PSK key establishment, the
server sends a "pre_shared_key" extension indicating the selected
identity.

Clients MUST verify that the server's selected_identity is within the
range supplied by the client, that the server selected a cipher suite
indicating a Hash associated with the PSK and that a server
"key_share" extension is present if required by the
ClientHello "psk_key_exchange_modes". If these values are not
consistent the client MUST abort the handshake with an
"illegal_parameter" alert.

If the server supplies an "early_data" extension, the client MUST
verify that the server's selected_identity is 0. If any
other value is returned, the client MUST abort the handshake
with an "illegal_parameter" alert.

This extension MUST be the last extension in the ClientHello (this
facilitates implementation as described below). Servers MUST check
that it is the last extension and otherwise fail the handshake with an
"illegal_parameter" alert.

#### Ticket Age

The client's view of the age of a ticket is the time since the receipt
of the NewSessionTicket message. Clients MUST NOT attempt to use
tickets which have ages greater than the "ticket_lifetime" value which
was provided with the ticket. The "obfuscated_ticket_age" field of
each PskIdentity contains an obfuscated version of the ticket age
formed by taking the age in milliseconds and adding the "ticket_age_add"
value that was included with the ticket (see {{NSTMessage}}), modulo 2^32.
This addition prevents passive observers from correlating connections
unless tickets are reused. Note that the "ticket_lifetime" field in
the NewSessionTicket message is in seconds but the "obfuscated_ticket_age"
is in milliseconds. Because ticket lifetimes are
restricted to a week, 32 bits is enough to represent any plausible
age, even in milliseconds.

#### PSK Binder

The PSK binder value forms a binding between a PSK and the current
handshake, as well as a binding between the handshake in which the PSK was
generated (if via a NewSessionTicket message) and the current handshake.
Each entry in the binders list is computed as an HMAC
over a transcript hash (see {{the-transcript-hash}}) containing a partial ClientHello
up to and including the PreSharedKeyExtension.identities field. That
is, it includes all of the ClientHello but not the binders list
itself. The length fields for the message (including the overall
length, the length of the extensions block, and the length of the
"pre_shared_key" extension) are all set as if binders of the correct
lengths were present.

The PskBinderEntry is computed in the same way as the Finished
message ({{finished}}) but with the BaseKey being the binder_key
derived via the key schedule from the corresponding PSK which
is being offered (see {{key-schedule}}).

If the handshake includes a HelloRetryRequest, the initial ClientHello
and HelloRetryRequest are included in the transcript along with the
new ClientHello.  For instance, if the client sends ClientHello1, its
binder will be computed over:

       Transcript-Hash(Truncate(ClientHello1))

Where Truncate() removes the binders list from the ClientHello.

If the server responds with HelloRetryRequest, and the client then sends
ClientHello2, its binder will be computed over:

       Transcript-Hash(ClientHello1,
                       HelloRetryRequest,
                       Truncate(ClientHello2))

The full ClientHello1/ClientHello2 is included in all other handshake hash computations.
Note that in the first flight, Truncate(ClientHello1) is hashed directly,
but in the second flight, ClientHello1 is hashed and then reinjected as a
"message_hash" message, as described in {{the-transcript-hash}}.

#### Processing Order

Clients are permitted to "stream" 0-RTT data until they
receive the server's Finished, only then sending the EndOfEarlyData
message, followed by the rest of the handshake.
In order to avoid deadlocks, when accepting "early_data",
the server MUST process the client's ClientHello and then immediately
send its ServerHello, rather than waiting for the client's
EndOfEarlyData message before sending its ServerHello.

## Server Parameters

The next two messages from the server, EncryptedExtensions and
CertificateRequest, contain information from the server
that determines the rest of the handshake. These messages
are encrypted with keys derived from the server_handshake_traffic_secret.

###  Encrypted Extensions

In all handshakes, the server MUST send the
EncryptedExtensions message immediately after the
ServerHello message. This is the first message that is encrypted
under keys derived from the server_handshake_traffic_secret.

The EncryptedExtensions message contains extensions
that can be protected, i.e., any which are not needed to
establish the cryptographic context, but which are not
associated with individual certificates. The client
MUST check EncryptedExtensions for the presence of any forbidden
extensions and if any are found MUST abort the handshake with an
"illegal_parameter" alert.

Structure of this message:

%%% Server Parameters Messages

       struct {
           Extension extensions<0..2^16-1>;
       } EncryptedExtensions;

extensions
: A list of extensions. For more information, see the table in {{extensions}}.
{:br }

###  Certificate Request

A server which is authenticating with a certificate MAY optionally
request a certificate from the client. This message, if sent, MUST
follow EncryptedExtensions.

Structure of this message:

%%% Server Parameters Messages

       struct {
           opaque certificate_request_context<0..2^8-1>;
           Extension extensions<2..2^16-1>;
       } CertificateRequest;

certificate_request_context
: An opaque string which identifies the certificate request and
  which will be echoed in the client's Certificate message. The
  certificate_request_context MUST be unique within the scope
  of this connection (thus preventing replay of client
  CertificateVerify messages). This field SHALL be zero length
  unless used for the post-handshake authentication exchanges
  described in {{post-handshake-authentication}}.
  When requesting post-handshake authentication, the server SHOULD
  make the context unpredictable to the client (e.g., by
  randomly generating it) in order to prevent an attacker who
  has temporary access to the client's private key from
  pre-computing valid CertificateVerify messages.

extensions
: A set of extensions describing the parameters of the
  certificate being requested. The "signature_algorithms"
  extension MUST be specified, and other extensions may optionally be
  included if defined for this message.
  Clients MUST ignore unrecognized extensions.
{:br}

In prior versions of TLS, the CertificateRequest message
carried a list of signature algorithms and certificate authorities
which the server would accept. In TLS 1.3 the former is expressed
by sending the "signature_algorithms" and optionally "signature_algorithms_cert"
extensions. The latter is
expressed by sending the "certificate_authorities" extension
(see {{certificate-authorities}}).

Servers which are authenticating with a PSK MUST NOT send the
CertificateRequest message in the main handshake, though they
MAY send it in post-handshake authentication (see {{post-handshake-authentication}})
provided that the client has sent the "post_handshake_auth"
extension (see {{post_handshake_auth}}).


## Authentication Messages

As discussed in {{protocol-overview}}, TLS generally uses a common
set of messages for authentication, key confirmation, and handshake
integrity: Certificate, CertificateVerify, and Finished.
(The PreSharedKey binders also perform key confirmation, in a
similar fashion.) These three
messages are always sent as the last messages in their handshake
flight. The Certificate and CertificateVerify messages are only
sent under certain circumstances, as defined below. The Finished
message is always sent as part of the Authentication block.
These messages are encrypted under keys derived from
\[sender]_handshake_traffic_secret.

The computations for the Authentication messages all uniformly
take the following inputs:

- The certificate and signing key to be used.
- A Handshake Context consisting of the set of messages to be
  included in the transcript hash.
- A base key to be used to compute a MAC key.

Based on these inputs, the messages then contain:

Certificate
: The certificate to be used for authentication, and any
  supporting certificates in the chain. Note that certificate-based
  client authentication is not available in PSK (including 0-RTT) flows.

CertificateVerify
: A signature over the value Transcript-Hash(Handshake Context, Certificate)

Finished
: A MAC over the value Transcript-Hash(Handshake Context, Certificate, CertificateVerify)
  using a MAC key derived from the base key.
{:br}


The following table defines the Handshake Context and MAC Base Key
for each scenario:

| Mode | Handshake Context | Base Key |
|------|-------------------|----------|
| Server | ClientHello ... later of EncryptedExtensions/CertificateRequest | server_handshake_traffic_secret |
| Client | ClientHello ... later of server Finished/EndOfEarlyData | client_handshake_traffic_secret |
| Post-Handshake | ClientHello ... client Finished + CertificateRequest | client_application_traffic_secret_N |

### The Transcript Hash

Many of the cryptographic computations in TLS make use of a transcript
hash. This value is computed by hashing the concatenation of
each included handshake message, including the handshake
message header carrying the handshake message type and length fields,
but not including record layer headers. I.e.,

     Transcript-Hash(M1, M2, ... MN) = Hash(M1 || M2 ... MN)

As an exception to this general rule, when the server responds to a
ClientHello with a HelloRetryRequest, the value of ClientHello1 is
replaced with a special synthetic handshake message of handshake
type "message_hash" containing Hash(ClientHello1). I.e.,

     Transcript-Hash(ClientHello1, HelloRetryRequest, ... MN) =
         Hash(message_hash ||        /* Handshake type */
              00 00 Hash.length ||   /* Handshake message length (bytes) */
              Hash(ClientHello1) ||  /* Hash of ClientHello1 */
              HelloRetryRequest ... MN)

The reason for this construction is to allow the server to do a
stateless HelloRetryRequest by storing just the hash of ClientHello1
in the cookie, rather than requiring it to export the entire intermediate
hash state (see {{cookie}}).

For concreteness, the transcript hash is always taken from the
following sequence of handshake messages, starting at the first
ClientHello and including only those messages that were sent:
ClientHello, HelloRetryRequest, ClientHello, ServerHello,
EncryptedExtensions, server CertificateRequest, server Certificate,
server CertificateVerify, server Finished, EndOfEarlyData, client
Certificate, client CertificateVerify, client Finished.

In general, implementations can implement the transcript by keeping a
running transcript hash value based on the negotiated hash. Note,
however, that subsequent post-handshake authentications do not include
each other, just the messages through the end of the main handshake.

###  Certificate

This message conveys the endpoint's certificate chain to the peer.

The server MUST send a Certificate message whenever the agreed-upon
key exchange method uses certificates for authentication (this
includes all key exchange methods defined in this document except PSK).

The client MUST send a Certificate message if and only if the server has
requested client authentication via a CertificateRequest message
({{certificate-request}}). If the server requests client authentication
but no suitable certificate is available, the client
MUST send a Certificate message containing no certificates (i.e., with
the "certificate_list" field having length 0).  A Finished message MUST
be sent regardless of whether the Certificate message is empty.

Structure of this message:

%%% Authentication Messages

       /* Managed by IANA */
       enum {
           X509(0),
           OpenPGP_RESERVED(1),
           RawPublicKey(2),
           (255)
       } CertificateType;

       struct {
           select (certificate_type) {
               case RawPublicKey:
                 /* From RFC 7250 ASN.1_subjectPublicKeyInfo */
                 opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;

               case X509:
                 opaque cert_data<1..2^24-1>;
           };
           Extension extensions<0..2^16-1>;
       } CertificateEntry;

       struct {
           opaque certificate_request_context<0..2^8-1>;
           CertificateEntry certificate_list<0..2^24-1>;
       } Certificate;

certificate_request_context
: If this message is in response to a CertificateRequest, the
  value of certificate_request_context in that message. Otherwise
  (in the case of server authentication), this field SHALL be zero length.

certificate_list
: This is a sequence (chain) of CertificateEntry structures, each
  containing a single certificate and set of extensions.

extensions:
: A set of extension values for the CertificateEntry. The "Extension"
  format is defined in {{extensions}}. Valid extensions for server certificates
  at present include OCSP Status extension ({{RFC6066}}) and
  SignedCertificateTimestamps ({{!RFC6962}}); future extensions may
  be defined for this message as well. Extensions in the Certificate
  message from the server MUST correspond to ones from the ClientHello message.
  Extensions in the Certificate from the client MUST correspond with
  extensions in the CertificateRequest message from the server.
  If an extension applies to the entire chain, it SHOULD be included
  in the first CertificateEntry.
{:br }

If the corresponding certificate type extension
("server_certificate_type" or "client_certificate_type") was not negotiated
in Encrypted Extensions, or the X.509 certificate type was negotiated, then each
CertificateEntry contains a DER-encoded X.509 certificate. The sender's
certificate MUST come in the first CertificateEntry in the list.  Each
following certificate SHOULD directly certify one preceding it.
Because certificate validation requires that trust anchors be
distributed independently, a certificate that specifies a trust anchor
MAY be omitted from the chain, provided that supported peers are known
to possess any omitted certificates.

Note: Prior to TLS 1.3, "certificate_list" ordering required each certificate
to certify the one immediately preceding it;
however, some implementations allowed some flexibility. Servers sometimes send
both a current and deprecated intermediate for transitional purposes, and others
are simply configured incorrectly, but these cases can nonetheless be validated
properly. For maximum compatibility, all implementations SHOULD be prepared to
handle potentially extraneous certificates and arbitrary orderings from any TLS
version, with the exception of the end-entity certificate which MUST be first.

If the RawPublicKey certificate type was negotiated, then the
certificate_list MUST contain no more than one CertificateEntry, which
contains an ASN1_subjectPublicKeyInfo value as defined in {{RFC7250}},
Section 3.

The OpenPGP certificate type {{RFC6091}} MUST NOT be used with TLS 1.3.

The server's certificate_list MUST always be non-empty. A client will
send an empty certificate_list if it does not have an appropriate
certificate to send in response to the server's authentication
request.

#### OCSP Status and SCT Extensions {#ocsp-and-sct}

{{RFC6066}} and {{!RFC6961}} provide extensions to negotiate the server
sending OCSP responses to the client. In TLS 1.2 and below, the
server replies with an empty extension to indicate negotiation of this
extension and the OCSP information is carried in a CertificateStatus
message. In TLS 1.3, the server's OCSP information is carried in
an extension in the CertificateEntry containing the associated
certificate. Specifically:
The body of the "status_request" extension
from the server MUST be a CertificateStatus structure as defined
in {{RFC6066}}, which is interpreted as defined in {{!RFC6960}}.

Note: status_request_v2 extension ({{!RFC6961}}) is deprecated. TLS 1.3 servers
MUST NOT act upon its presence or information in it when processing Client
Hello, in particular they MUST NOT send the status_request_v2 extension in the
Encrypted Extensions, Certificate Request or the Certificate messages.
TLS 1.3 servers MUST be able to process Client Hello messages that include it,
as it MAY be sent by clients that wish to use it in earlier protocol versions.

A server MAY request that a client present an OCSP response with its
certificate by sending an empty "status_request" extension in its
CertificateRequest message. If the client opts to send an OCSP response, the
body of its "status_request" extension MUST be a CertificateStatus structure as
defined in {{RFC6066}}.

Similarly, {{!RFC6962}} provides a mechanism for a server to send a
Signed Certificate Timestamp (SCT) as an extension in the ServerHello
in TLS 1.2 and below.
In TLS 1.3, the server's SCT information is carried in an extension in
CertificateEntry.

#### Server Certificate Selection

The following rules apply to the certificates sent by the server:

- The certificate type MUST be X.509v3 {{RFC5280}}, unless explicitly negotiated
  otherwise (e.g., {{RFC7250}}).

- The server's end-entity certificate's public key (and associated
  restrictions) MUST be compatible with the selected authentication
  algorithm from the client's "signature_algorithms" extension
  (currently RSA, ECDSA, or EdDSA).

- The certificate MUST allow the key to be used for signing (i.e., the
  digitalSignature bit MUST be set if the Key Usage extension is present) with
  a signature scheme indicated in the client's "signature_algorithms"/"signature_algorithms_cert"
  extensions (see {{signature-algorithms}}).

- The "server_name" {{RFC6066}} and "certificate_authorities" extensions are used to
  guide certificate selection. As servers MAY require the presence of the "server_name"
  extension, clients SHOULD send this extension, when applicable.

All certificates provided by the server MUST be signed by a
signature algorithm advertised by the client, if they are able to provide such
a chain (see {{signature-algorithms}}).
Certificates that are self-signed
or certificates that are expected to be trust anchors are not validated as
part of the chain and therefore MAY be signed with any algorithm.

If the server cannot produce a certificate chain that is signed only via the
indicated supported algorithms, then it SHOULD continue the handshake by sending
the client a certificate chain of its choice that may include algorithms
that are not known to be supported by the client.
This fallback chain SHOULD NOT use the deprecated SHA-1 hash algorithm in general,
but MAY do so if the client's advertisement permits it,
and MUST NOT do so otherwise.

If the client cannot construct an acceptable chain using the provided
certificates and decides to abort the handshake, then it MUST abort the
handshake with an appropriate certificate-related alert (by default,
"unsupported_certificate"; see {{error-alerts}} for more).

If the server has multiple certificates, it chooses one of them based on the
above-mentioned criteria (in addition to other criteria, such as transport
layer endpoint, local configuration and preferences).

#### Client Certificate Selection

The following rules apply to certificates sent by the client:

- The certificate type MUST be X.509v3 {{RFC5280}}, unless explicitly negotiated
  otherwise (e.g., {{RFC7250}}).

- If the "certificate_authorities" extension in the CertificateRequest
  message was present, at least one of the certificates in the certificate
  chain SHOULD be issued by one of the listed CAs.

- The certificates MUST be signed using an acceptable signature
  algorithm, as described in {{certificate-request}}.  Note that this
  relaxes the constraints on certificate-signing algorithms found in
  prior versions of TLS.

- If the CertificateRequest message contained a non-empty "oid_filters"
  extension, the end-entity certificate MUST match the extension OIDs
  recognized by the client, as described in {{oid-filters}}.

Note that, as with the server certificate, there are certificates that use
algorithm combinations that cannot be currently used with TLS.

#### Receiving a Certificate Message

In general, detailed certificate validation procedures are out of scope for
TLS (see {{RFC5280}}). This section provides TLS-specific requirements.

If the server supplies an empty Certificate message, the client MUST abort
the handshake with a "decode_error" alert.

If the client does not send any certificates (i.e., it sends an empty
Certificate message),
the server MAY at its discretion either continue the handshake without client
authentication, or abort the handshake with a "certificate_required" alert. Also, if some
aspect of the certificate chain was unacceptable (e.g., it was not signed by a
known, trusted CA), the server MAY at its discretion either continue the
handshake (considering the client unauthenticated) or abort the handshake.

Any endpoint receiving any certificate which it would need to validate
using any signature algorithm using an MD5 hash MUST abort the
handshake with a "bad_certificate" alert.  SHA-1 is deprecated and it
is RECOMMENDED that any endpoint receiving any certificate which it
would need to validate using any signature algorithm using a SHA-1
hash abort the handshake with a "bad_certificate" alert. For clarity,
this means that endpoints MAY accept these algorithms for
certificates that are self-signed or are trust anchors.

All endpoints are RECOMMENDED to transition to SHA-256 or better as soon
as possible to maintain interoperability with implementations
currently in the process of phasing out SHA-1 support.

Note that a certificate containing a key for one signature algorithm
MAY be signed using a different signature algorithm (for instance,
an RSA key signed with an ECDSA key).

###  Certificate Verify

This message is used to provide explicit proof that an endpoint
possesses the private key corresponding to its certificate.
The CertificateVerify message also provides integrity for the handshake up
to this point. Servers MUST send this message when authenticating via a certificate.
Clients MUST send this message whenever authenticating via a certificate (i.e., when
the Certificate message is non-empty). When sent, this message MUST appear immediately
after the Certificate message and immediately prior to the Finished message.

Structure of this message:

%%% Authentication Messages

       struct {
           SignatureScheme algorithm;
           opaque signature<0..2^16-1>;
       } CertificateVerify;

The algorithm field specifies the signature algorithm used (see
{{signature-algorithms}} for the definition of this field). The
signature is a digital signature using that algorithm. The
content that is covered under the signature is the hash output as described in
{{the-transcript-hash}}, namely:

       Transcript-Hash(Handshake Context, Certificate)

The digital signature is then computed over the concatenation of:

- A string that consists of octet 32 (0x20) repeated 64 times
- The context string
- A single 0 byte which serves as the separator
- The content to be signed

This structure is intended to prevent an attack on previous versions
of TLS in which the ServerKeyExchange format meant that
attackers could obtain a signature of a message with a chosen 32-byte
prefix (ClientHello.random). The initial 64-byte pad clears that prefix
along with the server-controlled ServerHello.random.

The context string for a server signature is:
"TLS 1.3, server CertificateVerify"
The context string for a client signature is:
"TLS 1.3, client CertificateVerify"
It is used to provide separation between signatures made in different
contexts, helping against potential cross-protocol attacks.

For example, if the transcript hash was 32 bytes of
01 (this length would make sense for SHA-256), the content covered by
the digital signature for a server CertificateVerify would be:

       2020202020202020202020202020202020202020202020202020202020202020
       2020202020202020202020202020202020202020202020202020202020202020
       544c5320312e332c207365727665722043657274696669636174655665726966
       79
       00
       0101010101010101010101010101010101010101010101010101010101010101

On the sender side the process for computing the signature field of the
CertificateVerify message takes as input:

- The content covered by the digital signature
- The private signing key corresponding to the certificate sent in the
  previous message

If the CertificateVerify message is sent by a server, the signature
algorithm MUST be one offered in the client's "signature_algorithms" extension
unless no valid certificate chain can be produced without unsupported
algorithms (see {{signature-algorithms}}).

If sent by a client, the signature algorithm used in the signature
MUST be one of those present in the supported_signature_algorithms
field of the "signature_algorithms" extension in the CertificateRequest message.

In addition, the signature algorithm MUST be compatible with the key
in the sender's end-entity certificate. RSA signatures MUST use an
RSASSA-PSS algorithm, regardless of whether RSASSA-PKCS1-v1_5 algorithms
appear in "signature_algorithms". The SHA-1 algorithm MUST NOT be used
in any signatures of CertificateVerify messages.
All SHA-1 signature algorithms in this specification are defined solely
for use in legacy certificates and are not valid for CertificateVerify
signatures.

The receiver of a CertificateVerify message MUST verify the signature field.
The verification process takes as input:

- The content covered by the digital signature
- The public key contained in the end-entity certificate found in the
  associated Certificate message.
- The digital signature received in the signature field of the
  CertificateVerify message

If the verification fails, the receiver MUST terminate the handshake
with a "decrypt_error" alert.

###  Finished

The Finished message is the final message in the authentication
block. It is essential for providing authentication of the handshake
and of the computed keys.

Recipients of Finished messages MUST verify that the contents are
correct and if incorrect MUST terminate the connection
with a "decrypt_error" alert.

Once a side has sent its Finished message and received and
validated the Finished message from its peer, it may begin to send and
receive application data over the connection. There are two
settings in which it is permitted to send data prior to
receiving the peer's Finished:

1. Clients sending 0-RTT data as described in {{early-data-indication}}.
2. Servers MAY send data after sending their first flight, but
   because the handshake is not yet complete, they have no assurance
   of either the peer's identity or of its liveness (i.e.,
   the ClientHello might have been replayed).

The key used to compute the finished message is computed from the
Base key defined in {{authentication-messages}} using HKDF (see
{{key-schedule}}). Specifically:

~~~
finished_key =
    HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
~~~

Structure of this message:

%%% Authentication Messages

       struct {
           opaque verify_data[Hash.length];
       } Finished;


The verify_data value is computed as follows:

       verify_data =
           HMAC(finished_key,
                Transcript-Hash(Handshake Context,
                                Certificate*, CertificateVerify*))

       * Only included if present.

HMAC {{RFC2104}} uses the Hash algorithm for the handshake.
As noted above, the HMAC input can generally be implemented by a running
hash, i.e., just the handshake hash at this point.

In previous versions of TLS, the verify_data was always 12 octets long. In
TLS 1.3, it is the size of the HMAC output for the Hash used for the handshake.

Note: Alerts and any other record types are not handshake messages
and are not included in the hash computations.

Any records following a 1-RTT Finished message MUST be encrypted under the
appropriate application traffic key as described in {{updating-traffic-keys}}.
In particular, this includes any alerts sent by the
server in response to client Certificate and CertificateVerify messages.


## End of Early Data

%%% Updating Keys

       struct {} EndOfEarlyData;

If the server sent an "early_data" extension, the client MUST send an
EndOfEarlyData message after receiving the server Finished.  If the server does
not send an "early_data" extension, then the client MUST NOT send an
EndOfEarlyData message. This message indicates that all
0-RTT application_data messages, if any, have been transmitted and
that the following records are protected under handshake traffic keys.
Servers MUST NOT send this message and clients receiving it
MUST terminate the connection with an "unexpected_message" alert.
This message is encrypted under keys derived from the client_early_traffic_secret.


## Post-Handshake Messages

TLS also allows other messages to be sent after the main handshake.
These messages use a handshake content type and are encrypted under the
appropriate application traffic key.

### New Session Ticket Message {#NSTMessage}

At any time after the server has received the client Finished message,
it MAY send a NewSessionTicket message. This message creates a unique
association between the ticket value and a secret PSK
derived from the resumption master secret.

The client MAY use this PSK for future handshakes by including the
ticket value in the "pre_shared_key" extension in its ClientHello
({{pre-shared-key-extension}}). Servers MAY send multiple tickets on a
single connection, either immediately after each other or
after specific events (see {{client-tracking}}).
For instance, the server might send a new ticket after post-handshake
authentication in order to encapsulate the additional client
authentication state. Multiple tickets are useful for clients
for a variety of purposes, including:

- Opening multiple parallel HTTP connections.
- Performing connection racing across interfaces and address families
via, e.g., Happy Eyeballs {{RFC8305}} or related techniques.

Any ticket MUST only be resumed with a cipher suite that has the
same KDF hash algorithm as that used to establish the original connection.

Clients MUST only resume if the new SNI value is valid for the server
certificate presented in the original session, and SHOULD only resume if
the SNI value matches the one used in the original session.  The latter
is a performance optimization: normally, there is no reason to expect
that different servers covered by a single certificate would be able to
accept each other's tickets, hence attempting resumption in that case
would waste a single-use ticket.  If such an indication is provided
(externally or by any other means), clients MAY resume with a different
SNI value.

On resumption, if reporting an SNI value to the calling application,
implementations MUST use the value sent in the resumption ClientHello rather
than the value sent in the previous session. Note that if a server
implementation declines all PSK identities with different SNI values, these two
values are always the same.

Note: Although the resumption master secret depends on the client's second
flight, servers which do not request client authentication MAY compute
the remainder of the transcript independently and then send a
NewSessionTicket immediately upon sending its Finished rather than
waiting for the client Finished.  This might be appropriate in cases
where the client is expected to open multiple TLS connections in
parallel and would benefit from the reduced overhead of a resumption
handshake, for example.


%%% Ticket Establishment

       struct {
           uint32 ticket_lifetime;
           uint32 ticket_age_add;
           opaque ticket_nonce<0..255>;
           opaque ticket<1..2^16-1>;
           Extension extensions<0..2^16-2>;
       } NewSessionTicket;

ticket_lifetime
: Indicates the lifetime in seconds as a 32-bit unsigned integer in
  network byte order from the time of ticket issuance.
  Servers MUST NOT use any value greater than 604800 seconds (7 days).
  The value of zero indicates that the ticket should be discarded
  immediately. Clients MUST NOT cache tickets for longer than
  7 days, regardless of the ticket_lifetime, and MAY delete tickets
  earlier based on local policy. A server MAY treat a ticket as valid
  for a shorter period of time than what is stated in the
  ticket_lifetime.

ticket_age_add
: A securely generated, random 32-bit value that is used to obscure the age of
  the ticket that the client includes in the "pre_shared_key" extension.
  The client-side ticket age is added to this value modulo 2^32 to
  obtain the value that is transmitted by the client.
  The server MUST generate a fresh value for each ticket it sends.

ticket_nonce
: A per-ticket value that is unique across all tickets issued on this connection.

ticket
: The value of the ticket to be used as the PSK identity.
  The ticket itself is an opaque label. It MAY either be a database
  lookup key or a self-encrypted and self-authenticated value. Section
  4 of {{RFC5077}} describes a recommended ticket construction mechanism.

extensions
: A set of extension values for the ticket. The "Extension"
  format is defined in {{extensions}}. Clients MUST ignore
  unrecognized extensions.
{:br }

The sole extension currently defined for NewSessionTicket is
"early_data", indicating that the ticket may be used to send 0-RTT data
({{early-data-indication}})). It contains the following value:

max_early_data_size
: The maximum amount of 0-RTT data that the client is allowed to send when using
  this ticket, in bytes. Only Application Data payload (i.e., plaintext but
  not padding or the inner content type byte) is counted. A server
  receiving more than max_early_data_size bytes of 0-RTT data
  SHOULD terminate the connection with an "unexpected_message" alert.
  Note that servers that reject early data due to lack of cryptographic material
  will be unable to differentiate padding from content, so clients SHOULD NOT
  depend on being able to send large quantities of padding in early data records.
{:br }

The PSK associated with the ticket is computed as:

~~~~
    HKDF-Expand-Label(resumption_master_secret,
                     "resumption", ticket_nonce, Hash.length)
~~~~

Because the ticket_nonce value is distinct for each NewSessionTicket
message, a different PSK will be derived for each ticket.

Note that in principle it is possible to continue issuing new tickets
which indefinitely extend the lifetime of the keying
material originally derived from an initial non-PSK handshake (which
was most likely tied to the peer's certificate). It is RECOMMENDED
that implementations place limits on the total lifetime of such keying
material; these limits should take into account the lifetime of the
peer's certificate, the likelihood of intervening revocation,
and the time since the peer's online CertificateVerify signature.

### Post-Handshake Authentication

When the client has sent the "post_handshake_auth" extension (see
{{post_handshake_auth}}), a server MAY request client authentication at any time
after the handshake has completed by sending a CertificateRequest message. The
client MUST respond with the appropriate Authentication messages (see
{{authentication-messages}}). If the client chooses to authenticate, it MUST
send Certificate, CertificateVerify, and Finished. If it declines, it MUST send
a Certificate message containing no certificates followed by Finished.
All of the client's messages for a given response
MUST appear consecutively on the wire with no intervening messages of other types.

A client that receives a CertificateRequest message without having sent
the "post_handshake_auth" extension MUST send an "unexpected_message" fatal
alert.

Note: Because client authentication could involve prompting the user, servers
MUST be prepared for some delay, including receiving an arbitrary number of
other messages between sending the CertificateRequest and receiving a
response. In addition, clients which receive multiple CertificateRequests in
close succession MAY respond to them in a different order than they were
received (the certificate_request_context value allows the server to
disambiguate the responses).


### Key and IV Update {#key-update}

%%% Updating Keys

       enum {
           update_not_requested(0), update_requested(1), (255)
       } KeyUpdateRequest;

       struct {
           KeyUpdateRequest request_update;
       } KeyUpdate;


request_update
: Indicates whether the recipient of the KeyUpdate should respond with its
  own KeyUpdate. If an implementation receives any other value, it MUST
  terminate the connection with an "illegal_parameter" alert.
{:br }

The KeyUpdate handshake message is used to indicate that the sender is
updating its sending cryptographic keys. This message can be sent by
either peer after it has sent a Finished message.
Implementations that receive a KeyUpdate message prior to receiving a Finished message
MUST terminate the connection with an "unexpected_message" alert.
After sending a KeyUpdate message, the sender SHALL send all its traffic using the
next generation of keys, computed as described in {{updating-traffic-keys}}.
Upon receiving a KeyUpdate, the receiver MUST update its receiving keys.

If the request_update field is set to "update_requested" then the receiver MUST
send a KeyUpdate of its own with request_update set to "update_not_requested" prior
to sending its next application data record. This mechanism allows either side to force an update to the
entire connection, but causes an implementation which
receives multiple KeyUpdates while it is silent to respond with
a single update. Note that implementations may receive an arbitrary
number of messages between sending a KeyUpdate with request_update set
to update_requested and receiving the
peer's KeyUpdate, because those messages may already be in flight.
However, because send and receive keys are derived from independent
traffic secrets, retaining the receive traffic secret does not threaten
the forward secrecy of data sent before the sender changed keys.

If implementations independently send their own KeyUpdates with
request_update set to "update_requested", and they cross in flight, then each side
will also send a response, with the result that each side increments
by two generations.

Both sender and receiver MUST encrypt their KeyUpdate
messages with the old keys. Additionally, both sides MUST enforce that
a KeyUpdate with the old key is received before accepting any messages
encrypted with the new key. Failure to do so may allow message truncation
attacks.


#  Record Protocol

The TLS record protocol takes messages to be transmitted, fragments
the data into manageable blocks, protects the records, and transmits
the result. Received data is verified, decrypted, reassembled, and
then delivered to higher-level clients.

TLS records are typed, which allows multiple higher-level protocols to
be multiplexed over the same record layer. This document specifies
four content types: handshake, application data, alert, and
change_cipher_spec.
The change_cipher_spec record is used only for compatibility purposes
(see {{middlebox}}).

An implementation may receive an unencrypted record of type
change_cipher_spec consisting of the single byte value 0x01 at any
time after the first ClientHello message has been sent or received and before
the peer's Finished message has been received and MUST simply drop it without
further processing.  Note that this record may appear at a point at the
handshake where the implementation is expecting protected records
and so it is necessary to detect this
condition prior to attempting to deprotect the record. An
implementation which receives any other change_cipher_spec value or
which receives a protected change_cipher_spec record MUST abort the
handshake with an "unexpected_message" alert. A change_cipher_spec record
received before the first ClientHello message or after the peer's Finished
message MUST be treated as an unexpected record type (though stateless
servers may not be able to distinguish these cases from allowed cases).


Implementations MUST NOT send record types not defined in this
document unless negotiated by some extension.  If a TLS implementation
receives an unexpected record type, it MUST terminate the connection
with an "unexpected_message" alert.  New record content type values
are assigned by IANA in the TLS Content Type Registry as described in
{{iana-considerations}}.

## Record Layer

The record layer fragments information blocks into TLSPlaintext
records carrying data in chunks of 2^14 bytes or less. Message
boundaries are handled differently depending on the underlying
ContentType. Any future content types MUST specify appropriate
rules.
Note that these rules are stricter than what was enforced in TLS 1.2.

Handshake messages MAY be coalesced into a single TLSPlaintext
record or fragmented across several records, provided that:

- Handshake messages MUST NOT be interleaved with other record
  types. That is, if a handshake message is split over two or more
  records, there MUST NOT be any other records between them.

- Handshake messages MUST NOT span key changes. Implementations MUST verify that
  all messages immediately preceding a key change align with a record boundary;
  if not, then they MUST terminate the connection with an "unexpected_message"
  alert. Because the ClientHello, EndOfEarlyData, ServerHello, Finished, and
  KeyUpdate messages can immediately precede a key change, implementations MUST
  send these messages in alignment with a record boundary.

Implementations MUST NOT send zero-length fragments of Handshake
types, even if those fragments contain padding.

Alert messages ({{alert-protocol}}) MUST NOT be fragmented across
records and multiple Alert messages MUST NOT be coalesced into a
single TLSPlaintext record. In other words, a record with an Alert
type MUST contain exactly one message.

Application Data messages contain data that is opaque to
TLS. Application Data messages are always protected. Zero-length
fragments of Application Data MAY be sent as they are potentially
useful as a traffic analysis countermeasure.  Application Data fragments
MAY be split across multiple records or coalesced into a single record.


%%% Record Layer

       enum {
           invalid(0),
           change_cipher_spec(20),
           alert(21),
           handshake(22),
           application_data(23),
           (255)
       } ContentType;

       struct {
           ContentType type;
           ProtocolVersion legacy_record_version;
           uint16 length;
           opaque fragment[TLSPlaintext.length];
       } TLSPlaintext;

type
: The higher-level protocol used to process the enclosed fragment.

legacy_record_version
: This value MUST be set to 0x0303 for all records generated by a
  TLS 1.3 implementation other than an initial ClientHello (i.e., one
  not generated after a HelloRetryRequest), where it
  MAY also be 0x0301 for compatibility purposes.
  This field is deprecated and MUST be ignored for all purposes.
  Previous versions of TLS would use other values in this field
  under some circumstances.

length
: The length (in bytes) of the following TLSPlaintext.fragment. The
  length MUST NOT exceed 2^14 bytes. An endpoint that receives a record
  that exceeds this length MUST terminate the connection with a
  "record_overflow" alert.

fragment
: The data being transmitted. This value is transparent and is treated as an
  independent block to be dealt with by the higher-level protocol
  specified by the type field.
{:br }

This document describes TLS 1.3, which uses the version 0x0304.
This version value is historical, deriving from the use of 0x0301
for TLS 1.0 and 0x0300 for SSL 3.0. In order to maximize backwards
compatibility, records containing an initial ClientHello SHOULD have version
0x0301 and a record containing a second ClientHello or
a ServerHello MUST have version
0x0303, reflecting TLS 1.0 and TLS 1.2 respectively.
When negotiating prior versions of TLS, endpoints
follow the procedure and requirements in {{backward-compatibility}}.

When record protection has not yet been engaged, TLSPlaintext
structures are written directly onto the wire. Once record protection
has started, TLSPlaintext records are protected and sent as
described in the following section.

## Record Payload Protection

The record protection functions translate a TLSPlaintext structure into a
TLSCiphertext. The deprotection functions reverse the process. In TLS 1.3,
as opposed to previous versions of TLS, all ciphers are modeled as
"Authenticated Encryption with Additional Data" (AEAD) {{RFC5116}}.
AEAD functions provide an unified encryption and authentication
operation which turns plaintext into authenticated ciphertext and
back again. Each encrypted record consists of a plaintext header followed
by an encrypted body, which itself contains a type and optional padding.

%%% Record Layer

       struct {
           opaque content[TLSPlaintext.length];
           ContentType type;
           uint8 zeros[length_of_padding];
       } TLSInnerPlaintext;

       struct {
           ContentType opaque_type = application_data; /* 23 */
           ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
           uint16 length;
           opaque encrypted_record[TLSCiphertext.length];
       } TLSCiphertext;

content
: The byte encoding of a handshake or an alert message, or the raw bytes of
  the application's data to send.

type
: The content type of the record.

zeros
: An arbitrary-length run of zero-valued bytes may
  appear in the cleartext after the type field.  This provides an
  opportunity for senders to pad any TLS record by a chosen amount as
  long as the total stays within record size limits.  See
  {{record-padding}} for more details.

opaque_type
: The outer opaque_type field of a TLSCiphertext record is always set to the
  value 23 (application_data) for outward compatibility with
  middleboxes accustomed to parsing previous versions of TLS.  The
  actual content type of the record is found in TLSInnerPlaintext.type after
  decryption.

legacy_record_version
: The legacy_record_version field is always 0x0303.  TLS 1.3 TLSCiphertexts
  are not generated until after TLS 1.3 has been negotiated, so there are
  no historical compatibility concerns where other values might be received.
  Note that the handshake protocol including the ClientHello and ServerHello
  messages authenticates the protocol version, so this value is redundant.

length
: The length (in bytes) of the following TLSCiphertext.encrypted_record, which
  is the sum of the lengths of the content and the padding, plus one
  for the inner content type, plus any expansion added by the AEAD algorithm.
  The length MUST NOT exceed 2^14 + 256 bytes.
  An endpoint that receives a record that exceeds this length MUST
  terminate the connection with a "record_overflow" alert.

encrypted_record
: The AEAD-encrypted form of the serialized TLSInnerPlaintext structure.
{:br }


AEAD algorithms take as input a single key, a nonce, a plaintext, and "additional
data" to be included in the authentication check, as described in Section 2.1
of {{RFC5116}}. The key is either the client_write_key or the server_write_key,
the nonce is derived from the sequence number (see {{nonce}}) and the
client_write_iv or server_write_iv, and the additional data input is the
record header. I.e., 

       additional_data = TLSCiphertext.opaque_type ||
                         TLSCiphertext.legacy_record_version ||
                         TLSCiphertext.length

The plaintext input to the AEAD algorithm is the encoded TLSInnerPlaintext structure.
Derivation of traffic keys is defined in {{traffic-key-calculation}}.

The AEAD output consists of the ciphertext output from the AEAD
encryption operation. The length of the plaintext is greater than the
corresponding TLSPlaintext.length due to the inclusion of TLSInnerPlaintext.type and
any padding supplied by the sender. The length of the
AEAD output will generally be larger than the plaintext, but by an
amount that varies with the AEAD algorithm. Since the ciphers might
incorporate padding, the amount of overhead could vary with different
lengths of plaintext. Symbolically,

       AEADEncrypted =
           AEAD-Encrypt(write_key, nonce, additional_data, plaintext)

Then the encrypted_record field of TLSCiphertext is set to AEADEncrypted.

In order to decrypt and verify, the cipher takes as input the key, nonce,
additional data, and the AEADEncrypted value. The output is either the plaintext
or an error indicating that the decryption failed. There is no separate
integrity check. That is:

       plaintext of encrypted_record =
           AEAD-Decrypt(peer_write_key, nonce, additional_data, AEADEncrypted)

If the decryption fails, the receiver MUST terminate the connection
with a "bad_record_mac" alert.

An AEAD algorithm used in TLS 1.3 MUST NOT produce an expansion greater than
255 octets. An endpoint that receives a record from its peer with
TLSCiphertext.length larger than 2^14 + 256 octets MUST terminate
the connection with a "record_overflow" alert.
This limit is derived from the maximum TLSPlaintext length of
2^14 octets + 1 octet for ContentType + the maximum AEAD expansion of 255 octets.


## Per-Record Nonce {#nonce}

A 64-bit sequence number is maintained separately for reading and writing
records.  Each sequence number is set to zero at the beginning of a connection
and whenever the key is changed.

The appropriate sequence number is incremented by one after reading
or writing each record. The first record transmitted under a particular
traffic key MUST use sequence number 0.

Because the size of sequence numbers is 64-bit, they should not
wrap. If a TLS implementation would need to
wrap a sequence number, it MUST either re-key ({{key-update}}) or
terminate the connection.

Each AEAD algorithm will specify a range of possible lengths for the
per-record nonce, from N_MIN bytes to N_MAX bytes of input ({{RFC5116}}).
The length of the TLS per-record nonce (iv_length) is set to the larger of
8 bytes and N_MIN for the AEAD algorithm (see {{RFC5116}} Section 4).
An AEAD algorithm where N_MAX is less than 8 bytes MUST NOT be used with TLS.
The per-record nonce for the AEAD construction is formed as follows:

  1. The 64-bit record sequence number is encoded in network byte order
     and padded to the left with zeros to iv_length.

  2. The padded sequence number is XORed with the static client_write_iv
     or server_write_iv, depending on the role.

The resulting quantity (of length iv_length) is used as the per-record nonce.

Note: This is a different construction from that in TLS 1.2, which
specified a partially explicit nonce.


## Record Padding

All encrypted TLS records can be padded to inflate the size of the
TLSCiphertext.  This allows the sender to hide the size of the
traffic from an observer.

When generating a TLSCiphertext record, implementations MAY choose to pad.
An unpadded record is just a record with a padding length of zero.
Padding is a string of zero-valued bytes appended to the ContentType
field before encryption.  Implementations MUST set the padding octets
to all zeros before encrypting.

Application Data records may contain a zero-length TLSInnerPlaintext.content if
the sender desires.  This permits generation of plausibly-sized cover
traffic in contexts where the presence or absence of activity may be
sensitive.  Implementations MUST NOT send Handshake or Alert records
that have a zero-length TLSInnerPlaintext.content; if such a message
is received, the receiving implementation MUST terminate the connection
with an "unexpected_message" alert.

The padding sent is automatically verified by the record protection
mechanism; upon successful decryption of a TLSCiphertext.encrypted_record,
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
a non-zero octet in the cleartext, it MUST terminate the
connection with an "unexpected_message" alert.

The presence of padding does not change the overall record size limitations
- the full encoded TLSInnerPlaintext MUST NOT exceed 2^14 + 1 octets. If the
maximum fragment length is reduced, as for example by the max_fragment_length
extension from [RFC6066], then the reduced limit applies to the full plaintext,
including the content type and padding.

Selecting a padding policy that suggests when and how much to pad is a
complex topic and is beyond the scope of this specification. If the
application layer protocol on top of TLS has its own padding, it may be
preferable to pad application_data TLS records within the application
layer.  Padding for encrypted handshake and alert TLS records must
still be handled at the TLS layer, though.  Later documents may define
padding selection algorithms or define a padding policy request
mechanism through TLS extensions or some other means.


## Limits on Key Usage

There are cryptographic limits on the amount of plaintext which can be
safely encrypted under a given set of keys.  {{AEAD-LIMITS}} provides
an analysis of these limits under the assumption that the underlying
primitive (AES or ChaCha20) has no weaknesses. Implementations SHOULD
do a key update as described in {{key-update}} prior to reaching these limits.

For AES-GCM, up to 2^24.5 full-size records (about 24 million)
may be encrypted on a given connection while keeping a safety
margin of approximately 2^-57 for Authenticated Encryption (AE) security.
For ChaCha20/Poly1305, the record sequence number would wrap before the
safety limit is reached.

#  Alert Protocol

One of the content types supported by the TLS record layer is the
alert type.  Like other messages, alert messages are encrypted as
specified by the current connection state.

Alert messages convey a description of the alert and a legacy field
that conveyed the severity of the message in previous versions of
TLS.  In TLS 1.3, the severity is implicit in the type of alert
being sent, and the 'level' field can safely be ignored. The "close_notify" alert
is used to indicate orderly closure of one direction of the connection.
Upon receiving such an alert, the TLS implementation SHOULD
indicate end-of-data to the application.

Error alerts indicate abortive closure of the
connection (see {{error-alerts}}). Upon receiving an error alert,
the TLS implementation SHOULD indicate an error to the application and
MUST NOT allow any further data to be sent or received on the
connection.  Servers and clients MUST forget keys and secrets
associated with a failed connection. Stateful implementations of
tickets (as in many clients) SHOULD discard tickets associated
with failed connections.

All the alerts listed in {{error-alerts}} MUST be sent as fatal and
MUST be treated as fatal regardless of the AlertLevel in the
message. Unknown alert types MUST be treated as fatal.

Note: TLS defines two generic alerts (see {{alert-protocol}}) to use
upon failure to parse a message. Peers which receive a message which
cannot be parsed according to the syntax (e.g., have a length
extending beyond the message boundary or contain an out-of-range
length) MUST terminate the connection with a "decode_error"
alert. Peers which receive a message which is syntactically correct
but semantically invalid (e.g., a DHE share of p - 1, or an invalid
enum) MUST terminate the connection with an "illegal_parameter" alert.


%%% Alert Messages

       enum { warning(1), fatal(2), (255) } AlertLevel;

       enum {
           close_notify(0),
           unexpected_message(10),
           bad_record_mac(20),
           decryption_failed_RESERVED(21),
           record_overflow(22),
           decompression_failure_RESERVED(30),
           handshake_failure(40),
           no_certificate_RESERVED(41),
           bad_certificate(42),
           unsupported_certificate(43),
           certificate_revoked(44),
           certificate_expired(45),
           certificate_unknown(46),
           illegal_parameter(47),
           unknown_ca(48),
           access_denied(49),
           decode_error(50),
           decrypt_error(51),
           export_restriction_RESERVED(60),
           protocol_version(70),
           insufficient_security(71),
           internal_error(80),
           inappropriate_fallback(86),
           user_canceled(90),
           no_renegotiation_RESERVED(100),
           missing_extension(109),
           unsupported_extension(110),
           certificate_unobtainable_RESERVED(111),
           unrecognized_name(112),
           bad_certificate_status_response(113),
           bad_certificate_hash_value_RESERVED(114),
           unknown_psk_identity(115),
           certificate_required(116),
           no_application_protocol(120),
           (255)
       } AlertDescription;

       struct {
           AlertLevel level;
           AlertDescription description;
       } Alert;


##  Closure Alerts

The client and the server must share knowledge that the connection is ending in
order to avoid a truncation attack.

close_notify
: This alert notifies the recipient that the sender will not send
  any more messages on this connection. Any data received after a
  closure alert has been received MUST be ignored.

user_canceled
: This alert notifies the recipient that the sender is canceling the
  handshake for some reason unrelated to a protocol failure. If a user
  cancels an operation after the handshake is complete, just closing the
  connection by sending a "close_notify" is more appropriate. This alert
  SHOULD be followed by a "close_notify". This alert is generally a warning.
{:br }

Either party MAY initiate a close of its write side of the connection by
sending a "close_notify" alert. Any data received after a closure alert has
been received MUST be ignored. If a transport-level close is received prior
to a "close_notify", the receiver cannot know that all the data that was sent
has been received.

Each party MUST send a "close_notify" alert before closing its write side
of the connection, unless it has already sent some other fatal alert. This
does not have any effect on its read side of the connection. Note that this is
a change from versions of TLS prior to TLS 1.3 in which implementations were
required to react to a "close_notify" by discarding pending writes and
sending an immediate "close_notify" alert of their own. That previous
requirement could cause truncation in the read side. Both parties need not
wait to receive a "close_notify" alert before closing their read side of the
connection, though doing so would introduce the possibility of truncation.

If the application protocol using TLS provides that any data may be carried
over the underlying transport after the TLS connection is closed, the TLS
implementation MUST receive a "close_notify" alert before indicating
end-of-data to the application-layer. No part of this
standard should be taken to dictate the manner in which a usage profile for TLS
manages its data transport, including when connections are opened or closed.

Note: It is assumed that closing the write side of a connection reliably
delivers pending data before destroying the transport.


##  Error Alerts

Error handling in the TLS Handshake Protocol is very simple. When an
error is detected, the detecting party sends a message to its
peer. Upon transmission or receipt of a fatal alert message, both
parties MUST immediately close the connection.

Whenever an implementation encounters a fatal error condition, it
SHOULD send an appropriate fatal alert and MUST close the connection
without sending or receiving any additional data. In the rest of this
specification, when the phrases "terminate the connection" and "abort the
handshake" are used without a specific alert it means that the
implementation SHOULD send the alert indicated by the descriptions
below. The phrases "terminate the connection with a X alert" and
"abort the handshake with a X alert" mean that the implementation
MUST send alert X if it sends any alert. All
alerts defined in this section below, as well as all unknown alerts,
are universally considered fatal as of TLS 1.3 (see {{alert-protocol}}).
The implementation SHOULD provide a way to facilitate logging
the sending and receiving of alerts.

The following error alerts are defined:

unexpected_message
: An inappropriate message (e.g., the wrong handshake message, premature
  application data, etc.) was received. This alert should never be
  observed in communication between proper implementations.

bad_record_mac
: This alert is returned if a record is received which cannot be
  deprotected. Because AEAD algorithms combine decryption and
  verification, and also to avoid side channel attacks,
  this alert is used for all deprotection failures.
  This alert should never be observed in communication between
  proper implementations, except when messages were corrupted
  in the network.

record_overflow
: A TLSCiphertext record was received that had a length more than
  2^14 + 256 bytes, or a record decrypted to a TLSPlaintext record
  with more than 2^14 bytes (or some other negotiated limit).
  This alert should never be observed in communication between
  proper implementations, except when messages were corrupted
  in the network.

handshake_failure
: Receipt of a "handshake_failure" alert message indicates that the
  sender was unable to negotiate an acceptable set of security
  parameters given the options available.

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
: A field in the handshake was incorrect or inconsistent with
  other fields. This alert is used for errors which conform to
  the formal protocol syntax but are otherwise incorrect.

unknown_ca
: A valid certificate chain or partial chain was received, but the
  certificate was not accepted because the CA certificate could not
  be located or could not be matched with a known trust anchor.

access_denied
: A valid certificate or PSK was received, but when access control was
  applied, the sender decided not to proceed with negotiation.

decode_error
: A message could not be decoded because some field was out of the
  specified range or the length of the message was incorrect.
  This alert is used for errors where the message does not conform
  to the formal protocol syntax.
  This alert should never be observed in communication between
  proper implementations, except when messages were corrupted
  in the network.

decrypt_error
: A handshake (not record-layer) cryptographic operation failed, including being unable
  to correctly verify a signature or validate a Finished message
  or a PSK binder.

protocol_version
: The protocol version the peer has attempted to negotiate is
  recognized but not supported. (see {{backward-compatibility}})

insufficient_security
: Returned instead of "handshake_failure" when a negotiation has
  failed specifically because the server requires parameters more
  secure than those supported by the client.

internal_error
: An internal error unrelated to the peer or the correctness of the
  protocol (such as a memory allocation failure) makes it impossible
  to continue.

inappropriate_fallback
: Sent by a server in response to an invalid connection retry attempt
  from a client (see {{!RFC7507}}).

missing_extension
: Sent by endpoints that receive a handshake message not containing an
  extension that is mandatory to send for the offered TLS version
  or other negotiated parameters.

unsupported_extension
: Sent by endpoints receiving any handshake message containing an extension
  known to be prohibited for inclusion in the given handshake message, or including
  any extensions in a ServerHello or Certificate not first offered in the
  corresponding ClientHello.

unrecognized_name
: Sent by servers when no server exists identified by the name
  provided by the client via the "server_name" extension
  (see {{RFC6066}}).

bad_certificate_status_response
: Sent by clients when an invalid or unacceptable OCSP response is
  provided by the server via the "status_request" extension
  (see {{RFC6066}}).

unknown_psk_identity
: Sent by servers when PSK key establishment is desired but no
 acceptable PSK identity is provided by the client. Sending this alert
 is OPTIONAL; servers MAY instead choose to send a "decrypt_error"
 alert to merely indicate an invalid PSK identity.

certificate_required
: Sent by servers when a client certificate is desired but none was provided by
  the client.

no_application_protocol
: Sent by servers when a client
  "application_layer_protocol_negotiation" extension advertises
  only protocols that the server does not support
  (see {{RFC7301}}).
{:br }

New Alert values are assigned by IANA as described in {{iana-considerations}}.


#  Cryptographic Computations

The TLS handshake establishes one or more input secrets which
are combined to create the actual working keying material, as detailed
below. The key derivation process incorporates both the input secrets
and the handshake transcript. Note that because the handshake
transcript includes the random values from the Hello messages,
any given handshake will have different traffic secrets, even
if the same input secrets are used, as is the case when
the same PSK is used for multiple connections.


## Key Schedule

The key derivation process makes use of the HKDF-Extract and HKDF-Expand
functions as defined for HKDF {{RFC5869}}, as well as the functions
defined below:

~~~~
    HKDF-Expand-Label(Secret, Label, Context, Length) =
         HKDF-Expand(Secret, HkdfLabel, Length)

    Where HkdfLabel is specified as:

    struct {
        uint16 length = Length;
        opaque label<7..255> = "tls13 " + Label;
        opaque context<0..255> = Context;
    } HkdfLabel;

    Derive-Secret(Secret, Label, Messages) =
         HKDF-Expand-Label(Secret, Label,
                           Transcript-Hash(Messages), Hash.length)
~~~~

The Hash function used by Transcript-Hash and HKDF is the cipher suite hash
algorithm.
Hash.length is its output length in bytes. Messages are the concatenation of the
indicated handshake messages, including the handshake message type
and length fields, but not including record layer headers. Note that
in some cases a zero-length Context (indicated by "") is passed to
HKDF-Expand-Label.  The Labels specified in this document are all
ASCII strings, and do not include a trailing NUL byte.

Note: with common hash functions, any label longer than 12 characters
requires an additional iteration of the hash function to compute.
The labels in this specification have all been chosen to fit within
this limit.

Given a set of n InputSecrets, the final "master secret" is computed
by iteratively invoking HKDF-Extract with InputSecret_1, InputSecret_2,
etc.  The initial secret is simply a string of Hash.length bytes set to zeros.
Concretely, for the present version of TLS 1.3, secrets are
added in the following order:

- PSK (a pre-shared key established externally or derived from
  the resumption_master_secret value from a previous connection)
- (EC)DHE shared secret ({{ecdhe-shared-secret-calculation}})

This produces a full key derivation schedule shown in the diagram below.
In this diagram, the following formatting conventions apply:

- HKDF-Extract is drawn as taking the Salt argument from the top and the IKM argument
  from the left.
- Derive-Secret's Secret argument is indicated by the incoming
  arrow. For instance, the Early Secret is the Secret for
  generating the client_early_traffic_secret.

~~~~
                 0
                 |
                 v
   PSK ->  HKDF-Extract = Early Secret
                 |
                 +-----> Derive-Secret(.,
                 |                     "ext binder" |
                 |                     "res binder",
                 |                     "")
                 |                     = binder_key
                 |
                 +-----> Derive-Secret(., "c e traffic",
                 |                     ClientHello)
                 |                     = client_early_traffic_secret
                 |
                 +-----> Derive-Secret(., "e exp master",
                 |                     ClientHello)
                 |                     = early_exporter_master_secret
                 v
           Derive-Secret(., "derived", "")
                 |
                 v
(EC)DHE -> HKDF-Extract = Handshake Secret
                 |
                 +-----> Derive-Secret(., "c hs traffic",
                 |                     ClientHello...ServerHello)
                 |                     = client_handshake_traffic_secret
                 |
                 +-----> Derive-Secret(., "s hs traffic",
                 |                     ClientHello...ServerHello)
                 |                     = server_handshake_traffic_secret
                 v
           Derive-Secret(., "derived", "")
                 |
                 v
      0 -> HKDF-Extract = Master Secret
                 |
                 +-----> Derive-Secret(., "c ap traffic",
                 |                     ClientHello...server Finished)
                 |                     = client_application_traffic_secret_0
                 |
                 +-----> Derive-Secret(., "s ap traffic",
                 |                     ClientHello...server Finished)
                 |                     = server_application_traffic_secret_0
                 |
                 +-----> Derive-Secret(., "exp master",
                 |                     ClientHello...server Finished)
                 |                     = exporter_master_secret
                 |
                 +-----> Derive-Secret(., "res master",
                                       ClientHello...client Finished)
                                       = resumption_master_secret
~~~~

The general pattern here is that the secrets shown down the left side
of the diagram are just raw entropy without context, whereas the
secrets down the right side include handshake context and therefore
can be used to derive working keys without additional context.
Note that the different
calls to Derive-Secret may take different Messages arguments,
even with the same secret. In a 0-RTT exchange, Derive-Secret is
called with four distinct transcripts; in a 1-RTT-only exchange
with three distinct transcripts.

If a given secret is not available, then the 0-value consisting of
a string of Hash.length bytes set to zeros is used.  Note that this does not mean skipping
rounds, so if PSK is not in use Early Secret will still be
HKDF-Extract(0, 0). For the computation of the binder_secret, the label is
"ext binder" for external PSKs (those provisioned outside of TLS)
and "res binder" for resumption PSKs (those provisioned as the resumption
master secret of a previous handshake). The different labels prevent
the substitution of one type of PSK for the other.

There are multiple potential Early Secret values depending on
which PSK the server ultimately selects. The client will need to compute
one for each potential PSK; if no PSK is selected, it will then need to
compute the early secret corresponding to the zero PSK.

Once all the values which are to be derived from a given secret have
been computed, that secret SHOULD be erased.


## Updating Traffic Keys and IVs {#updating-traffic-keys}

Once the handshake is complete, it is possible for either side to
update its sending traffic keys using the KeyUpdate handshake message
defined in {{key-update}}.  The next generation of traffic keys is computed by
generating client_/server_application_traffic_secret_N+1 from
client_/server_application_traffic_secret_N as described in
this section then re-deriving the traffic keys as described in
{{traffic-key-calculation}}.

The next-generation application_traffic_secret is computed as:

~~~~
    application_traffic_secret_N+1 =
        HKDF-Expand-Label(application_traffic_secret_N,
                          "traffic upd", "", Hash.length)
~~~~

Once client/server_application_traffic_secret_N+1 and its associated
traffic keys have been computed, implementations SHOULD delete
client_/server_application_traffic_secret_N and its associated traffic keys.


## Traffic Key Calculation

The traffic keying material is generated from the following input values:

- A secret value
- A purpose value indicating the specific value being generated
- The length of the key being generated

The traffic keying material is generated from an input traffic secret value using:

~~~~
    [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
    [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv" , "", iv_length)
~~~~

\[sender] denotes the sending side. The Secret value for each record type
is shown in the table below.

| Record Type | Secret |
|:------------|--------|
| 0-RTT Application | client_early_traffic_secret |
| Handshake         | \[sender]_handshake_traffic_secret |
| Application Data  | \[sender]_application_traffic_secret_N |

All the traffic keying material is recomputed whenever the
underlying Secret changes (e.g., when changing from the handshake to
application data keys or upon a key update).


## (EC)DHE Shared Secret Calculation {#ecdhe-shared-secret-calculation}

###  Finite Field Diffie-Hellman

For finite field groups, a conventional Diffie-Hellman computation is performed.
The negotiated key (Z) is converted to a byte string by encoding in big-endian and
left padded with zeros up to the size of the prime. This byte string is used as the
shared secret in the key schedule as specified above.

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

- The public key to put into the KeyShareEntry.key_exchange structure is the
  result of applying the ECDH scalar multiplication function to the secret key
  of appropriate length (into scalar input) and the standard public basepoint
  (into u-coordinate point input).

- The ECDH shared secret is the result of applying the ECDH scalar multiplication
  function to the secret key (into scalar input) and the peer's public key
  (into u-coordinate point input). The output is used raw, with no processing.

For X25519 and X448, implementations SHOULD use the approach specified
in {{RFC7748}} to calculate the Diffie-Hellman shared secret.
Implementations MUST check whether the computed Diffie-Hellman
shared secret is the all-zero value and abort if so, as described in
Section 6 of {{RFC7748}}. If implementers use an alternative
implementation of these elliptic curves, they SHOULD perform the
additional checks specified in Section 7 of {{RFC7748}}.


## Exporters

{{!RFC5705}} defines keying material exporters for TLS in terms of the TLS
pseudorandom function (PRF). This document replaces the PRF with HKDF, thus
requiring a new construction. The exporter interface remains the same.

The exporter value is computed as:

    TLS-Exporter(label, context_value, key_length) =
        HKDF-Expand-Label(Derive-Secret(Secret, label, ""),
                          "exporter", Hash(context_value), key_length)

Where Secret is either the early_exporter_master_secret or the
exporter_master_secret.  Implementations MUST use the exporter_master_secret unless
explicitly specified by the application. The early_exporter_master_secret is
defined for use in settings where an exporter is needed for 0-RTT data.
A separate interface for the early exporter is RECOMMENDED.

If no context is provided, the context_value is zero-length. Consequently,
providing no context computes the same value as providing an empty context.
This is a change from previous versions of TLS where an empty context produced a
different output to an absent context. As of this document's publication, no
allocated exporter label is used both with and without a context. Future
specifications MUST NOT define a use of exporters that permit both an empty
context and no context with the same label. New uses of exporters SHOULD provide
a context in all exporter computations, though the value could be empty.

Requirements for the format of exporter labels are defined in section 4
of {{RFC5705}}.


# 0-RTT and Anti-Replay {#anti-replay}

As noted in {{zero-rtt-data}} and {{replay-0rtt}}, TLS does not provide inherent replay
protections for 0-RTT data. There are two potential threats to be
concerned with:

- Network attackers who mount a replay attack by simply duplicating a
  flight of 0-RTT data.

- Network attackers who take advantage of client retry behavior
  to arrange for the server to receive multiple copies of an application
  message. This threat already exists
  to some extent because clients that value robustness respond to network errors by
  attempting to retry requests. However, 0-RTT adds an additional
  dimension for any server system which does not maintain globally
  consistent server state. Specifically, if a server system has
  multiple zones where tickets from zone A will not be accepted in
  zone B, then an attacker can duplicate a ClientHello and early
  data intended for A to both A and B. At A, the data will
  be accepted in 0-RTT, but at B the server will reject 0-RTT
  data and instead force a full handshake. If the attacker blocks
  the ServerHello from A, then the client will complete the
  handshake with B and probably retry the request, leading to duplication on
  the server system as a whole.

The first class of attack can be prevented by sharing state to guarantee that
the 0-RTT data is accepted at most once.  Servers SHOULD provide that level of
replay safety, by implementing one of the methods described in this section or
by equivalent means.  It is understood, however, that due to operational
concerns not all deployments will maintain state at that level.  Therefore, in
normal operation, clients will not know which, if any, of these mechanisms
servers actually implement and hence MUST only send early data which they deem
safe to be replayed.

In addition to the direct effects of replays, there is a class of attacks where
even operations normally considered idempotent could be exploited by a large
number of replays (timing attacks, resource limit exhaustion and others
described in {{replay-0rtt}}).  Those can be mitigated by ensuring that every
0-RTT payload can be replayed only a limited number of times.  The server MUST
ensure that any instance of it (be it a machine, a thread or any other entity
within the relevant serving infrastructure) would accept 0-RTT for the same
0-RTT handshake at most once; this limits the number of replays to the number of
server instances in the deployment.  Such a guarantee can be accomplished by
locally recording data from recently-received ClientHellos and rejecting
repeats, or by any other method that provides the same or a stronger guarantee.
The "at most once per server instance" guarantee is a minimum requirement;
servers SHOULD limit 0-RTT replays further when feasible.

The second class of attack cannot be prevented at the TLS layer and
MUST be dealt with by any application. Note that any application whose
clients implement any kind of retry behavior already needs to
implement some sort of anti-replay defense.


## Single-Use Tickets

The simplest form of anti-replay defense is for the server to only
allow each session ticket to be used once. For instance, the server
can maintain a database of all outstanding valid tickets; deleting each
ticket from the database as it is used. If an unknown ticket is
provided, the server would then fall back to a full handshake.

If the tickets are not self-contained but rather are database keys,
and the corresponding PSKs are deleted upon use, then connections established
using one PSK enjoy forward secrecy. This improves security for
all 0-RTT data and PSK usage when PSK is used without (EC)DHE.

Because this mechanism requires sharing the session database between
server nodes in environments with multiple distributed servers,
it may be hard to achieve high rates of successful PSK 0-RTT
connections when compared to self-encrypted tickets. Unlike
session databases, session tickets can successfully do PSK-based
session establishment even without consistent storage, though when
0-RTT is allowed they still require consistent storage for anti-replay
of 0-RTT data, as detailed in the following
section.

## Client Hello Recording

An alternative form of anti-replay is to record a unique value derived
from the ClientHello (generally either the random value or the PSK
binder) and reject duplicates. Recording all ClientHellos causes state
to grow without bound, but a server can instead record ClientHellos within
a given time window and use the "obfuscated_ticket_age" to ensure that
tickets aren't reused outside that window.

In order to implement this, when a ClientHello is received, the server
first verifies the PSK binder as described
{{pre-shared-key-extension}}. It then computes the
expected_arrival_time as described in the next section and rejects
0-RTT if it is outside the recording window, falling back to the
1-RTT handshake.

If the expected arrival time is in the window, then the server
checks to see if it has recorded a matching ClientHello. If one
is found, it either aborts the handshake with an "illegal_parameter" alert
or accepts the PSK but reject 0-RTT. If no matching ClientHello
is found, then it accepts 0-RTT and then stores the ClientHello for
as long as the expected_arrival_time is inside the window.
Servers MAY also implement data stores with false positives, such as
Bloom filters, in which case they MUST respond to apparent replay by
rejecting 0-RTT but MUST NOT abort the handshake.

The server MUST derive the storage key only from validated sections
of the ClientHello. If the ClientHello contains multiple
PSK identities, then an attacker can create multiple ClientHellos
with different binder values for the less-preferred identity on the
assumption that the server will not verify it, as recommended
by {{pre-shared-key-extension}}.
I.e., if the
client sends PSKs A and B but the server prefers A, then the
attacker can change the binder for B without affecting the binder
for A. This will cause the ClientHello to be accepted, and may
cause side effects such as replay cache pollution, although any
0-RTT data will not be decryptable because it will use different
keys. If the validated binder or the ClientHello.random
are used as the storage key, then this attack is not possible.

Because this mechanism does not require storing all outstanding
tickets, it may be easier to implement in distributed systems with
high rates of resumption and 0-RTT, at the cost of potentially
weaker anti-replay defense because of the difficulty of reliably
storing and retrieving the received ClientHello messages.
In many such systems, it is impractical to have globally
consistent storage of all the received ClientHellos.
In this case, the best anti-replay protection is provided by
having a single storage zone be
authoritative for a given ticket and refusing 0-RTT for that
ticket in any other zone. This approach prevents simple
replay by the attacker because only one zone will accept
0-RTT data. A weaker design is to implement separate storage for
each zone but allow 0-RTT in any zone. This approach limits
the number of replays to once per zone. Application message
duplication of course remains possible with either design.

When implementations are freshly started, they SHOULD
reject 0-RTT as long as any portion of their recording window overlaps
the startup time. Otherwise, they run the risk of accepting
replays which were originally sent during that period.

Note: If the client's clock is running much faster than the server's
then a ClientHello may be received that is outside the window in the
future, in which case it might be accepted for 1-RTT, causing a client retry,
and then acceptable later for 0-RTT. This is another variant of
the second form of attack described above.



## Freshness Checks

Because the ClientHello indicates the time at which the client sent
it, it is possible to efficiently determine whether a ClientHello was
likely sent reasonably recently and only accept 0-RTT for such a
ClientHello, otherwise falling back to a 1-RTT handshake.
This is necessary for the ClientHello storage mechanism
described in {{client-hello-recording}} because otherwise the server
needs to store an unlimited number of ClientHellos and is a useful optimization for
self-contained single-use tickets because it allows efficient rejection of ClientHellos
which cannot be used for 0-RTT.

In order to implement this mechanism, a server needs to store the time
that the server generated the session ticket, offset by an estimate of
the round trip time between client and server. I.e.,

~~~~
    adjusted_creation_time = creation_time + estimated_RTT
~~~~

This value can be encoded in the ticket, thus avoiding the need to
keep state for each outstanding ticket. The server can determine the
client's view of the age of the ticket by subtracting the ticket's
"ticket_age_add value" from the "obfuscated_ticket_age" parameter in
the client's "pre_shared_key" extension. The server can determine the
"expected arrival time" of the ClientHello as:

~~~~
    expected_arrival_time = adjusted_creation_time + clients_ticket_age
~~~~

When a new ClientHello is received, the expected_arrival_time is then
compared against the current server wall clock time and if they differ
by more than a certain amount, 0-RTT is rejected, though the 1-RTT
handshake can be allowed to complete.

There are several potential sources of error that might cause
mismatches between the expected arrival time and the measured
time. Variations in client and server clock
rates are likely to be minimal, though potentially with gross time
corrections.  Network propagation delays are the most likely causes of
a mismatch in legitimate values for elapsed time.  Both the
NewSessionTicket and ClientHello messages might be retransmitted and
therefore delayed, which might be hidden by TCP. For clients
on the Internet, this implies windows
on the order of ten seconds to account for errors in clocks and
variations in measurements; other deployment scenarios
may have different needs. Clock skew distributions are not
symmetric, so the optimal tradeoff may involve an asymmetric range
of permissible mismatch values.

Note that freshness checking alone is not sufficient to prevent
replays because it does not detect them during the error window,
which, depending on bandwidth and system capacity could include
billions of replays in real-world settings.  In addition, this
freshness checking is only done at the time the ClientHello is
received, and not when later early application data records are
received. After early data is accepted, records may continue to be
streamed to the server over a longer time period.

#  Compliance Requirements

##  Mandatory-to-Implement Cipher Suites

In the absence of an application profile standard specifying otherwise, a
TLS-compliant application MUST implement the TLS_AES_128_GCM_SHA256 [GCM]
cipher suite and SHOULD implement the TLS_AES_256_GCM_SHA384 [GCM] and
TLS_CHACHA20_POLY1305_SHA256 [RFC7539] cipher suites.  (see
{{cipher-suites}})

A TLS-compliant application MUST support digital signatures with
rsa_pkcs1_sha256 (for certificates), rsa_pss_rsae_sha256 (for
CertificateVerify and certificates), and ecdsa_secp256r1_sha256. A
TLS-compliant application MUST support key exchange with secp256r1
(NIST P-256) and SHOULD support key exchange with X25519 {{RFC7748}}.


##  Mandatory-to-Implement Extensions {#mti-extensions}

In the absence of an application profile standard specifying otherwise, a
TLS-compliant application MUST implement the following TLS extensions:

  * Supported Versions     ("supported_versions"; {{supported-versions}})
  * Cookie                 ("cookie"; {{cookie}})
  * Signature Algorithms   ("signature_algorithms"; {{signature-algorithms}})
  * Signature Algorithms Certificate  ("signature_algorithms_cert"; {{signature-algorithms}})
  * Negotiated Groups      ("supported_groups"; {{negotiated-groups}})
  * Key Share              ("key_share"; {{key-share}})
  * Server Name Indication ("server_name"; Section 3 of {{RFC6066}})

All implementations MUST send and use these extensions when offering
applicable features:

  * "supported_versions"   is REQUIRED for all ClientHello, ServerHello and HelloRetryRequest messages.
  * "signature_algorithms" is REQUIRED for certificate authentication.
  * "supported_groups"     is REQUIRED for ClientHello messages using
                            DHE or ECDHE key exchange.
  * "key_share"            is REQUIRED for DHE or ECDHE key exchange.
  * "pre_shared_key"       is REQUIRED for PSK key agreement.
  * "psk_key_exchange_modes" is REQUIRED for PSK key agreement.

A client is considered to be attempting to negotiate using this
specification if the ClientHello contains a "supported_versions"
extension with 0x0304 contained in its body.
Such a ClientHello message MUST meet the following requirements:

 - If not containing a "pre_shared_key" extension, it MUST contain both
   a "signature_algorithms" extension and a "supported_groups" extension.
 - If containing a "supported_groups" extension, it MUST also contain a
   "key_share" extension, and vice versa. An empty KeyShare.client_shares
   vector is permitted.

Servers receiving a ClientHello which does not conform to these
requirements MUST abort the handshake with a "missing_extension"
alert.

Additionally, all implementations MUST support use of the "server_name"
extension with applications capable of using it.
Servers MAY require clients to send a valid "server_name" extension.
Servers requiring this extension SHOULD respond to a ClientHello
lacking a "server_name" extension by terminating the connection with a
"missing_extension" alert.


## Protocol Invariants

This section describes invariants that TLS endpoints and middleboxes MUST
follow. It also applies to earlier versions, which assumed these rules but did
not document them.

TLS is designed to be securely and compatibly extensible. Newer clients or
servers, when communicating with newer peers, should negotiate the
most preferred common parameters. The TLS handshake provides downgrade
protection: Middleboxes passing traffic between a newer client and
newer server without terminating TLS should be unable to influence the
handshake (see {{security-handshake}}). At the same time, deployments
update at different rates, so a newer client or server MAY continue to
support older parameters, which would allow it to interoperate with
older endpoints.

For this to work, implementations MUST correctly handle extensible fields:

- A client sending a ClientHello MUST support all parameters advertised in it.
  Otherwise, the server may fail to interoperate by selecting one of those
  parameters.

- A server receiving a ClientHello MUST correctly ignore all unrecognized
  cipher suites, extensions, and other parameters. Otherwise, it may fail to
  interoperate with newer clients. In TLS 1.3, a client receiving a
  CertificateRequest or NewSessionTicket MUST also ignore all unrecognized
  extensions.

- A middlebox which terminates a TLS connection MUST behave as a compliant
  TLS server (to the original client), including having a certificate
  which the client is willing to accept, and as a compliant TLS client (to the
  original server), including verifying the original server's certificate.
  In particular, it MUST generate its own ClientHello
  containing only parameters it understands, and it MUST generate a fresh
  ServerHello random value, rather than forwarding the endpoint's value.

  Note that TLS's protocol requirements and security analysis only apply to the
  two connections separately. Safely deploying a TLS terminator requires
  additional security considerations which are beyond the scope of this document.

- An middlebox which forwards ClientHello parameters it does not understand MUST
  NOT process any messages beyond that ClientHello. It MUST forward all
  subsequent traffic unmodified. Otherwise, it may fail to interoperate with
  newer clients and servers.

  Forwarded ClientHellos may contain advertisements for features not supported
  by the middlebox, so the response may include future TLS additions the
  middlebox does not recognize. These additions MAY change any message beyond
  the ClientHello arbitrarily. In particular, the values sent in the ServerHello
  might change, the ServerHello format might change, and the TLSCiphertext format
  might change.

The design of TLS 1.3 was constrained by widely-deployed non-compliant TLS
middleboxes (see {{middlebox}}), however it does not relax the invariants.
Those middleboxes continue to be non-compliant.

#  Security Considerations

Security issues are discussed throughout this memo, especially in
{{implementation-notes}}, {{backward-compatibility}}, and {{security-analysis}}.


#  IANA Considerations

This document uses several registries that were originally created in
{{RFC4346}}. IANA \[SHALL update/has updated] these to reference this document.
The registries and their allocation policies are below:

- TLS Cipher Suite Registry: values with the first byte in the range
  0-254 (decimal) are assigned via Specification Required {{RFC8126}}.
  Values with the first byte 255 (decimal) are reserved for Private
  Use {{RFC8126}}.

  IANA \[SHALL add/has added] the cipher suites listed in {{cipher-suites}} to
  the registry. The "Value" and "Description" columns are taken from the table.
  The "DTLS-OK" and "Recommended" columns are both marked as "Yes" for each new
  cipher suite. \[\[This assumes {{?I-D.ietf-tls-iana-registry-updates}} has been
  applied.]]

- TLS ContentType Registry: Future values are allocated via
  Standards Action {{RFC8126}}.

- TLS Alert Registry: Future values are allocated via Standards
  Action {{RFC8126}}. IANA \[SHALL update/has updated] this registry
  to include values for "missing_extension" and "certificate_required".  The
  "DTLS-OK" column is marked as "Yes" for each new alert.

- TLS HandshakeType Registry: Future values are allocated via
  Standards Action {{RFC8126}}. IANA \[SHALL update/has updated] this registry
  to rename item 4 from "NewSessionTicket" to "new_session_ticket"
  and to add the "hello_retry_request_RESERVED", "encrypted_extensions",
  "end_of_early_data", "key_update", and "message_hash" values.  The "DTLS-OK"
  are marked as "Yes" for each of these additions.

This document also uses the TLS ExtensionType Registry originally created in
{{RFC4366}}. IANA has updated it to reference this document.  Changes to the
registry follow:

 - IANA \[SHALL update/has updated] the registration policy as follows:

   Values with the first byte in the range 0-254 (decimal) are assigned
   via Specification Required [RFC8126].  Values with the first byte
   255 (decimal) are reserved for Private Use [RFC8126].

- IANA \[SHALL update/has updated] this registry to include the
  "key_share", "pre_shared_key", "psk_key_exchange_modes",
  "early_data", "cookie", "supported_versions",
  "certificate_authorities", "oid_filters", "post_handshake_auth", and "signature_algorithms_cert",
  extensions with the values defined in this document and the Recommended value of "Yes".

- IANA \[SHALL update/has updated] this registry to include a "TLS
  1.3" column which lists the messages in which the extension may
  appear. This column \[SHALL be/has been]
  initially populated from the table in {{extensions}}
  with any extension not listed there marked as "-" to indicate that
  it is not used by TLS 1.3.

In addition, this document defines two new registries to be maintained
by IANA:

- TLS SignatureScheme Registry: Values with the first byte in the range
  0-253 (decimal) are assigned via Specification Required {{RFC8126}}.
  Values with the first byte 254 or 255 (decimal) are reserved for Private
  Use {{RFC8126}}. Values with the first byte in the range 0-6 or with the
  second byte in the range 0-3 that are not currently allocated are reserved for
  backwards compatibility.
  This registry SHALL have a "Recommended" column.
  The registry \[shall be/ has been] initially populated with the values described in
  {{signature-algorithms}}. The following values SHALL be marked as
  "Recommended": ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384,
  rsa_pss_rsae_sha256, rsa_pss_rsae_sha384, rsa_pss_rsae_sha512,
  rsa_pss_pss_sha256, rsa_pss_pss_sha384, rsa_pss_pss_sha512, and ed25519.

 - TLS PskKeyExchangeMode Registry: Values in the
   range 0-253 (decimal) are assigned via Specification Required
   [RFC8126].  Values with the first byte 254 or 255 (decimal) are
   reserved for Private Use [RFC8126].  This registry SHALL have a
   "Recommended" column.  The registry [shall be/ has been] initially
   populated psk_ke (0) and psk_dhe_ke (1).  Both SHALL be marked as
   "Recommended".

--- back


# State Machine

This section provides a summary of the legal state transitions for the
client and server handshakes.  State names (in all capitals, e.g.,
START) have no formal meaning but are provided for ease of
comprehension.  Actions which are taken only in certain circumstances are
indicated in []. The notation "K_{send,recv} = foo" means "set the send/recv
key to the given key".

## Client

~~~~
                           START <----+
            Send ClientHello |        | Recv HelloRetryRequest
       [K_send = early data] |        |
                             v        |
        /                 WAIT_SH ----+
        |                    | Recv ServerHello
        |                    | K_recv = handshake
    Can |                    V
   send |                 WAIT_EE
  early |                    | Recv EncryptedExtensions
   data |           +--------+--------+
        |     Using |                 | Using certificate
        |       PSK |                 v
        |           |            WAIT_CERT_CR
        |           |        Recv |       | Recv CertificateRequest
        |           | Certificate |       v
        |           |             |    WAIT_CERT
        |           |             |       | Recv Certificate
        |           |             v       v
        |           |              WAIT_CV
        |           |                 | Recv CertificateVerify
        |           +> WAIT_FINISHED <+
        |                  | Recv Finished
        \                  | [Send EndOfEarlyData]
                           | K_send = handshake
                           | [Send Certificate [+ CertificateVerify]]
 Can send                  | Send Finished
 app data   -->            | K_send = K_recv = application
 after here                v
                       CONNECTED
~~~~

Note that with the transitions as shown above, clients may send alerts
that derive from post-ServerHello messages in the clear or with the
early data keys. If clients need to send such alerts, they SHOULD
first rekey to the handshake keys if possible.


## Server

~~~~
                             START <-----+
              Recv ClientHello |         | Send HelloRetryRequest
                               v         |
                            RECVD_CH ----+
                               | Select parameters
                               v
                            NEGOTIATED
                               | Send ServerHello
                               | K_send = handshake
                               | Send EncryptedExtensions
                               | [Send CertificateRequest]
Can send                       | [Send Certificate + CertificateVerify]
app data                       | Send Finished
after   -->                    | K_send = application
here                  +--------+--------+
             No 0-RTT |                 | 0-RTT
                      |                 |
  K_recv = handshake  |                 | K_recv = early data
[Skip decrypt errors] |    +------> WAIT_EOED -+
                      |    |       Recv |      | Recv EndOfEarlyData
                      |    | early data |      | K_recv = handshake
                      |    +------------+      |
                      |                        |
                      +> WAIT_FLIGHT2 <--------+
                               |
                      +--------+--------+
              No auth |                 | Client auth
                      |                 |
                      |                 v
                      |             WAIT_CERT
                      |        Recv |       | Recv Certificate
                      |       empty |       v
                      | Certificate |    WAIT_CV
                      |             |       | Recv
                      |             v       | CertificateVerify
                      +-> WAIT_FINISHED <---+
                               | Recv Finished
                               | K_recv = application
                               v
                           CONNECTED
~~~~


# Protocol Data Structures and Constant Values

This section provides the normative protocol types and constants definitions.  Values listed as
_RESERVED were used in previous versions of TLS and are listed here
for completeness. TLS 1.3 implementations MUST NOT send them but
might receive them from older TLS implementations.

%%## Record Layer
%%## Alert Messages
%%## Handshake Protocol
%%### Key Exchange Messages
%%#### Version Extension
%%#### Cookie Extension
%%#### Signature Algorithm Extension
%%#### Supported Groups Extension

Values within "obsolete_RESERVED" ranges are used in previous versions
of TLS and MUST NOT be offered or negotiated by TLS 1.3 implementations.
The obsolete curves have various known/theoretical weaknesses or have
had very little usage, in some cases only due to unintentional
server configuration issues. They are no longer considered appropriate
for general use and should be assumed to be potentially unsafe. The set
of curves specified here is sufficient for interoperability with all
currently deployed and properly configured TLS implementations.

%%### Server Parameters Messages
%%### Authentication Messages
%%### Ticket Establishment
%%### Updating Keys


## Cipher Suites

A symmetric cipher suite defines the pair of the AEAD algorithm and hash
algorithm to be used with HKDF.
Cipher suite names follow the naming convention:

~~~
   CipherSuite TLS_AEAD_HASH = VALUE;
~~~

| Component | Contents |
|:----------|:---------|
| TLS       | The string "TLS" |
| AEAD      | The AEAD algorithm used for record protection |
| HASH      | The hash algorithm used with HKDF |
| VALUE     | The two byte ID assigned for this cipher suite |

This specification defines the following cipher suites for use with TLS 1.3.

|          Description            |    Value    |
|:--------------------------------|:------------|
| TLS_AES_128_GCM_SHA256          | {0x13,0x01} |
| TLS_AES_256_GCM_SHA384          | {0x13,0x02} |
| TLS_CHACHA20_POLY1305_SHA256    | {0x13,0x03} |
| TLS_AES_128_CCM_SHA256          | {0x13,0x04} |
| TLS_AES_128_CCM_8_SHA256        | {0x13,0x05} |

The corresponding AEAD algorithms AEAD_AES_128_GCM, AEAD_AES_256_GCM, and
AEAD_AES_128_CCM are defined in {{RFC5116}}. AEAD_CHACHA20_POLY1305 is defined
in {{RFC7539}}. AEAD_AES_128_CCM_8 is defined in {{RFC6655}}. The corresponding
hash algorithms are defined in {{!SHS}}.

Although TLS 1.3 uses the same cipher suite space as previous versions
of TLS, TLS 1.3 cipher suites are defined differently, only specifying
the symmetric ciphers, and cannot be used for TLS 1.2. Similarly,
TLS 1.2 and lower cipher suites cannot be used with TLS 1.3.

New cipher suite values are assigned by IANA as described in
{{iana-considerations}}.


# Implementation Notes

The TLS protocol cannot prevent many common security mistakes. This section
provides several recommendations to assist implementors.
{{?I-D.ietf-tls-tls13-vectors}} provides test vectors for TLS 1.3 handshakes.

## Random Number Generation and Seeding

TLS requires a cryptographically secure pseudorandom number generator (CSPRNG).
In most cases, the operating system provides an appropriate facility such
as /dev/urandom, which should be used absent other (performance) concerns.
It is RECOMMENDED to use an existing CSPRNG implementation in
preference to crafting a new one. Many adequate cryptographic libraries
are already available under favorable license terms.  Should those prove
unsatisfactory, {{RFC4086}} provides guidance on the generation of random values.

TLS uses random values both in public protocol fields such as the
public Random values in the ClientHello and ServerHello and to
generate keying material. With a properly functioning CSPRNG, this
does not present a security problem as it is not feasible to determine
the CSPRNG state from its output. However, with a broken CSPRNG, it
may be possible for an attacker to use the public output to determine
the CSPRNG internal state and thereby predict the keying material, as
documented in {{?CHECKOWAY=DOI.10.1145/2976749.2978395}}.
Implementations can provide extra security against
this form of attack by using separate CSPRNGs to generate public and
private values.


## Certificates and Authentication

Implementations are responsible for verifying the integrity of certificates and
should generally support certificate revocation messages. Absent a specific
indication from an application profile, Certificates should
always be verified to ensure proper signing by a trusted Certificate Authority
(CA). The selection and addition of trust anchors should be done very carefully.
Users should be able to view information about the certificate and trust anchor.
Applications SHOULD also enforce minimum and maximum key sizes. For example,
certification paths containing keys or signatures weaker than 2048-bit RSA or
224-bit ECDSA are not appropriate for secure applications.


## Implementation Pitfalls

Implementation experience has shown that certain parts of earlier TLS
specifications are not easy to understand and have been a source of
interoperability and security problems. Many of these areas have been clarified
in this document but this appendix contains a short list of the most important
things that require special attention from implementors.

TLS protocol issues:

- Do you correctly handle handshake messages that are fragmented to
  multiple TLS records (see {{record-layer}})? Including corner cases
  like a ClientHello that is split to several small fragments? Do
  you fragment handshake messages that exceed the maximum fragment
  size? In particular, the Certificate and CertificateRequest
  handshake messages can be large enough to require fragmentation.

- Do you ignore the TLS record layer version number in all unencrypted TLS
  records? (see {{backward-compatibility}})

- Have you ensured that all support for SSL, RC4, EXPORT ciphers, and
  MD5 (via the "signature_algorithms" extension) is completely removed from
  all possible configurations that support TLS 1.3 or later, and that
  attempts to use these obsolete capabilities fail correctly?
  (see {{backward-compatibility}})

- Do you handle TLS extensions in ClientHello correctly, including
  unknown extensions?

- When the server has requested a client certificate, but no
  suitable certificate is available, do you correctly send an empty
  Certificate message, instead of omitting the whole message (see
  {{client-certificate-selection}})?

- When processing the plaintext fragment produced by AEAD-Decrypt and
  scanning from the end for the ContentType, do you avoid scanning
  past the start of the cleartext in the event that the peer has sent
  a malformed plaintext of all-zeros?

- Do you properly ignore unrecognized cipher suites
  ({{client-hello}}), hello extensions ({{extensions}}), named groups
  ({{negotiated-groups}}), key shares ({{key-share}}),
  supported versions ({{supported-versions}}),
  and signature algorithms ({{signature-algorithms}}) in the
  ClientHello?

- As a server, do you send a HelloRetryRequest to clients which
  support a compatible (EC)DHE group but do not predict it in the
  "key_share" extension? As a client, do you correctly handle a
  HelloRetryRequest from the server?

Cryptographic details:

- What countermeasures do you use to prevent timing attacks {{TIMING}}?

- When using Diffie-Hellman key exchange, do you correctly preserve
  leading zero bytes in the negotiated key (see {{finite-field-diffie-hellman}})?

- Does your TLS client check that the Diffie-Hellman parameters sent
  by the server are acceptable, (see {{ffdhe-param}})?

- Do you use a strong and, most importantly, properly seeded random number
  generator (see {{random-number-generation-and-seeding}}) when generating Diffie-Hellman
  private values, the ECDSA "k" parameter, and other security-critical values?
  It is RECOMMENDED that implementations implement "deterministic ECDSA"
  as specified in {{!RFC6979}}.

- Do you zero-pad Diffie-Hellman public key values to the group size (see
  {{ffdhe-param}})?

- Do you verify signatures after making them to protect against RSA-CRT
  key leaks? {{FW15}}


## Client Tracking Prevention {#client-tracking}

Clients SHOULD NOT reuse a ticket for multiple connections. Reuse
of a ticket allows passive observers to correlate different connections.
Servers that issue tickets SHOULD offer at least as many tickets
as the number of connections that a client might use; for example, a web browser
using HTTP/1.1 {{RFC7230}} might open six connections to a server. Servers SHOULD
issue new tickets with every connection. This ensures that clients are
always able to use a new ticket when creating a new connection.


## Unauthenticated Operation

Previous versions of TLS offered explicitly unauthenticated cipher suites based
on anonymous Diffie-Hellman. These modes have been deprecated in TLS 1.3.
However, it is still possible to negotiate parameters that do not provide
verifiable server authentication by several methods, including:

- Raw public keys {{RFC7250}}.
- Using a public key contained in a certificate but without
  validation of the certificate chain or any of its contents.

Either technique used alone is vulnerable to man-in-the-middle attacks
and therefore unsafe for general use. However, it is also possible to
bind such connections to an external authentication mechanism via
out-of-band validation of the server's public key, trust on first
use, or a mechanism such as channel bindings (though the
channel bindings described in {{RFC5929}} are not defined for
TLS 1.3). If no such mechanism is used, then the connection has no protection
against active man-in-the-middle attack; applications MUST NOT use TLS
in such a way absent explicit configuration or a specific application
profile.


# Backward Compatibility

The TLS protocol provides a built-in mechanism for version negotiation between
endpoints potentially supporting different versions of TLS.

TLS 1.x and SSL 3.0 use compatible ClientHello messages. Servers can also handle
clients trying to use future versions of TLS as long as the ClientHello format
remains compatible and there is at least one protocol version supported by
both the client and the server.

Prior versions of TLS used the record layer version number for various
purposes (TLSPlaintext.legacy_record_version and TLSCiphertext.legacy_record_version).
As of TLS 1.3, this field is deprecated. The value of
TLSPlaintext.legacy_record_version MUST be ignored by all implementations.
The value of TLSCiphertext.legacy_record_version is included in the
additional data for deprotection but MAY otherwise be ignored
or MAY be validated to match the fixed constant value.
Version negotiation is performed using only the handshake versions
(ClientHello.legacy_version, ServerHello.legacy_version, as well as the
ClientHello, HelloRetryRequest and ServerHello "supported_versions" extensions).
In order to maximize interoperability with older endpoints, implementations
that negotiate the use of TLS 1.0-1.2 SHOULD set the record layer
version number to the negotiated version for the ServerHello and all
records thereafter.

For maximum compatibility with previously non-standard behavior and misconfigured
deployments, all implementations SHOULD support validation of certification paths
based on the expectations in this document, even when handling prior TLS versions'
handshakes. (see {{server-certificate-selection}})

TLS 1.2 and prior supported an "Extended Master Secret" {{RFC7627}} extension
which digested large parts of the handshake transcript into the master secret.
Because TLS 1.3 always hashes in the transcript up to the server CertificateVerify,
implementations which support both TLS 1.3 and earlier versions SHOULD
indicate the use of the Extended Master Secret extension in their APIs
whenever TLS 1.3 is used.


## Negotiating with an older server

A TLS 1.3 client who wishes to negotiate with servers that do not
support TLS 1.3 will send a
normal TLS 1.3 ClientHello containing 0x0303 (TLS 1.2) in
ClientHello.legacy_version but with the correct version(s) in the
"supported_versions" extension. If the server does not support TLS 1.3 it
will respond with a ServerHello containing an older version number. If the
client agrees to use this version, the negotiation will proceed as appropriate
for the negotiated protocol. A client using a ticket for resumption SHOULD initiate the
connection using the version that was previously negotiated.

Note that 0-RTT data is not compatible with older servers and SHOULD NOT
be sent absent knowledge that the server supports TLS 1.3.
See {{zero-rtt-backwards-compatibility}}.

If the version chosen by the server is not supported by the client (or not
acceptable), the client MUST abort the handshake with a "protocol_version" alert.

Some legacy server implementations are known to not implement the TLS
specification properly and might abort connections upon encountering
TLS extensions or versions which they are not aware of. Interoperability
with buggy servers is a complex topic beyond the scope of this document.
Multiple connection attempts may be required in order to negotiate
a backwards compatible connection; however, this practice is vulnerable
to downgrade attacks and is NOT RECOMMENDED.


## Negotiating with an older client

A TLS server can also receive a ClientHello indicating a version number smaller
than its highest supported version. If the "supported_versions" extension
is present, the server MUST negotiate using that extension as described in
{{supported-versions}}. If the "supported_versions" extension is not
present, the server MUST negotiate the minimum of ClientHello.legacy_version
and TLS 1.2. For example, if the server supports TLS 1.0, 1.1, and 1.2,
and legacy_version is TLS 1.0, the server will proceed with a TLS 1.0 ServerHello.
If the "supported_versions" extension is absent and the server only supports
versions greater than ClientHello.legacy_version, the server MUST abort the handshake
with a "protocol_version" alert.

Note that earlier versions of TLS did not clearly specify the record layer
version number value in all cases (TLSPlaintext.legacy_record_version). Servers
will receive various TLS 1.x versions in this field, but its value
MUST always be ignored.


## 0-RTT backwards compatibility {#zero-rtt-backwards-compatibility}

0-RTT data is not compatible with older servers. An older server will respond
to the ClientHello with an older ServerHello, but it will not correctly skip
the 0-RTT data and will fail to complete the handshake. This can cause issues when
a client attempts to use 0-RTT, particularly against multi-server deployments. For
example, a deployment could deploy TLS 1.3 gradually with some servers
implementing TLS 1.3 and some implementing TLS 1.2, or a TLS 1.3 deployment
could be downgraded to TLS 1.2.

A client that attempts to send 0-RTT data MUST fail a connection if it receives
a ServerHello with TLS 1.2 or older.  A client that attempts to repair this
error SHOULD NOT send a TLS 1.2 ClientHello, but instead send a TLS 1.3
ClientHello without 0-RTT data.

To avoid this error condition, multi-server deployments SHOULD ensure a uniform
and stable deployment of TLS 1.3 without 0-RTT prior to enabling 0-RTT.

## Middlebox Compatibility Mode {#middlebox}

Field measurements
{{Ben17a}}, {{Ben17b}}, {{Res17a}}, {{Res17b}} have found that a significant number of middleboxes
misbehave when a TLS client/server pair negotiates TLS 1.3. Implementations
can increase the chance of making connections through those middleboxes
by making the TLS 1.3 handshake look more like a TLS 1.2 handshake:

- The client always provides a non-empty session ID in the ClientHello,
  as described in the legacy_session_id section of {{client-hello}}.

- If not offering early data, the client sends a dummy
  change_cipher_spec record (see the third paragraph of {{record-layer}})
  immediately before its second flight. This
  may either be before its second ClientHello or before its encrypted
  handshake flight. If offering early data, the record is placed
  immediately after the first ClientHello.

- The server sends a dummy change_cipher_spec record immediately
  after its first handshake message. This may either be after a
  ServerHello or a HelloRetryRequest.

When put together, these changes make the TLS 1.3 handshake resemble
TLS 1.2 session resumption, which improves the chance of successfully
connecting through middleboxes. This "compatibility mode" is partially
negotiated: The client can opt to provide a session ID or not
and the server has to echo it. Either side can send change_cipher_spec
at any time during the handshake, as they must be ignored by the peer,
but if the client sends a non-empty session ID, the server MUST send
the change_cipher_spec as described in this section.


## Backwards Compatibility Security Restrictions

Implementations negotiating use of older versions of TLS SHOULD prefer
forward secret and AEAD cipher suites, when available.

The security of RC4 cipher suites is considered insufficient for the reasons
cited in {{RFC7465}}. Implementations MUST NOT offer or negotiate RC4 cipher suites
for any version of TLS for any reason.

Old versions of TLS permitted the use of very low strength ciphers.
Ciphers with a strength less than 112 bits MUST NOT be offered or
negotiated for any version of TLS for any reason.

The security of SSL 3.0 {{SSL3}} is considered insufficient for the reasons enumerated
in {{RFC7568}}, and MUST NOT be negotiated for any reason.

The security of SSL 2.0 {{SSL2}} is considered insufficient for the reasons enumerated
in {{RFC6176}}, and MUST NOT be negotiated for any reason.

Implementations MUST NOT send an SSL version 2.0 compatible CLIENT-HELLO.
Implementations MUST NOT negotiate TLS 1.3 or later using an SSL version 2.0 compatible
CLIENT-HELLO. Implementations are NOT RECOMMENDED to accept an SSL version 2.0 compatible
CLIENT-HELLO in order to negotiate older versions of TLS.

Implementations MUST NOT send a ClientHello.legacy_version or ServerHello.legacy_version
set to 0x0300 or less. Any endpoint receiving a Hello message with
ClientHello.legacy_version or ServerHello.legacy_version set to 0x0300 MUST
abort the handshake with a "protocol_version" alert.

Implementations MUST NOT send any records with a version less than 0x0300.
Implementations SHOULD NOT accept any records with a version less than 0x0300
(but may inadvertently do so if the record version number is ignored completely).

Implementations MUST NOT use the Truncated HMAC extension, defined in
Section 7 of [RFC6066], as it is not applicable to AEAD algorithms and has
been shown to be insecure in some scenarios.


#  Overview of Security Properties {#security-analysis}

A complete security analysis of TLS is outside the scope of this document.
In this section, we provide an informal description the desired properties
as well as references to more detailed work in the research literature
which provides more formal definitions.

We cover properties of the handshake separately from those of the record layer.


## Handshake {#security-handshake}

The TLS handshake is an Authenticated Key Exchange (AKE) protocol which
is intended to provide both one-way authenticated (server-only) and
mutually authenticated (client and server) functionality. At the completion
of the handshake, each side outputs its view of the following values:

- A set of "session keys" (the various secrets derived from the master secret)
  from which can be derived a set of working keys.
- A set of cryptographic parameters (algorithms, etc.)
- The identities of the communicating parties.

We assume the attacker to be an active network attacker, which means it
has complete control over the network used to communicate between the parties {{RFC3552}}.
Even under these conditions, the handshake should provide the properties listed below.
Note that these properties are not necessarily independent, but reflect
the protocol consumers' needs.

Establishing the same session keys.
: The handshake needs to output the same set of session keys on both sides of
the handshake, provided that it completes successfully on each endpoint
(See {{CK01}}; defn 1, part 1).

Secrecy of the session keys.
: The shared session keys should be known only to the communicating
  parties and not to the attacker (See {{CK01}}; defn 1, part 2).
  Note that in a unilaterally authenticated connection, the attacker can establish
  its own session keys with the server, but those session keys are distinct from
  those established by the client.

Peer Authentication.
: The client's view of the peer identity should reflect the server's
  identity. If the client is authenticated, the server's view of the
  peer identity should match the client's identity.

Uniqueness of the session keys:
: Any two distinct handshakes should produce distinct, unrelated session
  keys. Individual session keys produced by a handshake should also be distinct
  and unrelated.

Downgrade protection.
: The cryptographic parameters should be the same on both sides and
  should be the same as if the peers had been communicating in the
  absence of an attack (See {{BBFKZG16}}; defns 8 and 9}).

Forward secret with respect to long-term keys
: If the long-term keying material (in this case the signature keys in certificate-based
  authentication modes or the external/resumption PSK in PSK with (EC)DHE modes) is compromised after
  the handshake is complete, this does not compromise the security of the
  session key (See {{DOW92}}), as long as the session key itself has
  been erased. The forward secrecy property is not satisfied
  when PSK is used in the "psk_ke" PskKeyExchangeMode.

Key Compromise Impersonation (KCI) resistance
: In a mutually-authenticated connection with certificates, compromising the long-term
  secret of one actor should not break that actor’s authentication of their peer in
  the given connection (see {{HGFS15}}). For example, if a client's signature key is
  compromised, it should not be possible to impersonate arbitrary servers to that client
  in subsequent handshakes.

Protection of endpoint identities.
: The server's identity (certificate) should be protected against passive
  attackers. The client's identity should be protected against both passive
  and active attackers.
{:br}

Informally, the signature-based modes of TLS 1.3 provide for the
establishment of a unique, secret, shared key established by an
(EC)DHE key exchange and authenticated by the server's signature over
the handshake transcript, as well as tied to the server's identity by
a MAC. If the client is authenticated by a certificate, it also signs
over the handshake transcript and provides a MAC tied to both
identities. {{SIGMA}} describes the design and analysis of this type of key
exchange protocol. If fresh (EC)DHE keys are used for each connection,
then the output keys are forward secret.

The external PSK and resumption PSK bootstrap from a long-term shared
secret into a unique per-connection set of short-term session keys. This
secret may have been established in a previous handshake. If
PSK with (EC)DHE key establishment is used, these session keys will also be forward
secret. The resumption PSK has been designed so that the
resumption master secret computed by connection N and needed to form
connection N+1 is separate from the traffic keys used by connection N,
thus providing forward secrecy between the connections.
In addition, if multiple tickets are established on the same
connection, they are associated with different keys, so compromise of
the PSK associated with one ticket does not lead to the compromise of
connections established with PSKs associated with other tickets.
This property is most interesting if tickets are stored in a database
(and so can be deleted) rather than if they are self-encrypted.

The PSK binder value forms a binding between a PSK
and the current handshake, as well as between the session where the
PSK was established and the current session. This binding
transitively includes the original handshake transcript, because that
transcript is digested into the values which produce the Resumption
Master Secret. This requires that both the KDF used to produce the
resumption master secret and the MAC used to compute the binder be collision
resistant. See {{key-derivation-and-hkdf}} for more on this.
Note: The binder does not cover the binder values from other
PSKs, though they are included in the Finished MAC.

Note: TLS does not currently permit the server to send a certificate_request
message in non-certificate-based handshakes (e.g., PSK).
If this restriction were to be relaxed in future, the
client's signature would not cover the server's certificate directly.
However, if the PSK was established through a NewSessionTicket, the client's
signature would transitively cover the server's certificate through
the PSK binder. {{PSK-FINISHED}}
describes a concrete attack on constructions that do not bind to
the server's certificate (see also {{Kraw16}}). It is unsafe to use certificate-based client
authentication when the client might potentially share the same
PSK/key-id pair with two different endpoints.  Implementations MUST NOT combine
external PSKs with certificate-based authentication of either the
client or the server unless negotiated by some extension.

If an exporter is used, then it produces values which are unique
and secret (because they are generated from a unique session key).
Exporters computed with different labels and contexts are computationally
independent, so it is not feasible to compute one from another or
the session secret from the exported value. Note: exporters can
produce arbitrary-length values. If exporters are to be
used as channel bindings, the exported value MUST be large
enough to provide collision resistance. The exporters provided in
TLS 1.3 are derived from the same handshake contexts as the
early traffic keys and the application traffic keys respectively,
and thus have similar security properties. Note that they do
not include the client's certificate; future applications
which wish to bind to the client's certificate may need
to define a new exporter that includes the full handshake
transcript.

For all handshake modes, the Finished MAC (and where present, the
signature), prevents downgrade attacks. In addition, the use of
certain bytes in the random nonces as described in {{server-hello}}
allows the detection of downgrade to previous TLS versions.
See {{BBFKZG16}} for more detail on TLS 1.3 and downgrade.

As soon as the client and the server have exchanged enough information
to establish shared keys, the remainder of the handshake is encrypted,
thus providing protection against passive attackers, even if the
computed shared key is not authenticated. Because the server
authenticates before the client, the client can ensure that if it
authenticates to the server, it only
reveals its identity to an authenticated server. Note that implementations
must use the provided record padding mechanism during the handshake
to avoid leaking information about the identities due to length.
The client's proposed PSK identities are not encrypted, nor is the
one that the server selects.

### Key Derivation and HKDF

Key derivation in TLS 1.3 uses the HKDF function defined in {{RFC5869}} and
its two components, HKDF-Extract and HKDF-Expand. The full rationale for the HKDF
construction can be found in [Kraw10] and the rationale for the way it is used
in TLS 1.3 in [KW16].  Throughout this document, each
application of HKDF-Extract is followed by one or more invocations of
HKDF-Expand. This ordering should always be followed (including in future
revisions of this document), in particular, one SHOULD NOT use an output of
HKDF-Extract as an input to another application of HKDF-Extract without an
HKDF-Expand in between. Consecutive applications of HKDF-Expand are allowed as
long as these are differentiated via the key and/or the labels.

Note that HKDF-Expand implements a pseudorandom function (PRF) with both inputs and
outputs of variable length. In some of the uses of HKDF in this document
(e.g., for generating exporters and the resumption_master_secret), it is necessary
that the application of HKDF-Expand be collision-resistant, namely, it should
be infeasible to find two different inputs to HKDF-Expand that output the same
value. This requires the underlying hash function to be collision resistant
and the output length from HKDF-Expand to be of size at least 256 bits (or as
much as needed for the hash function to prevent finding collisions).

### Client Authentication

A client that has sent authentication data to a server, either during
the handshake or in post-handshake authentication, cannot be sure if
the server afterwards considers the client to be authenticated or not.
If the client needs to determine if the server considers the
connection to be unilaterally or mutually authenticated, this has to
be provisioned by the application layer. See {{CHHSV17}} for details.
In addition, the analysis of post-handshake authentication from
[Kraw16] shows that the client identified by the certificate sent in
the post-handshake phase possesses the traffic key. This party is
therefore the client that participated in the original handshake or
one to whom the original client delegated the traffic key (assuming
that the traffic key has not been compromised).

### 0-RTT

The 0-RTT mode of operation generally provides similar security
properties as 1-RTT data, with the two exceptions that the 0-RTT
encryption keys do not provide full forward secrecy and that the
server is not able to guarantee uniqueness of the handshake
(non-replayability) without keeping potentially undue amounts of
state. See {{early-data-indication}} for one mechanism to limit
the exposure to replay.

### Exporter Independence

The exporter_master_secret and early_exporter_master_secret are
derived to be independent of the traffic keys and therefore do
not represent a threat to the security of traffic encrypted with
those keys. However, because these secrets can be used to
compute any exporter value, they SHOULD be erased as soon as
possible. If the total set of exporter labels is known, then
implementations SHOULD pre-compute the inner Derive-Secret
stage of the exporter computation for all those labels,
then erase the \[early_]exporter_master_secret, followed by
each inner values as soon as it is known that it will not be
needed again.

### Post-Compromise Security

TLS does not provide security for handshakes which take place after the peer's
long-term secret (signature key or external PSK) is compromised. It therefore
does not provide post-compromise security {{CCG16}}, sometimes also referred to
as backwards or future secrecy. This is in contrast to KCI resistance, which
describes the security guarantees that a party has after its own long-term
secret has been compromised.

### External References

The reader should refer to the following references for analysis of the
TLS handshake: {{DFGS15}} {{CHSV16}} {{DFGS16}} {{KW16}} {{Kraw16}} {{FGSW16}}
{{LXZFH16}} {{FG17}} {{BBK17}}.


## Record Layer {#security-record-layer}

The record layer depends on the handshake producing strong traffic secrets
which can be used to derive bidirectional encryption keys and nonces.
Assuming that is true, and the keys are used for no more data than
indicated in {{limits-on-key-usage}} then the record layer should provide the following
guarantees:

Confidentiality.
: An attacker should not be able to determine the plaintext contents
  of a given record.
{::comment}Cite IND-CPA?{:/comment}

Integrity.
: An attacker should not be able to craft a new record which is
  different from an existing record which will be accepted by the receiver.
{::comment}Cite INT-CTXT?{:/comment}

Order protection/non-replayability
: An attacker should not be able to cause the receiver to accept a
  record which it has already accepted or cause the receiver to accept
  record N+1 without having first processed record N.

Length concealment.
: Given a record with a given external length, the attacker should not be able
to determine the amount of the record that is content versus padding.

Forward secrecy after key change.
: If the traffic key update mechanism described in {{key-update}} has been
  used and the previous generation key is deleted, an attacker who compromises
  the endpoint should not be able to decrypt traffic encrypted with the old key.
{:br}

Informally, TLS 1.3 provides these properties by AEAD-protecting the
plaintext with a strong key. AEAD encryption {{RFC5116}} provides confidentiality
and integrity for the data. Non-replayability is provided by using
a separate nonce for each record, with the nonce being derived from
the record sequence number ({{nonce}}), with the sequence
number being maintained independently at both sides thus records which
are delivered out of order result in AEAD deprotection failures.
In order to prevent mass cryptanalysis when the same plaintext is
repeatedly encrypted by different users under the same key
(as is commonly the case for HTTP), the nonce is formed by mixing
the sequence number with a secret per-connection initialization
vector derived along with the traffic keys.
See {{BT16}} for analysis of this construction.

The re-keying technique in TLS 1.3 (see {{updating-traffic-keys}}) follows the
construction of the serial generator in [REKEY], which shows that re-keying can
allow keys to be used for a larger number of encryptions than without
re-keying. This relies on the security of the HKDF-Expand-Label function as a
pseudorandom function (PRF).  In addition, as long as this function is truly
one way, it is not possible to compute traffic keys from prior to a key change
(forward secrecy).

TLS does not provide security for data which is communicated on a connection
after a traffic secret of that connection is compromised. That is, TLS does not
provide post-compromise security/future secrecy/backward secrecy with respect
to the traffic secret. Indeed, an attacker who learns a traffic secret can
compute all future traffic secrets on that connection.  Systems which want such
guarantees need to do a fresh handshake and establish a new connection with an
(EC)DHE exchange.

### External References

The reader should refer to the following references for analysis of the TLS record layer:
{{BMMT15}} {{BT16}} {{BDFKPPRSZZ16}} {{BBK17}} {{Anon18}}.


## Traffic Analysis

TLS is susceptible to a variety of traffic analysis attacks based on
observing the length and timing of encrypted packets
{{?CLINIC=DOI.10.1007/978-3-319-08506-7_8}}
{{?HCJ16=DOI.10.1186/s13635-016-0030-7}}.
This is particularly easy when there is a small
set of possible messages to be distinguished, such as for a video
server hosting a fixed corpus of content, but still provides usable
information even in more complicated scenarios.

TLS does not provide any specific defenses against this form of attack
but does include a padding mechanism for use by applications: The
plaintext protected by the AEAD function consists of content plus
variable-length padding, which allows the application to produce
arbitrary length encrypted records as well as padding-only cover traffic to
conceal the difference between periods of transmission and periods
of silence. Because the
padding is encrypted alongside the actual content, an attacker cannot
directly determine the length of the padding, but may be able to
measure it indirectly by the use of timing channels exposed during
record processing (i.e., seeing how long it takes to process a
record or trickling in records to see which ones elicit a response
from the server). In general, it is not known how to remove all of
these channels because even a constant time padding removal function will
likely feed the content into data-dependent functions.
At minimum, a fully constant time server or client would require close
cooperation with the application layer protocol implementation, including
making that higher level protocol constant time.

Note: Robust
traffic analysis defences will likely lead to inferior performance
due to delay in transmitting packets and increased traffic volume.


## Side Channel Attacks

In general, TLS does not have specific defenses against side-channel
attacks (i.e., those which attack the communications via secondary
channels such as timing) leaving those to the implementation of the relevant
cryptographic primitives. However, certain features of TLS are
designed to make it easier to write side-channel resistant code:

- Unlike previous versions of TLS which used a composite
  MAC-then-encrypt structure, TLS 1.3 only uses AEAD algorithms,
  allowing implementations to use self-contained constant-time
  implementations of those primitives.

- TLS uses a uniform "bad_record_mac" alert for all decryption
  errors, which is intended to prevent an attacker from gaining
  piecewise insight into portions of the message.  Additional resistance
  is provided by terminating the connection on such errors; a new
  connection will have different cryptographic material, preventing
  attacks against the cryptographic primitives that require multiple
  trials.

Information leakage through side channels can occur at layers above
TLS, in application protocols and the applications that use
them. Resistance to side-channel attacks depends on applications and
application protocols separately ensuring that confidential
information is not inadvertently leaked.


## Replay Attacks on 0-RTT {#replay-0rtt}

Replayable 0-RTT data presents a number of security threats to
TLS-using applications, unless those applications are specifically
engineered to be safe under replay
(minimally, this means idempotent, but in many cases may
also require other stronger conditions, such as constant-time
response). Potential attacks include:

- Duplication of actions which cause side effects (e.g., purchasing an
item or transferring money) to be duplicated, thus harming the site or
the user.

- Attackers can store and replay 0-RTT messages in order to
re-order them with respect to other messages (e.g., moving
a delete to after a create).

- Exploiting cache timing behavior to discover the content of 0-RTT
messages by replaying a 0-RTT message to a different cache node
and then using a separate connection to measure request latency,
to see if the two requests address the same resource.

If data can be replayed a large number of times, additional attacks
become possible, such as making repeated measurements of the
speed of cryptographic operations. In addition, they may
be able to overload rate-limiting systems. For further description of
these attacks, see {{Mac17}}.

Ultimately, servers have the responsibility to protect themselves
against attacks employing 0-RTT data replication. The mechanisms
described in {{anti-replay}} are intended to
prevent replay at the TLS layer but do not provide complete protection
against receiving multiple copies of client data.
TLS 1.3 falls back to the 1-RTT
handshake when the server does not have any information about the
client, e.g., because it is in a different cluster which does not
share state or because the ticket has been deleted as described in
{{single-use-tickets}}. If the application layer protocol retransmits
data in this setting, then it is possible for an attacker to induce
message duplication by sending the ClientHello to both the original cluster
(which processes the data immediately) and another cluster which will
fall back to 1-RTT and process the data upon application layer
replay. The scale of this attack is limited by the client's
willingness to retry transactions and therefore only allows a limited amount
of duplication, with each copy appearing as a new connection at
the server.

If implemented correctly, the mechanisms described in
{{single-use-tickets}} and {{client-hello-recording}} prevent a
replayed ClientHello and its associated 0-RTT data from being accepted
multiple times by any cluster with consistent state; for servers
which limit the use of 0-RTT to one cluster for a single ticket, then a given
ClientHello and its associated 0-RTT data will only be accepted once.
However, if state is not completely consistent,
then an attacker might be able to have multiple copies of the data be
accepted during the replication window.
Because clients do not know the exact details of server behavior, they
MUST NOT send messages in early data which are not safe to have
replayed and which they would not be willing to retry across multiple
1-RTT connections.

Application protocols MUST NOT use 0-RTT data without a profile that
defines its use. That profile needs to identify which messages or
interactions are safe to use with 0-RTT and how to handle the
situation when the server rejects 0-RTT and falls back to 1-RTT.

In addition, to avoid accidental misuse, TLS implementations MUST NOT
enable 0-RTT (either sending or accepting) unless specifically
requested by the application and MUST NOT automatically resend 0-RTT
data if it is rejected by the server unless instructed by the
application. Server-side applications may wish to implement special
processing for 0-RTT data for some kinds of application traffic (e.g.,
abort the connection, request that data be resent at the application
layer, or delay processing until the handshake completes). In order to
allow applications to implement this kind of processing, TLS
implementations MUST provide a way for the application to determine if
the handshake has completed.

### Replay and Exporters

Replays of the ClientHello produce the same early exporter, thus
requiring additional care by applications which use these exporters.
In particular, if these exporters are used as an authentication
channel binding (e.g., by signing the output of the exporter)
an attacker who compromises the PSK can transplant authenticators
between connections without compromising the authentication key.

In addition, the early exporter SHOULD NOT be used to generate
server-to-client encryption keys because that would entail
the reuse of those keys. This parallels the use of the early
application traffic keys only in the client-to-server direction.

## Attacks on Static RSA

Although TLS 1.3 does not use RSA key transport and so is not
directly susceptible to Bleichenbacher-type attacks, if TLS 1.3
servers also support static RSA in the context of previous
versions of TLS, then it may be possible to impersonate the server
for TLS 1.3 connections {{JSS15}}. TLS
1.3 implementations can prevent this attack by disabling support
for static RSA across all versions of TLS. In principle, implementations
might also be able to separate certificates with different keyUsage
bits for static RSA decryption and RSA signature, but this technique
relies on clients refusing to accept signatures using keys
in certificates that do not have the digitalSignature bit set,
and many clients do not enforce this restriction.

# Working Group Information

The discussion list for the IETF TLS working group is located at the e-mail
address <tls@ietf.org>. Information on the group and information on how to
subscribe to the list is at <https://www.ietf.org/mailman/listinfo/tls>

Archives of the list can be found at:
<https://www.ietf.org/mail-archive/web/tls/current/index.html>


# Contributors

* Martin Abadi \\
  University of California, Santa Cruz \\
  abadi@cs.ucsc.edu

* Christopher Allen (co-editor of TLS 1.0) \\
  Alacrity Ventures \\
  ChristopherA@AlacrityManagement.com

* Richard Barnes \\
  Cisco \\
  rlb@ipv.sx

* Steven M. Bellovin \\
  Columbia University \\
  smb@cs.columbia.edu

* David Benjamin \\
  Google \\
  davidben@google.com

* Benjamin Beurdouche \\
  INRIA & Microsoft Research \\
  benjamin.beurdouche@ens.fr

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

* Matt Caswell \\
  OpenSSL \\
  matt@openssl.org

* Stephen Checkoway \\
  University of Illinois at Chicago \\
  sfc@uic.edu

* Pete Chown \\
  Skygate Technology Ltd \\
  pc@skygate.co.uk

* Katriel Cohn-Gordon \\
  University of Oxford \\
  me@katriel.co.uk

* Cas Cremers \\
  University of Oxford \\
  cas.cremers@cs.ox.ac.uk

* Antoine Delignat-Lavaud (co-author of [RFC7627]) \\
  INRIA \\
  antdl@microsoft.com

* Tim Dierks (co-editor of TLS 1.0, 1.1, and 1.2) \\
  Independent \\
  tim@dierks.org

* Roelof DuToit \\
  Symantec Corporation \\
  roelof_dutoit@symantec.com

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

* David M. Garrett \\
  dave@nulldereference.com

* Illya Gerasymchuk \\
  Independent \\
  illya@iluxonchik.me

* Alessandro Ghedini \\
  Cloudflare Inc. \\
  alessandro@cloudflare.com

* Daniel Kahn Gillmor \\
  ACLU \\
  dkg@fifthhorseman.net

* Matthew Green \\
  Johns Hopkins University \\
  mgreen@cs.jhu.edu

* Jens Guballa \\
  ETAS \\
  jens.guballa@etas.com

* Felix Guenther \\
  TU Darmstadt \\
  mail@felixguenther.info

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

* Marko Horvat \\
  MPI-SWS \\
  mhorvat@mpi-sws.org

* Jonathan Hoyland \\
  Royal Holloway, University of London
  jonathan.hoyland@gmail.com

* Subodh Iyengar \\
  Facebook \\
  subodh@fb.com

* Benjamin Kaduk \\
  Akamai \\
  kaduk@mit.edu

* Hubert Kario \\
  Red Hat Inc. \\
  hkario@redhat.com

* Phil Karlton (co-author of SSL 3.0)

* Leon Klingele \\
  Independent \\
  mail@leonklingele.de

* Paul Kocher (co-author of SSL 3.0) \\
  Cryptography Research \\
  paul@cryptography.com

* Hugo Krawczyk \\
  IBM \\
  hugokraw@us.ibm.com

* Adam Langley (co-author of [RFC7627]) \\
  Google \\
  agl@google.com

* Olivier Levillain \\
  ANSSI \\
  olivier.levillain@ssi.gouv.fr

* Xiaoyin Liu \\
  University of North Carolina at Chapel Hill \\
  xiaoyin.l@outlook.com

* Ilari Liusvaara \\
  Independent \\
  ilariliusvaara@welho.com

* Atul Luykx \\
  K.U. Leuven \\
  atul.luykx@kuleuven.be

* Colm MacCarthaigh \\
  Amazon Web Services \\
  colm@allcosts.net

* Carl Mehner \\
  USAA \\
  carl.mehner@usaa.com

* Jan Mikkelsen \\
  Transactionware \\
  janm@transactionware.com

* Bodo Moeller (co-author of [RFC4492]) \\
  Google \\
  bodo@acm.org

* Kyle Nekritz \\
  Facebook \\
  knekritz@fb.com

* Erik Nygren \\
  Akamai Technologies \\
  erik+ietf@nygren.org

* Magnus Nystrom \\
  Microsoft \\
  mnystrom@microsoft.com

* Kazuho Oku \\
  DeNA Co., Ltd. \\
  kazuhooku@gmail.com

* Kenny Paterson \\
  Royal Holloway, University of London \\
  kenny.paterson@rhul.ac.uk

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
  Amazon \\
  jroskind@amazon.com

* Michael Sabin

* Joe Salowey \\
  Tableau Software \\
  joe@salowey.net

* Rich Salz \\
  Akamai \\
  rsalz@akamai.com

* David Schinazi \\
  Apple Inc. \\
  dschinazi@apple.com

* Sam Scott \\
  Royal Holloway, University of London \\
  me@samjs.co.uk

* Dan Simon \\
  Microsoft, Inc. \\
  dansimon@microsoft.com

* Brian Smith \\
  Independent \\
  brian@briansmith.org

* Brian Sniffen \\
  Akamai Technologies \\
  ietf@bts.evenmere.org

* Nick Sullivan \\
  Cloudflare Inc. \\
  nick@cloudflare.com

* Bjoern Tackmann \\
  University of California, San Diego \\
  btackmann@eng.ucsd.edu

* Tim Taubert \\
  Mozilla \\
  ttaubert@mozilla.com

* Martin Thomson \\
  Mozilla \\
  mt@mozilla.com

* Sean Turner \\
  sn3rd \\
  sean@sn3rd.com

* Steven Valdez \\
  Google \\
  svaldez@google.com

* Filippo Valsorda \\
  Cloudflare Inc. \\
  filippo@cloudflare.com

* Thyla van der Merwe \\
  Royal Holloway, University of London \\
  tjvdmerwe@gmail.com

* Victor Vasiliev \\
  Google \\
  vasilvv@google.com

* Tom Weinstein

* Hoeteck Wee \\
  Ecole Normale Superieure, Paris \\
  hoeteck@alum.mit.edu

* David Wong \\
  NCC Group \\
  david.wong@nccgroup.trust

* Christopher A. Wood \\
  Apple Inc. \\
  cawood@apple.com

* Tim Wright \\
  Vodafone \\
  timothy.wright@vodafone.com

* Peter Wu \\
  Independent \\
  peter@lekensteyn.nl

* Kazu Yamamoto \\
  Internet Initiative Japan Inc. \\
  kazu@iij.ad.jp
