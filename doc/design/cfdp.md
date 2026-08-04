# CFDP design

Audience: developers modifying the reusable CFDP implementation.

The codec layer parses and emits bounded PDUs. The transaction entity owns one
sender and one receiver slot and depends only on filestore and Unitdata
Transfer callbacks. The Space Packet adapter owns packet sequence state and a
maximum-PDU packet buffer. The service composes those pieces without creating
a thread.

```text
filestore <-> CFDP entity <-> UT callback <-> transport
                        \-> Space Packet adapter <-> APID router
```

Receiving writes into a temporary destination, verifies size and checksum,
then asks the application filestore to commit or discard it. CRC checksums
received out of order require rereading the completed temporary file. Protocol
completion never implies installation or activation of delivered content.

Fixed configuration bounds entity IDs, transaction sequence numbers,
filenames, PDUs, segments, missing ranges, and recovery rounds. Large-file
mode and optional metadata/TLV procedures are outside the current profile.

