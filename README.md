# Data-Centric Toolkit

This repository contains Pollere's **evolving** work on tools to enable data-centric applications (with a focus on "edge" applications). DCT is an effort to make data/information-centric applications easier to write and secure. DCT reflects Pollere's needs and will update with our needs but the intention is a toolkit for general use. The toolkit currently uses a version of the Named-Data Networking Forwarder (NFD) with Pollere's patches, with a future goal of something less fragile and more broadcast media friendly.

## State Vector Sync

This fork replaces the syncps transport with StateVectorSync-PubSub (SVS-PS). Several changes are required for getting this change to work and are described below.

- SVS (ndn-svs) is implemented in ndn-cxx while DCT uses ndn-ind. Since both libraries use the `ndn` namespace, they cannot be used together. To use this fork, you must patch your ndn-ind to use the `ndn_ind` namespace. A fork of ind using this namespace can be accessed [here](https://github.com/ucla-irl/ndn-ind).

- Since DCT uses ndn-ind, DCT must also be patched to use the `ndn_ind` namespace. This change is already present in this fork, but any client applications using DCT need to make the namespace access change.

- To use SVS instead of syncps, `SYNCPS_IS_SVS` must be defined at compile time. A syncps shim is used to transparently replace syncps with SVS.

- Conversions of types between ndn-cxx and ndn-ind can be done by wire-encoding from one library and wire-decoding using the other. Helper functions can be found in [include/ndn-cxx-ind.hpp](include/ndn-cxx-ind.hpp).


## Organization

This repository is organized into directories:

- tools: contains tools for using trust schema-based security. The README in this directory describes how the tools can be used to configure a domain to use a DCT trust schema and applications created using DCT. The binary schemaCompile should be added to this directory: download the compressed tar file corresponding to your OS available with the latest release.

- versec: Includes a description of the VerSec Language for expressing trust rules and a compiler that turns the language into a binary trust schema. 

- include: bespoke transport modules developed and used by Pollere to handle secure data-centric communications:
  
  - syncps: the pub-sub sync protocol that interfaces with the packet forwarder
  
  - schema: the run-time library that makes use of the binary trust schema
  
  - sigmgrs: supplies a range of signing and validation methods
  
  - distributors: distribute certs and group keys and manage the associated collections

- examples:
  
  - mbps: bespoke transport that provides message-based publish/subscribe. The README in this directory may be useful in understanding how DCT's modules can be used.

This version (version 3) adds signature managers employing libsodium and removes the EcDSA sigmgr that had been used with legacy NDN code. It also includes distributors for certificate chains and group keys, certificate and publication validation, and tools for creating identity bundles of certificates. This has led to some changes in how modules interface to one another. Bug reports are welcome.

### Installing and building the pieces

All the modules are header-only C++ 'libraries' so the `DCT/include` tree has to be made available to programs using it via a `-I` c++ compiler flag or installed in a standard include path like `/usr/local/include`. The code requires c++20 and compiles with the current xcode compiler or clang-11 on MacOS and Linux and gcc-9 on Linux. It uses the new c++20 formatted output model which, unfortunately, is not yet in either compiler's standard library. To fill that gap we suggest using the excellent implementation available at https://fmt.dev/latest/index.html. This should be installed somewhere on your system and its `include/fmt` directory symlinked from `DCT/include`. (This distribution has a copy of the current 8.0.1 `fmt` dist in DCT/include/fmt; that should be removed and replaced with the symlink.) Patches available at https://github.com/pollere/NDNpatches will be needed.

The included versec compiler is required to compile new schemas but pre-compiled schemas for the examples are available as a \*.scm file in the example source directory. To compile and run an example using the pre-compiled schema, for example, mbps:

- (one time) Install `ndn-ind` (from  https://github.com/operantnetworks/ndn-ind) version b72bbf7e. As of July, 2021, ndn-ind doesn't contain the async-face needed by these tools. To add it, apply the Pollere patch patch.ndn-ind  immediately after cloning the Operant Networks ndn-ind github repo.
- (one time) `cd DCT/tools && make` to build all the tools needed.
- `cd DCT/examples/mbps`  then `make` to build the example. If the make is successful, follow the readme to create 'identity bundles' and run it.

### References and related work

Some concepts here may be better understood by referencing earlier Pollere work: 

[Lessons Learned Building a Secure Network Measurement Framework using Basic NDN ](http://www.pollere.net/Pdfdocs/icn19-p20.pdf), K. Nichols, Proceedings of ACM ICN '19, September 24-16, Macao, China (available at http://www.pollere.net/publications.html)

Related talks at http://www.pollere.net/talks.html

See also GitHub.com/pollere/DNMP-v2 for Pollere's first bespoke transport.

---

Copyright (C) 2021 Pollere, Inc 
