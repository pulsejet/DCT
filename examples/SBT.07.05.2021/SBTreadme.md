# Sentinel Bespoke Transport (SBT) using Trust Schema

A trust schema lays out the rules for creating publications and the signatures they require. This document supplements the code and documentation at GitHub.com/pollere/DCT with descriptions specific to Operant's SBT. This deliverable includes a sbt.trust file written in Versec’s domain specific language using rules based on the Operant document “SBT Trust Rules v1.pdf” (included in the deliverables of 10.07.2020). This requires the latest (dated 07.02.2021 or later) tools and includes in the github repository.

### Running this version

This requires some patches to non-ind (supplied) and one to ndn-cxx (available at github.com/pollere/NDNpatches). You should clone the DCT directory, make an SBT directory under the "examples" directory and put the SBT files there.

 Once these are in place, read the Creating Identity Bundles section in the *examples/mbps* README. Similarly, there is a mkIDs.sh script in the *examples/sbt* directory that can be used to make a set of sbt identity bundles. This script can be edited to make more entities or devices. (A set of bundles is available in the id subdirectory.) DCT no longer requires the use of the NDN PIB. Identity bundles contain everything needed. Use the *sbt.trust* schema to make unencrypted (but signed) Publications and "wire" Data and the *sbte.trust* schema to make signed Publications carried in encrypted "wire" Data.

As in the prior deliverables, the test application is called sbtAdaptor.cpp. Do a `make` and sbtAdaptor should be ready to run. To start an sbtAdaptor with a manager zeek type (if "c" is not set, a value of 10 is used):

​    `    sbtAdaptor -c 50 id/mgr.bundle`

then start one or more worker identity sbtAdaptors (using a value of i from 1 to 4), e.g.:

​    `    sbtAdaptor id/w<i>.bundle`

Use prxy.bundle for a proxy. It's still possible to specify a textfile of your choice to be in the message body, but a short message is created otherwise. For example:

`    sbtAdaptor -f <textfile> -c 50 id/prxy.bundle`

Only the manager will make a group symmetric key so for *sbte.trust*, it must be running before communications will start.

### Details

##### Name notes

The sbtShim creates and receives publications which have eight distinct name components appended to two components that identify the local network, and a content portion that holds a piece of the message. Note this has ***changed*** since the last version.

| component  | description                                                      |
| ---------- | ---------------------------------------------------------------- |
| networkID  | e.g., poc                                                        |
| namespace  | **sbt** (could be changed to **zeek**)                           |
| target     | **logs**, **control**, **cluster**                               |
| topic      | next component of "Zeek topic" from RK's document                |
| arguments  | more specific info for Collection when needed ("-" if unused)    |
| role       | role of the publisher                                            |
| identifier | role-specific ID                                                 |
| msgID      | unsigned 32 bit number, either message hash or sequence          |
| pCnt       | indicates if single publication message or multiples (see below) |
| timestamp  | message creation time in UTC microseconds                        |

**Rules for Publication Names**

The way the “must be” is enforced is by requiring that the publication be signed with a certificate that certifies that role type. This is specified in the trust schema.

For messages of target **cluster**:

- Must be a manager to publish in topic *node* with argument *worker<id>* (where id is an integer identifier)
- Must be a manager or a proxy to publish in topic *worker*
- Must be a worker to publish in topic *manager*
- Must be a worker to publish in topic *node* with argument *proxy<id>*

For messages of target **logs**:

- Must be a worker or proxy to publish in an *internal* topic
- Must be a worker to publish in a *networkTraffic* topic
- Must be a proxy to publish in a *host* topic

For messages of target **control**:

- Must be a worker or proxy or manager. Topic is set to some  <hex ID> which is not that of the publisher

**Subscriptions**

Subscriptions are coded into the shim based on the entity’s identity role (manager, proxy, worker). Publications could be encrypted with keys known only to the subscriber if privacy within the enclave is needed. Here are the subscriptions organized as *target/topic/*<opt>*argument*:

For  **worker** identity:

- cluster/node/worker<my id>
- cluster/worker
- control/<my hex id>

For **manager** identity:

- cluster/manager
- control/<my hex id>
- logs (i.e. all subtopics in target **logs**)

For **proxy** identity:

- cluster/node/proxy<my id>

- control/<my hex id>

##### SBT Trust Schema

The SBT trust rules are in sbt.trust (and sbte.trust) and the language is described in the language.pdf document in the DCT repo. The basic publication format is defined: 

`#sbtPub: _network/_domain/target/topic/args/_role/_Id/msgID/pCnt/mts & {`
`    _Id:   _roleId`
`}`

The **sbtPub** publication Name uses the definitions of *network* and *domain*, indicated by a leading '`__`'. Names without the leading '`__`' are parameters that will be passed to **schemaLib**'s publication builder at runtime for each publication. The **sbtPub** definition continues inside the brackets which show that *_Id* is set from the _roleId component of a cert in the signing chain (in this case, the roleCert).

Publication #**wirePrefix** section describes the SyncData packet that carries **sbtPub**s, and specifies the signing rules, here EdDSA (change to AEAD to encrypt the wire Data packets. This requires making a new binary schema and set of bundles). 
