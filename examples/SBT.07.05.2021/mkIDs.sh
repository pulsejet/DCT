#! /bin/bash
# mkIDs schema - script to create id bundles needed to run an app with some sbt schema
#  'schema' is the filename of the schema's .trust file
PATH=../../../tools:$PATH

device=(sensor1 sensor2 sensor3 sensor4)
worker=(w1 w2 w3 w4)
other=(mgr prxy)

if [ -z "$1" ]; then echo "-$0: must supply a .trust schema filename"; exit 1; fi;
if [ ! -r "$1" ]; then echo "-$0: file $1 not readable"; exit 1; fi;

Schema=${1##*/}
Schema=${Schema%.trust}
Bschema=$Schema.scm
RootCert=$Schema.root
SchemaCert=$Schema.schema

schemaCompile -o $Bschema $1

# extract the info needed to make certs from the compiled schema
Pub=$(schema_info $Bschema);
PubPrefix=$(schema_info $Bschema "#pubPrefix");
PubValidator=$(schema_info -t $Bschema "#pubValidator");

make_cert -s $PubValidator -o $RootCert $PubPrefix
schema_cert -o $SchemaCert $Bschema $RootCert

# make the configurer cert
make_cert -s $PubValidator -o config.cert $PubPrefix//config/c1 $RootCert

# make the device certs: one controller and 4 sensors
make_cert -s $PubValidator -o controller.cert $PubPrefix/cntrlDevice/controller config.cert
for nm in ${device[@]}; do
    make_cert -s $PubValidator -o $nm.cert $PubPrefix/sensorDevice/$nm config.cert
done

# make the worker certs
make_cert -s $PubValidator -o w1.cert $PubPrefix/worker/1 sensor1.cert
make_cert -s $PubValidator -o w2.cert $PubPrefix/worker/2 sensor2.cert
make_cert -s $PubValidator -o w3.cert $PubPrefix/worker/3 sensor3.cert
make_cert -s $PubValidator -o w4.cert $PubPrefix/worker/4 sensor4.cert

# make the manager cert
make_cert -s $PubValidator -o mgr.cert $PubPrefix/manager/0 controller.cert
# make the proxy cert
make_cert -s $PubValidator -o prxy.cert $PubPrefix/proxy/0 controller.cert

# The sbt schema signing certs are signed by a device cert which is signed by a
# configurer cert which is signed by the root cert. Both pubs and
# syncData use EdDSA sigmgrs. Each identity's bundle consist of the root cert,
# the schema cert, the config cert, the device cert, and the role cert, in that order.
# The "+" on the role cert indicates that its signing key should be included in the bundle.
# The other certs don't (and shouldn't) have signing keys.

# make the ID bundles
make_bundle -v -o w1.bundle $RootCert $SchemaCert config.cert sensor1.cert +w1.cert
make_bundle -v -o w2.bundle $RootCert $SchemaCert config.cert sensor2.cert +w2.cert
make_bundle -v -o w3.bundle $RootCert $SchemaCert config.cert sensor3.cert +w3.cert
make_bundle -v -o w4.bundle $RootCert $SchemaCert config.cert sensor4.cert +w4.cert
make_bundle -v -o mgr.bundle $RootCert $SchemaCert config.cert controller.cert +mgr.cert
make_bundle -v -o prxy.bundle $RootCert $SchemaCert config.cert controller.cert +prxy.cert
