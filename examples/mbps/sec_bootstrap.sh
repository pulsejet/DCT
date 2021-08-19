    ./schemaCompile -o mbps1.scm mbps1.trust
    ../../tools/make_cert -s EdDSA -o mbps1.root myNet/mbps1
    ../../tools/schema_cert -o mbps1.schema mbps1.scm mbps1.root

    ../../tools/make_cert -s EdDSA -o alice.cert myNet/mbps1/operator/alice mbps1.root
    ../../tools/make_cert -s EdDSA -o bob.cert myNet/mbps1/operator/bob mbps1.root
    ../../tools/make_cert -s EdDSA -o cathy.cert myNet/mbps1/operator/cathy mbps1.root
    ../../tools/make_cert -s EdDSA -o frontdoor.cert myNet/mbps1/device/frontdoor mbps1.root
    
    ../../tools/make_bundle -o alice.bundle mbps1.root mbps1.schema +alice.cert
    ../../tools/make_bundle -o bob.bundle mbps1.root mbps1.schema +bob.cert
    ../../tools/make_bundle -o cathy.bundle mbps1.root mbps1.schema +cathy.cert
    ../../tools/make_bundle -o frontdoor.bundle mbps1.root mbps1.schema +frontdoor.cert