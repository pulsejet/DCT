    ./schemaCompile -o mbpsDemo.scm mbpsDemo.trust
    ../../tools/make_cert -s EdDSA -o mbpsDemo.root myNet/mbpsDemo
    ../../tools/schema_cert -o mbpsDemo.schema mbpsDemo.scm mbpsDemo.root
    ../../tools/make_cert -s EdDSA -o alice.cert myNet/mbpsDemo/controller/alice mbpsDemo.root
    ../../tools/make_cert -s EdDSA -o bob.cert myNet/mbpsDemo/viewer/bob mbpsDemo.root
    ../../tools/make_cert -s EdDSA -o frontdoor.cert myNet/mbpsDemo/gateway/frontdoor mbpsDemo.root
    ../../tools/make_bundle -o alice.bundle mbpsDemo.root mbpsDemo.schema +alice.cert
    ../../tools/make_bundle -o bob.bundle mbpsDemo.root mbpsDemo.schema +bob.cert
    ../../tools/make_bundle -o frontdoor.bundle mbpsDemo.root mbpsDemo.schema +frontdoor.cert