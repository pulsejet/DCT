    ./schemaCompile -o mbpsDemo.scm mbpsDemo.trust
    ../../tools/make_cert -s EdDSA -o mbpsDemo.root myNet/mbpsDemo
    ../../tools/schema_cert -o mbpsDemo.schema mbpsDemo.scm mbpsDemo.root
    ../../tools/make_cert -s EdDSA -o alice.cert myNet/mbpsDemo/controller/alice mbpsDemo.root
    ../../tools/make_cert -s EdDSA -o bob.cert myNet/mbpsDemo/viewer/bob mbpsDemo.root
    ../../tools/make_cert -s EdDSA -o California.cert myNet/mbpsDemo/gateway/California mbpsDemo.root
    ../../tools/make_cert -s EdDSA -o Texas.cert myNet/mbpsDemo/gateway/Texas mbpsDemo.root
    ../../tools/make_bundle -o alice.bundle mbpsDemo.root mbpsDemo.schema +alice.cert
    ../../tools/make_bundle -o bob.bundle mbpsDemo.root mbpsDemo.schema +bob.cert
    ../../tools/make_bundle -o California.bundle mbpsDemo.root mbpsDemo.schema +California.cert
    ../../tools/make_bundle -o Texas.bundle mbpsDemo.root mbpsDemo.schema +Texas.cert