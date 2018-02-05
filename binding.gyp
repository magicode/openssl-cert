{
    "targets": [{
            "target_name": "openssl-cert",
            "sources": [
                "openssl-cert.cc"
            ],
            "include_dirs": [
                "<!(node -e \"require('nan')\")"
            ]
        }

    ]
}
