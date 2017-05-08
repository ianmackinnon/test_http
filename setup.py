#!/usr/bin/env python3



from distutils.core import setup



setup(
    name="test_http",
    version="0.1.0",
    py_modules=["test_http"],
    license="Creative Commons Attribution license",
    install_requires=[
        "lxml",
        "onetimepass",
        "requests[socks]",
    ]
)
