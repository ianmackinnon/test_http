SHELL := /bin/bash
.PHONY : all package install uninstall

NAME = test_http
TMP = /tmp/$(name).tmp
BIN = /usr/local/bin


package :
	./setup.py sdist

install :
	./setup.py build
	sudo ./setup.py install
	sudo cp test_http/test_http.py $(BIN)/test_http

clean :
	sudo rm -rf AUTHORS ChangeLog build .eggs test_http.egg-info __pycache__

uninstall :
	sudo rm -rf \
	  /usr/local/lib/python*/dist-packages/test_http* \
	  $(BIN)/test_http

test :
	HTTP_TEST_CONF=example.json ./test_http.py

serve-test :
	cd test_data && python3 -m SimpleHTTPServer 8088
