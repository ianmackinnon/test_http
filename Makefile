SHELL := /bin/bash

PYTHON = python3
NAME = test_http
TMP = /tmp/$(name).tmp
BIN = /usr/local/bin


all :

.PHONY : dist
dist :
	./setup.py sdist

.PHONY : build
build :
	$(PYTHON) setup.py build

install : build
	sudo $(PYTHON) setup.py install
	sudo cp test_http/test_http.py $(BIN)/test_http

install-pip : dist
	sudo -H $(PYTHON) -m pip install dist/$(NAME)-*.tar.gz

clean :
	rm -rf AUTHORS ChangeLog build .eggs test_http.egg-info __pycache__ dist MANIFEST

uninstall :
	sudo rm -rf \
	  /usr/local/lib/python*/dist-packages/test_http* \
	  $(BIN)/test_http

test :
	HTTP_TEST_CONF=example.json ./test_http.py

serve-test :
	cd test_data && $(PYTHON) -m SimpleHTTPServer 8088
