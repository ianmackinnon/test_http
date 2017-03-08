SHELL := /bin/bash
.PHONY : all package install uninstall

NAME = test_http
TMP = /tmp/$(name).tmp
VERSION = 0.1.0
DIST := dist/$(NAME)-$(VERSION).tar.gz


package : test_http.py setup.py
	python3 setup.py sdist

$(DIST) : package


install : package
	cp test_http.py /usr/local/bin/test_http
	python3 setup.py install

uninstall :
	rm -f /usr/local/bin/test_http
	yes | sudo pip uninstall $(NAME)

test :
	HTTP_TEST_CONF=example.json ./test_http.py

serve :
	cd test_data && python3 -m SimpleHTTPServer 8088
