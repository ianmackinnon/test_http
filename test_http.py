#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import json
import random
import logging
import unittest
from optparse import OptionParser
from urlparse import urlparse, urlunparse

import httplib2
import lxml.html



log = logging.getLogger('test_http')
log.addHandler(logging.StreamHandler())



conf_path_key = "HTTP_TEST_CONF"
conf_path = os.getenv(conf_path_key, None)
conf = json.load(open(conf_path))



class Http(object):
    error_html = "/tmp/test_http_error.html"

    @classmethod
    def make_http(cls):
        if hasattr(cls, "http"):
            return
        cls.http = httplib2.Http(
            cache=None,
            disable_ssl_certificate_validation=True,
        )
        cls.http.follow_redirects = False

    @classmethod
    def get_cookies(cls, url):
        cls.make_http()
        response, content = cls.http.request(url)
        return response["set-cookie"]
        
    def __init__(self):
        self.make_http()

    def http_request_title(self, content):
        try:
            page = lxml.html.document_fromstring(content)
        except Exception as e:
            print "", e
            return
            
        title = page.find(".//title")
        if title is not None:
            return title.text

    def get_http_old(self, path, headers):
        url = path
        response, content = self.http.request(url, headers=headers)
        if response.status == 200:
            title = self.http_request_title(content)
        else:
            title = None

        log.info(u"\n%-64s  %s" % (url, title or u""))
        content = content.decode("utf-8")
            
        return response, content

    def get_json_data(self, path, cookie=None):
        headers = {
                "Accept": "application/json",
                }
        if cookie:
            headers["Cookie"] = cookie
        response, content = self.get_http_old(path, headers)
        
        self.assertEqual(response.status, 200, msg=path)
        self.assertNotEqual(response["content-length"], 0)
        self.assertEqual(response["content-type"],
                         'application/json; charset=UTF-8')
        
        data = json.loads(content)

        return data

    def http_request(self, path, cookie=None, mime=None, headers=None, checks=None, status=200):
        if headers is None:
            headers = {}
        if cookie:
            headers["Cookie"] = cookie
        response, content = self.get_http_old(path, headers)

        # Set mime by check if mime is null

        automime = None
        check_functions = []
        for check in checks:
            if isinstance(check, basestring):
                f_kwargs = {}
                check_name = check
            else:
                f_kwargs = check.copy()
                check_name = f_kwargs.pop("name", None)
            f_name = self.checks.get(check_name, None)
            if not f_name:
                log.warning("No check function found for \"%s\"." % check_name)
                continue
            check_functions.append((f_name, f_kwargs))

            if mime is None:
                check_automime = self.automime.get(check_name, None)
                if check_automime:
                    if automime:
                        log.warning(u"Automatic mime type already set (%s, %s)." % (automime, check_automime))
                    automime = check_automime

        if mime is None:
            mime = automime or 'text/html'

        response_mime = response["content-type"] or None
        if mime:
            mime = mime.split(";")[0] or None
        if response_mime:
            response_mime = response_mime.split(";")[0] or None
        
        self.assertEqual(response.status, status, path)
        self.assertEqual(response_mime, mime)
        self.assertNotEqual(response["content-length"], 0)

        for f_name, f_kwargs in check_functions:
            getattr(self, f_name)(content, **f_kwargs)
        
        return content
        
    def http_request_not_found(self, path, cookie=None):
        headers = {}
        if cookie:
            headers["Cookie"] = cookie
        response, content = self.get_http_old(path, headers)
        
        self.assertEqual(response.status, 404, msg=path)

        return content

    def http_request_not_authenticated(self, path, cookie=None):
        headers = {}
        if cookie:
            headers["Cookie"] = cookie
        response, content = self.get_http_old(path, headers)
        
        self.assertEqual(response.status, 302, msg=path)
        self.assertEqual(response["location"][:11], "/auth/login")

    def http_request_not_authorised(self, path, cookie=None):
        headers = {}
        if cookie:
            headers["Cookie"] = cookie
        response, content = self.get_http_old(path, headers)
        
        self.assertEqual(response.status, 403, msg=path)

    # Checks

    automime = {
        "json": "application/json"
        }
    
    checks = {
        "json": "assert_json_ok",
        "mako": "assert_mako_ok",
        "php": "assert_php_ok",

        "jsonCount": "check_json_count",
        "contains": "check_contains",
        "containsNot": "check_contains_not",
    }

    def assert_json_ok(self, content):
        try:
            json.loads(content)
        except ValueError as e:
            self.fail("JSON decode error: %s." % unicode(e))

    def assert_mako_ok(self, html):
        if "Mako Runtime Error" in html:
            with open(self.error_html, "w") as html_file:
                html_file.write(html)
                html_file.close()
            self.fail("Mako template error. See '%s'." % self.error_html)

    def assert_php_ok(self, html):
        if ".php</b> on line <b>" in html:
            with open(self.error_html, "w") as html_file:
                html_file.write(html)
                html_file.close()
            self.fail("PHP error. See '%s'." % self.error_html)

    def check_json_count(self, content, count, path):
        try:
            data = json.loads(content)
        except ValueError as e:
            self.fail("JSON decode error: %s." % unicode(e))

        cursor = data
        keys = path.split(".")[1:]
        for key in keys:
            try:
                cursor = cursor[key]
            except KeyError as e:
                self.fail("Path does not exist: \"%s\"" % path)

        self.assertEqual(len(cursor), count)

    def check_contains(self, content, term):
        if not term in content:
            self.fail("Term \"%s\" not found in content." % term)

    def check_contains_not(self, content, term):
        if term in content:
            self.fail("Term \"%s\" found in content." % term)


    # Other

    @staticmethod
    def logged_in(response):
        if not 'set-cookie' in response:
            return None
        text = response["set-cookie"]
        if not text:
            return None
        cookies = {}
        for cookie in text.split("; "):
            name, value = cookie.split('=', 1)
            cookies[name] = value
        return bool(cookies.get('s', None))

    def assertLoggedIn(self, response):
        self.assertEqual(self.logged_in(response), True)

    def assertNotLoggedIn(self, response):
        self.assertEqual(self.logged_in(response), False)


        
class HttpTest(unittest.TestCase, Http):
    _multiprocess_can_split_ = True
    
    def __init__(self, *args, **kwargs):
        unittest.TestCase.__init__(self, *args, **kwargs)
        Http.__init__(self)
        
    @classmethod
    def setUpClass(cls):
        cls.longMessage = True

        

def http_helper(url, mime=None, headers=None, checks=None):
    def f(self):
        html = self.http_request(url, mime=mime, headers=headers, checks=checks)
    return f



if not conf_path:
    parser.print_usage()
    sys.exit(1)


default_checks = [
    "mako"
]
    
counter = 0
tests = conf.get("tests", None)
if tests:
    for group in tests:
        group_name = str(group.get("group", None))
        group_tests = group.get("tests", None)
        group_headers = group.get("header", None) or {}
        group_checks = group.get("checks", None) or default_checks[:]
        if not (group_name and group_tests):
            continue

        class_name = "Test%s" % group_name

        class_dict = {}

        for test in group_tests:
            resource_name = None
            resource_mime = None
            resource_headers = group_headers.copy()
            resource_checks = group_checks[:]
            if isinstance(test, basestring):
                url = test
            else:
                url = test.get("url", None)
                resource_name = str(test.get("name", ""))
                resource_mime = test.get("mime", None)
                if "checks" in test and test["checks"]:
                    resource_checks = test["checks"]
                if "header" in test and test["header"]:
                    resource_headers = test["header"]

            resource_name = resource_name or ""

            if not url:
                continue

            counter += 1
            test_name = "test_%04d" % counter
            if resource_name:
                test_name += "_%s" % resource_name

            func = http_helper(url, mime=resource_mime, headers=resource_headers, checks=resource_checks)
            func.func_name = test_name
            class_dict[test_name] = func

        if not class_dict:
            continue

        globals()[class_name] = type(class_name, (HttpTest, ), class_dict)



if __name__ == "__main__":
    usage = """%s=JSON %%prog

JSON    Test data in JSON format, supplied as an environment variable.
""" % conf_path_key

    parser = OptionParser(usage=usage)
    parser.add_option("-v", "--verbose", action="count", dest="verbose",
                      help="Print verbose information for debugging.", default=0)
    parser.add_option("-q", "--quiet", action="count", dest="quiet",
                      help="Suppress warnings.", default=0)

    (options, args) = parser.parse_args()
    args = [arg.decode(sys.getfilesystemencoding()) for arg in args]

    log_level = (logging.ERROR, logging.WARNING, logging.INFO, logging.DEBUG,)[
        max(0, min(3, 1 + options.verbose - options.quiet))]

    log.setLevel(log_level)

    unittest.main()
