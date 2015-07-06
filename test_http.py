#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import copy
import json
import stat
import random
import logging
import unittest
import requests
from urllib import urlencode
from optparse import OptionParser
from urlparse import urlparse, urlunparse



log = logging.getLogger('test_http')
log.addHandler(logging.StreamHandler())



DEFAULT_METHOD = 'GET'
DEFAULT_MIME = 'text/html'
DEFAULT_STATUS = 200
CONF_PATH_KEY = "HTTP_TEST_CONF"



conf_path = os.getenv(CONF_PATH_KEY, None)
if conf_path is None:
    sys.stderr.write(u"Environment variable %s must be set to the path of a JSON configuration file.\n" % CONF_PATH_KEY)
    sys.exit(1)

conf_dir = os.path.dirname(conf_path)
try:
    conf_handle=open(conf_path)
except IOError as e:
    sys.stderr.write(u"Could not open configuration file %s.\n" % conf_path)
    sys.stderr.write(unicode(e) + "\n")
    sys.exit(1)

try:
    conf = json.load(conf_handle)
except ValueError as e:
    sys.stderr.write(u"configuration file %s is not valid JSON.\n" % conf_path)
    sys.stderr.write(unicode(e) + "\n")
    sys.exit(1)

    

class Http(object):
    error_html = "/tmp/test_http_error.html"

    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False,

    def http_request(
            self,
            uri,
            identity=None,
            headers=None,
            method=None,
            cookie=None,
            status=None,
            mime=None, 
            checks=None,
    ):
        if identity:
            session = self.identities[identity]
        else:
            session = self.session

        if headers is None:
            headers = {}
#        if cookie:
#            headers["Cookie"] = cookie

        if method is None:
            method = DEFAULT_METHOD

        data = None
        if method in ("POST", "PUT", "DELETE") and self.xsrf:
            name = self.xsrf["cookie"]
            query = self.xsrf["query"]
            for cookie in session.cookies:
                if cookie.name == name and cookie.domain in uri:
                    data = {}
                    data[query] = cookie.value
                    break

        response = session.request(
            method,
            uri,
            headers=headers,
            data=data,
            allow_redirects=False,
        )

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
            mime = automime or DEFAULT_MIME
        if mime:
            mime = mime.split(";")[0] or None

        response_mime = response.headers["content-type"] or None
        if response_mime:
            response_mime = response_mime.split(";")[0] or None

        if status is None:
            status = DEFAULT_STATUS

        self.assertEqual(response.status_code, status, uri)
        self.assertEqual(response_mime, mime, uri)
        if "content-length" in response.headers:
            self.assertNotEqual(response.headers["content-length"], 0, uri)
        else:
            log.warning("Required header missing: \"content-length\"")

        for f_name, f_kwargs in check_functions:
            getattr(self, f_name)(response.text, **f_kwargs)
        
        return response.text
        
    # Checks

    automime = {
        "json": "application/json"
        }
    
    checks = {
        "json": "check_json_ok",
        "mako": "check_mako_ok",
        "php": "check_php_ok",

        "jsonValue": "check_json_value",
        "jsonCount": "check_json_count",
        "contains": "check_contains",
        "containsNot": "check_contains_not",
    }

    def check_json_ok(self, content):
        try:
            json.loads(content)
        except ValueError as e:
            self.fail("JSON decode error: %s." % unicode(e))

    def check_mako_ok(self, html):
        if "Mako Runtime Error" in html:
            with open(self.error_html, "w") as html_file:
                html_file.write(html)
                html_file.close()
            self.fail("Mako template error. See '%s'." % self.error_html)

    def check_php_ok(self, html):
        if ".php</b> on line <b>" in html:
            with open(self.error_html, "w") as html_file:
                html_file.write(html)
                html_file.close()
            self.fail("PHP error. See '%s'." % self.error_html)

    def check_json_path(self, content, path):
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
                self.fail(u"Path does not exist: \"%s\"" % path)

        log.debug(u"JSON path: \"%s\"; value: \"%s\"." % (path, cursor))

        return cursor

    def check_json_value(self, content, path, **kwargs):
        value = self.check_json_path(content, path)
        if "equal" in kwargs:
            self.assertEqual(value, kwargs["equal"])
        if "gte" in kwargs:
            self.assertGreaterEqual(value, kwargs["gte"])
        if "lte" in kwargs:
            self.assertLessEqual(value, kwargs["lte"])

    def check_json_count(self, content, path, **kwargs):
        value = len(self.check_json_path(content, path))
        if "equal" in kwargs:
            self.assertEqual(value, kwargs["equal"])
        if "gte" in kwargs:
            self.assertGreaterEqual(value, kwargs["gte"])
        if "lte" in kwargs:
            self.assertLessEqual(value, kwargs["lte"])

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

        

def http_helper(url, params):
    identity = params.get("identity", None)

    headers = params.get("headers", None)
    method = params.get("method", None)

    status = params.get("status", None)
    mime = params.get("mime", None)
    checks = params.get("checks", None)

    def f(self):
        html = self.http_request(
            url,
            identity=identity,
            headers=headers,
            method=method,
            cookie=None,
            status=status,
            mime=mime,
            checks=checks,
        )
    return f


def setupclass_helper(params, auth=None, xsrf=None):
    identities = None
    
    if auth:
        assert auth["type"] == "google-oauth2"
        from auth import google_oauth2, log_handler

        scheme = params["scheme"]
        host = params["host"]
        path = auth["path"]

        log_handler.setLevel(log.level)

        credentials_path = os.path.join(conf_dir, auth["credentials"])

        st = os.stat(credentials_path)
        if st.st_mode & stat.S_IROTH or st.st_mode & stat.S_IWOTH:
            sys.stderr.write(u"%s: Credential paths may not be readable or writable by all.\n" % credentials_path);
            sys.exit(1)

        with open(credentials_path) as cr_handle:
            cr_data = json.load(cr_handle)

        identities = {}

        for name in auth["identities"]:
            credentials = cr_data[name]
            email = credentials["email"]
            password = credentials["password"]

            identities[name] = google_oauth2(scheme, host, path, email, password)
            identities[name].verify = False

    @classmethod
    def f(cls):
        HttpTest.setUpClass()
        cls.identities = identities
        cls.xsrf = xsrf

    return f



PARAMS = {
    "url": {},

    "scheme": {},
    "host": {},
    "path": {},
    "query": {},

    "identity": {},

    "headers": {},
    "method": {},

    "status": {},
    "mime": {},
    "checks": {},
}


def update_params(*args):
    updated = {}
    for key in PARAMS:
        append = None
        if key.endswith("Append"):
            key = key[-6:]
            if key in PARAMS:
                raise Exception("Duplicate Key %s" % key)
            append = True
        for params in args:
            if key in params:
                if append and updated[key]:
                    updated[key] += copy.deepcopy(params[key])
                else:
                    updated[key] = copy.deepcopy(params[key])
    return updated



def env_params(params, env=None):
    updated = copy.deepcopy(params)
    for key, value in params.items():
        if isinstance(value, basestring) and value.startswith("$"):
            env_key = value[1:]
            value = os.getenv(env_key, None)
            if value is not None:
                updated[key] = value
            elif env and env_key in env:
                updated[key] = env[env_key]
                        
    return updated


    

default_params = {
    "scheme": "http",
    "checks": [
        "mako"
    ]
}



if __name__ == "__main__":
    usage = """%s=JSON %%prog

JSON    Test data in JSON format, supplied as an environment variable.
""" % CONF_PATH_KEY

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



if not conf_path:
    parser.print_usage()
    sys.exit(1)



counter = 0
env = conf.get("env", None)
tests = conf.get("tests", None)
if tests:
    for group in tests:
        group_params = update_params(default_params, group)
        group_name = group.get("group", None)
        group_tests = group.get("tests", None)

        group_auth = group.get("auth", None)
        group_xsrf = group.get("xsrf", None)

        if not (group_name and group_tests):
            continue

        class_name = "Test%s" % str(group_name)
        class_dict = {}

        setupclass = setupclass_helper(
            env_params(group_params, env),
            group_auth,
            group_xsrf
        )
        if setupclass:
            class_dict["setUpClass"] = setupclass

        test_names = set()
        for test in group_tests:
            if isinstance(test, basestring):
                test = {
                    "url": test
                }
            resource_params = update_params(group_params, test)
            resource_params = env_params(resource_params, env)

            url = resource_params.get("url", None)
            if url is None:
                query = resource_params.get("query", "")
                if query:
                    query = urlencode(query, True)
                try:
                    url = urlunparse((
                        resource_params["scheme"],
                        resource_params["host"],
                        resource_params.get("path", ""),
                        "",
                        query,
                        "",
                        ))
                except ValueError as e:
                    url = None
            if url is None:
                log.warning("Parameter `url` missing from test and could not be constructed from `scheme` and `host`.")
                continue

            counter += 1
            name = resource_params.get("name", None)
            if name:
                if name in test_names:
                    log.warning("Duplicate test name '%s'" % name)
                test_names.add(name)
                test_name = "test_%s" % name
            else:
                test_name = "test_%04d" % counter

            log.debug(url)

            func = http_helper(url, resource_params)
            func.func_name = test_name
            class_dict[test_name] = func

        if not class_dict:
            continue

        globals()[class_name] = type(class_name, (HttpTest, ), class_dict)



if __name__ == "__main__":
    unittest.main()



