#!/usr/bin/env python3

import os
import re
import sys
import copy
import json
import stat
import pprint
import warnings
import logging
import argparse
import unittest
from urllib.parse import urlencode
from urllib.parse import urlunparse

from onetimepass import get_totp

import requests



LOG = logging.getLogger('test_http')
LOG.addHandler(logging.StreamHandler())



ENV_CONF = "HTTP_TEST_CONF"
ENV_HOST = "HTTP_TEST_HOST"

DEFAULT_METHOD = 'GET'
DEFAULT_MIME = 'text/html'
DEFAULT_STATUS = 200
DEFAULT_PARAMS = {
    "scheme": "http",
    "checks": [
        "mako"
    ]
}

VERIFY = True



CONF_PATH = None
CONF_DIR = None
CONF_HANDLE = None
CONF = None

COUNTER = None
ENV = None
TESTS = None



class Http(object):
    error_html = "/tmp/test_http_error.html"

    def http_request(
            self,
            uri,
            headers=None,
            method=None,
            cookie=None,
            status=None,
            mime=None,
            checks=None,
    ):

        if self.session:
            session = self.session
        else:
            session = requests.Session()  # Close at end of `http_request`.
            session.verify = VERIFY

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

        headers.update({
            # Because `gzip` distorts `Content-Length`:
            "Accept-Encoding": "identity"
        })

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
            if isinstance(check, str):
                f_kwargs = {}
                check_name = check
            else:
                f_kwargs = check.copy()
                check_name = f_kwargs.pop("name", None)
            f_name = self.checks.get(check_name, None)
            if not f_name:
                LOG.warning("No check function found for \"%s\".", check_name)
                continue
            check_functions.append((f_name, f_kwargs))

            if mime is None:
                check_automime = self.automime.get(check_name, None)
                if check_automime:
                    if automime:
                        LOG.warning(
                            "Automatic mime type already set (%s, %s).",
                            automime, check_automime)
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
            if (
                    int(response.headers["content-length"]) !=
                    len(response.text)
            ):
                LOG.warning(
                    "`Content-Length` header (%d) does not "
                    "match content length (%d).",
                    int(response.headers["content-length"]),
                    len(response.text)
                )
        elif "transfer-encoding" in response.headers:
            if response.headers["transfer-encoding"].lower() != "chunked":
                LOG.warning(
                    "`Content-Length` header missing and "
                    "`Transfer-Encoding` (%s) is not `chunked`.",
                    int(response.headers["transfer-encoding"]))
        else:
            LOG.warning(repr(response.headers))
            LOG.warning(
                "Required header missing: `content-length`. "
                "Content length %d.", len(response.text))
        for f_name, f_kwargs in check_functions:
            getattr(self, f_name)(response.text, **f_kwargs)

        if not self.session:
            session.close()

        return response.text

    # Checks

    automime = {
        "json": "application/json"
        }

    checks = {
        "json": "check_json_ok",
        "mako": "check_mako_ok",
        "php": "check_php_ok",

        "jsonPrint": "check_json_print",

        "jsonValue": "check_json_value",
        "jsonCount": "check_json_count",
        "contains": "check_contains",
        "containsNot": "check_contains_not",
    }

    def check_json_ok(self, content):
        try:
            json.loads(content)
        except ValueError as e:
            self.fail("JSON decode error: %s." % str(e))

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

    def check_json_print(self, content):
        try:
            data = json.loads(content)
        except ValueError as e:
            self.fail("JSON decode error: %s." % str(e))

        pprint.pprint(data)

    def check_json_path(self, content, path):
        try:
            data = json.loads(content)
        except ValueError as e:
            self.fail("JSON decode error: %s." % str(e))

        cursor = data
        keys = path.split(".")
        if keys:
            first = keys.pop(0)
            assert not first, \
                "path be empty or start with `.`, not %s." % repr(first)
        for key in keys:
            if re.match(r"[0-9]+$", key):
                key = int(key)
            try:
                cursor = cursor[key]
            except KeyError as e:
                self.fail(
                    "Path does not exist: `%s`. Key: %s, Cursor: `%s`." %
                    (path, repr(key), cursor))

        LOG.debug("JSON path: \"%s\"; value: \"%s\".", path, cursor)

        return cursor

    def check_json_value(self, content, path, **kwargs):
        value = self.check_json_path(content, path)
        if "equal" in kwargs:
            self.assertEqual(value, kwargs["equal"])
        if "gte" in kwargs:
            self.assertGreaterEqual(value, kwargs["gte"])
        if "lte" in kwargs:
            self.assertLessEqual(value, kwargs["lte"])
        if "contains" in kwargs:
            self.assertIn(kwargs["contains"], value)
        if "icontains" in kwargs:
            self.assertIn(kwargs["icontains"].lower(), value.lower())

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

    def assert_logged_in(self, response):
        self.assertEqual(self.logged_in(response), True)

    def assert_not_logged_in(self, response):
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
    headers = params.get("headers", None)
    method = params.get("method", None)

    status = params.get("status", None)
    mime = params.get("mime", None)
    checks = params.get("checks", None)

    url = params_expand_url(params, url)

    def func(self):
        self.http_request(
            url,
            headers=headers,
            method=method,
            cookie=None,
            status=status,
            mime=mime,
            checks=checks,
        )
    return func



def params_expand_url(params, url):
    if "://" in url:
        return url

    scheme = params["scheme"]
    host = params["host"]
    if host == "$HOST":
        host = os.getenv(ENV_HOST, None)

    if not "://" in host:
        host = "%s://%s" % (scheme, host)

    url = host + url

    return url



class AuthenticationException(Exception):
    pass



def setupclass_helper(params, auth=None, xsrf=None):
    session = None

    if auth:
        if not auth.get("type", None):
            LOG.error("Auth `type` not supplied.")
            sys.exit()
        if auth["type"] == "firma-password":
            credentials_path = auth.get("credentials", None)
            if not credentials_path:
                LOG.error("No credentials path supplied.")
                sys.exit()

            credentials_path = os.path.join(
                os.path.dirname(os.path.realpath(CONF_PATH)),
                credentials_path
            )

            st = os.stat(credentials_path)
            if st.st_mode & stat.S_IROTH or st.st_mode & stat.S_IWOTH:
                LOG.error("%s: Credential paths may not be "
                          "readable or writable by `other`.\n",
                          credentials_path)
                sys.exit(1)

            with open(credentials_path, "r", encoding="utf-8") as fp:
                credentials = json.load(fp)

            account = auth.get("account", None)
            if not account:
                LOG.error("No account name supplied.")
                sys.exit()

            if account not in credentials:
                LOG.error("Account name %s not found in credentials.", account)
                sys.exit()

            account_data = credentials[account]

            email = account_data.get("email", None)
            user_id = account_data.get("user_id", None)
            password = account_data.get("password", None)
            onetime_secret = account_data.get("onetime_secret", None)

            if not (email or user_id):
                LOG.error("`email` or `user_id` not supplied in credentials.")
                sys.exit()

            if not password:
                LOG.error("`password` not supplied in credentials.")
                sys.exit()

            if not onetime_secret:
                LOG.error("`onetime_secret` not supplied in credentials.")
                sys.exit()

            host = params.get("host", None)
            if host == "$HOST":
                host = os.getenv(ENV_HOST, None)

            url = auth.get("url", None)
            if not url:
                LOG.error("No URL supplied.")
                sys.exit()

            url = params_expand_url(params, url)

            data = {
                "password": password,
                "token": get_totp(onetime_secret),
            }

            if email:
                data["email"] = email

            if user_id:
                data["user_id"] = user_id

            session = requests.Session()  # Close in `teardownclass_helper`
            r = session.get(url, data=data)

            if r.status_code != 200:
                raise AuthenticationException(
                    "Error: %s login failed (%d)." %
                    (auth["type"], r.status_code))

            session.verify = VERIFY
        else:
            LOG.error("Unknown auth type `%s`.", auth["type"])
            sys.exit()

    @classmethod
    def func(cls):
        HttpTest.setUpClass()
        cls.session = session
        cls.xsrf = xsrf
        warnings.simplefilter("ignore", ResourceWarning)

    return func



def teardownclass_helper():
    @classmethod
    def func(cls):
        if cls.session:
            cls.session.close()
        HttpTest.tearDownClass()

    return func



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
    for key, value in list(params.items()):
        if isinstance(value, str) and value.startswith("$"):
            env_key = value[1:]
            value = os.getenv(env_key, None)
            if value is not None:
                updated[key] = value
            elif env and env_key in env:
                updated[key] = env[env_key]

    return updated



def build_tests():
    global CONF_PATH, CONF_DIR, CONF_HANDLE, CONF
    global COUNTER, ENV, TESTS

    CONF_PATH = os.getenv(ENV_CONF, None)
    if CONF_PATH is None:
        sys.stderr.write(
            "Environment variable %s must be set to the path of a "
            "JSON configuration file.\n" % ENV_CONF)
        sys.exit(1)

    CONF_DIR = os.path.dirname(CONF_PATH)
    try:
        CONF_HANDLE = open(CONF_PATH, "r", encoding="utf-8")
    except IOError as e:
        sys.stderr.write("Could not open configuration file %s.\n" % CONF_PATH)
        sys.stderr.write(str(e) + "\n")
        sys.exit(1)

    try:
        CONF = json.load(CONF_HANDLE)
    except ValueError as e:
        sys.stderr.write(
            "configuration file %s is not valid JSON.\n" % CONF_PATH)
        sys.stderr.write(str(e) + "\n")
        sys.exit(1)

    if not CONF_PATH:
        LOG.error("Must supply configuration path as environment variable.")
        sys.exit(1)


    COUNTER = 0
    ENV = CONF.get("env", None)
    TESTS = CONF.get("tests", None)

    if TESTS:
        for group in TESTS:
            group_params = update_params(DEFAULT_PARAMS, group)
            group_name = group.get("group", None)
            group_tests = group.get("tests", None)

            group_auth = group.get("auth", None)
            group_xsrf = group.get("xsrf", None)

            if not (group_name and group_tests):
                continue

            class_name = "Test%s" % str(group_name)
            class_dict = {}

            class_dict["setUpClass"] = setupclass_helper(
                env_params(group_params, ENV),
                group_auth,
                group_xsrf
            )
            class_dict["tearDownClass"] = teardownclass_helper()

            test_names = set()
            for test in group_tests:
                if isinstance(test, str):
                    test = {
                        "url": test
                    }
                resource_params = update_params(group_params, test)
                resource_params = env_params(resource_params, ENV)

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
                    LOG.warning(
                        "Parameter `url` missing from test and could not "
                        "be constructed from `scheme` and `host`.")
                    continue

                COUNTER += 1
                name = resource_params.get("name", None)
                if name:
                    if name in test_names:
                        LOG.warning("Duplicate test name '%s'", name)
                    test_names.add(name)
                    test_name = "test_%s" % name
                else:
                    test_name = "test_%04d" % COUNTER

                func = http_helper(url, resource_params)
                func.__name__ = test_name
                class_dict[test_name] = func

            if not class_dict:
                continue

            globals()[class_name] = type(class_name, (HttpTest, ), class_dict)



def parse_arguments():
    parser = argparse.ArgumentParser(
        description= \
        """Test HTTP services using Python unitests and JSON descriptions.

    Usage: %s=JSON test_http.py

""" % ENV_CONF)
    parser.add_argument(
        "--verbose", "-v",
        action="count", default=0,
        help="Print verbose information for debugging.")
    parser.add_argument(
        "--quiet", "-q",
        action="count", default=0,
        help="Suppress warnings.")

    parser.add_argument(
        "tests", metavar="TESTS",
        nargs="*",
        help="Tests to run.")

    args = parser.parse_args()

    level = (logging.ERROR, logging.WARNING, logging.INFO, logging.DEBUG)[
        max(0, min(3, 1 + args.verbose - args.quiet))]
    LOG.setLevel(level)



def run_tests():
    test_object = unittest.main(exit=False)
    sys.exit(not test_object.result.wasSuccessful())



if __name__ == "__main__":
    parse_arguments()

build_tests()

if __name__ == "__main__":
    run_tests()
