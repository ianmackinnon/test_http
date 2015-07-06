# -*- coding: utf-8 -*-

import sys
import logging
import requests
from urlparse import urlparse
from optparse import OptionParser
from requests.utils import dict_from_cookiejar, cookiejar_from_dict

try:
    from bs4 import BeautifulSoup
except ImportError as e:
    sys.stderr.write("Python package `bs4` required for auth.")

try:
    import lxml
except ImportError as e:
    sys.stderr.write("Python package `lxml` required for auth.")

try:
    from selenium import webdriver
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.common.exceptions import TimeoutException
except ImportError as e:
    sys.stderr.write("Python package `selenium` required for auth.")


GOOGLE_LOGIN_ID = "gaia_loginform"
GOOGLE_APPROVE_ID = "connect-approve"

log = logging.getLogger('auth')
log_handler = logging.StreamHandler()
log.addHandler(log_handler)
log.setLevel(logging.INFO)



def parse_form(text, id_, credentials=None):
    soup = BeautifulSoup(text, "lxml")

    form = soup.find("form", {"id": id_})

    if not form:
        log.error("Could not find #%s" % id_)
        log.error("Form IDs:")
        for form in soup.find_all("form"):
            log.error("  %s" % form.get("id", None))
            for input_ in form.find_all("input"):
                log.error("    %s" % input_.get("name", None))
        sys.exit(1)

    form_dict = {}

    for i, input_ in enumerate(form.find_all("input")):
        name = input_["name"]
        type_ = input_["type"]
        value = input_.get("value", None)
        if type_ in ("submit", ):
            continue
        elif credentials and type_ in credentials:
            form_dict[name] = credentials[type_]
        else:
            form_dict[name] = value
            
    action_url = form["action"]

    return action_url, form_dict



def google_login(text, credentials):
    soup = BeautifulSoup(text, "lxml")
    
    return parse_form(text, GOOGLE_LOGIN_ID,
                      credentials=credentials)



def debug_history(r):
    if r.history:
        for request in r.history:
            log.debug(">   %s : %s" % (request.status_code, request.url))
    log.debug(">>  %s : %s" % (r.status_code, r.url))



def google_oauth2(scheme, host, path, email, password):
    "Return a `requests` session logged in as given email."

    s = requests.session()

    root = u"%s://%s" % (scheme, host)
    login_url = root + path

    log.info(r"Requesting URL: %s", login_url)
    r = s.get(login_url)
    debug_history(r)
    log.debug(r"Done")

    credentials = {
        "email": email,
        "password": password,
    }

    url2, data = google_login(r.text, credentials)

    log.info(r"Requesting URL: %s", url2)
    r = s.post(url2, data=data)
    debug_history(r)
    log.debug(r"Done")

    if r.url.startswith(root):
        log.info("Authentication successful")
        return s

    if GOOGLE_LOGIN_ID in r.text:
        log.error("Authentication for %s failed. Check credentials." % email)
        sys.exit(1)

    if not GOOGLE_APPROVE_ID in r.text:
        log.error("Authentication failed. Redirected to unknown page.")
        log.error("URL: %s" % r.url)
        log.debug("\nContent:\n" + r.text)
        sys.exit(1)
    
    netloc = urlparse(r.url).netloc

    driver = webdriver.Firefox()

    domain_cookies = {}
    for cookie in s.cookies:
        if cookie.domain not in domain_cookies:
            domain_cookies[cookie.domain] = []
        domain_cookies[cookie.domain].append(cookie)

    for domain, cookies in domain_cookies.items():
        if domain not in driver.current_url:
            if domain.startswith("."):
                domain = "www" + domain
            domain_url = u"http://%s/404.html" % domain
            driver.get(domain_url)
        for cookie in cookies:
            driver.add_cookie({
                "name": cookie.name,
                "value": cookie.value,
                "domain": cookie.domain,
                "secure": cookie.secure,
                "path": cookie.path,
            })

    driver.get(r.url)

    try:
        WebDriverWait(driver, 60, poll_frequency=1).until(
            lambda driver: driver.current_url.startswith(root)
        )
    except TimeoutException as e:
        log.error("Timed out after 60s.")
    finally:
        driver.quit()

    return s
