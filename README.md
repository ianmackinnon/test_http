# test_http

Test HTTP services using Python unittest


## Installation

    make install


## Use

As Python unittests don't accept any parameters, the configuration file is set by use of an environment variable:

    HTTP_TEST_CONF=example.json ./test_http.py


## Configuration

Configuration is supplied as a JSON file. See the example file for details.

Tests are organised in groups, which corresponse to unittest classes. These should be named as a class would be named, ie. in camel case, starting with a capital letter.


### URLs

Tests themselves may be a simple URL, or an object containing separate parameters. For example:

    {
      "url": "http://www.example.com",
      "name": "root",
      "mime": "text/html"
    }

-    `name` is the name that will be given to the test, and should be a combination of lowercase letters, numbers and underscores.

-    `mime` is the expected mimetype of the resource.


### Checks

A list of checks can be included in a group or a test. They replace any checks that were defined higher up in the hierarchy.

A check can be a name, or an object containing the check name and some parameters. For example:

    {
      "url": "http://www.my-api.com/test.json",
      "checks": [
        "json",
        {
          "name": "jsonCount",
          "path": ".user.messages",
          "count": 5
        }
      ]
    }

Including the "json" check will automatically set the mime type to "application/json" if it has not been set explicitly already.


## Test

In one shell:

    make serve
    
in another:

    make test
