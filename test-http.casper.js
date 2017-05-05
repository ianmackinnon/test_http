/* global require, casper, console, document, XPathResult, $ */

"use strict"; // jshint -W097

var colorizer = require("colorizer").create("Colorizer");
var system = require("system");
var _ = require("underscore");
var utils = require("utils");
var x = require("casper").selectXPath;
var process = require("child_process");

// Print debug information to `stderr`.
_.each({
  "info": "INFO",
  "warn": "WARNING",
  "error": "ERROR",
  "trace": "TRACE"
}, function (level, f) {
  console[f] = function () {
    system.stderr.write(colorizer.colorize(
      Array.prototype.join.call(arguments, " ") + "\n",
      level
    ));
  };
});

console.traceLines = function (trace) {
  _.each(trace, function (v, k) {
    console.trace(v.file + ":" + v.line + " (" + v.function + ")");
  });
};

casper.on("remote.message", function (text) {
  casper.echo(colorizer.format("  " + text, {
    fg: "cyan"
  }));
});

casper.on("page.error", function (msg, trace) {
  console.warn("Page Error: " + msg);
  console.traceLines(trace);
});

casper.on("resource.error", function (error) {
  if (error.errorCode === 5) {
    return;
  }
  console.log(
    "Resource Error: " + error.url + " " + error.errorCode + ": " + error.errorString);
});

casper.on("error", function (msg, trace) {
  this.capture("/tmp/casperjs-error.png");
  console.warn("Error: " + msg);
  console.traceLines(trace);
});

casper.waitForTitleChange = function (then, onTimeout, timeout) {
  var oldTitle, newTitle;
  this.then(function () {
    oldTitle = this.getTitle();
  }).waitFor(function () {
    newTitle = this.getTitle();
    return newTitle !== oldTitle;
  }, then, onTimeout, timeout);
  return this;
};

var xpathValues = function (selector) {
  var result = document.evaluate(
    selector, document, null, XPathResult.ANY_TYPE, null);
  var values = [];
  while (true) {
    var node = result.iterateNext();
    if (!node) {
      break;
    }
    values.push(node.nodeValue);
  }
  return values;
};

var splitRemain = function (text, separator, n) {
  var out = [];
  var offset = 0;
  while (n--) {
    var next = text.indexOf(separator, offset);
    if (next === -1) {
      break;
    }
    out.push(text.slice(offset, next));
    offset = next + separator.length;
  }
  out.push(text.substr(offset));
  return out;
};

var host = casper.cli.get("host");
if (!host) {
  console.error("Variable `host` not defined (use argument `--host=HOST`).");
  casper.exit(1);
}

var conf = casper.cli.get("conf");
if (!conf) {
  console.error("Variable `conf` not defined (use argument `--conf=JSON`).");
  casper.exit(1);
}

var limits;
var testLimits = casper.cli.get("tests");
if (testLimits) {
  limits = {};
  _.each(testLimits.split(","), function (text) {
    var parts = splitRemain(text, ".", 1);
    var group = parts[0];
    var url = parts.length === 2 ? parts[1] : null;
    if (_.isUndefined(limits[group])) {
      limits[group] = {};
    }
    if (url) {
      limits[group][url] = true;
    }
  });
}

var setupTests = function (tests) {
  casper.start();

  _.each(tests.tests, function (group) {
    if (limits && !_.has(limits, group.group)) {
      return;
    }

    _.each(group.tests, function (groupTest) {
      if (limits && _.size(limits[group.group]) &&
          !_.has(limits[group.group], groupTest.url)) {
        return;
      }

      var name = group.group + "." + groupTest.url;
      var fullUrl = host + groupTest.url;
      casper.thenOpen(fullUrl, function () {
        console.info(name);
        var page = this;
        var title = page.getTitle();
        _.each(groupTest.checks, function (check) {
          if (check.name === "htmlTitle") {
            var value = page.getTitle();
            casper.test.assertEquals(
              title, check.value,
              fullUrl + " : htmlTitle");
          } else if (check.name === "htmlXpath") {
            var values = casper.evaluate(xpathValues, check.selector);
            casper.test.assertEquals(
              values, check.values,
              fullUrl + " : htmlXpath : " + check.selector);
          } else {
            console.warn("Ignoring test: " + check.name);
          }
        });
      });
    });

  });
};

// Expand `conf` path
process.execFile("bash", ["-c", "echo " + conf], null, function (err, stdout, stderr) {
  var conf = stdout.slice(0, -1);
  var tests = require(conf);
  setupTests(tests);
  casper.run();
});
