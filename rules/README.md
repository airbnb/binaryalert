# BinaryAlert YARA Rules
This folder contains the YARA rules that are bundled into BinaryAlert.


## Adding/Updating YARA Rules
To add or update YARA rules:
  1. Clone YARA rules from other open-source repos: `python3 ../manage.py update_rules`.
  At the time of writing, third-party YARA rules are pulled from subsets of
  [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) and
  [YARA-Rules/rules](https://github.com/YARA-Rules/rules).
  2. Add your own custom `.yar` or `.yara` rules files anywhere in this directory tree.


### Supported YARA Modules
YARA has a variety of [different modules](http://yara.readthedocs.io/en/latest/modules.html); only
the `Math` and `PE` modules are officially supported at this time.


## Compiling YARA Rules
YARA rules can be compiled into a single binary file: `python3 compile_rules.py`. This happens
automatically during unit tests and for Lambda deployment.
See the Troubleshooting section below for help resolving any issues that may arise.


### Troubleshooting Rule Compilation
YARA rules can fail to compile for a variety of reasons. In most cases, we just remove the offending
rules file. A few examples are listed below:


#### Failures During Local Testing

```
yara.SyntaxError: ...: internal fatal error
```

This is a [known issue](https://github.com/Yara-Rules/rules/issues/176) due to YARA being unable to
handle very long regexes.

```
yara.SyntaxError: ...: undefined identifier "extension"
```
This rule is expecting an
[external variable](http://yara.readthedocs.io/en/latest/writingrules.html#external-variables)
named "extension." Look at the YARA rule to understand what it's expecting the variable to
represent. Add a new external variable definition during rule compilation and rule matching.


#### Failures In Lambda
If, when testing in the Lambda console, you see an error similar to `internal error: 34: Error`,
it's likely that there is a new rule using an unsupported module. The rule may pass local testing
but fail in the Lambda env because the sets of YARA modules are different between
the two environments.
