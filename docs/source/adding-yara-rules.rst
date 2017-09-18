Adding YARA Rules
=================
`YARA <http://virustotal.github.io/yara/>`_ is a powerful pattern-matching tool designed for identifying and classifying malware. BinaryAlert includes a number of custom YARA rules and makes it easy to add more of your own. Rules are automatically compiled and bundled with every deploy.


Included Rules
--------------
BinaryAlert includes a number of `custom YARA rules <https://github.com/airbnb/binaryalert/tree/master/rules/public>`_  written by Airbnb's analysts which detect a variety of hacktools, malware, and ransomware. All included rules have been tested against a corpus of more than 2 million binaries to ensure the highest fidelity.


Clone Rules From Other Projects
-------------------------------
BinaryAlert makes it easy to clone YARA rules from other open-source projects:

.. code-block:: bash

  $ ./manage.py clone_rules

This will copy a subset of YARA rules from each of the following repositories:

* `Neo23x0/signature-base <https://github.com/Neo23x0/signature-base>`_
* `YARA-Rules/rules <https://github.com/YARA-Rules/rules>`_

You can add more rule sources in `rules/clone_rules.py <https://github.com/airbnb/binaryalert/blob/master/rules/clone_rules.py>`_


Write Your Own Rules
--------------------
You can add your own ``.yar`` or ``.yara`` files anywhere in the ``rules/`` directory tree. Refer to the `writing YARA rules <http://yara.readthedocs.io/en/latest/writingrules.html>`_ documentation for guidance and examples. Note that when BinaryAlert finds a file which matches a YARA rule, the rule name, `metadata <http://yara.readthedocs.io/en/latest/writingrules.html#metadata>`_, `tags <http://yara.readthedocs.io/en/latest/writingrules.html#rule-tags>`_, and matched `string <http://yara.readthedocs.io/en/latest/writingrules.html#strings>`_ names will be included in the alert for your convenience.


.. _external-variables:

External Variables
------------------
In order to support the rule repositories listed above, BinaryAlert provides the following `external variables <http://yara.readthedocs.io/en/latest/writingrules.html#external-variables>`_:

* ``extension`` - File extension (".docx", ".exe", ".pdf", etc)
* ``filename`` - File basename ("file.exe")
* ``filepath`` - Full file path ("/path/to/file.exe")
* ``filetype`` - Uppercase ``extension`` without leading period ("DOCX", "EXE", "PDF"), etc

You can use these variables in your own rules to match or exclude certain filepaths. (Note that the variables will default to empty strings if they are not available.) For example, this is a YARA rule which matches only files containing the string "evil" in the ``/home/`` directory:

.. code-block:: none

  rule evil_at_home
  {
      strings:
          $evil = "evil" nocase wide ascii

      condition:
          $evil and filepath matches /\/home\/*/
  }


.. _supported_yara_modules:

Supported Modules
-----------------
BinaryAlert supports all of the default `YARA modules <http://yara.readthedocs.io/en/latest/modules.html>`_, including ELF, Math, Hash, and PE.


.. _testing_yara_rules:

Testing Your Rules
------------------
The easiest way to test individual YARA rules is to `install YARA locally <http://yara.readthedocs.io/en/latest/gettingstarted.html#getting-started>`_. Note that you will need the ``-d`` flag to define external variables. For example, to test the ``evil_at_home`` rule above:

.. code-block:: bash

  $ brew install yara  # MacOS
  $ yara evil_at_home.yar file_to_test.exe -d filepath="/home/user/file_to_test.exe"
  # evil_at_home file_to_text.exe

To test *all* of your YARA rules, you first need to compile them into a single binary file:

.. code-block:: bash

  $ ./manage.py compile_rules  # Saves "compiled_yara_rules.bin"

This compiled rules file is what gets bundled with the BinaryAlert analyzers. Now, from a Python interpreter:

.. code-block:: python

  import yara
  rules = yara.load('compiled_yara_rules.bin')
  matches = rules.match('file_to_text.exe')
  print(matches)

See the `yara-python <http://yara.readthedocs.io/en/latest/yarapython.html>`_ docs for more information about using YARA from Python.
