Adding YARA Rules
=================
`YARA <http://virustotal.github.io/yara/>`_ is a powerful pattern-matching tool designed for identifying and classifying malware. BinaryAlert includes a number of custom YARA rules and makes it easy to add more of your own. Rules are automatically compiled and bundled with every deploy.


Included Rules
--------------
BinaryAlert includes a number of `custom YARA rules <https://github.com/airbnb/binaryalert/tree/master/rules/public>`_  written by Airbnb's analysts which detect a variety of hacktools, malware, and ransomware. All included rules have been tested against a corpus of more than 2 million binaries to ensure the highest fidelity.


.. _clone-yara-rules:

Clone Rules From Other Projects
-------------------------------
BinaryAlert makes it easy to clone YARA rules from other projects:

.. code-block:: bash

  $ ./manage.py clone_rules

This will copy a subset of YARA rules from several default :ref:`open-source collections <yara-credits>` into the ``rules/`` folder.
The cloned folder structure will mirror that of the remote repository.

.. note:: To ensure all upstream changes are copied (including deletions), the cloned folder structure for each repo will be deleted before cloning. For example, ``rules/github.com/Yara-Rules/rules.git`` will be deleted from your local filesystem before cloning from ``Yara-Rules``.

Configuring Rule Sources
........................

You can configure the remote rule sources in `rules/rule_sources.json <https://github.com/airbnb/binaryalert/blob/master/rules/rule_sources.json>`_. Each rule source is defined by a git-cloneable ``url``, an optional list of file paths to ``include``, and an optional list of file paths to ``exclude``.

Some examples using the `Yara-Rules <https://github.com/Yara-Rules/rules>`_ repository:

**1. URL only**

.. code-block:: json

    {
      "repos": [
        {
          "url": "https://github.com/Yara-Rules/rules.git"
        }
      ]
    }

If you specify just the ``git`` URL, BinaryAlert will traverse the entire repo and copy every ``.yar`` and ``.yara`` file (case insensitive).
SSH URLs (e.g. ``git@github.com:Yara-Rules/rules.git``) are also supported, since BinaryAlert just runs a ``git clone`` on the specified URL.

**2. Filter with Include and Exclude**

The ``Yara-Rules`` repo is very large, and you may only be interested in a specific subset of rules:

.. code-block:: json

    {
      "repos": [
        {
          "url": "https://github.com/Yara-Rules/rules.git",
          "include": [
            "CVE_Rules/*",
            "Malware/*"
          ],
          "exclude": [
            "Malware/POS*",
            "*_index.yar"
          ]
        }
      ]
    }

.. note:: This example is for demonstrative purposes only and is not necessarily recommended.

This will copy rules from the ``CVE_Rules`` and ``Malware`` folders, excluding POS and index files. BinaryAlert runs Unix filename pattern matching via `fnmatch <https://docs.python.org/3.6/library/fnmatch.html>`_.

In summary, BinaryAlert will copy a file from a remote repository if and only if the following conditions apply:

1. The file name ends in ``.yar`` or ``.yara`` (case insensitive), AND
2. The file path matches a pattern in the ``include`` list (OR the ``include`` list is empty), AND
3. The file path *does not* match a pattern in the ``exclude`` list.

Write Your Own Rules
--------------------
You can add your own ``.yar`` or ``.yara`` files anywhere in the ``rules/`` directory tree. Refer to the `writing YARA rules <http://yara.readthedocs.io/en/latest/writingrules.html>`_ documentation for guidance and examples. Note that when BinaryAlert finds a file which matches a YARA rule, the rule name, `metadata <http://yara.readthedocs.io/en/latest/writingrules.html#metadata>`_, `tags <http://yara.readthedocs.io/en/latest/writingrules.html#rule-tags>`_, and matched `string <http://yara.readthedocs.io/en/latest/writingrules.html#strings>`_ names and string data will be included in the alert for your convenience.

.. note:: Because the folders for each remote source will be overwritten during rule cloning, we recommend keeping your own YARA rules in ``rules/private`` or similar.

.. _external-variables:

External Variables
------------------
In order to support the rule repositories listed above, BinaryAlert provides the following `external variables <http://yara.readthedocs.io/en/latest/writingrules.html#external-variables>`_ to YARA:

* ``extension`` - File extension (".docx", ".exe", ".pdf", etc)
* ``filename`` - File basename ("file.exe")
* ``filepath`` - Full file path ("/path/to/file.exe")
* ``filetype`` - Uppercase ``extension`` without leading period ("DOCX", "EXE", "PDF"), etc

You can use these variables in your own rules to match or exclude certain file paths. (Note that the variables will default to empty strings if they are not available.) For example, this is a YARA rule which matches only files containing the string "evil" in the ``/home/`` directory:

.. code-block:: none

  rule evil_at_home
  {
      strings:
          $evil = "evil" nocase wide ascii

      condition:
          $evil and filepath matches /\/home\/*/
  }

.. warning:: YARA analysis of archives `does not yet support external variables <https://github.com/BayshoreNetworks/yextend/issues/17>`_.

.. _supported_yara_modules:

Supported Modules
-----------------
BinaryAlert supports all of the default `YARA modules <http://yara.readthedocs.io/en/latest/modules.html>`_, including ELF, Math, Hash, and PE. Support for other modules is not planned at this time, but please `let us know <https://github.com/airbnb/binaryalert/issues>`_ if you need a special module.


Disabling Rules
---------------
There may be times you want to disable certain YARA rules, but not delete them (e.g. rules with high false-positive rates). Since only ``.yar`` and ``.yara`` files in the ``rules/`` directory tree are bundled in a BinaryAlert deploy, you can simply rename ``rules.yar`` to any other extension, e.g. ``rules.yar.DISABLED``, to skip it during rules compilation.

If you want to disable an individual rule (not the entire file), you can either comment it out or prefix the rule with the ``private`` modifier to elide it from reported YARA match results.


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

This compiled rules file is what gets bundled with the BinaryAlert analyzers, and you can use it with YARA just like any other rules file:

.. code-block:: bash

  $ yara compiled_yara_rules.bin file_to_test
