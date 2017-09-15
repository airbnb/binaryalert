Deploying
=========
After you've `setup your environment <getting-started.html>`_, deploying BinaryAlert is as easy as:

.. code-block:: bash

  $ ./manage.py deploy

A ``deploy`` is equivalent to the following 4 operations executed in sequence:

.. code-block:: bash

  $ ./manage.py unit_test    # Unit tests ensure YARA rules compile correctly
  $ ./manage.py build        # Build the Lambda ".zip" deployment packages
  $ ./manage.py apply        # Runs "terraform apply" to update the infrastructure
  $ ./manage.py analyze_all  # Starts a batch analysis of the entire S3 bucket

.. warning:: To ensure new YARA rules are applied ASAP, *every* ``deploy`` starts a batch analysis. If this is undesired behavior, you can execute any of the aforementioned commands individually (e.g. only ``apply`` the changes).


Terraform State
---------------
By default, Terraform will save the state of the infrastructure locally in ``terraform/terraform.tfstate``. If you are deploying BinaryAlert in an enterprise environment, we recommend configuring `Terraform remote state <https://www.terraform.io/docs/state/remote.html>`_. For example, you can store the Terraform state in a versioned `S3 bucket <https://www.terraform.io/docs/backends/types/s3.html>`_.


Terraform Commands
------------------
We recommend using the ``manage.py`` wrapper script for most BinaryAlert management because it provides additional validation. However, you can run ``terraform`` commands directly from the ``terraform/`` directory. Examples:

.. code-block:: bash

  $ cd terraform/
  $ terraform plan  # Show pending changes
  $ terraform show  # Print the current state of the infrastructure


Terraform Destroy
.................
To teardown all of the BinaryAlert infrastructure:

.. code-block:: bash

  $ cd terraform/
  $ terraform destroy

.. note:: By default, S3 objects will not be deleted by ``terraform destroy``. To do so, you have to enable the ``force_destroy`` option in the ``terraform/terraform.tfvars`` configuration file.
