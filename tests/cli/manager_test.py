"""Unit tests for cli/manager.py"""
import inspect
import subprocess
from unittest import mock

from cli import config as config_module
from cli import manager as manager_module
from cli.config import BinaryAlertConfig
from cli.exceptions import InvalidConfigError, TestFailureError
from cli.manager import Manager
from tests.cli._common import mock_input, FakeFilesystemBase


class ManagerTest(FakeFilesystemBase):
    """Tests for the Manager class."""

    @mock.patch('sys.stderr', mock.MagicMock())  # pyhcl complains about unused tokens to stderr.
    def setUp(self):
        super().setUp()
        self.manager = Manager()

    def test_commands(self):
        """Each command should be a function in the class."""
        for command in self.manager.commands:
            self.assertTrue(hasattr(self.manager, command))

    def test_help(self):
        """Help string should contain as many lines as there are commands."""
        self.assertEqual(len(self.manager.commands), len(self.manager.help.split('\n')))

    @mock.patch.object(subprocess, 'check_call')
    def test_apply(self, mock_subprocess: mock.MagicMock):
        """Validate order of Terraform operations."""
        self.manager.apply()
        mock_subprocess.assert_has_calls([
            mock.call(['terraform', 'init']),
            mock.call(['terraform', 'fmt']),
            mock.call(['terraform', 'apply', '-auto-approve=false'])
        ])

    @mock.patch.object(manager_module, 'lambda_build')
    def test_build(self, mock_build: mock.MagicMock):
        """Calls lambda_build function (tested elsewhere)."""
        self.manager.build()
        mock_build.assert_called_once()

    def test_cb_copy_all_not_enabled(self):
        """Raises InvalidConfigError if the downloader is not enabled."""
        self._write_config(enable_downloader=False)
        self.manager = Manager()  # Reload manager with the new config.
        with self.assertRaises(InvalidConfigError):
            self.manager.cb_copy_all()

    @mock.patch.object(manager_module.clone_rules, 'clone_remote_rules')
    def test_clone_rules(self, mock_clone: mock.MagicMock):
        """Calls clone_remote_rules (tested elsewhere)."""
        self.manager.clone_rules()
        mock_clone.assert_called_once()

    @mock.patch.object(manager_module.compile_rules, 'compile_rules')
    @mock.patch.object(manager_module, 'print')
    def test_compile_rules(self, mock_print: mock.MagicMock, mock_compile: mock.MagicMock):
        """Calls compile_rules (tested elsewhere)."""
        self.manager.compile_rules()
        mock_compile.assert_called_once()
        mock_print.assert_called_once()

    @mock.patch.object(BinaryAlertConfig, 'configure')
    @mock.patch.object(manager_module, 'print')
    def test_configure(self, mock_print: mock.MagicMock, mock_configure: mock.MagicMock):
        """Calls BinaryAlertConfig:configure() (tested elsewhere)."""
        self.manager.configure()
        mock_configure.assert_called_once()
        mock_print.assert_called_once()

    @mock.patch.object(Manager, 'unit_test')
    @mock.patch.object(Manager, 'build')
    @mock.patch.object(Manager, 'apply')
    def test_deploy(self, mock_apply: mock.MagicMock, mock_build: mock.MagicMock,
                    mock_test: mock.MagicMock):
        """Deploy docstring includes each executed command and runs each."""
        for command in ['unit_test', 'build', 'apply']:
            self.assertIn(command, inspect.getdoc(Manager.deploy))

        self.manager.deploy()
        mock_test.assert_called_once()
        mock_build.assert_called_once()
        mock_apply.assert_called_once()

    @mock.patch.object(config_module, 'input', side_effect=mock_input)
    @mock.patch.object(manager_module, 'print')
    @mock.patch.object(subprocess, 'call')
    @mock.patch.object(subprocess, 'check_call')
    def test_destroy(self, mock_check_call: mock.MagicMock, mock_call: mock.MagicMock,
                     mock_print: mock.MagicMock, mock_user_input: mock.MagicMock):
        """Destroy asks whether S3 objects should also be deleted."""
        self.manager.destroy()
        mock_user_input.assert_called_once()
        mock_print.assert_called_once()
        mock_check_call.assert_called_once()
        mock_call.assert_called_once()

    @mock.patch.object(manager_module.live_test, 'run', return_value=False)
    def test_live_test(self, mock_live_test: mock.MagicMock):
        """Live test wrapper raises TestFailureError if appropriate."""
        with self.assertRaises(TestFailureError):
            self.manager.live_test()
        mock_live_test.assert_called_once()
