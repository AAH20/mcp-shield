import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from mcpshield.core import MCPShield, GENESIS_HASH


class TestMCPShield(unittest.TestCase):
    def setUp(self):
        self.shield = MCPShield(target_server_name='postgres-mcp')

    def test_benign_tool_call_and_cryptographic_ledger(self):
        # 1. Normal benign SQL query execution
        allowed, receipt = self.shield.guard_tool_call(
            'query_database',
            {'query': 'SELECT id, username, email FROM users WHERE active = true LIMIT 50;'}
        )
        self.assertTrue(allowed)
        self.assertEqual(receipt.status, 'AUTHORIZED')
        self.assertEqual(receipt.index, 0)
        self.assertNotEqual(receipt.signature_hash, GENESIS_HASH)

        # 2. Continuous chain verification
        is_valid, err = self.shield.registry.verify_chain_integrity()
        self.assertTrue(is_valid, f'Cryptographic chain verification failed: {err}')

    def test_destructive_sql_quarantine(self):
        # Malicious drop table injection
        allowed, receipt = self.shield.guard_tool_call(
            'query_database',
            {'query': 'DROP TABLE users CASCADE;'}
        )
        self.assertFalse(allowed)
        self.assertIn('QUARANTINED', receipt.status)
        self.assertGreaterEqual(receipt.anomaly_score, 99.0)

    def test_path_traversal_quarantine(self):
        # Malicious file system traversal
        allowed, receipt = self.shield.guard_tool_call(
            'read_file',
            {'path': '/etc/shadow'}
        )
        self.assertFalse(allowed)
        self.assertIn('QUARANTINED', receipt.status)

    def test_kill_switch_fail_safe(self):
        self.shield.kill_switch_active = True
        allowed, receipt = self.shield.guard_tool_call(
            'benign_tool',
            {'param': 'value'}
        )
        self.assertFalse(allowed)
        self.assertEqual(receipt.status, 'HALTED_BY_EMERGENCY_KILL_SWITCH')


if __name__ == '__main__':
    unittest.main()
