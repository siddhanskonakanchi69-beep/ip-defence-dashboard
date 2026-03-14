import os
import sys
import unittest
import json
import sqlite3
import time
from datetime import datetime

# Set api key environment variable
os.environ['DASHBOARD_API_KEY'] = 'test-api-key'

# Add the dashboard directory to the python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, init_db, get_db_connection

class TestDashboardAPI(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        
        # Override the database path for tests
        global DATABASE
        self.test_db = 'test_database.db'
        import app as dashboard_app
        dashboard_app.DATABASE = self.test_db
        
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
            
        init_db()

    def tearDown(self):
        if os.path.exists(self.test_db):
            os.remove(self.test_db)

    def test_block_ip_requires_api_key(self):
        response = self.client.post('/api/block_ip', json={'ip': '1.2.3.4'})
        self.assertEqual(response.status_code, 401)
        self.assertIn(b"Invalid or missing API key", response.data)

    def test_block_ip_success(self):
        headers = {'X-API-Key': 'test-api-key'}
        response = self.client.post(
            '/api/block_ip', 
            json={'ip': '5.5.5.5', 'reason': 'test block', 'duration_minutes': 10},
            headers=headers
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertIn('Blocked 5.5.5.5', data['message'])

        # Verify in DB
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT ip_address, reason, duration_minutes FROM blocked_ips WHERE ip_address='5.5.5.5'")
        row = c.fetchone()
        conn.close()
        
        self.assertIsNotNone(row)
        self.assertEqual(row['ip_address'], '5.5.5.5')
        self.assertEqual(row['reason'], 'test block')
        self.assertEqual(row['duration_minutes'], 10)

    def test_unblock_ip_success(self):
        # First block it
        headers = {'X-API-Key': 'test-api-key'}
        self.client.post(
            '/api/block_ip', 
            json={'ip': '6.6.6.6'},
            headers=headers
        )
        
        # Now unblock it
        response = self.client.post(
            '/api/unblock_ip', 
            json={'ip': '6.6.6.6'},
            headers=headers
        )
        self.assertEqual(response.status_code, 200)
        
        # Verify removed from DB
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT ip_address FROM blocked_ips WHERE ip_address='6.6.6.6'")
        row = c.fetchone()
        conn.close()
        self.assertIsNone(row)

    def test_blocked_ips_list(self):
        headers = {'X-API-Key': 'test-api-key'}
        self.client.post('/api/block_ip', json={'ip': '7.7.7.7', 'duration_minutes': 1}, headers=headers)
        self.client.post('/api/block_ip', json={'ip': '8.8.8.8', 'duration_minutes': 2}, headers=headers)
        
        response = self.client.get('/api/blocked_ips', headers=headers)
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertEqual(len(data), 2)
        ips = [r['ip_address'] for r in data]
        self.assertIn('7.7.7.7', ips)
        self.assertIn('8.8.8.8', ips)

if __name__ == '__main__':
    unittest.main()
