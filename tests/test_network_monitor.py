import unittest
import sys
import os

# Add the parent directory to the path so we can import the module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from network_monitor import PIIDetector, ContentProcessor

class TestPIIDetector(unittest.TestCase):
    def setUp(self):
        self.detector = PIIDetector()
    
    def test_email_detection(self):
        """Test if the detector can find email addresses in content"""
        content = "Please contact me at user@example.com for more information."
        results = self.detector.detect_pii(content)
        self.assertTrue(any("email" in r.lower() for r in results))
        
    def test_phone_detection(self):
        """Test if the detector can find phone numbers in content"""
        content = "Call me at (123) 456-7890 or 987-654-3210"
        results = self.detector.detect_pii(content)
        self.assertTrue(any("phone" in r.lower() for r in results))
        
class TestContentProcessor(unittest.TestCase):
    def setUp(self):
        self.processor = ContentProcessor()
        
    def test_content_type_detection(self):
        """Test content type detection functionality"""
        json_content = '{"name": "Test", "value": 123}'
        content_type = self.processor.detect_content_type(json_content)
        self.assertEqual(content_type, "application/json")

if __name__ == '__main__':
    unittest.main()