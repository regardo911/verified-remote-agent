import unittest
class DeliberateFailure(unittest.TestCase):
    def test_fixture_fails(self):
        self.fail("deliberate negative fixture")
