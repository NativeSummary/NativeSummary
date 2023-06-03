import unittest

class TestSymbolParser(unittest.TestCase):

    def test_upper(self):
        from native_summary.pre_analysis.symbol_parser import parse_params_from_sig
        plist, has_obj = parse_params_from_sig('(Lio/realm/log/RealmLogger;)V')
        self.assertEqual(len(plist), 1)

if __name__ == '__main__':
    unittest.main()
