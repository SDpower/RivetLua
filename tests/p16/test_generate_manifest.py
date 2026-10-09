"""固定 header 清單的 C literal 與註解邊界回歸。"""

import unittest

from generate_manifest import normalize, without_comments


class CTokenWhitespaceTests(unittest.TestCase):
    def test_normalize_preserves_literal_whitespace_and_escapes(self) -> None:
        source = r'''  #define  LUA_COPYRIGHT  "Lua  5.5\" //  text"   '\\'  x  '''
        self.assertEqual(
            normalize(source),
            r'''#define LUA_COPYRIGHT "Lua  5.5\" //  text" '\\' x''',
        )

    def test_comment_markers_inside_literals_are_not_removed(self) -> None:
        source = 'const char *value = "/* keep */ // keep"; /* drop\nmore */ int x; // drop\n'
        cleaned = without_comments(source)
        self.assertEqual(cleaned.count("\n"), source.count("\n"))
        self.assertIn('"/* keep */ // keep"', cleaned)
        self.assertIn("int x;", cleaned)
        self.assertNotIn("more", cleaned)
        self.assertNotIn("// drop", cleaned)


if __name__ == "__main__":
    unittest.main()
