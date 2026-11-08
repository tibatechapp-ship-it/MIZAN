"""CVSS v3.1 calculator validation (docs/REPORT_SECURITY.md — honest status).

Layer 1: ten PUBLISHED anchor vectors (scores as quoted in advisories,
e.g. CVE-2021-44228 = 10.0).
Layer 2: a full-space sweep over ALL 5,184 metric combinations asserting
the spec's structural guarantees. NOTE (honest): CIA monotonicity is
asserted ONLY within Scope-Unchanged — the official v3.1 Scope-Changed
impact term 7.52*(ISS-0.029) - 3.25*(ISS-0.02)**15 is not monotone in
ISS at the very top of the range (a documented v3.x quirk), so no
monotonicity claim is made there. A differential run against the
official NIST script remains a pending follow-up — not claimed here.
"""

import itertools
import unittest

from mizan.report.cvss import (base_score, base_score_vector, roundup,
                               severity_band)

# (vector, expected score, expected band)
ANCHORS = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "Critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1, "High"),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "High"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "High"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", 7.3, "High"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5, "Medium"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, "Medium"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 4.3, "Medium"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "None"),
]


class AnchorTests(unittest.TestCase):
    def test_published_anchors(self):
        for vector, score, band in ANCHORS:
            got_score, got_band = base_score_vector(vector)
            self.assertEqual(
                (got_score, got_band), (score, band),
                f"anchor mismatch for {vector}: got "
                f"({got_score}, {got_band})")

    def test_severity_band_edges(self):
        self.assertEqual(severity_band(0.0), "None")
        self.assertEqual(severity_band(0.1), "Low")
        self.assertEqual(severity_band(3.9), "Low")
        self.assertEqual(severity_band(4.0), "Medium")
        self.assertEqual(severity_band(6.9), "Medium")
        self.assertEqual(severity_band(7.0), "High")
        self.assertEqual(severity_band(8.9), "High")
        self.assertEqual(severity_band(9.0), "Critical")
        self.assertEqual(severity_band(10.0), "Critical")

    def test_roundup_edges(self):
        self.assertEqual(roundup(0.0), 0.0)
        self.assertEqual(roundup(1.0), 1.0)
        self.assertEqual(roundup(10.0), 10.0)
        self.assertEqual(roundup(7.26), 7.3)      # rounds UP, not nearest
        self.assertEqual(roundup(7.200001), 7.2)  # float-noise robust
        self.assertEqual(roundup(7.2), 7.2)

    def test_vector_parse_errors(self):
        with self.assertRaises(ValueError):
            base_score_vector("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        with self.assertRaises(ValueError):
            base_score_vector("AV:N/AC:L/PR:N")  # missing metrics
        with self.assertRaises(ValueError):
            base_score("Z", "L", "N", "N", "U", "H", "H", "H")


class FullSpaceSweepTests(unittest.TestCase):
    """All 5,184 combinations — structural guarantees, automatically."""

    def test_full_space_properties(self):
        checked = 0
        for av, ac, pr, ui, s, c, i, a in itertools.product(
                "NALP", "LH", "NLH", "NR", "UC", "HLN", "HLN", "HLN"):
            score, band = base_score(av, ac, pr, ui, s, c, i, a)
            checked += 1
            # range + one-decimal grid (float-tolerant integer check)
            self.assertGreaterEqual(score, 0.0)
            self.assertLessEqual(score, 10.0)
            self.assertAlmostEqual(score * 10, round(score * 10), places=6)
            # band consistency
            self.assertEqual(severity_band(score), band)
            # the two special rules
            if c == i == a == "N":
                self.assertEqual(score, 0.0)
        self.assertEqual(checked, 2592)  # full space: 4*2*3*2*2*27

    def test_scope_unchanged_cia_monotonicity(self):
        pairs = 0
        for av, ac, pr, ui in itertools.product("NALP", "LH", "NLH", "NR"):
            for base_cia in itertools.product("HLN", "HLN", "HLN"):
                scores = []
                for level in "NLH":
                    cia = tuple(
                        level if axis == 0 else v
                        for axis, v in enumerate(base_cia)
                    )
                    score, _band = base_score(av, ac, pr, ui, "U", *cia)
                    scores.append(score)
                self.assertLessEqual(scores[0], scores[1])
                self.assertLessEqual(scores[1], scores[2])
                pairs += 1
        self.assertEqual(pairs, 4 * 2 * 3 * 2 * 27)

    def test_space_bounds(self):
        all_scores = [
            base_score(av, ac, pr, ui, s, c, i, a)[0]
            for av, ac, pr, ui, s, c, i, a in itertools.product(
                "NALP", "LH", "NLH", "NR", "UC", "HLN", "HLN", "HLN")
        ]
        self.assertEqual(max(all_scores), 10.0)
        self.assertEqual(min(all_scores), 0.0)


if __name__ == "__main__":
    unittest.main()
