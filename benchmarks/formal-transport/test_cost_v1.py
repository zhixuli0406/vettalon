"""Pure synthetic cost-attachment contracts; no provider or filesystem dispatch."""
import copy
from decimal import localcontext
from fractions import Fraction
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


RAW_SHA = hashlib.sha256(b'unit raw bytes only').hexdigest()
ATTACHMENT_SHA = hashlib.sha256(b'unit attachment bytes only').hexdigest()
MODEL = {'name': 'unit-model', 'digest': 'a' * 64, 'family': 'unit-family'}


def attempt(key='a', input_tokens=1000, output_tokens=200):
    return {'attempt_key': key, 'model': copy.deepcopy(MODEL),
            'attempt_artifact_sha256': hashlib.sha256(key.encode()).hexdigest(),
            'usage': {'input_tokens': input_tokens, 'output_tokens': output_tokens}}


def price():
    return {'price_id': 'unit-price', 'model': copy.deepcopy(MODEL),
            'price_version': 'unit-v1', 'source_ref': 'unit://price-v1',
            'provided_by': 'unit operator', 'input_usd_per_million': '2',
            'output_usd_per_million': '8'}


def entry(item):
    return {'attempt_key': item['attempt_key'], 'model': copy.deepcopy(item['model']),
            'attempt_artifact_sha256': item['attempt_artifact_sha256'],
            'price_id': 'unit-price', 'price_version': 'unit-v1',
            'human_minutes': '2.5', 'human_source_ref': 'unit://effort-a',
            'human_version': 'unit-v1', 'human_provided_by': 'unit operator'}


def attachment(items):
    return {'schema': 'cost-attachment-v1', 'raw_sha256': RAW_SHA,
            'prices': [price()], 'entries': [entry(item) for item in items]}


class CostTests(unittest.TestCase):
    def setUp(self):
        for target in ('subprocess.Popen', 'http.client.HTTPConnection', 'urllib.request.urlopen'):
            guard = patch(target, side_effect=AssertionError('Pure costs cannot dispatch'))
            guard.start(); self.addCleanup(guard.stop)
        # The implementation is deliberately absent in the tests-first snapshot.
        path = Path(__file__).with_name('cost_v1.py')
        spec = importlib.util.spec_from_file_location('unit_cost_v1', path)
        self.cost = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.cost)

    def summarize(self, items, document, **kwargs):
        return self.cost.summarize_cost(RAW_SHA, items, document,
                                       attachment_sha256=ATTACHMENT_SHA, **kwargs)

    def test_missing_attachment_and_empty_inventory_never_infer_zero_billing(self):
        for items in ([attempt()], []):
            with self.subTest(count=len(items)):
                result = self.cost.summarize_cost(RAW_SHA, items)
                self.assertIsNone(result['usd']); self.assertIsNone(result['human_minutes'])
                self.assertIsNone(result['attachment_sha256'])
                self.assertEqual(result['unknown_usd_attempts'], len(items))
                self.assertEqual(result['unknown_human_minutes_attempts'], len(items))
                self.assertFalse(result['billing_verified'])

    def test_observed_usage_and_reported_effort_are_exact_decimal_estimates(self):
        items = [attempt('a'), attempt('b', 2000, 100)]
        document = attachment(items); before = copy.deepcopy((items, document))
        result = self.summarize(items, document)
        self.assertEqual(result['usd'], '0.0084')
        self.assertEqual(result['known_usd_subtotal'], '0.0084')
        self.assertEqual(result['human_minutes'], '5')
        self.assertEqual(result['known_human_minutes_subtotal'], '5')
        self.assertEqual(result['unknown_usd_attempts'], 0)
        self.assertEqual(result['unknown_human_minutes_attempts'], 0)
        self.assertEqual(result['attachment_sha256'], ATTACHMENT_SHA)
        self.assertEqual(result['raw_sha256'], RAW_SHA)
        self.assertFalse(result['billing_verified'])
        self.assertIn('operator', result['human_effort_scope'].casefold())
        self.assertIn('attempt', result['human_effort_scope'])
        self.assertIn('declared', result['model_identity_scope'])
        self.assertEqual(result['entries'][0]['source_ref'], 'unit://price-v1')
        self.assertEqual(result['entries'][0]['price_version'], 'unit-v1')
        self.assertEqual(result['entries'][0]['provided_by'], 'unit operator')
        self.assertEqual((items, document), before)

    def test_partial_usage_or_unattached_attempt_keeps_totals_unknown(self):
        items = [attempt('a'), attempt('b', 50, None), attempt('c')]
        document = attachment(items[:2]); document['entries'][1].update(
            human_minutes=None, human_source_ref=None, human_version=None, human_provided_by=None)
        result = self.summarize(items, document)
        self.assertIsNone(result['usd']); self.assertIsNone(result['human_minutes'])
        self.assertEqual(result['known_usd_subtotal'], '0.0036')
        self.assertEqual(result['known_human_minutes_subtotal'], '2.5')
        self.assertEqual(result['unknown_usd_attempts'], 2)
        self.assertEqual(result['unknown_human_minutes_attempts'], 2)
        self.assertEqual(len(result['entries']), 3)

    def test_zero_observed_usage_and_explicit_zero_effort_can_be_zero(self):
        items = [attempt('a', 0, 0)]; document = attachment(items)
        document['entries'][0]['human_minutes'] = '0'
        result = self.summarize(items, document)
        self.assertEqual(result['usd'], '0'); self.assertEqual(result['human_minutes'], '0')
        self.assertFalse(result['billing_verified'])

    def test_max_precision_prices_and_large_token_counts_remain_exact(self):
        for count in (1000001, 10 ** 80 + 123):
            items = [attempt('a', count, 7)]; document = attachment(items)
            document['prices'][0].update(input_usd_per_million='123456789012.123456789012',
                                         output_usd_per_million='987654321098.987654321098')
            expected = (count * Fraction('123456789012.123456789012')
                        + 7 * Fraction('987654321098.987654321098')) / 1000000
            with self.subTest(count=count), localcontext() as context:
                context.prec = 4
                result = self.summarize(items, document)
                self.assertEqual(Fraction(result['usd']), expected)
                self.assertEqual(result['usd'], result['known_usd_subtotal'])
                self.assertEqual(context.prec, 4)
                self.assertNotIn('E', result['usd'])

    def test_wrong_raw_or_malformed_attachment_digest_is_rejected(self):
        items = [attempt()]; bad = attachment(items); bad['raw_sha256'] = 'f' * 64
        with self.assertRaises(ValueError): self.summarize(items, bad)
        for value in (None, True, 'wrong', 'A' * 64):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.cost.summarize_cost(RAW_SHA, items, attachment(items), attachment_sha256=value)

    def test_unknown_duplicate_ids_and_wrong_price_version_are_rejected(self):
        items = [attempt()]; original = attachment(items)
        bads = []
        for key, value in [('attempt_key', 'unknown'), ('price_id', 'unknown'), ('price_version', 'wrong')]:
            bad = copy.deepcopy(original); bad['entries'][0][key] = value; bads.append(bad)
        bad = copy.deepcopy(original); bad['entries'].append(copy.deepcopy(bad['entries'][0])); bads.append(bad)
        bad = copy.deepcopy(original); bad['prices'].append(copy.deepcopy(bad['prices'][0])); bads.append(bad)
        for bad in bads:
            with self.subTest(document=bad), self.assertRaises(ValueError): self.summarize(items, bad)
        with self.assertRaises(ValueError): self.summarize(items + copy.deepcopy(items), original)

    def test_name_digest_and_family_must_match_inventory_and_price(self):
        items = [attempt()]
        for location in ('entries', 'prices'):
            for key, value in [('name', 'other'), ('digest', 'b' * 64), ('family', 'other')]:
                bad = attachment(items); bad[location][0]['model'][key] = value
                with self.subTest(location=location, key=key), self.assertRaises(ValueError):
                    self.summarize(items, bad)

    def test_artifact_identity_cannot_be_substituted(self):
        items = [attempt()]; bad = attachment(items)
        bad['entries'][0]['attempt_artifact_sha256'] = 'e' * 64
        with self.assertRaises(ValueError): self.summarize(items, bad)

    def test_invalid_observed_token_types_never_become_usd(self):
        for key in ('input_tokens', 'output_tokens'):
            for value in (True, -1, 1.0, '1', float('nan'), float('inf')):
                items = [attempt()]; items[0]['usage'][key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    self.summarize(items, attachment(items))

    def test_invalid_money_or_minutes_and_metadata_are_rejected(self):
        items = [attempt()]
        for key in ('input_usd_per_million', 'output_usd_per_million', 'human_minutes'):
            for value in (True, -1, 1, 1.0, float('nan'), float('inf'), '-1', 'NaN', 'Infinity',
                          '1e2', ' 1', '1.0000000000001', '1000000000000'):
                bad = attachment(items); section = 'entries' if key == 'human_minutes' else 'prices'
                bad[section][0][key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    self.summarize(items, bad)
        for section, key in [('prices', 'source_ref'), ('prices', 'provided_by'), ('prices', 'price_version'),
                             ('entries', 'human_source_ref'), ('entries', 'human_version'),
                             ('entries', 'human_provided_by')]:
            bad = attachment(items); bad[section][0][key] = ''
            with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                self.summarize(items, bad)

    def test_null_pairs_and_strict_schema_do_not_hide_partial_annotations(self):
        items = [attempt()]; original = attachment(items)
        bads = []
        bad = copy.deepcopy(original); bad['entries'][0]['price_id'] = None; bads.append(bad)
        bad = copy.deepcopy(original); bad['entries'][0]['human_minutes'] = None; bads.append(bad)
        bad = copy.deepcopy(original); bad['schema'] = 'other'; bads.append(bad)
        bad = copy.deepcopy(original); bad['usd'] = 999; bads.append(bad)
        bad = copy.deepcopy(original); del bad['entries'][0]['attempt_artifact_sha256']; bads.append(bad)
        for bad in bads:
            with self.subTest(document=bad), self.assertRaises(ValueError): self.summarize(items, bad)

    def test_no_fs_network_or_process_and_no_reservation_substitution(self):
        items = [attempt('a', None, 7)]; document = attachment(items)
        with patch('builtins.open', side_effect=AssertionError('No I/O in pure cost reader')), \
             patch.object(Path, 'open', side_effect=AssertionError('No path I/O')):
            result = self.summarize(items, document)
        self.assertIsNone(result['usd']); self.assertEqual(result['known_usd_subtotal'], '0')
        bad_inventory = copy.deepcopy(items); bad_inventory[0]['reserved_output_tokens'] = 1024
        with self.assertRaises(ValueError): self.summarize(bad_inventory, document)
        bad_inventory = copy.deepcopy(items); bad_inventory[0]['wall_seconds'] = 2.5
        with self.assertRaises(ValueError): self.summarize(bad_inventory, document)


if __name__ == '__main__': unittest.main()
