import unittest
from rag import build, retrieve, dry_run

class RagTests(unittest.TestCase):
    def test_no_family_or_id_leak_to_holdout(self):
        corpus,queries=build()
        self.assertFalse({x['id'] for x in corpus}&{x['id'] for x in queries})
        self.assertFalse({x['family'] for x in corpus}&{x['family'] for x in queries})
        self.assertTrue(all(set(q)=={'id','family','source','source_sha256'} for q in queries))
    def test_retrieval_known_corpus_only(self):
        corpus,queries=build()
        ids={x['id'] for x in corpus}
        self.assertTrue(all(x['id'] in ids for x in retrieve(queries[0]['source'],corpus,2)))
    def test_three_arms_capped_and_no_effectiveness_claim(self):
        result=dry_run()
        self.assertEqual(len(result['rows']),24)
        self.assertEqual({x['arm'] for x in result['rows']},{'baseline','random','retrieval'})
        self.assertTrue(all(x['payload_bytes']<=4096 for x in result['rows']))
        self.assertIsNone(result['model_effectiveness'])
        self.assertTrue(all(x['citation_integrity'] for x in result['rows']))
