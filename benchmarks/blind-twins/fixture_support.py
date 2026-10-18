"""Self-authored unit denominator; never runs a canonical oracle."""
from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
from unittest.mock import patch

import protocol
import run


@contextmanager
def synthetic_denominator():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory).resolve()
        canonical = json.dumps({'kind': 'unit-fixture-only', 'oracle_executed': False}) + '\n'
        (root / 'canonical-oracle.json').write_text(canonical)
        _, labels = protocol.generate()
        frozen = {'schema': protocol.SCHEMA, 'canonical_sha256': protocol.digest(canonical),
                  'manifest_sha256': protocol.digest(labels),
                  'positive_denominator': len(labels)//2,
                  'canonical_rebuildable_denominator': 0,
                  'eligible_pairs': [],
                  'excluded_from_canonical_denominator': sorted({x['pair_id'] for x in labels})}
        (root / 'denominator.json').write_text(json.dumps(frozen))
        with patch.object(protocol, 'ARTIFACTS', root), patch.object(run, 'ARTIFACTS', root):
            yield root
