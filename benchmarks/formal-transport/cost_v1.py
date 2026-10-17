"""Pure operator-declared cost estimates for already validated attempt inventories."""
from decimal import Decimal
import re


SCALE = 10 ** 12
ATTEMPT_KEYS = {'attempt_key', 'model', 'attempt_artifact_sha256', 'usage'}
PRICE_KEYS = {'price_id', 'model', 'price_version', 'source_ref', 'provided_by',
              'input_usd_per_million', 'output_usd_per_million'}
ENTRY_KEYS = {'attempt_key', 'model', 'attempt_artifact_sha256', 'price_id', 'price_version',
              'human_minutes', 'human_source_ref', 'human_version', 'human_provided_by'}
HUMAN_KEYS = ('human_source_ref', 'human_version', 'human_provided_by')


def _require(value, message):
    if not value:
        raise ValueError(message)


def _object(value, keys):
    _require(type(value) is dict and set(value) == keys, 'Unexpected cost record fields')


def _text(value, maximum):
    _require(type(value) is str and bool(value.strip()) and len(value) <= maximum,
             'Invalid declared cost metadata')


def _hash(value):
    _require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None,
             'Invalid cost binding SHA256')


def _model(value):
    _object(value, {'name', 'digest', 'family'})
    _text(value['name'], 256); _text(value['family'], 128); _hash(value['digest'])


def _scaled(value):
    _require(type(value) is str and len(value) <= 25
             and re.fullmatch(r'(?:0|[1-9][0-9]{0,11})(?:\.[0-9]{1,12})?', value) is not None,
             'Cost values require bounded nonnegative decimal strings')
    whole, _, fraction = value.partition('.')
    return int(whole) * SCALE + int(fraction.ljust(12, '0'))


def _decimal(units, places):
    # Constructing a Decimal tuple and formatting do not apply context precision.
    # All arithmetic uses exact scaled integers, including million-token pricing.
    digits = Decimal(units).as_tuple().digits
    text = format(Decimal((0, digits, -places)), 'f')
    return text.rstrip('0').rstrip('.') if '.' in text else text


def _inventory(attempts):
    _require(type(attempts) is list, 'Attempt inventory must be a list')
    result = {}
    for item in attempts:
        _object(item, ATTEMPT_KEYS)
        _text(item['attempt_key'], 2048); _model(item['model'])
        _hash(item['attempt_artifact_sha256'])
        _object(item['usage'], {'input_tokens', 'output_tokens'})
        for count in item['usage'].values():
            _require(count is None or (type(count) is int and count >= 0),
                     'Invalid observed token count')
        key = item['attempt_key']
        _require(key not in result, 'Duplicate inventory attempt')
        result[key] = item
    return result


def _prices(rows):
    _require(type(rows) is list, 'Prices must be a list')
    result = {}
    for row in rows:
        _object(row, PRICE_KEYS); _model(row['model'])
        for field, maximum in [('price_id', 128), ('price_version', 128),
                               ('source_ref', 2048), ('provided_by', 256)]:
            _text(row[field], maximum)
        rates = (_scaled(row['input_usd_per_million']), _scaled(row['output_usd_per_million']))
        _require(row['price_id'] not in result, 'Duplicate price ID')
        result[row['price_id']] = (row, rates)
    return result


def _annotations(rows, inventory, prices):
    _require(type(rows) is list, 'Cost entries must be a list')
    result = {}
    for row in rows:
        _object(row, ENTRY_KEYS); _text(row['attempt_key'], 2048)
        _model(row['model']); _hash(row['attempt_artifact_sha256'])
        key = row['attempt_key']
        _require(key in inventory and key not in result, 'Unknown or duplicate cost attempt')
        item = inventory[key]
        _require(row['model'] == item['model']
                 and row['attempt_artifact_sha256'] == item['attempt_artifact_sha256'],
                 'Attempt model or artifact binding mismatch')
        selected = None
        if row['price_id'] is None:
            _require(row['price_version'] is None, 'Unknown price must have no version')
        else:
            _text(row['price_id'], 128); _text(row['price_version'], 128)
            _require(row['price_id'] in prices, 'Unknown price ID')
            selected = prices[row['price_id']]
            _require(selected[0]['model'] == item['model']
                     and row['price_version'] == selected[0]['price_version'],
                     'Price model or version binding mismatch')
        minutes = None
        if row['human_minutes'] is None:
            _require(all(row[field] is None for field in HUMAN_KEYS),
                     'Unknown effort must have no partial provenance')
        else:
            minutes = _scaled(row['human_minutes'])
            for field, maximum in zip(HUMAN_KEYS, (2048, 128, 256)):
                _text(row[field], maximum)
        result[key] = (row, selected, minutes)
    return result


def summarize_cost(raw_sha256, attempts, attachment=None, *, attachment_sha256=None):
    """Estimate recorded-attempt costs; caller owns bounded raw/artifact validation."""
    _hash(raw_sha256)
    inventory = _inventory(attempts)
    annotations = {}
    if attachment is None:
        _require(attachment_sha256 is None, 'Absent attachment cannot have a source hash')
    else:
        _hash(attachment_sha256)
        _object(attachment, {'schema', 'raw_sha256', 'prices', 'entries'})
        _hash(attachment['raw_sha256'])
        _require(attachment['schema'] == 'cost-attachment-v1'
                 and attachment['raw_sha256'] == raw_sha256, 'Wrong attachment schema or raw binding')
        annotations = _annotations(attachment['entries'], inventory, _prices(attachment['prices']))
    rows = []; known_usd = 0; known_minutes = 0; unknown_usd = 0; unknown_minutes = 0
    for key, item in inventory.items():
        annotation, selected, minutes = annotations.get(key, (None, None, None))
        usd = None
        if selected is not None and all(value is not None for value in item['usage'].values()):
            input_rate, output_rate = selected[1]
            usd = item['usage']['input_tokens'] * input_rate + item['usage']['output_tokens'] * output_rate
            known_usd += usd
        else:
            unknown_usd += 1
        if minutes is None:
            unknown_minutes += 1
        else:
            known_minutes += minutes
        price = selected[0] if selected is not None else None
        rows.append({'attempt_key': key, 'model': dict(item['model']),
            'attempt_artifact_sha256': item['attempt_artifact_sha256'],
            'usd': _decimal(usd, 18) if usd is not None else None,
            'human_minutes': _decimal(minutes, 12) if minutes is not None else None,
            'usd_unknown_reason': None if usd is not None else 'missing-price-or-complete-observed-usage',
            'human_minutes_unknown_reason': None if minutes is not None else 'missing-allocated-effort',
            'price_id': price['price_id'] if price else None,
            'price_version': price['price_version'] if price else None,
            'source_ref': price['source_ref'] if price else None,
            'provided_by': price['provided_by'] if price else None,
            **{field: annotation[field] if annotation else None for field in HUMAN_KEYS}})
    usd_subtotal = _decimal(known_usd, 18); minutes_subtotal = _decimal(known_minutes, 12)
    return {'raw_sha256': raw_sha256, 'attachment_sha256': attachment_sha256,
        'usd': usd_subtotal if inventory and not unknown_usd else None,
        'known_usd_subtotal': usd_subtotal, 'unknown_usd_attempts': unknown_usd,
        'human_minutes': minutes_subtotal if inventory and not unknown_minutes else None,
        'known_human_minutes_subtotal': minutes_subtotal,
        'unknown_human_minutes_attempts': unknown_minutes,
        'billing_verified': False,
        'estimation_scope': 'Observed tokens priced using operator-declared versioned rates; not an invoice or verified billing.',
        'model_identity_scope': 'Validated raw declared-roster binding; serving model identity is not independently verified.',
        'human_effort_scope': 'Operator-declared reported effort allocated to recorded artifact-bound attempts only; excludes unattempted rows and whole-project effort.',
        'entries': rows}
