"""Runner-process accounting only; never measures model servers or child processes."""
import math
import os
import sys

try:
    import resource
except ImportError:
    resource = None

SCHEMA = 'runner-resource-v1'
EXCLUSIONS = ['model-server-process', 'child-processes', 'gpu', 'electricity', 'usd', 'human-review']


def _usage():
    if resource is None:
        raise OSError('Python resource API unavailable')
    return resource.getrusage(resource.RUSAGE_SELF)


def _number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


class RunnerResources:
    """CPU interval deltas plus explicitly non-resettable lifetime RSS observations."""
    def __init__(self, implementation, platform_name=None, read_usage=None):
        self.implementation = dict(implementation)
        self.platform = sys.platform if platform_name is None else platform_name
        self.read_usage = _usage if read_usage is None else read_usage
        self.start, self.start_error = self._read()

    def _read(self):
        try:
            value = self.read_usage()
            return {'user':value.ru_utime, 'system':value.ru_stime, 'rss':value.ru_maxrss}, None
        except (OSError, AttributeError, ValueError) as exc:
            return None, type(exc).__name__

    def finish(self):
        end, end_error = self._read()
        cpu = {'status':'unavailable', 'user_seconds':None, 'system_seconds':None,
               'total_seconds':None, 'reason':self.start_error or end_error}
        rss = {'status':'unavailable', 'start_bytes':None, 'end_bytes':None,
               'native_unit':None, 'reason':'resource API unavailable'}
        if self.start is not None and end is not None:
            valid_counters=all(_number(self.start[key]) and _number(end[key]) for key in ['user','system'])
            deltas = {key:end[key] - self.start[key] for key in ['user','system']} if valid_counters else {}
            if valid_counters and all(_number(value) for value in deltas.values()):
                cpu.update(status='measured', user_seconds=deltas['user'], system_seconds=deltas['system'],
                           total_seconds=sum(deltas.values()), reason=None)
            else:
                cpu['reason'] = 'invalid or non-monotonic CPU counters'
            factor = 1 if self.platform == 'darwin' else 1024 if self.platform.startswith('linux') else None
            if factor is None:
                rss['reason'] = 'unsupported ru_maxrss unit on this platform'
            elif all(_number(item['rss']) for item in [self.start,end]) and end['rss'] >= self.start['rss']:
                rss.update(status='observed', start_bytes=self.start['rss'] * factor,
                           end_bytes=end['rss'] * factor, native_unit='bytes' if factor == 1 else 'KiB', reason=None)
            else:
                rss['reason'] = 'invalid or non-monotonic lifetime RSS counters'
        return {'schema':SCHEMA, 'implementation':self.implementation,
                'scope':'runner-process-only', 'pid':os.getpid(), 'platform':self.platform,
                'api':'resource.getrusage(RUSAGE_SELF)',
                'interval':'after artifact initialization through observation before final serialization',
                'cpu':cpu, 'rss_lifetime_observation':rss,
                'rss_scope':'runner-process-lifetime-high-water-mark', 'excluded':EXCLUSIONS}


def summarize(evidence, implementation):
    """Read recorded counters, never fabricate measurements for historical raw records."""
    summary = {'cpu_seconds':None, 'peak_memory_bytes':None,
               'resource_measurement':{'status':'not-measured', 'scope':'runner-process-only',
                                       'rss_scope':'runner-process-lifetime-high-water-mark',
                                       'rss_lifetime_observation':None, 'excluded':EXCLUSIONS}}
    if evidence is None:
        return summary
    if (not isinstance(evidence,dict) or evidence.get('schema') != SCHEMA or
            evidence.get('scope') != 'runner-process-only' or evidence.get('excluded') != EXCLUSIONS or
            evidence.get('api') != 'resource.getrusage(RUSAGE_SELF)' or
            evidence.get('rss_scope') != 'runner-process-lifetime-high-water-mark' or
            evidence.get('implementation') != implementation or not isinstance(implementation,dict) or
            not all(isinstance(implementation.get(key),str) and len(implementation[key]) == 64 and
                    all(character in '0123456789abcdef' for character in implementation[key])
                    for key in ['runner_sha256','protocol_sha256','measurement_sha256'])):
        raise ValueError('Resource evidence schema or recorded implementation binding mismatch')
    cpu=evidence.get('cpu',{})
    rss=evidence.get('rss_lifetime_observation',{})
    if cpu.get('status') == 'measured':
        if (not all(_number(cpu.get(key)) for key in ['user_seconds','system_seconds','total_seconds']) or
                not math.isclose(cpu['user_seconds'] + cpu['system_seconds'],cpu['total_seconds'],rel_tol=1e-9,abs_tol=1e-12)):
            raise ValueError('Invalid resource CPU measurement')
        summary['cpu_seconds'] = cpu['total_seconds']
    elif cpu.get('status') != 'unavailable' or not cpu.get('reason') or any(cpu.get(key) is not None for key in ['user_seconds','system_seconds','total_seconds']):
        raise ValueError('Invalid unavailable CPU measurement')
    if rss.get('status') == 'observed':
        expected_unit='bytes' if evidence.get('platform') == 'darwin' else 'KiB' if isinstance(evidence.get('platform'),str) and evidence['platform'].startswith('linux') else None
        if (not all(_number(rss.get(key)) for key in ['start_bytes','end_bytes']) or
                rss['end_bytes'] < rss['start_bytes'] or expected_unit is None or rss.get('native_unit') != expected_unit):
            raise ValueError('Invalid lifetime RSS observation')
    elif rss.get('status') != 'unavailable' or not rss.get('reason') or any(rss.get(key) is not None for key in ['start_bytes','end_bytes']):
        raise ValueError('Invalid unavailable RSS observation')
    summary['resource_measurement'].update(status='measured' if cpu['status'] == 'measured' else 'unavailable',
                                           cpu=cpu, rss_lifetime_observation=rss,
                                           implementation_binding='matches recorded raw implementation; not a signature or trusted provenance',
                                           platform=evidence.get('platform'),api=evidence.get('api'))
    return summary
