"""Runner-local accounting contracts; no model, Docker, or network requests."""
import json
import math
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

import measurement
import protocol
import run


class MeasurementTests(unittest.TestCase):
    implementation = {'runner_sha256':'a'*64, 'protocol_sha256':'b'*64, 'measurement_sha256':'c'*64}

    def usage(self, user, system, rss):
        return types.SimpleNamespace(ru_utime=user, ru_stime=system, ru_maxrss=rss)

    def evidence(self, platform='darwin'):
        snapshots=iter([self.usage(2, 1, 100), self.usage(2.5, 1.25, 200)])
        meter=measurement.RunnerResources(self.implementation, platform_name=platform,
                                          read_usage=lambda: next(snapshots))
        return meter.finish()

    def test_cpu_delta_and_lifetime_rss_not_per_run_peak(self):
        evidence=self.evidence()
        self.assertEqual(evidence['cpu']['user_seconds'], .5)
        self.assertEqual(evidence['cpu']['system_seconds'], .25)
        self.assertEqual(evidence['cpu']['total_seconds'], .75)
        self.assertEqual(evidence['rss_lifetime_observation']['end_bytes'], 200)
        summary=measurement.summarize(evidence, self.implementation)
        self.assertEqual(summary['cpu_seconds'], .75)
        self.assertIsNone(summary['peak_memory_bytes'])
        self.assertEqual(summary['resource_measurement']['rss_scope'], 'runner-process-lifetime-high-water-mark')

    def test_linux_kib_conversion_and_unknown_units(self):
        self.assertEqual(self.evidence('linux')['rss_lifetime_observation']['end_bytes'], 204800)
        evidence=self.evidence('unrecognized')
        self.assertEqual(evidence['cpu']['status'], 'measured')
        self.assertEqual(evidence['rss_lifetime_observation']['status'], 'unavailable')
        self.assertIsNone(evidence['rss_lifetime_observation']['end_bytes'])

    def test_unavailable_api_is_unknown_not_zero(self):
        def unavailable(): raise OSError('controlled unavailable')
        evidence=measurement.RunnerResources(self.implementation, read_usage=unavailable).finish()
        self.assertEqual(evidence['cpu']['status'], 'unavailable')
        self.assertIsNone(measurement.summarize(evidence, self.implementation)['cpu_seconds'])

    def test_legacy_does_not_acquire_current_measurements(self):
        result=measurement.summarize(None, {})
        self.assertIsNone(result['cpu_seconds'])
        self.assertIsNone(result['peak_memory_bytes'])
        self.assertEqual(result['resource_measurement']['status'], 'not-measured')

    def test_invalid_or_unbound_evidence_rejected(self):
        for value in [-1, math.nan, math.inf, True, '0.75']:
            evidence=self.evidence()
            evidence['cpu']['total_seconds']=value
            with self.subTest(value=value), self.assertRaises(ValueError):
                measurement.summarize(evidence,self.implementation)
        evidence=self.evidence()
        with self.assertRaises(ValueError): measurement.summarize(evidence, {})
        evidence['cpu']['total_seconds']=.5
        with self.assertRaises(ValueError): measurement.summarize(evidence,self.implementation)

    def test_failed_calls_record_cpu_and_keep_denominator(self):
        def failure(*args,**kwargs): raise TimeoutError('controlled failure')
        with tempfile.TemporaryDirectory() as directory, patch.object(measurement,'_usage',return_value=self.usage(2,1,100)):
            result=run.run(Path(directory)/'failure.json', transport=failure, mock=True,max_calls=1)
        self.assertEqual(result['rows'][0]['status'],'timeout')
        self.assertEqual(result['metrics']['incomplete'],20)
        self.assertEqual(result['resource_evidence']['cpu']['status'],'measured')
        self.assertGreaterEqual(result['metrics']['cpu_seconds'],0)
        self.assertIsNone(result['metrics']['peak_memory_bytes'])
        self.assertEqual(result['resource_evidence']['implementation'],result['implementation'])

    def test_unexpected_failure_persists_partial_resource_evidence(self):
        def failure(*args,**kwargs): raise RuntimeError('controlled unexpected failure')
        with tempfile.TemporaryDirectory() as directory, patch.object(measurement,'_usage',return_value=self.usage(2,1,100)):
            output=Path(directory)/'partial.json'
            with self.assertRaises(RuntimeError):
                run.run(output,transport=failure,mock=True,max_calls=1)
            result=json.loads(output.read_text())
        self.assertEqual(result['status'],'incomplete')
        self.assertEqual(result['resource_evidence']['cpu']['status'],'measured')
        self.assertEqual(result['metrics']['positive_denominator'],10)
        self.assertEqual(result['metrics']['incomplete'],20)
        self.assertEqual(result['rows'][0]['status'],'engine_failure')
        self.assertEqual(result['rows'][0]['attempts'][0]['error'],'RuntimeError')

    def test_metrics_do_not_filter_failed_or_missing_when_resources_measured(self):
        _,labels=protocol.generate()
        result=protocol.metrics(labels,[{'id':labels[0]['id'],'status':'timeout'}],[],
                                self.evidence(),self.implementation)
        self.assertEqual(result['cpu_seconds'],.75)
        self.assertEqual(result['incomplete'],20)
        self.assertEqual(len(result['missing_ids']),19)


class ResourceAggregationTests(unittest.TestCase):
    def test_recompute_binds_recorded_version_and_never_retrofits_legacy(self):
        import aggregate
        with tempfile.TemporaryDirectory() as directory:
            raw_path=Path(directory)/'raw.json'
            run.run(raw_path,mock=True,max_calls=1,transport=lambda *args,**kwargs: (_ for _ in ()).throw(TimeoutError('controlled')))
            original=json.loads(raw_path.read_text())
            # A source revision after recording is not a reason to fabricate or reject historical counters.
            recomputed=aggregate.aggregate(raw_path,protocol.ARTIFACTS/'denominator.json')
            self.assertEqual(recomputed['metrics']['cpu_seconds'],original['metrics']['cpu_seconds'])
            self.assertEqual(recomputed['metrics']['incomplete'],20)
            original.pop('resource_evidence')
            original['metrics']['cpu_seconds']=999
            raw_path.write_text(json.dumps(original))
            legacy=aggregate.aggregate(raw_path,protocol.ARTIFACTS/'denominator.json')
            self.assertIsNone(legacy['metrics']['cpu_seconds'])
            original['resource_evidence']={'schema':'runner-resource-v1'}
            raw_path.write_text(json.dumps(original))
            with self.assertRaises(ValueError): aggregate.aggregate(raw_path,protocol.ARTIFACTS/'denominator.json')

    def test_multiple_runs_do_not_reset_or_add_lifetime_rss(self):
        implementation=MeasurementTests.implementation
        snapshots=iter([types.SimpleNamespace(ru_utime=x,ru_stime=0,ru_maxrss=rss)
                        for x,rss in [(1,500),(2,600),(3,600),(4,600)]])
        first=measurement.RunnerResources(implementation,platform_name='darwin',read_usage=lambda:next(snapshots)).finish()
        second=measurement.RunnerResources(implementation,platform_name='darwin',read_usage=lambda:next(snapshots)).finish()
        self.assertEqual(first['rss_lifetime_observation']['end_bytes'],600)
        self.assertEqual(second['rss_lifetime_observation']['start_bytes'],600)
        self.assertIsNone(measurement.summarize(second,implementation)['peak_memory_bytes'])


if __name__=='__main__': unittest.main()
