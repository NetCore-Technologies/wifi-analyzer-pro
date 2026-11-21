import test from 'node:test';
import assert from 'node:assert/strict';
import { CLIENT_EXPERIENCE_CSV_COLUMNS, parseClientExperienceCsv } from './clientExperienceCsv.js';

const HEADER = CLIENT_EXPERIENCE_CSV_COLUMNS.join(',');
const ROW = [
  'sample-001',
  'office',
  '"station-opaque-01"',
  '2026-11-21T10:00:00Z',
  '"controller"',
  'ap-01',
  '-62',
  '31',
  '4.5',
  '40',
  '0.2',
  '24',
  '3.5',
  '180',
].join(',');

test('imports a complete observation CSV into the F292 API payload shape', () => {
  const samples = parseClientExperienceCsv(HEADER + '\r\n' + ROW + '\r\n');
  assert.equal(samples.length, 1);
  assert.deepEqual(samples[0], {
    sample_id: 'sample-001',
    site_id: 'office',
    client_ref: 'station-opaque-01',
    ap_id: 'ap-01',
    observed_at: '2026-11-21T10:00:00.000Z',
    evidence_source: 'controller',
    metrics: {
      rssi_dbm: -62,
      snr_db: 31,
      retry_rate_pct: 4.5,
      airtime_utilization_pct: 40,
      packet_loss_pct: 0.2,
      rtt_ms: 24,
      jitter_ms: 3.5,
      throughput_mbps: 180,
    },
  });
});

test('accepts UTF-8 BOM, arbitrary header ordering, omitted optional columns and blank metrics', () => {
  const csv = '\uFEFFclient_ref,site_id,sample_id,observed_at,evidence_source,packet_loss_pct,rtt_ms\n'
    + 'station-02,branch,sample-002,2026-11-21T10:00:00+00:00,probe,0.5,\n';
  const samples = parseClientExperienceCsv(csv);
  assert.deepEqual(samples[0].metrics, { packet_loss_pct: 0.5 });
  assert.equal(samples[0].site_id, 'branch');
  assert.equal(samples[0].evidence_source, 'probe');
  assert.equal(samples[0].observed_at, '2026-11-21T10:00:00.000Z');
  assert.equal(Object.hasOwn(samples[0], 'ap_id'), false);
});

test('preserves RFC 4180 escaped quote and quoted delimiters before field validation', () => {
  const csv = 'sample_id,site_id,client_ref,observed_at,evidence_source,ap_id,rssi_dbm\n'
    + 'sample-003,office,station-03,2026-11-21T10:00:00Z,"agent",ap-03,-61\n';
  const samples = parseClientExperienceCsv(csv);
  assert.equal(samples[0].metrics.rssi_dbm, -61);
  assert.equal(samples[0].ap_id, 'ap-03');
});

test('rejects missing, duplicate and unsupported column headers', () => {
  assert.throws(() => parseClientExperienceCsv('sample_id,site_id\nsample-1,office\n'), /missing required column/);
  assert.throws(() => parseClientExperienceCsv('sample_id,site_id,site_id,client_ref,observed_at,evidence_source\n'), /unique/);
  assert.throws(() => parseClientExperienceCsv(HEADER + ',password\n'), /Unsupported CSV column/);
});

test('rejects rows with wrong column counts and malformed quoting', () => {
  assert.throws(() => parseClientExperienceCsv(
    'sample_id,site_id,client_ref,observed_at,evidence_source,rssi_dbm\nsample-1,office,station-1,2026-11-21T10:00:00Z,probe\n',
  ), /expected 6/);
  assert.throws(() => parseClientExperienceCsv(
    'sample_id,site_id,client_ref,observed_at,evidence_source,rssi_dbm\nsample-1,office,"station-1,2026-11-21T10:00:00Z,probe,-60\n',
  ), /ended inside a quoted field/);
  assert.throws(() => parseClientExperienceCsv(
    'sample_id,site_id,client_ref,observed_at,evidence_source,rssi_dbm\nsample-1,office,sta"tion,2026-11-21T10:00:00Z,probe,-60\n',
  ), /quote appeared inside an unquoted CSV field/);
});

test('rejects duplicate IDs, invalid timestamps, unknown evidence and out-of-range metrics', () => {
  assert.throws(() => parseClientExperienceCsv(
    'sample_id,site_id,client_ref,observed_at,evidence_source,rssi_dbm\n'
    + 'sample-1,office,station-1,2026-11-21T10:00:00Z,probe,-60\n'
    + 'sample-1,office,station-2,2026-11-21T10:01:00Z,probe,-61\n',
  ), /sample_id values must be unique/);
  assert.throws(() => parseClientExperienceCsv(
    'sample_id,site_id,client_ref,observed_at,evidence_source,rssi_dbm\nsample-1,office,station-1,2026-11-21T10:00:00,probe,-60\n',
  ), /timezone-aware ISO-8601/);
  assert.throws(() => parseClientExperienceCsv(
    'sample_id,site_id,client_ref,observed_at,evidence_source,rssi_dbm\nsample-1,office,station-1,2026-11-21T10:00:00Z,unknown,-60\n',
  ), /evidence_source/);
  assert.throws(() => parseClientExperienceCsv(
    'sample_id,site_id,client_ref,observed_at,evidence_source,packet_loss_pct\nsample-1,office,station-1,2026-11-21T10:00:00Z,probe,101\n',
  ), /packet_loss_pct must be between 0 and 100/);
});

test('rejects rows without measured metrics and enforces the file-size limit', () => {
  assert.throws(() => parseClientExperienceCsv(
    'sample_id,site_id,client_ref,observed_at,evidence_source,rssi_dbm\nsample-1,office,station-1,2026-11-21T10:00:00Z,probe,\n',
  ), /at least one measured metric/);
  assert.throws(() => parseClientExperienceCsv('x'.repeat(1024 * 1024 + 1)), /1 MiB import limit/);
});
