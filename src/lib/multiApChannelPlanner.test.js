import test from 'node:test';
import assert from 'node:assert/strict';
import { buildMultiApPlannerPayload, parsePlannerChannelOptions } from './multiApChannelPlanner.js';

const radios = [
  { radio_id: 'ap-01-24', ap_id: 'ap-01', site_id: 'hq', band: '2.4GHz', width: '20', current_channel: '6', options: '1, 6, 11' },
  { radio_id: 'ap-02-24', ap_id: 'ap-02', site_id: 'hq', band: '2.4GHz', width: '20', current_channel: '6', options: '1, 6, 11' },
];
const edges = [{ left: 'ap-01-24', right: 'ap-02-24', weight: '0.8', source: 'survey' }];

test('builds a bounded planner payload from radio and evidence form rows', () => {
  const payload = buildMultiApPlannerPayload(radios, edges, '0.05');
  assert.equal(payload.radios.length, 2);
  assert.deepEqual(payload.radios[0].channel_options, [1, 6, 11]);
  assert.equal(payload.interference_edges[0].weight, 0.8);
  assert.equal(payload.change_penalty, 0.05);
});

test('supports wide-channel options with explicit centre frequencies', () => {
  assert.deepEqual(parsePlannerChannelOptions('36@5190, 44@5230', 80, 'ap-01-5'), [
    { channel: 36, center_frequency_mhz: 5190 },
    { channel: 44, center_frequency_mhz: 5230 },
  ]);
});

test('allows unknown current channels without inventing a baseline', () => {
  const payload = buildMultiApPlannerPayload(radios.map(radio => ({ ...radio, current_channel: '' })), edges, '0');
  assert.equal(payload.radios[0].current_channel, null);
});

test('rejects missing radio identity and duplicate radio IDs', () => {
  assert.throws(() => buildMultiApPlannerPayload([{ ...radios[0], ap_id: '' }, radios[1]], edges, '0.05'), /AP ID and site ID are required/);
  assert.throws(() => buildMultiApPlannerPayload([radios[0], { ...radios[1], radio_id: radios[0].radio_id }], edges, '0.05'), /Duplicate radio ID/);
});

test('rejects wide channel options without explicit centre frequencies', () => {
  assert.throws(() => parsePlannerChannelOptions('36,44', 80, 'ap-01-5'), /channel@centreMHz/);
  assert.throws(() => parsePlannerChannelOptions('36@NaN', 80, 'ap-01-5'), /channel@centreMHz/);
});

test('requires explicit, well-formed interference evidence', () => {
  assert.throws(() => buildMultiApPlannerPayload(radios, [], '0.05'), /does not infer proximity/);
  assert.throws(() => buildMultiApPlannerPayload(radios, [{ ...edges[0], source: '' }], '0.05'), /select an evidence source/);
  assert.throws(() => buildMultiApPlannerPayload(radios, [{ ...edges[0], weight: '1.5' }], '0.05'), /weight must be from 0 to 1/);
});

test('rejects relationships that cross site or band boundaries', () => {
  assert.throws(() => buildMultiApPlannerPayload([radios[0], { ...radios[1], site_id: 'branch' }], edges, '0.05'), /must share a site and band/);
  assert.throws(() => buildMultiApPlannerPayload([radios[0], { ...radios[1], band: '6GHz' }], edges, '0.05'), /must share a site and band/);
});

test('rejects repeated channel options and invalid change penalties', () => {
  assert.throws(() => parsePlannerChannelOptions('1,1,6', 20, 'ap-01'), /must be unique/);
  assert.throws(() => buildMultiApPlannerPayload(radios, edges, '0.75'), /penalty must be between 0 and 0.5/);
});
