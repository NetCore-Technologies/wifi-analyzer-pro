const MAX_CSV_BYTES = 1024 * 1024;
const MAX_ROWS = 10000;
const MAX_FIELD_LENGTH = 4096;
const REQUIRED_COLUMNS = ['sample_id', 'site_id', 'client_ref', 'observed_at', 'evidence_source'];
const METRIC_LIMITS = {
  rssi_dbm: [-120, -10],
  snr_db: [-30, 100],
  retry_rate_pct: [0, 100],
  airtime_utilization_pct: [0, 100],
  packet_loss_pct: [0, 100],
  rtt_ms: [0, 60000],
  jitter_ms: [0, 60000],
  throughput_mbps: [0, 100000],
};
const ALLOWED_COLUMNS = new Set([
  ...REQUIRED_COLUMNS,
  'ap_id',
  ...Object.keys(METRIC_LIMITS),
]);
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SAMPLE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const SOURCES = new Set(['controller', 'agent', 'client', 'probe', 'import']);

function parseCsvRows(input) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  let afterQuote = false;

  const pushField = () => {
    if (field.length > MAX_FIELD_LENGTH) throw new Error('A CSV field exceeds the 4096 character limit.');
    row.push(field);
    field = '';
    afterQuote = false;
    if (row.length > ALLOWED_COLUMNS.size) {
      throw new Error('A CSV record contains more columns than the supported schema.');
    }
  };
  const pushRow = () => {
    pushField();
    if (row.some(value => value.trim() !== '')) {
      rows.push(row);
      if (rows.length > MAX_ROWS + 1) throw new Error('CSV contains more than 10000 observation rows.');
    }
    row = [];
  };

  for (let index = 0; index < input.length; index += 1) {
    const char = input[index];
    if (quoted) {
      if (char === '"') {
        if (input[index + 1] === '"') {
          field += '"';
          index += 1;
        } else {
          quoted = false;
          afterQuote = true;
        }
      } else if (char === '\r') {
        if (input[index + 1] === '\n') index += 1;
        field += '\n';
      } else {
        field += char;
      }
      continue;
    }

    if (afterQuote) {
      if (char === ',') {
        pushField();
      } else if (char === '\n' || char === '\r') {
        if (char === '\r' && input[index + 1] === '\n') index += 1;
        pushRow();
      } else {
        throw new Error('Unexpected character after a quoted CSV field. Use standard RFC 4180 quoting.');
      }
      continue;
    }

    if (char === '"') {
      if (field.length !== 0) throw new Error('A quote appeared inside an unquoted CSV field.');
      quoted = true;
    } else if (char === ',') {
      pushField();
    } else if (char === '\n' || char === '\r') {
      if (char === '\r' && input[index + 1] === '\n') index += 1;
      pushRow();
    } else {
      field += char;
    }
    if (field.length > MAX_FIELD_LENGTH) throw new Error('A CSV field exceeds the 4096 character limit.');
  }

  if (quoted) throw new Error('CSV ended inside a quoted field.');
  if (field.length || row.length || afterQuote) pushRow();
  return rows;
}

function requiredText(value, field, rowNumber, maxLength = 128) {
  const normalized = String(value ?? '').trim();
  if (!normalized) throw new Error('CSV row ' + rowNumber + ': ' + field + ' is required.');
  if (normalized.length > maxLength) {
    throw new Error('CSV row ' + rowNumber + ': ' + field + ' exceeds ' + maxLength + ' characters.');
  }
  return normalized;
}

function parseTimestamp(value, rowNumber) {
  const timestamp = requiredText(value, 'observed_at', rowNumber, 64);
  if (!/(?:Z|[+-]\d{2}:\d{2})$/i.test(timestamp) || !Number.isFinite(Date.parse(timestamp))) {
    throw new Error('CSV row ' + rowNumber + ': observed_at must be a valid timezone-aware ISO-8601 timestamp.');
  }
  return new Date(timestamp).toISOString();
}

function parseMetric(value, key, rowNumber) {
  const normalized = String(value ?? '').trim();
  if (!normalized) return undefined;
  if (!/^-?(?:\d+\.?\d*|\.\d+)$/.test(normalized)) {
    throw new Error('CSV row ' + rowNumber + ': ' + key + ' must be a finite number.');
  }
  const number = Number(normalized);
  const [minimum, maximum] = METRIC_LIMITS[key];
  if (!Number.isFinite(number) || number < minimum || number > maximum) {
    throw new Error('CSV row ' + rowNumber + ': ' + key + ' must be between ' + minimum + ' and ' + maximum + '.');
  }
  return number;
}

export function parseClientExperienceCsv(input) {
  if (typeof input !== 'string') throw new Error('CSV content must be text.');
  if (input.length === 0) throw new Error('Choose a non-empty CSV file.');
  if (new TextEncoder().encode(input).byteLength > MAX_CSV_BYTES) {
    throw new Error('CSV exceeds the 1 MiB import limit.');
  }

  const text = input.charCodeAt(0) === 0xFEFF ? input.slice(1) : input;
  const rows = parseCsvRows(text);
  if (rows.length < 2) throw new Error('CSV must contain a header and at least one observation row.');

  const headers = rows[0].map(value => value.trim());
  if (headers.some(value => !value)) throw new Error('CSV headers cannot be empty.');
  if (new Set(headers).size !== headers.length) throw new Error('CSV headers must be unique.');
  const unknown = headers.filter(value => !ALLOWED_COLUMNS.has(value));
  if (unknown.length) throw new Error('Unsupported CSV column(s): ' + unknown.join(', '));
  const missing = REQUIRED_COLUMNS.filter(value => !headers.includes(value));
  if (missing.length) throw new Error('CSV is missing required column(s): ' + missing.join(', '));

  const columnIndex = new Map(headers.map((value, index) => [value, index]));
  const samples = [];
  const seenIds = new Set();

  rows.slice(1).forEach((cells, index) => {
    const rowNumber = index + 2;
    if (cells.length !== headers.length) {
      throw new Error('CSV row ' + rowNumber + ' has ' + cells.length + ' values; expected ' + headers.length + '.');
    }
    const read = key => columnIndex.has(key) ? cells[columnIndex.get(key)] : '';
    const sampleId = requiredText(read('sample_id'), 'sample_id', rowNumber, 64);
    if (!SAMPLE_IDENTIFIER.test(sampleId)) {
      throw new Error('CSV row ' + rowNumber + ': sample_id contains unsupported characters.');
    }
    if (seenIds.has(sampleId)) throw new Error('CSV row ' + rowNumber + ': sample_id values must be unique.');
    seenIds.add(sampleId);

    const siteId = requiredText(read('site_id'), 'site_id', rowNumber);
    const clientRef = requiredText(read('client_ref'), 'client_ref', rowNumber);
    if (!IDENTIFIER.test(siteId)) throw new Error('CSV row ' + rowNumber + ': site_id contains unsupported characters.');
    if (!IDENTIFIER.test(clientRef)) throw new Error('CSV row ' + rowNumber + ': client_ref contains unsupported characters.');
    const source = requiredText(read('evidence_source'), 'evidence_source', rowNumber, 32);
    if (!SOURCES.has(source)) {
      throw new Error('CSV row ' + rowNumber + ': evidence_source must be one of ' + [...SOURCES].join(', ') + '.');
    }

    const metrics = {};
    for (const key of Object.keys(METRIC_LIMITS)) {
      const value = parseMetric(read(key), key, rowNumber);
      if (value !== undefined) metrics[key] = value;
    }
    if (!Object.keys(metrics).length) {
      throw new Error('CSV row ' + rowNumber + ': include at least one measured metric.');
    }

    const sample = {
      sample_id: sampleId,
      site_id: siteId,
      client_ref: clientRef,
      observed_at: parseTimestamp(read('observed_at'), rowNumber),
      evidence_source: source,
      metrics,
    };
    const apId = String(read('ap_id') ?? '').trim();
    if (apId) {
      if (apId.length > 128 || !IDENTIFIER.test(apId)) {
        throw new Error('CSV row ' + rowNumber + ': ap_id contains unsupported characters.');
      }
      sample.ap_id = apId;
    }
    samples.push(sample);
  });

  if (!samples.length) throw new Error('CSV contains no observation rows.');
  return samples;
}

export const CLIENT_EXPERIENCE_CSV_COLUMNS = [
  ...REQUIRED_COLUMNS,
  'ap_id',
  ...Object.keys(METRIC_LIMITS),
];
