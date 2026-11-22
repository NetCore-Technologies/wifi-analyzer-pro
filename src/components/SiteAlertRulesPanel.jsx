import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { apiBase, apiFetch } from '../lib/api.js';
import {
  Activity, Bell, Check, CheckCircle2, Plus, RefreshCw,
  Save, ShieldAlert, X,
} from 'lucide-react';

const EMPTY_FORM = {
  name: '',
  metric: 'minimum_rssi_dbm',
  operator: 'lt',
  threshold: '-75',
  recovery_threshold: '-70',
  severity: 'warning',
  hold_for_seconds: '0',
  dedupe_window_seconds: '900',
  quiet_start: '',
  quiet_end: '',
  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
  enabled: true,
};

function metricDefaults(metric) {
  const values = {
    minimum_rssi_dbm: { operator: 'lt', threshold: '-75', recovery_threshold: '-70' },
    network_count: { operator: 'gt', threshold: '40', recovery_threshold: '30' },
    open_network_count: { operator: 'gte', threshold: '1', recovery_threshold: '0' },
    gateway_latency_ms: { operator: 'gt', threshold: '100', recovery_threshold: '80' },
    packet_loss_pct: { operator: 'gte', threshold: '5', recovery_threshold: '2' },
    gateway_jitter_ms: { operator: 'gt', threshold: '30', recovery_threshold: '20' },
    dns_resolution_ms: { operator: 'gt', threshold: '250', recovery_threshold: '200' },
  };
  return values[metric] || values.minimum_rssi_dbm;
}

function displayTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString();
}

function severityStyle(severity) {
  if (severity === 'critical') return 'border-red-400/30 bg-red-400/10 text-red-300';
  if (severity === 'warning') return 'border-amber-400/30 bg-amber-400/10 text-amber-300';
  return 'border-sky-400/30 bg-sky-400/10 text-sky-300';
}

function ruleToForm(rule) {
  return {
    name: rule.name,
    metric: rule.metric,
    operator: rule.operator,
    threshold: String(rule.threshold),
    recovery_threshold: rule.recovery_threshold == null ? '' : String(rule.recovery_threshold),
    severity: rule.severity,
    hold_for_seconds: String(rule.hold_for_seconds),
    dedupe_window_seconds: String(rule.dedupe_window_seconds),
    quiet_start: rule.quiet_start || '',
    quiet_end: rule.quiet_end || '',
    timezone: rule.timezone || 'UTC',
    enabled: rule.enabled === true,
  };
}

export default function SiteAlertRulesPanel() {
  const [siteIds, setSiteIds] = useState([]);
  const [siteId, setSiteId] = useState('');
  const [rules, setRules] = useState([]);
  const [events, setEvents] = useState([]);
  const [metricCatalog, setMetricCatalog] = useState([]);
  const [canManage, setCanManage] = useState(false);
  const [evaluationEnabled, setEvaluationEnabled] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [editingId, setEditingId] = useState('');
  const [deleteTarget, setDeleteTarget] = useState('');
  const [formOpen, setFormOpen] = useState(false);
  const [form, setForm] = useState(EMPTY_FORM);

  const activeEvents = useMemo(
    () => events.filter(event => event.status === 'active' || event.status === 'acknowledged'),
    [events],
  );
  const resolvedEvents = useMemo(
    () => events.filter(event => event.status === 'resolved'),
    [events],
  );

  const loadSites = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const response = await apiFetch(apiBase() + '/api/sites', { signal: AbortSignal.timeout(12000) });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'Unable to load sites available to this account.');
      const values = Array.isArray(data.site_ids)
        ? [...new Set(data.site_ids.filter(value => typeof value === 'string' && value.length > 0))].sort()
        : [];
      setSiteIds(values);
      setSiteId(current => values.includes(current) ? current : values[0] || '');
    } catch (loadError) {
      setSiteIds([]);
      setSiteId('');
      setRules([]);
      setEvents([]);
      setCanManage(false);
      setEvaluationEnabled(false);
      setError(loadError.message || 'Unable to load the site directory.');
    } finally {
      setLoading(false);
    }
  }, []);

  const loadSiteData = useCallback(async signal => {
    if (!siteId) {
      setRules([]);
      setEvents([]);
      setCanManage(false);
      setMetricCatalog([]);
      return;
    }
    setLoading(true);
    setError('');
    try {
      const url = apiBase() + '/api/sites/alert-rules?site_id=' + encodeURIComponent(siteId);
      const response = await apiFetch(url, { signal: signal || AbortSignal.timeout(12000) });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'Unable to load alert policies for this site.');
      if (!Array.isArray(data.rules) || !Array.isArray(data.events)) {
        throw new Error('The alert service returned an invalid site snapshot.');
      }
      setRules(data.rules);
      setEvents(data.events);
      setCanManage(data.can_manage === true);
      setEvaluationEnabled(data.evaluation_enabled === true);
      setMetricCatalog(Array.isArray(data.metric_catalog) ? data.metric_catalog : []);
    } catch (loadError) {
      if (loadError.name === 'AbortError') return;
      setRules([]);
      setEvents([]);
      setCanManage(false);
      setEvaluationEnabled(false);
      setError(loadError.message || 'Unable to load site alert state.');
    } finally {
      setLoading(false);
    }
  }, [siteId]);

  useEffect(() => { void loadSites(); }, [loadSites]);
  useEffect(() => {
    const controller = new AbortController();
    void loadSiteData(controller.signal);
    return () => controller.abort();
  }, [loadSiteData]);

  function resetForm() {
    setEditingId('');
    setForm(EMPTY_FORM);
    setFormOpen(false);
  }

  function updateField(field, value) {
    setForm(current => ({ ...current, [field]: value }));
  }

  function editRule(rule) {
    setEditingId(rule.rule_id);
    setForm(ruleToForm(rule));
    setFormOpen(true);
    setNotice('');
    setError('');
  }

  async function saveRule(event) {
    event.preventDefault();
    if (!siteId || !canManage) return;
    setSaving(true);
    setError('');
    setNotice('');
    try {
      const payloadRule = {
        name: form.name.trim(),
        metric: form.metric,
        operator: form.operator,
        threshold: Number(form.threshold),
        recovery_threshold: form.recovery_threshold.trim() === '' ? null : Number(form.recovery_threshold),
        severity: form.severity,
        hold_for_seconds: Number(form.hold_for_seconds),
        dedupe_window_seconds: Number(form.dedupe_window_seconds),
        quiet_start: form.quiet_start || null,
        quiet_end: form.quiet_end || null,
        timezone: form.timezone.trim() || 'UTC',
        enabled: form.enabled,
      };
      const response = await apiFetch(apiBase() + '/api/sites/alert-rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          operation: 'save',
          site_id: siteId,
          ...(editingId ? { rule_id: editingId } : {}),
          rule: payloadRule,
        }),
        signal: AbortSignal.timeout(15000),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'Unable to save the alert rule.');
      resetForm();
      setNotice(data.audit_status || (editingId ? 'Alert rule updated.' : 'Alert rule created.'));
      await loadSiteData();
    } catch (saveError) {
      setError(saveError.message || 'Unable to save the alert rule.');
    } finally {
      setSaving(false);
    }
  }

  async function deleteRule(rule) {
    if (!canManage || !siteId || !rule?.rule_id) return;
    setSaving(true);
    setError('');
    try {
      const response = await apiFetch(apiBase() + '/api/sites/alert-rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ operation: 'delete', site_id: siteId, rule_id: rule.rule_id }),
        signal: AbortSignal.timeout(12000),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'Unable to delete the alert rule.');
      setDeleteTarget('');
      if (editingId === rule.rule_id) resetForm();
      setNotice(data.audit_status || 'Alert rule deleted; any active incident was resolved.');
      await loadSiteData();
    } catch (deleteError) {
      setError(deleteError.message || 'Unable to delete the alert rule.');
    } finally {
      setSaving(false);
    }
  }

  async function acknowledge(event) {
    if (!canManage || !siteId || !event?.event_id) return;
    setSaving(true);
    setError('');
    try {
      const response = await apiFetch(apiBase() + '/api/sites/alert-rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ operation: 'acknowledge', site_id: siteId, event_id: event.event_id }),
        signal: AbortSignal.timeout(12000),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'Unable to acknowledge the alert.');
      setNotice(data.audit_status || 'Incident acknowledged and recorded in the security audit ledger.');
      await loadSiteData();
    } catch (ackError) {
      setError(ackError.message || 'Unable to acknowledge the alert.');
    } finally {
      setSaving(false);
    }
  }

  const selectedMetric = metricCatalog.find(item => item.key === form.metric);
  const metricLabel = metric => metricCatalog.find(item => item.key === metric)?.description || metric;

  return (
    <div className="space-y-4">
      <section className="glass rounded-xl p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2 text-sm font-semibold text-foreground">
              <Activity className="w-4 h-4 text-primary" /> Site alert policies
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              Persistent threshold rules evaluated against measured scan and host-diagnostic telemetry
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <select aria-label="Alert policy site" value={siteId} onChange={event => setSiteId(event.target.value)}
              disabled={loading || !siteIds.length}
              className="px-3 py-2 rounded-lg bg-background/60 border border-border text-xs text-foreground disabled:opacity-50">
              {siteIds.length
                ? siteIds.map(id => <option key={id} value={id}>{id}</option>)
                : <option value="">No assigned sites</option>}
            </select>
            <button type="button" onClick={() => void loadSiteData()} disabled={loading || !siteId}
              className="flex items-center gap-2 px-3 py-2 rounded-lg bg-secondary border border-border text-xs text-foreground disabled:opacity-50">
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
            </button>
            {canManage && evaluationEnabled && (
              <button type="button" onClick={() => { resetForm(); setFormOpen(true); }}
                className="flex items-center gap-2 px-3 py-2 rounded-lg bg-primary/10 border border-primary/30 text-primary text-xs">
                <Plus className="w-3.5 h-3.5" /> New rule
              </button>
            )}
          </div>
        </div>
        {error && <div role="alert" className="rounded-lg border border-red-400/30 bg-red-400/5 p-3 text-xs text-red-300">{error}</div>}
        {notice && <div role="status" className="rounded-lg border border-emerald-400/20 bg-emerald-400/5 p-3 text-xs text-emerald-300">{notice}</div>}
        {!loading && siteId && !evaluationEnabled && <div className="rounded-lg border border-amber-400/20 bg-amber-400/5 p-3 text-xs text-amber-200">Rules for remote sites are read-only until an authenticated telemetry evaluator is connected. This host currently evaluates only its local site ({siteId}).</div>}
        {!loading && !siteIds.length && (
          <div className="rounded-lg border border-border p-4 text-xs text-muted-foreground">No sites are assigned to this account. Ask an administrator to grant site access.</div>
        )}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="rounded-lg bg-secondary/40 p-3"><div className="text-2xl font-mono font-semibold text-foreground">{rules.length}</div><div className="text-xs text-muted-foreground">Configured rules</div></div>
          <div className="rounded-lg bg-secondary/40 p-3"><div className="text-2xl font-mono font-semibold text-red-300">{activeEvents.filter(item => item.severity === 'critical').length}</div><div className="text-xs text-muted-foreground">Critical incidents</div></div>
          <div className="rounded-lg bg-secondary/40 p-3"><div className="text-2xl font-mono font-semibold text-amber-300">{activeEvents.filter(item => item.severity === 'warning').length}</div><div className="text-xs text-muted-foreground">Warning incidents</div></div>
          <div className="rounded-lg bg-secondary/40 p-3"><div className="text-2xl font-mono font-semibold text-emerald-300">{resolvedEvents.length}</div><div className="text-xs text-muted-foreground">Resolved in history</div></div>
        </div>
      </section>

      {formOpen && canManage && evaluationEnabled && (
        <form onSubmit={saveRule} className="glass rounded-xl p-4 space-y-4">
          <div className="flex items-center justify-between gap-2">
            <div className="text-sm font-semibold text-foreground">{editingId ? 'Edit alert policy' : 'Create alert policy'}</div>
            <button type="button" onClick={resetForm} className="p-1.5 rounded-lg text-muted-foreground hover:bg-secondary" aria-label="Close rule editor"><X className="w-4 h-4" /></button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <label className="text-xs text-muted-foreground">Rule name
              <input required maxLength={128} value={form.name} onChange={event => updateField('name', event.target.value)}
                className="mt-1 w-full px-3 py-2 rounded-lg bg-background/60 border border-border text-sm text-foreground" />
            </label>
            <label className="text-xs text-muted-foreground">Measured metric
              <select value={form.metric} onChange={event => {
                const metric = event.target.value;
                setForm(current => ({ ...current, metric, ...metricDefaults(metric) }));
              }}
                className="mt-1 w-full px-3 py-2 rounded-lg bg-background/60 border border-border text-sm text-foreground">
                {metricCatalog.map(metric => <option key={metric.key} value={metric.key}>{metric.key} ({metric.unit})</option>)}
              </select>
            </label>
            <label className="text-xs text-muted-foreground">Condition
              <select value={form.operator} onChange={event => updateField('operator', event.target.value)}
                className="mt-1 w-full px-3 py-2 rounded-lg bg-background/60 border border-border text-sm text-foreground">
                <option value="lt">Less than</option><option value="lte">Less than or equal</option>
                <option value="gt">Greater than</option><option value="gte">Greater than or equal</option>
              </select>
            </label>
            <label className="text-xs text-muted-foreground">Trigger threshold ({selectedMetric?.unit || ''})
              <input type="number" required step="any" min={selectedMetric?.minimum} max={selectedMetric?.maximum}
                value={form.threshold} onChange={event => updateField('threshold', event.target.value)}
                className="mt-1 w-full px-3 py-2 rounded-lg bg-background/60 border border-border text-sm text-foreground" />
            </label>
            <label className="text-xs text-muted-foreground">Recovery threshold (optional)
              <input type="number" step="any" min={selectedMetric?.minimum} max={selectedMetric?.maximum}
                value={form.recovery_threshold} onChange={event => updateField('recovery_threshold', event.target.value)}
                className="mt-1 w-full px-3 py-2 rounded-lg bg-background/60 border border-border text-sm text-foreground"
                placeholder="Use inverse trigger condition" />
            </label>
            <label className="text-xs text-muted-foreground">Severity
              <select value={form.severity} onChange={event => updateField('severity', event.target.value)}
                className="mt-1 w-full px-3 py-2 rounded-lg bg-background/60 border border-border text-sm text-foreground">
                <option value="info">Info</option><option value="warning">Warning</option><option value="critical">Critical</option>
              </select>
            </label>
            <label className="text-xs text-muted-foreground">Sustained breach (seconds)
              <input type="number" min="0" max="3600" step="1" value={form.hold_for_seconds}
                onChange={event => updateField('hold_for_seconds', event.target.value)}
                className="mt-1 w-full px-3 py-2 rounded-lg bg-background/60 border border-border text-sm text-foreground" />
            </label>
            <label className="text-xs text-muted-foreground">Deduplication window (seconds)
              <input type="number" min="60" max="86400" step="1" value={form.dedupe_window_seconds}
                onChange={event => updateField('dedupe_window_seconds', event.target.value)}
                className="mt-1 w-full px-3 py-2 rounded-lg bg-background/60 border border-border text-sm text-foreground" />
            </label>
          </div>
          <div className="border-t border-border pt-3 space-y-3">
            <div className="text-xs font-semibold text-foreground">Quiet hours (optional)</div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <label className="text-xs text-muted-foreground">Start
                <input type="time" value={form.quiet_start} onChange={event => updateField('quiet_start', event.target.value)}
                  className="mt-1 w-full px-3 py-2 rounded-lg bg-background/60 border border-border text-sm text-foreground" />
              </label>
              <label className="text-xs text-muted-foreground">End
                <input type="time" value={form.quiet_end} onChange={event => updateField('quiet_end', event.target.value)}
                  className="mt-1 w-full px-3 py-2 rounded-lg bg-background/60 border border-border text-sm text-foreground" />
              </label>
              <label className="text-xs text-muted-foreground">IANA time zone
                <input value={form.timezone} onChange={event => updateField('timezone', event.target.value)}
                  placeholder="Australia/Sydney" className="mt-1 w-full px-3 py-2 rounded-lg bg-background/60 border border-border text-sm text-foreground" />
              </label>
            </div>
            <label className="flex items-center gap-2 text-xs text-muted-foreground">
              <input type="checkbox" checked={form.enabled} onChange={event => updateField('enabled', event.target.checked)} />
              Enable this rule immediately
            </label>
          </div>
          <div className="text-xs text-muted-foreground">{selectedMetric?.description || 'Select a metric'} Missing observations do not resolve an active incident. Recovery requires a measured value.</div>
          <div className="flex justify-end gap-2">
            <button type="button" onClick={resetForm} className="px-3 py-2 rounded-lg bg-secondary text-xs text-foreground">Cancel</button>
            <button type="submit" disabled={saving || !canManage}
              className="flex items-center gap-2 px-3 py-2 rounded-lg bg-primary/10 border border-primary/30 text-primary text-xs disabled:opacity-50">
              <Save className="w-3.5 h-3.5" /> {saving ? 'Saving…' : editingId ? 'Update rule' : 'Create rule'}
            </button>
          </div>
        </form>
      )}

      <section className="glass rounded-xl p-4 space-y-3">
        <div className="flex items-center gap-2 text-sm font-semibold text-foreground"><Bell className="w-4 h-4 text-primary" /> Active incidents</div>
        {activeEvents.length === 0 && <div className="text-xs text-muted-foreground">No active incidents are recorded for this site. Missing telemetry is not treated as a healthy measurement.</div>}
        {activeEvents.map(event => (
          <div key={event.event_id} className={`rounded-lg border p-3 space-y-2 ${severityStyle(event.severity)}`}>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="text-xs font-semibold">{event.rule_name}</div>
              <span className="text-[10px] uppercase tracking-wide">{event.status}</span>
            </div>
            <div className="text-xs">{event.message}</div>
            <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] opacity-80">
              <span>First seen: {displayTime(event.first_seen_at)}</span>
              <span>Last seen: {displayTime(event.last_seen_at)}</span>
              <span>Occurrences: {event.occurrence_count}</span>
              <span>Deduplicated: {event.dedupe_suppressed_count}</span>
              {event.quiet_hours_active && <span>Quiet hours active · delivery suppressed</span>}
              {event.acknowledged_by && <span>Acknowledged by {event.acknowledged_by}</span>}
            </div>
            {canManage && event.status === 'active' && (
              <button type="button" onClick={() => void acknowledge(event)} disabled={saving}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-current/30 bg-black/10 text-xs disabled:opacity-50">
                <Check className="w-3.5 h-3.5" /> Acknowledge
              </button>
            )}
          </div>
        ))}
      </section>

      <section className="glass rounded-xl p-4 space-y-3">
        <div className="flex items-center gap-2 text-sm font-semibold text-foreground"><ShieldAlert className="w-4 h-4 text-primary" /> Configured rules</div>
        {rules.length === 0 && <div className="text-xs text-muted-foreground">No alert rules are configured for this site.</div>}
        {rules.map(rule => (
          <div key={rule.rule_id} className="rounded-lg border border-border bg-secondary/20 p-3 flex flex-wrap items-center justify-between gap-3">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs font-semibold text-foreground">{rule.name}</span>
                <span className={`text-[10px] uppercase px-2 py-0.5 rounded-full border ${severityStyle(rule.severity)}`}>{rule.severity}</span>
                <span className="text-[10px] text-muted-foreground">{rule.enabled ? 'Enabled' : 'Disabled'}</span>
              </div>
              <div className="text-xs text-muted-foreground mt-1">
                {metricLabel(rule.metric)} · {rule.operator} {rule.threshold} {rule.unit}
                {rule.recovery_threshold == null ? '' : ' · recovers at ' + rule.recovery_threshold}
                · hold {rule.hold_for_seconds}s · dedupe {rule.dedupe_window_seconds}s
              </div>
              {rule.quiet_start && <div className="text-[11px] text-muted-foreground mt-1">Quiet {rule.quiet_start}–{rule.quiet_end} ({rule.timezone})</div>}
            </div>
            {canManage && (
              <div className="flex gap-2">
                {evaluationEnabled && <button type="button" onClick={() => editRule(rule)} className="px-3 py-1.5 rounded-lg bg-secondary border border-border text-xs text-foreground">Edit</button>}
                <button type="button" onClick={() => setDeleteTarget(current => current === rule.rule_id ? '' : rule.rule_id)}
                  className="px-3 py-1.5 rounded-lg border border-red-400/30 text-red-300 text-xs">Delete</button>
              </div>
            )}
            {canManage && deleteTarget === rule.rule_id && (
              <div className="w-full border-t border-border pt-2 flex flex-wrap items-center justify-between gap-2">
                <span className="text-xs text-muted-foreground">Delete this rule? Any incident it owns will be resolved.</span>
                <div className="flex gap-2">
                  <button type="button" onClick={() => void deleteRule(rule)} disabled={saving}
                    className="px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-400/30 text-red-300 text-xs">Confirm delete</button>
                  <button type="button" onClick={() => setDeleteTarget('')} className="px-3 py-1.5 rounded-lg bg-secondary text-xs text-foreground">Cancel</button>
                </div>
              </div>
            )}
          </div>
        ))}
        {!canManage && <div className="text-xs text-muted-foreground">Read-only site access. A site administrator can change alert policies.</div>}
      </section>

      <section className="glass rounded-xl p-4 space-y-3">
        <div className="flex items-center gap-2 text-sm font-semibold text-foreground"><CheckCircle2 className="w-4 h-4 text-primary" /> Resolved incident history</div>
        {resolvedEvents.length === 0 && <div className="text-xs text-muted-foreground">No resolved incidents are retained yet.</div>}
        {resolvedEvents.slice(0, 20).map(event => (
          <div key={event.event_id} className="rounded-lg border border-border bg-secondary/20 p-3">
            <div className="flex flex-wrap justify-between gap-2 text-xs">
              <span className="font-semibold text-foreground">{event.rule_name}</span>
              <span className="text-emerald-300">Resolved {displayTime(event.resolved_at)}</span>
            </div>
            <div className="text-xs text-muted-foreground mt-1">{event.message}</div>
          </div>
        ))}
      </section>

      <div className="rounded-xl border border-border bg-secondary/20 p-3 text-xs text-muted-foreground">
        Rules are evaluated only for this host's configured local site when it records a live scan or measured gateway/DNS diagnostics. Quiet hours are stored with each incident as a delivery-suppression indicator. External email, Slack, Discord and MQTT alert delivery are not configured by this feature.
      </div>
    </div>
  );
}
