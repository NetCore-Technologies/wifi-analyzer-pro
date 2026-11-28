const panel = { background: '#111624', border: '1px solid #29374d', borderRadius: 9, padding: 12 };
const number = value => new Intl.NumberFormat().format(Number(value) || 0);

export default function SiteAuditReport({ data }) {
  const summary = data?.summary || {};
  const sites = Array.isArray(data?.sites) ? data.sites : [];
  const findings = Array.isArray(data?.findings) ? data.findings : [];
  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(125px, 1fr))', gap: 8 }}>
        {[
          ['Sites', summary.site_count],
          ['Access points', summary.access_point_count],
          ['Findings', summary.finding_count],
          ['Warnings', summary.warning_count],
          ['Critical', summary.critical_count],
          ['Checks not run', summary.not_run_check_count],
        ].map(([label, value]) => <div key={label} style={{ ...panel, padding: 10 }}>
          <div style={{ color: '#71829a', fontSize: 9, textTransform: 'uppercase', letterSpacing: '.08em' }}>{label}</div>
          <div style={{ color: '#f1f5fb', fontSize: 20, fontWeight: 750, marginTop: 4 }}>{number(value)}</div>
        </div>)}
      </div>
      {sites.map(site => <section key={site.site_id} style={panel}>
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap', marginBottom: 9 }}>
          <strong style={{ color: '#f1f5fb', fontSize: 12 }}>{site.site_id}</strong>
          <span style={{ color: '#71829a', fontSize: 10 }}>{number(site.access_point_count)} APs · {number(site.link_count)} links</span>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 7 }}>
          {Object.entries(site.checks || {}).map(([name, check]) => <div key={name} style={{ border: '1px solid #29374d', borderRadius: 7, padding: 8 }}>
            <div style={{ color: '#a8b6ca', fontSize: 10, fontWeight: 650 }}>{name.replaceAll('_', ' ')}</div>
            <div style={{ color: check.status === 'complete' ? '#56d6ae' : '#f2c36b', fontSize: 9, marginTop: 3 }}>{check.status === 'complete' ? 'Completed' : 'Not run'}</div>
            {check.reason ? <div style={{ color: '#71829a', fontSize: 9, marginTop: 4 }}>{check.reason}</div> : null}
          </div>)}
        </div>
      </section>)}
      <section style={panel}>
        <strong style={{ color: '#f1f5fb', fontSize: 12 }}>Consolidated findings</strong>
        {findings.length ? <div style={{ display: 'grid', gap: 7, marginTop: 9 }}>
          {findings.map((finding, index) => <div key={`${finding.site_id}-${finding.check}-${index}`} style={{ borderLeft: `3px solid ${finding.severity === 'critical' ? '#ff7185' : '#f2c36b'}`, background: '#111624', padding: 9, borderRadius: 6 }}>
            <div style={{ color: finding.severity === 'critical' ? '#ff9eac' : '#f2c36b', fontSize: 9, textTransform: 'uppercase', fontWeight: 750 }}>{finding.severity} · {finding.site_id} · {finding.check}</div>
            <div style={{ color: '#a8b6ca', fontSize: 10, marginTop: 4 }}>{finding.message}</div>
          </div>)}
        </div> : <div style={{ color: '#56d6ae', fontSize: 10, marginTop: 8 }}>No findings were raised by the supplied evidence.</div>}
      </section>
      <section style={panel}>
        <div style={{ color: '#a8b6ca', fontSize: 11, fontWeight: 700 }}>Cross-site comparison</div>
        <div style={{ color: '#a8b6ca', fontSize: 10, marginTop: 5 }}>
          {data?.cross_site_inventory?.status === 'complete'
            ? `${number(data.cross_site_inventory.result.site_count)} sites compared · ${number(data.cross_site_inventory.result.collision_count)} BSSID collisions`
            : data?.cross_site_inventory?.reason || 'Not run'}
        </div>
        <div style={{ color: '#71829a', fontSize: 10, marginTop: 8 }}>
          History: {data?.site_history?.status === 'complete' ? 'Compared' : data?.site_history?.reason || 'Not run'}
        </div>
      </section>
      <div style={{ color: '#71829a', fontSize: 10, lineHeight: 1.5 }}>{data?.note}</div>
    </div>
  );
}
