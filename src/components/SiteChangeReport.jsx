const panel = { background: '#111624', border: '1px solid #29374d', borderRadius: 9, padding: 12 };
const number = value => new Intl.NumberFormat().format(Number(value) || 0);

export default function SiteChangeReport({ data }) {
  const summary = data?.summary || {};
  const sites = Array.isArray(data?.sites) ? data.sites : [];
  const collisions = Array.isArray(data?.cross_site_bssid_collisions) ? data.cross_site_bssid_collisions : [];
  const metrics = [
    ['Sites compared', summary.site_count],
    ['APs currently inventoried', summary.current_access_point_count],
    ['APs added', summary.added_access_point_count],
    ['APs removed', summary.removed_access_point_count],
    ['APs changed', summary.changed_access_point_count],
    ['Cross-site BSSID reuse', summary.cross_site_bssid_collision_count],
  ];

  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(125px, 1fr))', gap: 8 }}>
        {metrics.map(([label, value]) => (
          <div key={label} style={{ ...panel, padding: 10 }}>
            <div style={{ color: '#71829a', fontSize: 9, textTransform: 'uppercase', letterSpacing: '.08em' }}>{label}</div>
            <div style={{ color: '#f1f5fb', fontSize: 20, fontWeight: 750, marginTop: 4 }}>{number(value)}</div>
          </div>
        ))}
      </div>
      <div style={{ ...panel, overflowX: 'auto' }}>
        <div style={{ color: '#f1f5fb', fontSize: 12, fontWeight: 700, marginBottom: 9 }}>Per-site change summary</div>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10, color: '#a8b6ca', minWidth: 520 }}>
          <thead><tr style={{ color: '#71829a', textAlign: 'left' }}>
            {['Site', 'Baseline', 'Current APs', 'Added', 'Removed', 'Changed', 'Latest snapshot'].map(label => <th key={label} style={{ padding: '7px 8px', borderBottom: '1px solid #29374d' }}>{label}</th>)}
          </tr></thead>
          <tbody>
            {sites.map(site => <tr key={site.site_id}>
              <td style={{ padding: '8px', borderBottom: '1px solid #18263a', fontWeight: 700 }}>{site.site_id}</td>
              <td style={{ padding: '8px', borderBottom: '1px solid #18263a', color: site.baseline_status === 'compared' ? '#56d6ae' : '#f2c36b' }}>{site.baseline_status === 'compared' ? 'Compared' : 'Initial'}</td>
              <td style={{ padding: '8px', borderBottom: '1px solid #18263a' }}>{number(site.current_access_point_count)}</td>
              <td style={{ padding: '8px', borderBottom: '1px solid #18263a' }}>{number(site.change_counts?.added_access_points)}</td>
              <td style={{ padding: '8px', borderBottom: '1px solid #18263a' }}>{number(site.change_counts?.removed_access_points)}</td>
              <td style={{ padding: '8px', borderBottom: '1px solid #18263a' }}>{number(site.change_counts?.changed_access_points)}</td>
              <td style={{ padding: '8px', borderBottom: '1px solid #18263a', whiteSpace: 'nowrap' }}>{site.current_captured_at || 'Unknown'}</td>
            </tr>)}
            {!sites.length ? <tr><td colSpan="7" style={{ padding: 12, color: '#71829a' }}>No stored site snapshots yet. Save an inventory snapshot for one or more sites first.</td></tr> : null}
          </tbody>
        </table>
      </div>
      <div style={panel}>
        <div style={{ color: '#f1f5fb', fontSize: 12, fontWeight: 700, marginBottom: 8 }}>Cross-site BSSID reuse</div>
        {collisions.length ? <div style={{ display: 'grid', gap: 7 }}>
          {collisions.map(item => <div key={item.bssid} style={{ padding: 9, background: '#172234', borderRadius: 7, fontSize: 10 }}>
            <div style={{ color: '#f2c36b', fontWeight: 700 }}>{item.bssid}</div>
            <div style={{ color: '#a8b6ca', marginTop: 3 }}>Seen at: {item.site_ids.join(', ')}</div>
          </div>)}
        </div> : <div style={{ color: '#56d6ae', fontSize: 10 }}>No valid BSSID was observed at more than one site in the selected snapshots.</div>}
      </div>
      <div style={{ color: '#71829a', fontSize: 10, lineHeight: 1.5 }}>{data?.note}</div>
    </div>
  );
}
