import { useMemo, useState } from 'react';
import { Eye, EyeOff, ZoomIn, ZoomOut } from 'lucide-react';

const relationshipStyles = {
  wired_uplink: { stroke: '#38bdf8', dash: undefined, label: 'Wired uplink' },
  wireless_backhaul: { stroke: '#a78bfa', dash: '8 4', label: 'Wireless backhaul' },
  mesh_backhaul: { stroke: '#34d399', dash: '3 4', label: 'Mesh backhaul' },
  rf_neighbor: { stroke: '#71829a', dash: '2 7', label: 'RF neighbour' },
};

const panel = { background: '#111624', border: '1px solid #29374d', borderRadius: 10, padding: 14 };

export default function SiteTopologyGraph({ data }) {
  const [selectedAp, setSelectedAp] = useState('');
  const [showRf, setShowRf] = useState(true);
  const [showLabels, setShowLabels] = useState(true);
  const [zoom, setZoom] = useState(1);

  const nodes = Array.isArray(data?.nodes) ? data.nodes : [];
  const edges = Array.isArray(data?.edges) ? data.edges : [];
  const groups = Array.isArray(data?.site_groups) ? data.site_groups : [];
  const nodeIndex = useMemo(() => new Map(nodes.map(node => [node.ap_id, node])), [nodes]);
  const selected = nodeIndex.get(selectedAp) || null;
  const visibleEdges = edges.filter(edge => showRf || edge.relationship !== 'rf_neighbor');

  if (!nodes.length) {
    return <div style={{ ...panel, color: '#a8b6ca', fontSize: 12 }}>No access points were supplied. Add AP records and run the feature again to build a topology view.</div>;
  }

  const width = Number(data?.canvas?.width) || 800;
  const height = Number(data?.canvas?.height) || 360;
  const number = value => new Intl.NumberFormat().format(Number(value) || 0);
  const buttonStyle = {
    display: 'inline-flex',
    alignItems: 'center',
    gap: 6,
    padding: '7px 9px',
    background: '#182235',
    border: '1px solid #263956',
    color: '#cbd5e1',
    borderRadius: 7,
    fontSize: 11,
    cursor: 'pointer',
  };

  return (
    <div style={{ ...panel, minWidth: 0 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 12 }}>
        <div>
          <div style={{ color: '#ff8359', fontSize: 12, fontWeight: 750 }}>Site topology map</div>
          <div style={{ color: '#71829a', fontSize: 10, marginTop: 3 }}>
            {number(data?.summary?.access_point_count)} APs · {number(data?.summary?.site_count)} sites · {number(data?.summary?.link_count)} links
          </div>
        </div>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          <button type="button" style={buttonStyle} onClick={() => setShowRf(value => !value)} aria-pressed={showRf}>
            {showRf ? <Eye size={13}/> : <EyeOff size={13}/>} RF links
          </button>
          <button type="button" style={buttonStyle} onClick={() => setShowLabels(value => !value)} aria-pressed={showLabels}>
            {showLabels ? 'Hide labels' : 'Show labels'}
          </button>
          <button type="button" style={buttonStyle} onClick={() => setZoom(value => Math.max(0.55, Math.round((value - 0.15) * 100) / 100))} aria-label="Zoom out" disabled={zoom <= 0.55}>
            <ZoomOut size={13}/>
          </button>
          <button type="button" style={buttonStyle} onClick={() => setZoom(value => Math.min(1.8, Math.round((value + 0.15) * 100) / 100))} aria-label="Zoom in" disabled={zoom >= 1.8}>
            <ZoomIn size={13}/>
          </button>
        </div>
      </div>

      <div style={{ overflow: 'auto', maxHeight: 680, border: '1px solid #29374d', borderRadius: 8, background: '#080e19' }}>
        <svg
          width={Math.max(560, width * zoom)}
          height={Math.max(300, height * zoom)}
          viewBox={`0 0 ${width} ${height}`}
          role="group"
          aria-label="Interactive access point topology. Select a node for details."
          style={{ display: 'block', minWidth: '100%' }}
        >
          <defs>
            <marker id="site-topology-arrow" markerWidth="7" markerHeight="7" refX="5" refY="3" orient="auto">
              <path d="M0,0 L6,3 L0,6" fill="none" stroke="#7890a8" strokeWidth="1"/>
            </marker>
          </defs>
          {groups.map(group => (
            <g key={group.site_id}>
              <rect x="12" y={group.y} width={width - 24} height={group.height} rx="13" fill="#101c2c" stroke="#263956"/>
              <text x="28" y={group.y + 25} fill="#7dd3fc" fontSize="12" fontWeight="700">{group.site_id}</text>
              <text x={width - 28} y={group.y + 25} textAnchor="end" fill="#71829a" fontSize="10">
                {number(group.access_point_count)} APs · {number(group.gateway_ap_ids?.length)} gateways
              </text>
            </g>
          ))}
          {visibleEdges.map((edge, index) => {
            const from = nodeIndex.get(edge.from_ap_id);
            const to = nodeIndex.get(edge.to_ap_id);
            if (!from || !to) return null;
            const style = relationshipStyles[edge.relationship] || relationshipStyles.wired_uplink;
            const x1 = from.x + 54;
            const y1 = from.y;
            const x2 = to.x - 54;
            const y2 = to.y;
            return (
              <g key={`${edge.from_ap_id}-${edge.to_ap_id}-${edge.relationship}-${index}`}>
                <line
                  x1={x1} y1={y1} x2={x2} y2={y2}
                  stroke={style.stroke}
                  strokeWidth={edge.cross_site ? 1.5 : 2}
                  strokeDasharray={edge.cross_site ? '5 5' : style.dash}
                  opacity={edge.cross_site ? 0.58 : 0.9}
                  markerEnd={edge.cross_site ? undefined : 'url(#site-topology-arrow)'}
                />
                <title>{`${style.label}${edge.cross_site ? ' · cross-site' : ''}: ${edge.from_ap_id} → ${edge.to_ap_id}`}</title>
              </g>
            );
          })}
          {nodes.map(node => {
            const active = selectedAp === node.ap_id;
            const fill = node.is_gateway ? '#123b45' : node.reachable_from_gateway === false ? '#38252d' : '#14243a';
            const stroke = active ? '#f8fafc' : node.is_gateway ? '#ff8359' : node.reachable_from_gateway === false ? '#f2c36b' : '#52708e';
            return (
              <g
                key={node.ap_id}
                transform={`translate(${node.x} ${node.y})`}
                role="button"
                tabIndex={0}
                aria-label={`${node.label}, ${node.site_id}${node.is_gateway ? ', gateway' : ''}`}
                aria-pressed={active}
                onClick={() => setSelectedAp(active ? '' : node.ap_id)}
                onKeyDown={event => {
                  if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    setSelectedAp(active ? '' : node.ap_id);
                  }
                }}
                style={{ cursor: 'pointer', outline: 'none' }}
              >
                <rect x="-54" y="-25" width="108" height="50" rx="9" fill={fill} stroke={stroke} strokeWidth={active ? 2.5 : 1.5}/>
                <circle cx="-40" cy="0" r="4" fill={node.is_gateway ? '#ff8359' : '#a8b6ca'}/>
                {showLabels ? (
                  <>
                    <text x="6" y="-3" textAnchor="middle" fill="#f1f5fb" fontSize="10" fontWeight="700">{node.label.length > 15 ? `${node.label.slice(0, 13)}…` : node.label}</text>
                    <text x="6" y="12" textAnchor="middle" fill="#8297b3" fontSize="8">{node.is_gateway ? 'GATEWAY' : node.reachable_from_gateway === false ? 'NO PATH' : `DEPTH ${node.layout_depth}`}</text>
                  </>
                ) : (
                  <text x="6" y="4" textAnchor="middle" fill="#f1f5fb" fontSize="10" fontWeight="700">{node.ap_id.slice(0, 12)}</text>
                )}
                <title>{node.ap_id} · {node.site_id}</title>
              </g>
            );
          })}
        </svg>
      </div>

      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 10, color: '#a8b6ca', fontSize: 10 }}>
        {Object.entries(relationshipStyles).filter(([key]) => showRf || key !== 'rf_neighbor').map(([key, style]) => (
          <span key={key} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 18, borderTop: `2px ${style.dash ? 'dashed' : 'solid'} ${style.stroke}` }}/>
            {style.label}
          </span>
        ))}
        <span>Dashed cross-site links are shown without joining site layouts.</span>
      </div>

      {selected ? (
        <div style={{ marginTop: 12, padding: 12, border: '1px solid #263956', borderRadius: 8, background: '#101827' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10 }}>
            <strong style={{ color: '#f1f5fb', fontSize: 12 }}>{selected.label}</strong>
            <button type="button" onClick={() => setSelectedAp('')} style={{ ...buttonStyle, padding: '3px 7px' }}>Clear</button>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 8, marginTop: 9 }}>
            <div><div style={{ color: '#71829a', fontSize: 9 }}>AP ID</div><div style={{ color: '#cbd5e1', fontSize: 11, overflowWrap: 'anywhere' }}>{selected.ap_id}</div></div>
            <div><div style={{ color: '#71829a', fontSize: 9 }}>SITE</div><div style={{ color: '#cbd5e1', fontSize: 11 }}>{selected.site_id}</div></div>
            <div><div style={{ color: '#71829a', fontSize: 9 }}>GATEWAY PATH</div><div style={{ color: '#cbd5e1', fontSize: 11 }}>{selected.is_gateway ? 'Gateway' : selected.reachable_from_gateway === true ? `${selected.layout_depth} hops from gateway` : selected.reachable_from_gateway === false ? 'No supplied path' : 'Unknown (no gateway supplied)'}</div></div>
            <div><div style={{ color: '#71829a', fontSize: 9 }}>COMPONENT ROOT</div><div style={{ color: '#cbd5e1', fontSize: 11, overflowWrap: 'anywhere' }}>{selected.component_root}</div></div>
          </div>
        </div>
      ) : (
        <div style={{ marginTop: 10, color: '#71829a', fontSize: 10 }}>Select an access point to inspect its site and gateway-path evidence.</div>
      )}
      <div style={{ marginTop: 10, color: '#71829a', fontSize: 10, lineHeight: 1.5 }}>{data?.note}</div>
    </div>
  );
}
