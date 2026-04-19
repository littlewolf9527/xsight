// Shared decoder config used by TrafficChart + TrafficOverview.
//
// Each decoder has:
//   key       - API identifier (matches shared/decoder/decoder.go Names[i])
//   label     - human-readable legend name
//   color     - hex for chart series + legend swatch
//   fixed     - true: reads from pre-v1.3 flat column (tcp_pps / etc.)
//               false: reads from v1.3 extra_decoder_pps JSONB map
//   hasBPS    - whether the decoder has a BPS counterpart (tcp_syn has no BPS)
//   ppsField  - flat API field name (fixed decoders only)
//   bpsField  - flat API field name (fixed decoders only, null if no BPS)
//   group     - grouping label for the filter popover

export const ALL_DECODERS = [
  // L4 standard (pre-v1.3)
  { key: 'tcp',          label: 'TCP',          color: '#e6a23c', fixed: true,  hasBPS: true,  ppsField: 'tcp_pps',     bpsField: 'tcp_bps',  group: 'L4' },
  { key: 'tcp_syn',      label: 'TCP SYN',      color: '#f56c6c', fixed: true,  hasBPS: false, ppsField: 'tcp_syn_pps', bpsField: null,        group: 'L4' },
  { key: 'udp',          label: 'UDP',          color: '#67c23a', fixed: true,  hasBPS: true,  ppsField: 'udp_pps',     bpsField: 'udp_bps',  group: 'L4' },
  { key: 'icmp',         label: 'ICMP',         color: '#909399', fixed: true,  hasBPS: true,  ppsField: 'icmp_pps',    bpsField: 'icmp_bps', group: 'L4' },
  { key: 'fragment',     label: 'Fragment',     color: '#c084fc', fixed: true,  hasBPS: true,  ppsField: 'frag_pps',    bpsField: 'frag_bps', group: 'L4' },
  // TCP flag family (v1.3)
  { key: 'tcp_ack',      label: 'TCP ACK',      color: '#fb7185', fixed: false, hasBPS: true,  group: 'TCP flags' },
  { key: 'tcp_rst',      label: 'TCP RST',      color: '#f97316', fixed: false, hasBPS: true,  group: 'TCP flags' },
  { key: 'tcp_fin',      label: 'TCP FIN',      color: '#84cc16', fixed: false, hasBPS: true,  group: 'TCP flags' },
  // Other IP protocols (v1.3)
  { key: 'gre',          label: 'GRE',          color: '#06b6d4', fixed: false, hasBPS: true,  group: 'IP proto' },
  { key: 'esp',          label: 'ESP',          color: '#8b5cf6', fixed: false, hasBPS: true,  group: 'IP proto' },
  { key: 'igmp',         label: 'IGMP',         color: '#ec4899', fixed: false, hasBPS: true,  group: 'IP proto' },
  { key: 'ip_other',     label: 'IP (other)',   color: '#14b8a6', fixed: false, hasBPS: true,  group: 'IP proto' },
  // Anomaly (v1.3)
  { key: 'bad_fragment', label: 'Bad Fragment', color: '#dc2626', fixed: false, hasBPS: true,  group: 'Anomaly' },
  { key: 'invalid',      label: 'Invalid',      color: '#78350f', fixed: false, hasBPS: true,  group: 'Anomaly' },
]

export const DECODER_GROUPS = [
  { label: 'L4 standard', decoders: ALL_DECODERS.filter(d => d.group === 'L4') },
  { label: 'TCP flags (v1.3)', decoders: ALL_DECODERS.filter(d => d.group === 'TCP flags') },
  { label: 'IP proto (v1.3)', decoders: ALL_DECODERS.filter(d => d.group === 'IP proto') },
  { label: 'Anomaly (v1.3)', decoders: ALL_DECODERS.filter(d => d.group === 'Anomaly') },
]

// Default visible = L4 minus fragment + tcp_fin (per user preference).
// Chosen because tcp_fin showed real live traffic in v1.3 deploy — reflects
// observed use-case, not abstract design.
export const DEFAULT_VISIBLE = ['tcp', 'udp', 'icmp', 'tcp_syn', 'tcp_fin']

export const LOCALSTORAGE_KEY = 'xsight.chart.visibleDecoders'

export function loadVisibleFromStorage() {
  try {
    const raw = localStorage.getItem(LOCALSTORAGE_KEY)
    if (!raw) return [...DEFAULT_VISIBLE]
    const parsed = JSON.parse(raw)
    if (!Array.isArray(parsed)) return [...DEFAULT_VISIBLE]
    const valid = parsed.filter(k => ALL_DECODERS.some(d => d.key === k))
    return valid.length > 0 ? valid : [...DEFAULT_VISIBLE]
  } catch {
    return [...DEFAULT_VISIBLE]
  }
}

export function saveVisibleToStorage(keys) {
  try { localStorage.setItem(LOCALSTORAGE_KEY, JSON.stringify(keys)) } catch { /* ignore quota */ }
}

// Extract the PPS or BPS value for a single decoder from an API point.
// Handles both fixed columns and the v1.3 extra_decoder_pps/bps JSONB maps.
// Returns 0 when the decoder is not applicable (e.g. BPS query for tcp_syn).
export function decoderValue(point, decoder, isPPS) {
  if (decoder.fixed) {
    const field = isPPS ? decoder.ppsField : decoder.bpsField
    if (!field) return 0
    return point[field] || 0
  }
  const map = isPPS ? point.extra_decoder_pps : point.extra_decoder_bps
  if (!map) return 0
  return map[decoder.key] || 0
}

// Whether any of the currently-visible decoders requires the include_extras API flag.
export function visibleNeedsExtras(visibleKeys) {
  return visibleKeys.some(k => {
    const d = ALL_DECODERS.find(x => x.key === k)
    return d && !d.fixed
  })
}
