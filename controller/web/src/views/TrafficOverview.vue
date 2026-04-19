<template>
  <div>
    <h2 style="margin-bottom: 20px;">{{ $t('nav.trafficOverview') }}</h2>

    <!-- Section 1: Stats cards -->
    <el-row :gutter="20">
      <el-col :span="6">
        <el-card shadow="hover">
          <div class="stat-card">
            <div class="stat-title">{{ $t('traffic.totalPps') }}</div>
            <div v-if="direction === 'both' && overviewOut" class="stat-value">
              {{ fmtVal(overview.total_pps) }} <span class="dir-label">↓</span>
              <span class="dir-sep">/</span>
              {{ fmtVal(overviewOut.total_pps) }} <span class="dir-label">↑</span>
            </div>
            <div v-else class="stat-value">{{ fmtVal(overview.total_pps) }}</div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover">
          <div class="stat-card">
            <div class="stat-title">{{ $t('traffic.totalBps') }}</div>
            <div v-if="direction === 'both' && overviewOut" class="stat-value">
              {{ fmtBps(overview.total_bps) }} <span class="dir-label">↓</span>
              <span class="dir-sep">/</span>
              {{ fmtBps(overviewOut.total_bps) }} <span class="dir-label">↑</span>
            </div>
            <div v-else class="stat-value">{{ fmtBps(overview.total_bps) }}</div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover">
          <div class="stat-card">
            <div class="stat-title">{{ $t('traffic.activeNodes') }}</div>
            <div class="stat-value">{{ overview.node_count }}</div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover">
          <div class="stat-card">
            <div class="stat-title">{{ $t('traffic.activePrefixes') }}</div>
            <div v-if="direction === 'both' && overviewOut" class="stat-value">
              {{ overview.active_prefixes }} <span class="dir-label">↓</span>
              <span class="dir-sep">/</span>
              {{ overviewOut.active_prefixes }} <span class="dir-label">↑</span>
            </div>
            <div v-else class="stat-value">{{ overview.active_prefixes }}</div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- Direction toggle + Node filter -->
    <div style="margin-top: 16px; margin-bottom: -4px; display: flex; align-items: center; gap: 16px;">
      <el-radio-group v-model="direction" size="small" @change="onDirectionChange">
        <el-radio-button label="receives">↓ Inbound</el-radio-button>
        <el-radio-button label="sends">↑ Outbound</el-radio-button>
        <el-radio-button label="both">Both</el-radio-button>
      </el-radio-group>
      <el-select v-model="filterNodeId" size="small" style="width: 220px;" clearable :placeholder="$t('traffic.allNodes')" @change="onNodeFilterChange">
        <el-option :label="$t('traffic.allNodes')" value="" />
        <el-option v-for="n in nodeList" :key="n.id" :label="`${n.id} (${n.mode === 'flow' ? 'Flow' : 'XDP'})`" :value="n.id" />
      </el-select>
    </div>

    <!-- Section 2: Total traffic trend chart -->
    <el-card style="margin-top: 20px;">
      <template #header>
        <div style="display: flex; align-items: center; justify-content: space-between;">
          <span>{{ $t('traffic.totalTrend') }}</span>
          <div style="display: flex; gap: 8px;">
            <el-radio-group v-model="timeRange" size="small" @change="loadTimeseries">
              <el-radio-button label="1h">1H</el-radio-button>
              <el-radio-button label="6h">6H</el-radio-button>
              <el-radio-button label="24h">24H</el-radio-button>
            </el-radio-group>
            <el-radio-group v-model="metric" size="small" @change="renderChart">
              <el-radio-button label="pps">PPS</el-radio-button>
              <el-radio-button label="bps">BPS</el-radio-button>
            </el-radio-group>
            <el-popover placement="bottom-end" :width="280" trigger="click">
              <template #reference>
                <el-button size="small">Decoders ({{ visibleDecoders.length }}/{{ ALL_DECODERS.length }})</el-button>
              </template>
              <div style="max-height: 380px; overflow-y: auto;">
                <div style="display: flex; gap: 4px; margin-bottom: 8px;">
                  <el-button size="small" @click="selectAll">All</el-button>
                  <el-button size="small" @click="selectNone">None</el-button>
                  <el-button size="small" @click="resetDefaults">Default</el-button>
                </div>
                <el-divider style="margin: 4px 0;" />
                <el-checkbox-group v-model="visibleDecoders" @change="onFilterChange">
                  <div v-for="g in DECODER_GROUPS" :key="g.label" style="margin-bottom: 8px;">
                    <div style="font-size: 11px; color: #909399; margin-bottom: 2px;">{{ g.label }}</div>
                    <div style="display: flex; flex-direction: column; gap: 2px;">
                      <el-checkbox
                        v-for="d in g.decoders"
                        :key="d.key"
                        :value="d.key"
                        :disabled="metric === 'bps' && !d.hasBPS"
                      >
                        <span :style="{ color: d.color, fontWeight: 600 }">■</span>
                        {{ d.label }}
                        <span v-if="metric === 'bps' && !d.hasBPS" style="color: #c0c4cc; font-size: 10px;">(PPS only)</span>
                      </el-checkbox>
                    </div>
                  </div>
                </el-checkbox-group>
              </div>
            </el-popover>
          </div>
        </div>
      </template>
      <v-chart v-if="chartOption" :option="chartOption" :update-options="{ notMerge: true }" autoresize :style="{ height: direction === 'both' ? '500px' : '300px', width: '100%' }" />
      <el-empty v-else :description="tsLoading ? $t('common.loading') : $t('common.noData')" />
    </el-card>

    <!-- Section 3: Top prefix ranking -->
    <el-card style="margin-top: 20px;">
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <span>{{ $t('traffic.topPrefixes') }}</span>
          <el-select v-model="topPrefixLimit" size="small" style="width: 100px;" @change="loadOverview">
            <el-option :label="'Top 20'" :value="20" />
            <el-option :label="'Top 50'" :value="50" />
            <el-option :label="'Top 100'" :value="100" />
          </el-select>
        </div>
      </template>
      <!-- Single direction table -->
      <el-table v-if="direction !== 'both'" :data="topPrefixData" stripe size="small" :empty-text="$t('common.noData')"
        :default-sort="{ prop: 'pps', order: 'descending' }">
        <el-table-column prop="prefix" label="Prefix" min-width="180" />
        <el-table-column prop="pps" label="PPS" sortable width="120">
          <template #default="{ row }">{{ fmtVal(row.pps) }}</template>
        </el-table-column>
        <el-table-column prop="bps" label="BPS" sortable width="120">
          <template #default="{ row }">{{ fmtBps(row.bps) }}</template>
        </el-table-column>
        <el-table-column prop="tcp_pps" label="TCP PPS" sortable width="120">
          <template #default="{ row }">{{ fmtVal(row.tcp_pps) }}</template>
        </el-table-column>
        <el-table-column prop="udp_pps" label="UDP PPS" sortable width="120">
          <template #default="{ row }">{{ fmtVal(row.udp_pps) }}</template>
        </el-table-column>
        <el-table-column prop="icmp_pps" label="ICMP PPS" sortable width="120">
          <template #default="{ row }">{{ fmtVal(row.icmp_pps) }}</template>
        </el-table-column>
        <el-table-column prop="tcp_bps" label="TCP BPS" sortable width="120">
          <template #default="{ row }">{{ fmtBps(row.tcp_bps) }}</template>
        </el-table-column>
        <el-table-column prop="udp_bps" label="UDP BPS" sortable width="120">
          <template #default="{ row }">{{ fmtBps(row.udp_bps) }}</template>
        </el-table-column>
        <el-table-column prop="icmp_bps" label="ICMP BPS" sortable width="120">
          <template #default="{ row }">{{ fmtBps(row.icmp_bps) }}</template>
        </el-table-column>
        <el-table-column label="Nodes" width="200">
          <template #default="{ row }">
            <template v-if="Array.isArray(row.nodes)">
              <el-tag v-for="n in row.nodes" :key="n.id" :type="n.mode === 'flow' ? 'warning' : 'primary'" size="small" style="margin-right: 4px;">
                {{ n.id }}
              </el-tag>
            </template>
            <template v-else>{{ row.nodes }}</template>
          </template>
        </el-table-column>
      </el-table>

      <!-- Both mode: IN / OUT dual display -->
      <el-table v-else :data="topPrefixData" stripe size="small" :empty-text="$t('common.noData')"
        :default-sort="{ prop: 'pps', order: 'descending' }">
        <el-table-column prop="prefix" label="Prefix" min-width="180" />
        <el-table-column prop="pps" label="PPS" sortable width="200">
          <template #default="{ row }">
            <span>{{ fmtVal(row.pps_in) }}</span> <span class="dir-label">↓</span>
            <span class="dir-sep">/</span>
            <span>{{ fmtVal(row.pps_out) }}</span> <span class="dir-label">↑</span>
          </template>
        </el-table-column>
        <el-table-column prop="bps" label="BPS" sortable width="220">
          <template #default="{ row }">
            <span>{{ fmtBps(row.bps_in) }}</span> <span class="dir-label">↓</span>
            <span class="dir-sep">/</span>
            <span>{{ fmtBps(row.bps_out) }}</span> <span class="dir-label">↑</span>
          </template>
        </el-table-column>
        <el-table-column label="TCP PPS" width="200">
          <template #default="{ row }">
            {{ fmtVal(row.tcp_pps_in) }} <span class="dir-label">↓</span>
            <span class="dir-sep">/</span>
            {{ fmtVal(row.tcp_pps_out) }} <span class="dir-label">↑</span>
          </template>
        </el-table-column>
        <el-table-column label="UDP PPS" width="200">
          <template #default="{ row }">
            {{ fmtVal(row.udp_pps_in) }} <span class="dir-label">↓</span>
            <span class="dir-sep">/</span>
            {{ fmtVal(row.udp_pps_out) }} <span class="dir-label">↑</span>
          </template>
        </el-table-column>
        <el-table-column label="Nodes" width="200">
          <template #default="{ row }">
            <template v-if="Array.isArray(row.nodes)">
              <el-tag v-for="n in row.nodes" :key="n.id" :type="n.mode === 'flow' ? 'warning' : 'primary'" size="small" style="margin-right: 4px;">
                {{ n.id }}
              </el-tag>
            </template>
            <template v-else>{{ row.nodes }}</template>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { LineChart } from 'echarts/charts'
import { GridComponent, TooltipComponent, LegendComponent, DataZoomComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import api from '../api'
import {
  ALL_DECODERS,
  DECODER_GROUPS,
  DEFAULT_VISIBLE,
  loadVisibleFromStorage,
  saveVisibleToStorage,
  decoderValue,
  visibleNeedsExtras,
} from '../config/decoders'

use([LineChart, GridComponent, TooltipComponent, LegendComponent, DataZoomComponent, CanvasRenderer])

const overview = ref({ total_pps: 0, total_bps: 0, node_count: 0, active_prefixes: 0, top_prefixes: [] })
const overviewOut = ref(null) // outbound overview for Both mode
const overviewMerged = ref(null) // merged overview for Both mode (deduped nodes)
const topPrefixLimit = ref(20)
const timeRange = ref('1h')
const metric = ref('pps')
const direction = ref('receives')
const filterNodeId = ref('')
const nodeList = ref([])
const chartOption = ref(null)
const tsLoading = ref(false)
const visibleDecoders = ref(loadVisibleFromStorage())
let cachedPoints = null
let cachedInbound = null
let cachedOutbound = null
let cachedHasExtras = false

const needsExtras = computed(() => visibleNeedsExtras(visibleDecoders.value))

function selectAll()     { visibleDecoders.value = ALL_DECODERS.map(d => d.key); onFilterChange() }
function selectNone()    { visibleDecoders.value = []; onFilterChange() }
function resetDefaults() { visibleDecoders.value = [...DEFAULT_VISIBLE]; onFilterChange() }

async function onFilterChange() {
  saveVisibleToStorage(visibleDecoders.value)
  if (needsExtras.value !== cachedHasExtras) {
    await loadTimeseries()
  } else {
    renderChart()
  }
}

function buildSeries(points, isPPS) {
  const out = []
  for (const key of visibleDecoders.value) {
    const d = ALL_DECODERS.find(x => x.key === key)
    if (!d) continue
    if (!isPPS && !d.hasBPS) continue
    out.push({
      name: d.label,
      color: d.color,
      data: points.map(p => decoderValue(p, d, isPPS)),
      width: 1,
    })
  }
  return out
}
// Merged prefix table for Both mode: combine in/out top_prefixes
const topPrefixData = computed(() => {
  if (direction.value !== 'both' || !overviewOut.value) {
    return overview.value.top_prefixes || []
  }
  const inList = overview.value.top_prefixes || []
  const outList = overviewOut.value.top_prefixes || []
  const mergedList = overviewMerged.value?.top_prefixes || []
  const outMap = {}
  const mergedMap = {}
  for (const p of outList) { outMap[p.prefix] = p }
  for (const p of mergedList) { mergedMap[p.prefix] = p }
  // Merge: start from inbound list, attach outbound values + deduped nodes from merged API
  const merged = inList.map(p => {
    const out = outMap[p.prefix] || {}
    const m = mergedMap[p.prefix] || {}
    return {
      prefix: p.prefix,
      pps_in: p.pps, pps_out: out.pps || 0,
      bps_in: p.bps, bps_out: out.bps || 0,
      tcp_pps_in: p.tcp_pps, tcp_pps_out: out.tcp_pps || 0,
      udp_pps_in: p.udp_pps, udp_pps_out: out.udp_pps || 0,
      icmp_pps_in: p.icmp_pps, icmp_pps_out: out.icmp_pps || 0,
      nodes: m.nodes || p.nodes, // use deduped nodes from merged API
      pps: p.pps, bps: p.bps,
    }
  })
  // Add prefixes only in outbound
  const inSet = new Set(inList.map(p => p.prefix))
  for (const p of outList) {
    if (!inSet.has(p.prefix)) {
      const m = mergedMap[p.prefix] || {}
      merged.push({
        prefix: p.prefix,
        pps_in: 0, pps_out: p.pps,
        bps_in: 0, bps_out: p.bps,
        tcp_pps_in: 0, tcp_pps_out: p.tcp_pps,
        udp_pps_in: 0, udp_pps_out: p.udp_pps,
        icmp_pps_in: 0, icmp_pps_out: p.icmp_pps,
        nodes: m.nodes || p.nodes,
        pps: 0, bps: 0,
      })
    }
  }
  return merged
})

let overviewTimer = null
let overviewLoading = false

function fmtVal(v) {
  if (v >= 1e9) return (v / 1e9).toFixed(1) + 'G'
  if (v >= 1e6) return (v / 1e6).toFixed(1) + 'M'
  if (v >= 1e3) return (v / 1e3).toFixed(0) + 'K'
  return v
}

function fmtBps(v) {
  if (v >= 1e12) return (v / 1e12).toFixed(1) + 'T'
  if (v >= 1e9) return (v / 1e9).toFixed(1) + 'G'
  if (v >= 1e6) return (v / 1e6).toFixed(1) + 'M'
  if (v >= 1e3) return (v / 1e3).toFixed(0) + 'K'
  return v
}

// Align two timeseries by timestamp — union all timestamps, fill gaps with bare point.
// decoderValue() handles missing fields by returning 0, so we don't prefill flat columns.
function alignTimeseries(inPts, outPts) {
  const inMap = new Map()
  const outMap = new Map()
  const allTimes = new Set()
  for (const p of inPts) { inMap.set(p.time, p); allTimes.add(p.time) }
  for (const p of outPts) { outMap.set(p.time, p); allTimes.add(p.time) }
  const sorted = [...allTimes].sort()
  return {
    times: sorted,
    inPts: sorted.map(t => inMap.get(t) || { time: t }),
    outPts: sorted.map(t => outMap.get(t) || { time: t }),
  }
}

function onDirectionChange() {
  loadOverview()
  loadTimeseries()
}

function onNodeFilterChange() {
  loadOverview()
  loadTimeseries()
}

async function loadNodeList() {
  try {
    const nodes = await api.get('/nodes')
    nodeList.value = nodes.filter(n => n.online)
  } catch (e) { console.error('load nodes error:', e) }
}

async function loadOverview() {
  if (overviewLoading) return
  overviewLoading = true
  try {
    const nodeParam = filterNodeId.value || undefined
    if (direction.value === 'both') {
      // Both: fetch in + out + merged for correct shared fields (node_count, nodes dedup)
      const [inData, outData, mergedData] = await Promise.all([
        api.get('/stats/overview', { params: { limit: topPrefixLimit.value, direction: 'receives', node_id: nodeParam } }),
        api.get('/stats/overview', { params: { limit: topPrefixLimit.value, direction: 'sends', node_id: nodeParam } }),
        api.get('/stats/overview', { params: { limit: topPrefixLimit.value, direction: 'both', node_id: nodeParam } }),
      ])
      overview.value = inData
      overview.value.node_count = mergedData.node_count // use deduped node count
      overviewOut.value = outData
      overviewMerged.value = mergedData
    } else {
      const data = await api.get('/stats/overview', { params: { limit: topPrefixLimit.value, direction: direction.value, node_id: nodeParam } })
      overview.value = data
      overviewOut.value = null
      overviewMerged.value = null
    }
  } catch (e) { console.error('overview error:', e) }
  finally { overviewLoading = false }
}

async function loadTimeseries() {
  tsLoading.value = true
  try {
    const hours = { '1h': 1, '6h': 6, '24h': 24 }[timeRange.value] || 1
    const resolution = hours <= 6 ? '5min' : '1h'
    const from = new Date(Date.now() - hours * 3600000).toISOString()
    const wantExtras = needsExtras.value
    cachedHasExtras = wantExtras
    const baseParams = { from, resolution }
    if (wantExtras) baseParams.include_extras = 'true'

    if (direction.value === 'both') {
      const [inPts, outPts] = await Promise.all([
        api.get('/stats/total-timeseries', { params: { ...baseParams, direction: 'receives' } }),
        api.get('/stats/total-timeseries', { params: { ...baseParams, direction: 'sends' } }),
      ])
      cachedInbound = inPts && inPts.length ? inPts : null
      cachedOutbound = outPts && outPts.length ? outPts : null
      cachedPoints = null
    } else {
      const points = await api.get('/stats/total-timeseries', {
        params: { ...baseParams, direction: direction.value }
      })
      cachedPoints = points && points.length ? points : null
      cachedInbound = null
      cachedOutbound = null
    }
    renderChart()
  } catch (e) {
    console.error('total timeseries error:', e)
    cachedPoints = null
    cachedInbound = null
    cachedOutbound = null
    chartOption.value = null
  } finally {
    tsLoading.value = false
  }
}

function renderChart() {
  const theme = document.documentElement.getAttribute('data-theme')
  const isAmber = theme === 'amber'
  const isPPS = metric.value === 'pps'
  const fmt = isPPS ? fmtVal : fmtBps
  const primaryColor = isAmber ? '#1a8a28' : '#533afd'

  // === Both mode: dual grid with per-decoder ===
  if (direction.value === 'both') {
    if (!cachedInbound && !cachedOutbound) { chartOption.value = null; return }
    const aligned = alignTimeseries(cachedInbound || [], cachedOutbound || [])
    const times = aligned.times.map(t => new Date(t).toLocaleTimeString())
    const totalField = isPPS ? 'pps' : 'bps'
    const totalName = isPPS ? 'PPS' : 'BPS'
    const inTotal = aligned.inPts.map(p => p[totalField] || 0)
    const outTotal = aligned.outPts.map(p => p[totalField] || 0)
    const inDecoderSeries = buildSeries(aligned.inPts, isPPS)
    const outDecoderSeries = buildSeries(aligned.outPts, isPPS)
    const sharedMax = Math.max(Math.max(...inTotal, 0), Math.max(...outTotal, 0)) * 1.1 || 1
    const axisLabelStyle = { color: '#909399', fontSize: 10 }
    const splitLineStyle = { lineStyle: { color: '#e4e7ed' } }

    // Inbound and outbound share the SAME series name per decoder so the legend
    // toggles both at once. Grid/axis indexes handle visual separation. Do NOT
    // alias with a trailing space — that broke legend toggling in the first
    // v1.3.2 iteration.
    const allSeries = [
      { name: totalName, type: 'line', data: inTotal, smooth: true, xAxisIndex: 0, yAxisIndex: 0, lineStyle: { width: 2 }, symbol: 'none', itemStyle: { color: primaryColor } },
      ...inDecoderSeries.map(s => ({ name: s.name, type: 'line', data: s.data, smooth: true, xAxisIndex: 0, yAxisIndex: 0, lineStyle: { width: s.width }, symbol: 'none', itemStyle: { color: s.color } })),
      { name: totalName, type: 'line', data: outTotal, smooth: true, xAxisIndex: 1, yAxisIndex: 1, lineStyle: { width: 2 }, symbol: 'none', itemStyle: { color: primaryColor } },
      ...outDecoderSeries.map(s => ({ name: s.name, type: 'line', data: s.data, smooth: true, xAxisIndex: 1, yAxisIndex: 1, lineStyle: { width: s.width }, symbol: 'none', itemStyle: { color: s.color } })),
    ]
    const legendNames = [totalName, ...inDecoderSeries.map(s => s.name)]
    const allColors = [primaryColor, ...inDecoderSeries.map(s => s.color)]

    chartOption.value = {
      backgroundColor: 'transparent',
      textStyle: { color: '#303133' },
      tooltip: { trigger: 'axis', axisPointer: { type: 'cross', label: { formatter: p => p.axisDimension === 'y' ? fmt(p.value) : p.value } }, formatter: params => { let s = params[0].axisValue + '<br/>'; params.forEach(p => { s += `${p.marker} ${p.seriesName}: ${fmt(p.value)}<br/>` }); return s } },
      legend: { data: legendNames, textStyle: { color: '#606266' } },
      color: allColors,
      grid: [{ left: 70, right: 20, top: 40, height: '35%' }, { left: 70, right: 20, top: '58%', height: '28%' }],
      dataZoom: [{ type: 'inside', xAxisIndex: [0, 1] }, { type: 'slider', height: 20, bottom: 5, xAxisIndex: [0, 1] }],
      xAxis: [
        { type: 'category', data: times, gridIndex: 0, axisLabel: { show: false } },
        { type: 'category', data: times, gridIndex: 1, axisLabel: axisLabelStyle },
      ],
      yAxis: [
        { type: 'value', gridIndex: 0, max: sharedMax, axisLabel: { ...axisLabelStyle, formatter: v => fmt(v) }, splitLine: splitLineStyle, name: '↓ Inbound', nameTextStyle: { color: '#606266', fontSize: 11 } },
        { type: 'value', gridIndex: 1, max: sharedMax, axisLabel: { ...axisLabelStyle, formatter: v => fmt(v) }, splitLine: splitLineStyle, name: '↑ Outbound', nameTextStyle: { color: '#606266', fontSize: 11 } },
      ],
      series: allSeries,
    }
    return
  }

  // === Single direction ===
  if (!cachedPoints) { chartOption.value = null; return }
  const points = cachedPoints
  const times = points.map(p => new Date(p.time).toLocaleTimeString())
  const totalField = isPPS ? 'pps' : 'bps'
  const totalName = isPPS ? 'PPS' : 'BPS'
  const total = points.map(p => p[totalField] || 0)
  const decoderSeries = buildSeries(points, isPPS)
  const seriesData = [
    { name: totalName, data: total, width: 2, color: primaryColor },
    ...decoderSeries,
  ]

  chartOption.value = {
    backgroundColor: 'transparent',
    textStyle: { color: '#303133' },
    tooltip: { trigger: 'axis', axisPointer: { type: 'cross', label: { formatter: p => p.axisDimension === 'y' ? fmt(p.value) : p.value } }, formatter: params => { let s = params[0].axisValue + '<br/>'; params.forEach(p => { s += `${p.marker} ${p.seriesName}: ${fmt(p.value)}<br/>` }); return s } },
    legend: { data: seriesData.map(s => s.name), textStyle: { color: '#606266' } },
    grid: { left: 70, right: 20, top: 40, bottom: 60 },
    dataZoom: [{ type: 'inside' }, { type: 'slider', height: 20, bottom: 5 }],
    xAxis: { type: 'category', data: times, axisLabel: { color: '#909399', fontSize: 10 } },
    yAxis: { type: 'value', axisLabel: { color: '#909399', formatter: v => fmt(v) }, splitLine: { lineStyle: { color: '#e4e7ed' } } },
    series: seriesData.map(s => ({
      name: s.name, type: 'line', data: s.data, smooth: true,
      lineStyle: { width: s.width }, symbol: 'none', itemStyle: { color: s.color }
    }))
  }
}

onMounted(() => {
  loadNodeList()
  loadOverview()
  loadTimeseries()
  overviewTimer = setInterval(loadOverview, 5000)
})

onUnmounted(() => {
  if (overviewTimer) clearInterval(overviewTimer)
})
</script>

<style scoped>
.stat-card { padding: 4px 0; }
.stat-title { font-size: 12px; color: var(--el-text-color-regular); margin-bottom: 4px; }
.stat-value { font-size: 28px; font-weight: 600; color: var(--el-text-color-primary); font-variant-numeric: tabular-nums; }
.dir-label { font-size: 16px; font-weight: 400; color: var(--el-text-color-secondary); }
.dir-sep { font-size: 16px; font-weight: 300; color: var(--el-text-color-placeholder); margin: 0 4px; }
</style>

<style>
/* Amber theme: TrafficOverview stat cards — DSEG14 LCD digits (unscoped to override scoped styles) */
[data-theme="amber"] .stat-value {
  font-family: 'DSEG14', monospace;
  font-size: 32px;
  font-weight: 400;
  letter-spacing: 0.04em;
  color: #1a8a28;
  text-shadow: 0 0 8px rgba(46, 204, 64, 0.4), 0 0 16px rgba(46, 204, 64, 0.15);
}
[data-theme="amber"] .stat-title {
  font-family: 'Courier New', monospace;
  letter-spacing: 0.1em;
  color: #7a7560;
  text-transform: uppercase;
}
[data-theme="amber"] .stat-card {
  background: #f7f5ee;
}
</style>
