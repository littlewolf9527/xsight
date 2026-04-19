<template>
  <div>
    <div style="display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; align-items: center;">
      <el-select v-model="selectedPrefix" placeholder="Select Prefix" size="small" style="width: 200px;" @change="load">
        <el-option v-for="p in prefixes" :key="p.prefix" :label="p.prefix + ' (' + p.name + ')'" :value="p.prefix" />
      </el-select>
      <el-radio-group v-model="timeRange" size="small" @change="load">
        <el-radio-button label="1h">1H</el-radio-button>
        <el-radio-button label="6h">6H</el-radio-button>
        <el-radio-button label="24h">24H</el-radio-button>
      </el-radio-group>
      <el-radio-group v-model="metric" size="small" @change="render">
        <el-radio-button label="pps">PPS</el-radio-button>
        <el-radio-button label="bps">BPS</el-radio-button>
      </el-radio-group>
      <el-radio-group v-model="direction" size="small" @change="load">
        <el-radio-button label="receives">↓ In</el-radio-button>
        <el-radio-button label="sends">↑ Out</el-radio-button>
        <el-radio-button label="both">Both</el-radio-button>
      </el-radio-group>

      <el-popover placement="bottom-end" :width="280" trigger="click">
        <template #reference>
          <el-button size="small">
            Decoders ({{ visibleDecoders.length }}/{{ ALL_DECODERS.length }})
          </el-button>
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
    <v-chart v-if="chartOption" :option="chartOption" :update-options="{ notMerge: true }" autoresize :style="{ height: direction === 'both' ? '450px' : '300px', width: '100%' }" />
    <el-empty v-else :description="loading ? 'Loading...' : 'No data'" />
  </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { LineChart } from 'echarts/charts'
import { GridComponent, TooltipComponent, LegendComponent, DataZoomComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import api from '../api'
import { getPrefixes } from '../api'
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

const prefixes = ref([])
const selectedPrefix = ref('')
const timeRange = ref('1h')
const metric = ref('pps')
const direction = ref('receives')
const chartOption = ref(null)
const loading = ref(false)
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
  // If we flipped between needs-extras and not-needs-extras, refetch; else just re-render.
  if (needsExtras.value !== cachedHasExtras) {
    await load()
  } else {
    render()
  }
}

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

async function load() {
  if (!selectedPrefix.value) return
  loading.value = true
  try {
    const hours = { '1h': 1, '6h': 6, '24h': 24 }[timeRange.value] || 1
    const resolution = hours <= 1 ? '5min' : hours <= 6 ? '5min' : '1h'
    const from = new Date(Date.now() - hours * 3600000).toISOString()
    const prefix = selectedPrefix.value
    const wantExtras = needsExtras.value
    cachedHasExtras = wantExtras
    const baseParams = { prefix, from, resolution }
    if (wantExtras) baseParams.include_extras = 'true'

    if (direction.value === 'both') {
      const [inPts, outPts] = await Promise.all([
        api.get('/stats/timeseries', { params: { ...baseParams, direction: 'receives' } }),
        api.get('/stats/timeseries', { params: { ...baseParams, direction: 'sends' } }),
      ])
      cachedInbound = inPts && inPts.length ? inPts : null
      cachedOutbound = outPts && outPts.length ? outPts : null
      cachedPoints = null
    } else {
      const points = await api.get('/stats/timeseries', {
        params: { ...baseParams, direction: direction.value }
      })
      cachedPoints = points && points.length ? points : null
      cachedInbound = null
      cachedOutbound = null
    }
    render()
  } catch (e) {
    console.error('timeseries error:', e)
    cachedPoints = null
    cachedInbound = null
    cachedOutbound = null
    chartOption.value = null
  } finally {
    loading.value = false
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

function render() {
  const isPPS = metric.value === 'pps'
  const fmt = isPPS ? fmtVal : fmtBps
  const primaryColor = document.documentElement.getAttribute('data-theme') === 'amber' ? '#1a8a28' : '#533afd'

  if (direction.value === 'both') {
    if (!cachedInbound && !cachedOutbound) { chartOption.value = null; return }
    const aligned = alignTimeseries(cachedInbound || [], cachedOutbound || [])
    const times = aligned.times.map(t => new Date(t).toLocaleTimeString())
    const totalField = isPPS ? 'pps' : 'bps'
    const inTotal = aligned.inPts.map(p => p[totalField] || 0)
    const outTotal = aligned.outPts.map(p => p[totalField] || 0)
    const inDecoderSeries = buildSeries(aligned.inPts, isPPS)
    const outDecoderSeries = buildSeries(aligned.outPts, isPPS)
    const totalName = isPPS ? 'PPS' : 'BPS'
    const sharedMax = Math.max(Math.max(...inTotal, 0), Math.max(...outTotal, 0)) * 1.1 || 1

    // Inbound and outbound share the SAME series name per decoder so the legend
    // toggles both at once (ECharts legend groups series by name). Grid/axis
    // indexes separate the two visually. Do NOT alias with a trailing space.
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
      grid: [{ left: 70, right: 20, top: 40, height: '33%' }, { left: 70, right: 20, top: '56%', height: '28%' }],
      dataZoom: [{ type: 'inside', xAxisIndex: [0, 1] }, { type: 'slider', height: 20, bottom: 5, xAxisIndex: [0, 1] }],
      xAxis: [
        { type: 'category', data: times, gridIndex: 0, axisLabel: { show: false } },
        { type: 'category', data: times, gridIndex: 1, axisLabel: { color: '#909399', fontSize: 10 } },
      ],
      yAxis: [
        { type: 'value', gridIndex: 0, max: sharedMax, axisLabel: { color: '#909399', fontSize: 10, formatter: v => fmt(v) }, splitLine: { lineStyle: { color: '#e4e7ed' } }, name: '↓ Inbound', nameTextStyle: { color: '#606266', fontSize: 11 } },
        { type: 'value', gridIndex: 1, max: sharedMax, axisLabel: { color: '#909399', fontSize: 10, formatter: v => fmt(v) }, splitLine: { lineStyle: { color: '#e4e7ed' } }, name: '↑ Outbound', nameTextStyle: { color: '#606266', fontSize: 11 } },
      ],
      series: allSeries,
    }
    return
  }

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

onMounted(async () => {
  prefixes.value = await getPrefixes()
  if (prefixes.value.length > 0) {
    selectedPrefix.value = prefixes.value[0].prefix
    load()
  }
})
</script>
