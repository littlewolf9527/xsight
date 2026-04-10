<template>
  <div>
    <div style="display: flex; gap: 8px; margin-bottom: 12px;">
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
    </div>
    <v-chart v-if="chartOption" :option="chartOption" :update-options="{ notMerge: true }" autoresize :style="{ height: direction === 'both' ? '450px' : '300px', width: '100%' }" />
    <el-empty v-else :description="loading ? 'Loading...' : 'No data'" />
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { LineChart } from 'echarts/charts'
import { GridComponent, TooltipComponent, LegendComponent, DataZoomComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import api from '../api'
import { getPrefixes } from '../api'

use([LineChart, GridComponent, TooltipComponent, LegendComponent, DataZoomComponent, CanvasRenderer])

const prefixes = ref([])
const selectedPrefix = ref('')
const timeRange = ref('1h')
const metric = ref('pps')
const direction = ref('receives')
const chartOption = ref(null)
const loading = ref(false)
let cachedPoints = null

function alignTimeseries(inPts, outPts) {
  const inMap = new Map()
  const outMap = new Map()
  const allTimes = new Set()
  for (const p of inPts) { inMap.set(p.time, p); allTimes.add(p.time) }
  for (const p of outPts) { outMap.set(p.time, p); allTimes.add(p.time) }
  const sorted = [...allTimes].sort()
  const zero = { pps: 0, bps: 0, tcp_pps: 0, tcp_syn_pps: 0, udp_pps: 0, icmp_pps: 0, tcp_bps: 0, udp_bps: 0, icmp_bps: 0 }
  return {
    times: sorted,
    inPts: sorted.map(t => inMap.get(t) || { time: t, ...zero }),
    outPts: sorted.map(t => outMap.get(t) || { time: t, ...zero }),
  }
}

function fmtVal(v) {
  if (v >= 1e9) return (v / 1e9).toFixed(1) + 'G'
  if (v >= 1e6) return (v / 1e6).toFixed(1) + 'M'
  if (v >= 1e3) return (v / 1e3).toFixed(0) + 'K'
  return v
}

let cachedInbound = null
let cachedOutbound = null

async function load() {
  if (!selectedPrefix.value) return
  loading.value = true
  try {
    const hours = { '1h': 1, '6h': 6, '24h': 24 }[timeRange.value] || 1
    const resolution = hours <= 1 ? '5min' : hours <= 6 ? '5min' : '1h'
    const from = new Date(Date.now() - hours * 3600000).toISOString()
    const prefix = selectedPrefix.value

    if (direction.value === 'both') {
      const [inPts, outPts] = await Promise.all([
        api.get('/stats/timeseries', { params: { prefix, from, resolution, direction: 'receives' } }),
        api.get('/stats/timeseries', { params: { prefix, from, resolution, direction: 'sends' } }),
      ])
      cachedInbound = inPts && inPts.length ? inPts : null
      cachedOutbound = outPts && outPts.length ? outPts : null
      cachedPoints = null
    } else {
      const points = await api.get('/stats/timeseries', {
        params: { prefix, from, resolution, direction: direction.value }
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

function fmtBps(v) {
  if (v >= 1e12) return (v / 1e12).toFixed(1) + 'T'
  if (v >= 1e9) return (v / 1e9).toFixed(1) + 'G'
  if (v >= 1e6) return (v / 1e6).toFixed(1) + 'M'
  if (v >= 1e3) return (v / 1e3).toFixed(0) + 'K'
  return v
}

function render() {
  const theme = document.documentElement.getAttribute('data-theme')
  const isAmber = theme === 'amber'
  const isPPS = metric.value === 'pps'
  const fmt = isPPS ? fmtVal : fmtBps
  const primaryColor = isAmber ? '#1a8a28' : '#533afd'

  // === Both: Wanguard-style dual direction ===
  if (direction.value === 'both') {
    if (!cachedInbound && !cachedOutbound) { chartOption.value = null; return }
    const aligned = alignTimeseries(cachedInbound || [], cachedOutbound || [])
    const inPts = aligned.inPts
    const outPts = aligned.outPts
    const times = aligned.times.map(t => new Date(t).toLocaleTimeString())

    const axisLabelStyle = { color: '#909399', fontSize: 10 }
    const splitLineStyle = { lineStyle: { color: '#e4e7ed' } }
    const names = isPPS ? ['PPS', 'TCP', 'UDP', 'ICMP'] : ['BPS', 'TCP', 'UDP', 'ICMP']
    const colors = [primaryColor, '#e6a23c', '#67c23a', '#909399']

    const inSeries = isPPS
      ? [{ n: names[0], d: inPts.map(p => p.pps), w: 2 }, { n: names[1], d: inPts.map(p => p.tcp_pps), w: 1 }, { n: names[2], d: inPts.map(p => p.udp_pps), w: 1 }, { n: names[3], d: inPts.map(p => p.icmp_pps), w: 1 }]
      : [{ n: names[0], d: inPts.map(p => p.bps), w: 2 }, { n: names[1], d: inPts.map(p => p.tcp_bps), w: 1 }, { n: names[2], d: inPts.map(p => p.udp_bps), w: 1 }, { n: names[3], d: inPts.map(p => p.icmp_bps), w: 1 }]
    const outSeries = isPPS
      ? [{ n: names[0], d: outPts.map(p => p.pps), w: 2 }, { n: names[1], d: outPts.map(p => p.tcp_pps), w: 1 }, { n: names[2], d: outPts.map(p => p.udp_pps), w: 1 }, { n: names[3], d: outPts.map(p => p.icmp_pps), w: 1 }]
      : [{ n: names[0], d: outPts.map(p => p.bps), w: 2 }, { n: names[1], d: outPts.map(p => p.tcp_bps), w: 1 }, { n: names[2], d: outPts.map(p => p.udp_bps), w: 1 }, { n: names[3], d: outPts.map(p => p.icmp_bps), w: 1 }]

    const sharedMax = Math.max(Math.max(...(inSeries[0].d || [0]), 0), Math.max(...(outSeries[0].d || [0]), 0)) * 1.1 || 1

    chartOption.value = {
      backgroundColor: 'transparent',
      textStyle: { color: '#303133' },
      tooltip: { trigger: 'axis', axisPointer: { type: 'cross', label: { formatter: p => p.axisDimension === 'y' ? fmt(p.value) : p.value } }, formatter: params => { let s = params[0].axisValue + '<br/>'; params.forEach(p => { s += `${p.marker} ${p.seriesName}: ${fmt(p.value)}<br/>` }); return s } },
      legend: { data: names, textStyle: { color: '#606266' } },
      color: colors,
      grid: [{ left: 70, right: 20, top: 40, height: '33%' }, { left: 70, right: 20, top: '56%', height: '28%' }],
      dataZoom: [{ type: 'inside', xAxisIndex: [0, 1] }, { type: 'slider', height: 20, bottom: 5, xAxisIndex: [0, 1] }],
      xAxis: [{ type: 'category', data: times, gridIndex: 0, axisLabel: { show: false } }, { type: 'category', data: times, gridIndex: 1, axisLabel: axisLabelStyle }],
      yAxis: [
        { type: 'value', gridIndex: 0, max: sharedMax, axisLabel: { ...axisLabelStyle, formatter: v => fmt(v) }, splitLine: splitLineStyle, name: '↓ Inbound', nameTextStyle: { color: '#606266', fontSize: 11 } },
        { type: 'value', gridIndex: 1, max: sharedMax, axisLabel: { ...axisLabelStyle, formatter: v => fmt(v) }, splitLine: splitLineStyle, name: '↑ Outbound', nameTextStyle: { color: '#606266', fontSize: 11 } },
      ],
      series: [
        ...inSeries.map((s, i) => ({ name: s.n, type: 'line', data: s.d, smooth: true, xAxisIndex: 0, yAxisIndex: 0, lineStyle: { width: s.w }, symbol: 'none', itemStyle: { color: colors[i] } })),
        ...outSeries.map((s, i) => ({ name: s.n, type: 'line', data: s.d, smooth: true, xAxisIndex: 1, yAxisIndex: 1, lineStyle: { width: s.w }, symbol: 'none', itemStyle: { color: colors[i] } })),
      ]
    }
    return
  }

  // === Single direction: per-decoder chart ===
  if (!cachedPoints) { chartOption.value = null; return }
  const points = cachedPoints
  const times = points.map(p => new Date(p.time).toLocaleTimeString())

  const seriesData = isPPS
    ? [
        { name: 'PPS', data: points.map(p => p.pps), width: 2 },
        { name: 'TCP', data: points.map(p => p.tcp_pps), width: 1 },
        { name: 'TCP SYN', data: points.map(p => p.tcp_syn_pps), width: 1 },
        { name: 'UDP', data: points.map(p => p.udp_pps), width: 1 },
        { name: 'ICMP', data: points.map(p => p.icmp_pps), width: 1 },
      ]
    : [
        { name: 'BPS', data: points.map(p => p.bps), width: 2 },
        { name: 'TCP', data: points.map(p => p.tcp_bps), width: 1 },
        { name: 'UDP', data: points.map(p => p.udp_bps), width: 1 },
        { name: 'ICMP', data: points.map(p => p.icmp_bps), width: 1 },
      ]

  const colors = isPPS
    ? [primaryColor, '#e6a23c', '#f56c6c', '#67c23a', '#909399']
    : [primaryColor, '#e6a23c', '#67c23a', '#909399']

  chartOption.value = {
    backgroundColor: 'transparent',
    textStyle: { color: '#303133' },
    tooltip: { trigger: 'axis', axisPointer: { type: 'cross', label: { formatter: p => p.axisDimension === 'y' ? fmt(p.value) : p.value } }, formatter: params => { let s = params[0].axisValue + '<br/>'; params.forEach(p => { s += `${p.marker} ${p.seriesName}: ${fmt(p.value)}<br/>` }); return s } },
    legend: { data: seriesData.map(s => s.name), textStyle: { color: '#606266' } },
    grid: { left: 70, right: 20, top: 40, bottom: 60 },
    dataZoom: [{ type: 'inside' }, { type: 'slider', height: 20, bottom: 5 }],
    xAxis: { type: 'category', data: times, axisLabel: { color: '#909399', fontSize: 10 } },
    yAxis: { type: 'value', axisLabel: { color: '#909399', formatter: v => fmt(v) }, splitLine: { lineStyle: { color: '#e4e7ed' } } },
    series: seriesData.map((s, i) => ({
      name: s.name, type: 'line', data: s.data, smooth: true,
      lineStyle: { width: s.width }, symbol: 'none', itemStyle: { color: colors[i] }
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
