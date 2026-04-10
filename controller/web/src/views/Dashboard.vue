<template>
  <div class="xs-page">
    <div class="xs-page-header">
      <h2>{{ $t('nav.dashboard') }}</h2>
      <span class="xs-page-subtitle">Real-time system overview</span>
    </div>

    <!-- Stats cards -->
    <div class="xs-stats-grid">
      <div class="xs-stat-card xs-stat-attacks" @click="router.push('/attacks?active=true')">
        <div class="xs-stat-label">{{ $t('attacks.active') }}</div>
        <div class="xs-stat-value" :class="{ 'xs-stat-alert': stats.activeAttacks > 0 }">
          {{ stats.activeAttacks }}
        </div>
        <div class="xs-stat-indicator" v-if="stats.activeAttacks > 0">
          <span class="xs-pulse"></span> Active
        </div>
      </div>
      <div class="xs-stat-card" @click="router.push('/nodes')">
        <div class="xs-stat-label">{{ $t('nav.nodes') }}</div>
        <div class="xs-stat-value">{{ stats.totalNodes }}</div>
        <div class="xs-stat-sub">{{ stats.onlineNodes || '—' }} online</div>
      </div>
      <div class="xs-stat-card" @click="router.push('/prefixes')">
        <div class="xs-stat-label">{{ $t('nav.prefixes') }}</div>
        <div class="xs-stat-value">{{ stats.totalPrefixes }}</div>
        <div class="xs-stat-sub">Monitored</div>
      </div>
      <div class="xs-stat-card" @click="router.push('/templates')">
        <div class="xs-stat-label">{{ $t('nav.thresholds') }}</div>
        <div class="xs-stat-value">{{ stats.totalThresholds }}</div>
        <div class="xs-stat-sub">Rules active</div>
      </div>
    </div>

    <!-- Active attacks table -->
    <div class="xs-section">
      <div class="xs-section-header">
        <h3>{{ $t('attacks.active') }}</h3>
        <span v-if="stats.activeAttacks > 10" class="xs-section-badge">
          top 10 / {{ stats.activeAttacks }}
        </span>
      </div>
      <el-table :data="topAttacks" stripe size="small" :empty-text="$t('common.noData')"
        :row-style="{ cursor: 'pointer' }" @row-click="row => router.push(`/attacks/${row.id}`)">
        <el-table-column prop="dst_ip" :label="$t('attacks.dstIp')" width="160" />
        <el-table-column prop="decoder_family" :label="$t('attacks.decoder')" width="100">
          <template #default="{ row }">
            <span class="xs-mono">{{ row.decoder_family }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="attack_type" :label="$t('attacks.attackType')" width="170">
          <template #default="{ row }">
            <span class="xs-mono">{{ row.attack_type }}</span>
          </template>
        </el-table-column>
        <el-table-column :label="$t('attacks.severity')" width="100">
          <template #default="{ row }">
            <span :class="['xs-severity', `xs-severity-${row.severity}`]">{{ row.severity }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="peak_pps" :label="$t('attacks.peakPps')" width="120">
          <template #default="{ row }">
            <span class="xs-mono">{{ formatPPS(row.peak_pps) }}</span>
          </template>
        </el-table-column>
        <el-table-column :label="$t('attacks.triggerRule')" width="160">
          <template #default="{ row }">
            <template v-if="row.template_name">
              <span style="font-weight: 500;">{{ row.template_name }}</span>
              <div v-if="row.rule_summary" style="font-size: 11px; color: var(--xs-text-secondary); font-family: 'SF Mono', monospace; margin-top: 2px;">{{ row.rule_summary }}</div>
            </template>
            <span v-else style="color: var(--xs-text-secondary);">—</span>
          </template>
        </el-table-column>
        <el-table-column prop="started_at" :label="$t('attacks.startedAt')" width="180">
          <template #default="{ row }">{{ formatTime(row.started_at) }}</template>
        </el-table-column>
        <el-table-column :label="$t('attacks.nodeSources')">
          <template #default="{ row }">
            <span v-for="n in (row.node_sources || [])" :key="n" class="xs-node-tag">{{ n }}</span>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- Traffic chart -->
    <div class="xs-section">
      <div class="xs-section-header">
        <h3>Traffic Trend</h3>
      </div>
      <TrafficChart />
    </div>
  </div>
</template>

<script setup>
import { ref, defineAsyncComponent, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import api from '../api'

const router = useRouter()
const TrafficChart = defineAsyncComponent(() => import('../components/TrafficChart.vue'))

const stats = ref({ activeAttacks: 0, totalNodes: 0, totalPrefixes: 0, totalThresholds: 0, onlineNodes: 0 })
const topAttacks = ref([])
let pollTimer = null
let loading = false

function formatTime(t) { return t ? new Date(t).toLocaleString() : '-' }
function formatPPS(v) {
  if (v >= 1000000) return (v / 1000000).toFixed(1) + 'M'
  if (v >= 1000) return (v / 1000).toFixed(0) + 'K'
  return v
}

async function load() {
  if (loading) return
  loading = true
  try {
    const summary = await api.get('/stats/summary')
    stats.value = {
      activeAttacks: summary.active_attacks || 0,
      totalNodes: summary.total_nodes || 0,
      totalPrefixes: summary.total_prefixes || 0,
      totalThresholds: summary.total_thresholds || 0,
      onlineNodes: summary.online_nodes || 0,
    }
    const atk = await api.get('/attacks/active?limit=10')
    topAttacks.value = atk.attacks || []
  } catch (e) { console.error(e) }
  finally { loading = false }
}

onMounted(() => { load(); pollTimer = setInterval(load, 3000) })
onUnmounted(() => { if (pollTimer) clearInterval(pollTimer) })
</script>

<style scoped>
.xs-page {}

.xs-page-header {
  margin-bottom: 24px;
}
.xs-page-header h2 {
  font-size: 22px;
  margin-bottom: 2px;
}
.xs-page-subtitle {
  font-size: 13px;
  color: var(--xs-text-secondary);
}

/* Stats grid */
.xs-stats-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 16px;
  margin-bottom: 24px;
}
.xs-stat-card {
  background: var(--xs-card-bg);
  border: 1px solid var(--xs-card-border);
  border-radius: var(--xs-radius-lg);
  padding: 20px 24px;
  cursor: pointer;
  transition: all 0.2s;
  box-shadow: var(--xs-shadow);
  position: relative;
}
.xs-stat-card:hover {
  border-color: var(--xs-card-hover-border);
  box-shadow: var(--xs-shadow-lg);
  transform: translateY(-1px);
}
.xs-stat-label {
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--xs-text-secondary);
  margin-bottom: 8px;
}
.xs-stat-value {
  font-size: 32px;
  font-weight: 700;
  letter-spacing: -0.03em;
  color: var(--xs-stat-color);
  line-height: 1;
}
.xs-stat-alert {
  color: var(--xs-danger) !important;
}
.xs-stat-sub {
  font-size: 12px;
  color: var(--xs-text-secondary);
  margin-top: 6px;
}
.xs-stat-indicator {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-top: 8px;
  font-size: 12px;
  color: var(--xs-danger);
  font-weight: 500;
}
.xs-pulse {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--xs-danger);
  animation: pulse 1.5s infinite;
}
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}

/* Sections */
.xs-section {
  background: var(--xs-card-bg);
  border: 1px solid var(--xs-card-border);
  border-radius: var(--xs-radius-lg);
  box-shadow: var(--xs-shadow);
  margin-bottom: 20px;
  overflow: hidden;
}
.xs-section-header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 16px 20px;
  border-bottom: 1px solid var(--xs-border);
}
.xs-section-header h3 {
  font-size: 14px;
  font-weight: 600;
  color: var(--xs-text-primary);
  margin: 0;
}
.xs-section-badge {
  font-size: 11px;
  color: var(--xs-text-secondary);
  background: var(--xs-accent-subtle);
  padding: 2px 8px;
  border-radius: 10px;
}

/* Table helpers */
.xs-mono {
  font-family: 'SF Mono', 'Fira Code', monospace;
  font-size: 12px;
}
.xs-severity {
  display: inline-block;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  padding: 2px 8px;
  border-radius: 4px;
}
.xs-severity-critical {
  background: rgba(239, 68, 68, 0.12);
  color: var(--xs-danger);
}
.xs-severity-high {
  background: rgba(245, 158, 11, 0.12);
  color: var(--xs-warning);
}
.xs-severity-medium {
  background: var(--xs-accent-subtle);
  color: var(--xs-accent);
}
.xs-severity-low {
  background: rgba(100, 116, 141, 0.1);
  color: var(--xs-text-secondary);
}
.xs-node-tag {
  display: inline-block;
  font-size: 11px;
  font-weight: 500;
  background: var(--xs-accent-subtle);
  color: var(--xs-accent);
  padding: 1px 6px;
  border-radius: 3px;
  margin-right: 4px;
}
</style>

<style>
/* Amber theme: Dashboard stat cards — light bg + green LCD digits */
[data-theme="amber"] .xs-stat-value {
  font-family: 'DSEG14', monospace;
  font-size: 36px;
  font-weight: 400;
  letter-spacing: 0.04em;
  color: #1a8a28;
  text-shadow: 0 0 8px rgba(46, 204, 64, 0.4), 0 0 16px rgba(46, 204, 64, 0.15);
}
[data-theme="amber"] .xs-stat-card {
  background: #f7f5ee;
  border: 1px solid #d8d2c0;
}
[data-theme="amber"] .xs-stat-card:hover {
  border-color: #2ecc40;
  box-shadow: 0 0 12px rgba(46, 204, 64, 0.1) !important;
}
[data-theme="amber"] .xs-stat-label {
  font-family: 'Courier New', monospace;
  letter-spacing: 0.1em;
  color: #7a7560;
}
[data-theme="amber"] .xs-stat-alert {
  color: #d63031 !important;
  text-shadow: 0 0 8px rgba(214, 48, 49, 0.5) !important;
}
[data-theme="amber"] .xs-section {
  border: 1px solid #d8d2c0;
  background: #f7f5ee;
}
[data-theme="amber"] .xs-section-header {
  border-bottom: 1px dashed #d8d2c0;
}
[data-theme="amber"] .xs-section-header h3 {
  font-family: 'Courier New', monospace;
  letter-spacing: 0.08em;
  font-size: 12px;
  text-transform: uppercase;
  color: #7a7560;
}
[data-theme="amber"] .xs-mono {
  color: #4a4530;
}
</style>
