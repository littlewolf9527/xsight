<template>
  <div>
    <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 20px;">
      <div>
        <h2 style="font-size: 22px;">{{ $t('attacks.title') }}</h2>
        <span style="font-size: 13px; color: var(--xs-text-secondary);">{{ $t('attacks.subtitle') }}</span>
      </div>
    </div>

    <el-tabs v-model="tab" @tab-change="onTabChange">
      <el-tab-pane :label="$t('attacks.active')" name="active" />
      <el-tab-pane :label="$t('attacks.all')" name="all" />
    </el-tabs>

    <div v-if="tab === 'active' && activeCount > attacks.length" style="margin-bottom: 12px; font-size: 12px; color: var(--xs-text-secondary); font-weight: 500;">
      {{ $t('attacks.showingTop', { count: attacks.length }) }} · {{ activeCount.toLocaleString() }} {{ $t('attacks.totalActive') }}
    </div>

    <div style="background: var(--xs-card-bg); border: 1px solid var(--xs-card-border); border-radius: var(--xs-radius-lg); box-shadow: var(--xs-shadow); overflow: hidden;">
      <el-table :data="attacks" stripe :empty-text="$t('common.noData')" :row-style="{ cursor: 'pointer' }"
        @row-click="row => $router.push(`/attacks/${row.id}`)">
        <el-table-column prop="id" label="ID" width="60" />
        <el-table-column prop="dst_ip" :label="$t('attacks.dstIp')" width="160">
          <template #default="{ row }">
            <span v-if="row.dst_ip === '0.0.0.0/0'" style="font-size: 11px; font-weight: 600; color: var(--xs-warning); background: rgba(245,158,11,0.1); padding: 2px 6px; border-radius: 3px;">{{ $t('attacks.global') }}</span>
            <span v-else style="font-family: 'SF Mono', monospace; font-size: 12px;">{{ row.dst_ip }}</span>
          </template>
        </el-table-column>
        <el-table-column :label="$t('attacks.direction')" width="100">
          <template #default="{ row }">
            <span :style="{ fontSize: '11px', fontWeight: 600, color: row.direction === 'sends' ? 'var(--xs-warning)' : 'var(--xs-accent)' }">
              {{ row.direction === 'sends' ? $t('attacks.outbound') : $t('attacks.inbound') }}
            </span>
          </template>
        </el-table-column>
        <el-table-column prop="decoder_family" :label="$t('attacks.decoder')" width="100">
          <template #default="{ row }">
            <span style="font-family: 'SF Mono', monospace; font-size: 12px;">{{ row.decoder_family }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="attack_type" :label="$t('attacks.attackType')" width="170">
          <template #default="{ row }">
            <span style="font-family: 'SF Mono', monospace; font-size: 12px;">{{ row.attack_type }}</span>
          </template>
        </el-table-column>
        <el-table-column :label="$t('attacks.severity')" width="100">
          <template #default="{ row }">
            <span :class="['xs-sev', `xs-sev-${row.severity}`]">{{ row.severity }}</span>
          </template>
        </el-table-column>
        <el-table-column :label="$t('attacks.peak')" width="130">
          <template #default="{ row }">
            <span style="font-weight: 600; font-family: 'SF Mono', monospace; font-size: 12px;">
              <template v-if="row.peak_pps > 0">{{ formatPPS(row.peak_pps) }} <span style="font-weight: 400; color: var(--xs-text-secondary);">PPS</span></template>
              <template v-else-if="row.peak_bps > 0">{{ formatBPS(row.peak_bps) }} <span style="font-weight: 400; color: var(--xs-text-secondary);">BPS</span></template>
              <template v-else>—</template>
            </span>
          </template>
        </el-table-column>
        <el-table-column :label="$t('attacks.triggerRule')" min-width="150">
          <template #default="{ row }">
            <template v-if="row.template_name">
              <span style="font-weight: 500;">{{ row.template_name }}</span>
              <div v-if="row.rule_summary" style="font-size: 11px; color: var(--xs-text-secondary); font-family: 'SF Mono', monospace; margin-top: 2px;">{{ row.rule_summary }}</div>
            </template>
            <span v-else style="color: var(--xs-text-secondary);">—</span>
          </template>
        </el-table-column>
        <el-table-column prop="started_at" :label="$t('attacks.startedAt')" width="170">
          <template #default="{ row }">{{ formatTime(row.started_at) }}</template>
        </el-table-column>
        <el-table-column prop="ended_at" :label="$t('attacks.endedAt')" min-width="170">
          <template #default="{ row }">{{ row.ended_at ? formatTime(row.ended_at) : '—' }}</template>
        </el-table-column>
        <el-table-column v-if="tab === 'active'" :label="$t('attacks.timer')" width="120">
          <template #default="{ row }">
            <template v-if="timers[row.id]">
              <span v-if="timers[row.id].state === 'expiring'" style="font-family: 'SF Mono', monospace; font-size: 12px; color: var(--xs-warning);">
                {{ formatTimer(timers[row.id].expires_in) }}
              </span>
              <el-tag v-else type="danger" size="small">{{ $t('attacks.breaching') }}</el-tag>
            </template>
            <span v-else style="color: var(--xs-text-secondary);">—</span>
          </template>
        </el-table-column>
        <el-table-column :label="$t('common.actions')" width="130">
          <template #default="{ row }">
            <el-button v-if="!row.ended_at" size="small" type="danger" plain @click.stop="handleExpire(row)">
              {{ $t('attacks.expire') || 'Expire' }}
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <el-pagination v-if="tab === 'all'" style="margin-top: 16px;" layout="prev, pager, next, total"
      :total="totalCount" :page-size="50" @current-change="p => { offset = (p-1)*50; load() }" />

  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import api, { getAttacks, getActiveAttacks } from '../api'

const { t } = useI18n()

const tab = ref('active')
const attacks = ref([])
const activeCount = ref(0)
const totalCount = ref(0)
const offset = ref(0)
const timers = ref({})

function formatTime(t) { return t ? new Date(t).toLocaleString() : '-' }
let loading = false
async function load() {
  if (loading) return
  loading = true
  try {
    if (tab.value === 'active') {
      const res = await getActiveAttacks()
      attacks.value = res.attacks || []
      activeCount.value = res.active_count || 0
      timers.value = res.timers || {}
    } else if (tab.value === 'all') {
      const res = await getAttacks({ limit: 50, offset: offset.value })
      attacks.value = res.attacks || []
      totalCount.value = res.total || 0
    }
  } catch (e) { console.error(e) }
  finally { loading = false }
}

function onTabChange() { load() }

async function handleExpire(row) {
  try {
    await ElMessageBox.confirm(`Expire attack #${row.id} (${row.dst_ip})?`, 'Confirm', { type: 'warning' })
    await api.post(`/attacks/${row.id}/expire`)
    ElMessage.success(`Attack #${row.id} expired`)
    load()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error(e?.error || e?.message || 'Failed to expire')
  }
}

function formatPPS(v) {
  if (v >= 1000000) return (v / 1000000).toFixed(1) + 'M'
  if (v >= 1000) return (v / 1000).toFixed(0) + 'K'
  return v
}
function formatTimer(seconds) {
  if (!seconds || seconds <= 0) return '0s'
  const m = Math.floor(seconds / 60)
  const s = Math.floor(seconds % 60)
  return m > 0 ? `${m}m ${s}s` : `${s}s`
}
function formatBPS(v) {
  if (v >= 1e12) return (v / 1e12).toFixed(1) + 'T'
  if (v >= 1e9) return (v / 1e9).toFixed(1) + 'G'
  if (v >= 1e6) return (v / 1e6).toFixed(1) + 'M'
  if (v >= 1e3) return (v / 1e3).toFixed(0) + 'K'
  return v
}

let pollTimer = null
onMounted(() => { load(); pollTimer = setInterval(load, 3000) })
onUnmounted(() => { if (pollTimer) clearInterval(pollTimer) })
</script>

<style scoped>
.xs-sev {
  display: inline-block;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  padding: 2px 8px;
  border-radius: 4px;
}
.xs-sev-critical { background: rgba(239,68,68,0.12); color: var(--xs-danger); }
.xs-sev-high { background: rgba(245,158,11,0.12); color: var(--xs-warning); }
.xs-sev-medium { background: var(--xs-accent-subtle); color: var(--xs-accent); }
.xs-sev-low { background: rgba(100,116,141,0.1); color: var(--xs-text-secondary); }
</style>
