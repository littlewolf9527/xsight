<template>
  <div v-if="attack">
    <el-page-header @back="$router.back()" :title="$t('attacks.title')">
      <template #content>
        <span style="font-size: 18px; font-weight: bold;">
          <template v-if="attack.direction === 'sends'">Outbound</template>
          <template v-else>Attack</template>
          #{{ attack.id }} —
          <el-tag v-if="attack.dst_ip === '0.0.0.0/0'" type="warning">Global</el-tag>
          <template v-else>{{ attack.dst_ip }}</template>
        </span>
      </template>
    </el-page-header>

    <el-descriptions :column="2" border style="margin-top: 20px;">
      <el-descriptions-item :label="attack.direction === 'sends' ? $t('attacks.srcIpLabel') : $t('attacks.dstIp')">
        <el-tag v-if="attack.dst_ip === '0.0.0.0/0'" type="warning">Global (IPv4 + IPv6)</el-tag>
        <template v-else>{{ attack.dst_ip }}</template>
      </el-descriptions-item>
      <el-descriptions-item :label="$t('attacks.decoder')">{{ attack.decoder_family }}</el-descriptions-item>
      <el-descriptions-item :label="$t('attacks.attackType')">{{ attack.attack_type }}</el-descriptions-item>
      <el-descriptions-item :label="$t('attacks.severity')">
        <el-tag :type="severityType(attack.severity)">{{ attack.severity }}</el-tag>
      </el-descriptions-item>
      <el-descriptions-item :label="$t('attacks.confidence')">{{ (attack.confidence * 100).toFixed(0) }}%</el-descriptions-item>
      <el-descriptions-item :label="$t('attacks.peakPps')">{{ attack.peak_pps > 0 ? attack.peak_pps.toLocaleString() : '—' }}</el-descriptions-item>
      <el-descriptions-item :label="$t('attacks.peakBps')">{{ attack.peak_bps > 0 ? attack.peak_bps.toLocaleString() : '—' }}</el-descriptions-item>
      <el-descriptions-item :label="$t('attacks.startedAt')">{{ formatTime(attack.started_at) }}</el-descriptions-item>
      <el-descriptions-item :label="$t('attacks.endedAt')">
        <template v-if="attack.ended_at">{{ formatTime(attack.ended_at) }}</template>
        <template v-else>
          <el-tag v-if="timer && timer.state === 'expiring'" type="warning" size="small" style="margin-right: 8px;">
            {{ $t('attacks.expiringIn') }} {{ formatTimer(timer.expires_in) }}
          </el-tag>
          <el-tag v-else type="danger" size="small" style="margin-right: 8px;">{{ $t('attacks.breaching') }}</el-tag>
          <el-button size="small" type="danger" plain @click="handleExpire">{{ $t('attacks.expire') }}</el-button>
        </template>
      </el-descriptions-item>
      <el-descriptions-item :label="$t('attacks.nodeSources')">{{ (attack.node_sources || []).join(', ') }}</el-descriptions-item>
      <el-descriptions-item :label="$t('attacks.triggerRule')">
        <template v-if="attack.template_name">
          <span style="font-weight: 600;">{{ attack.template_name }}</span>
          <span v-if="attack.rule_summary" style="margin-left: 8px; font-family: 'SF Mono', monospace; font-size: 12px; color: var(--xs-text-secondary);">{{ attack.rule_summary }}</span>
        </template>
        <span v-else style="color: var(--xs-text-secondary);">—</span>
      </el-descriptions-item>
      <el-descriptions-item :label="$t('attacks.reasonCodes')" :span="2">
        <el-tag v-for="r in (attack.reason_codes || [])" :key="r" size="small" style="margin-right: 4px;">{{ r }}</el-tag>
      </el-descriptions-item>
    </el-descriptions>

    <el-tabs v-model="activeTab" style="margin-top: 20px;">
      <el-tab-pane :label="$t('attacks.actionsLog')" name="actionsLog">
        <el-table :data="actionsLog" stripe size="small" :empty-text="$t('common.noData')">
          <el-table-column prop="id" label="ID" width="60" />
          <el-table-column prop="execution_policy" label="Policy" width="140" />
          <el-table-column prop="status" :label="$t('common.status')" width="100">
            <template #default="{ row }">
              <el-tag :type="{ success: 'success', failed: 'danger', pending: 'warning', retrying: 'warning' }[row.status]" size="small">
                {{ row.status }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="last_result" label="Result" />
          <el-table-column prop="retry_count" label="Retries" width="80" />
          <el-table-column prop="last_attempt_at" label="Last Attempt" width="180">
            <template #default="{ row }">{{ formatTime(row.last_attempt_at) }}</template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <el-tab-pane :label="$t('attacks.responseActions')" name="responseActions">
        <el-button size="small" style="margin-bottom: 12px;" @click="loadActionLog">{{ $t('common.refresh') || 'Refresh' }}</el-button>
        <el-table :data="actionLog" stripe size="small" :empty-text="$t('common.noData')">
          <el-table-column prop="executed_at" :label="$t('attacks.time')" width="180">
            <template #default="{ row }">{{ formatTime(row.executed_at) }}</template>
          </el-table-column>
          <el-table-column prop="action_type" :label="$t('responses.actionType')" width="100" />
          <el-table-column prop="connector_name" :label="$t('responses.connectorName')" />
          <el-table-column prop="trigger_phase" :label="$t('attacks.triggerPhase')" width="120">
            <template #default="{ row }">
              <el-tag :type="row.trigger_phase === 'on_detected' ? 'danger' : 'success'" size="small">{{ row.trigger_phase }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="status" :label="$t('common.status')" width="100">
            <template #default="{ row }">
              <el-tag :type="{ success: 'success', failed: 'danger', pending: 'warning', running: 'warning', skipped: 'info' }[row.status]" size="small">
                {{ row.status }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="status_code" :label="$t('attacks.statusCode')" width="90" />
          <el-table-column prop="duration_ms" :label="$t('attacks.durationMs')" width="100">
            <template #default="{ row }">{{ row.duration_ms != null ? row.duration_ms + ' ms' : '-' }}</template>
          </el-table-column>
          <el-table-column :label="$t('common.actions')" width="80">
            <template #default="{ row }">
              <el-button size="small" link @click="viewActionDetail(row)">{{ $t('attacks.viewDetail') }}</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <el-tab-pane :label="$t('attacks.sensorLogs')" name="sensorLogs">
        <el-alert type="info" :closable="false" style="margin-bottom: 12px;" show-icon>
          {{ $t('attacks.sensorLogsNote') }}
        </el-alert>

        <el-button size="small" style="margin-bottom: 12px;" @click="loadSensorLogs" :loading="sensorLogsLoading">
          {{ $t('common.refresh') }}
        </el-button>

        <!-- Top aggregation panels -->
        <el-row :gutter="16" v-if="sensorLogs.length > 0" style="margin-bottom: 16px;">
          <el-col :span="8">
            <el-card shadow="never" size="small">
              <template #header><span style="font-weight: bold;">{{ $t('attacks.topSrcIps') }}</span></template>
              <div v-for="item in topSrcIps" :key="item.key" style="display: flex; justify-content: space-between; padding: 2px 0; font-size: 13px;">
                <span style="font-family: monospace;">{{ item.key }}</span>
                <span style="color: #909399;">{{ item.pct }}%</span>
              </div>
            </el-card>
          </el-col>
          <el-col :span="8">
            <el-card shadow="never" size="small">
              <template #header><span style="font-weight: bold;">{{ $t('attacks.topSrcPorts') }}</span></template>
              <div v-for="item in topSrcPorts" :key="item.key" style="display: flex; justify-content: space-between; padding: 2px 0; font-size: 13px;">
                <span style="font-family: monospace;">{{ item.key }}</span>
                <span style="color: #909399;">{{ item.pct }}%</span>
              </div>
            </el-card>
          </el-col>
          <el-col :span="8">
            <el-card shadow="never" size="small">
              <template #header><span style="font-weight: bold;">{{ $t('attacks.topDstPorts') }}</span></template>
              <div v-for="item in topDstPorts" :key="item.key" style="display: flex; justify-content: space-between; padding: 2px 0; font-size: 13px;">
                <span style="font-family: monospace;">{{ item.key }}</span>
                <span style="color: #909399;">{{ item.pct }}%</span>
              </div>
            </el-card>
          </el-col>
        </el-row>

        <el-alert v-if="isGlobalAttack" type="info" :closable="false" style="margin-bottom: 12px;" show-icon>
          {{ $t('attacks.globalNoFlowDetail') }}
        </el-alert>

        <el-alert v-else-if="!sensorLogsLoading && sensorLogs.length === 0 && flowDataExpired" type="warning" :closable="false" style="margin-bottom: 12px;" show-icon>
          {{ $t('attacks.flowDataExpired') }}
        </el-alert>

        <el-table v-if="!isGlobalAttack" :data="sensorLogs" stripe size="small" :empty-text="flowDataExpired ? $t('attacks.flowDataExpired') : $t('attacks.noFlowData')" v-loading="sensorLogsLoading" max-height="600">
          <el-table-column prop="time" :label="$t('attacks.time')" width="180">
            <template #default="{ row }">{{ formatTime(row.time) }}</template>
          </el-table-column>
          <el-table-column prop="protocol" :label="$t('attacks.protocol')" width="80">
            <template #default="{ row }">{{ protoName(row.protocol) }}</template>
          </el-table-column>
          <el-table-column prop="src_ip" :label="$t('attacks.srcIp')" min-width="140">
            <template #default="{ row }"><span style="font-family: monospace;">{{ row.src_ip }}</span></template>
          </el-table-column>
          <el-table-column prop="src_port" :label="$t('attacks.srcPort')" width="80" />
          <el-table-column prop="dst_ip" :label="$t('attacks.dstIp')" min-width="140">
            <template #default="{ row }"><span style="font-family: monospace;">{{ row.dst_ip }}</span></template>
          </el-table-column>
          <el-table-column prop="dst_port" :label="$t('attacks.dstPort')" width="80" />
          <el-table-column prop="tcp_flags" :label="$t('attacks.tcpFlags')" width="100">
            <template #default="{ row }">{{ row.protocol === 6 ? formatTCPFlags(row.tcp_flags) : '-' }}</template>
          </el-table-column>
          <el-table-column prop="packets" :label="$t('attacks.packets')" width="100" sortable>
            <template #default="{ row }">{{ row.packets?.toLocaleString() }}</template>
          </el-table-column>
          <el-table-column prop="bytes" :label="$t('attacks.bytes')" width="120" sortable>
            <template #default="{ row }">{{ formatBytes(row.bytes) }}</template>
          </el-table-column>
        </el-table>
      </el-tab-pane>
    </el-tabs>

    <!-- Action Detail Dialog -->
    <el-dialog v-model="showActionDetail" :title="$t('attacks.actionDetail')" width="600px">
      <el-descriptions :column="1" border v-if="selectedAction">
        <el-descriptions-item :label="$t('responses.actionType')">{{ selectedAction.action_type }}</el-descriptions-item>
        <el-descriptions-item :label="$t('responses.connectorName')">{{ selectedAction.connector_name }}</el-descriptions-item>
        <el-descriptions-item :label="$t('attacks.triggerPhase')">{{ selectedAction.trigger_phase }}</el-descriptions-item>
        <el-descriptions-item :label="$t('common.status')">{{ selectedAction.status }}</el-descriptions-item>
        <el-descriptions-item :label="$t('attacks.statusCode')">{{ selectedAction.status_code }}</el-descriptions-item>
        <el-descriptions-item :label="$t('attacks.durationMs')">{{ selectedAction.duration_ms != null ? selectedAction.duration_ms + ' ms' : '-' }}</el-descriptions-item>
        <el-descriptions-item :label="$t('attacks.time')">{{ formatTime(selectedAction.executed_at) }}</el-descriptions-item>
        <el-descriptions-item :label="$t('attacks.responseBody')">
          <div>
            <el-button size="small" link @click="showRawResponse = !showRawResponse" style="margin-bottom: 4px;">
              {{ showRawResponse ? $t('attacks.showFormatted') : $t('attacks.showRaw') }}
            </el-button>
            <pre style="max-height: 200px; overflow: auto; font-size: 12px; white-space: pre-wrap; word-break: break-all;">{{ showRawResponse ? (selectedAction.response_body || '-') : formatJSON(selectedAction.response_body) }}</pre>
          </div>
        </el-descriptions-item>
        <el-descriptions-item :label="$t('attacks.errorMessage')">{{ selectedAction.error_message || '-' }}</el-descriptions-item>
      </el-descriptions>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import api, { getAttack, getAttackActionLog, getAttackSensorLogs } from '../api'

const route = useRoute()
const attack = ref(null)
const timer = ref(null)
const actionsLog = ref([])
const actionLog = ref([])
const activeTab = ref('actionsLog')
const showActionDetail = ref(false)
const selectedAction = ref(null)
const showRawResponse = ref(false)

function formatJSON(str) {
  if (!str || str === '-') return '-'
  try {
    return JSON.stringify(JSON.parse(str), null, 2)
  } catch {
    return str
  }
}
const sensorLogs = ref([])
const sensorLogsLoading = ref(false)
const flowDataExpired = ref(false)

function severityType(s) {
  return { critical: 'danger', high: 'warning', medium: '', low: 'info' }[s] || 'info'
}
function formatTime(t) { return t ? new Date(t).toLocaleString() : '-' }
function formatTimer(seconds) {
  if (!seconds || seconds <= 0) return '0s'
  const m = Math.floor(seconds / 60)
  const s = Math.floor(seconds % 60)
  return m > 0 ? `${m}m ${s}s` : `${s}s`
}

async function handleExpire() {
  try {
    await ElMessageBox.confirm(`Expire attack #${attack.value.id}?`, 'Confirm', { type: 'warning' })
    await api.post(`/attacks/${attack.value.id}/expire`)
    ElMessage.success('Attack expired')
    const res = await getAttack(attack.value.id)
    attack.value = res.attack
  } catch (e) {
    if (e !== 'cancel') ElMessage.error(e?.error || e?.message || 'Failed to expire')
  }
}

async function loadActionLog() {
  try {
    actionLog.value = await getAttackActionLog(route.params.id) || []
  } catch { actionLog.value = [] }
}

function viewActionDetail(row) {
  selectedAction.value = row
  showRawResponse.value = false
  showActionDetail.value = true
}

async function loadSensorLogs() {
  sensorLogsLoading.value = true
  try {
    const res = await getAttackSensorLogs(route.params.id)
    sensorLogs.value = res.flows || []
    flowDataExpired.value = !!res.expired
  } catch (e) {
    sensorLogs.value = []
    flowDataExpired.value = false
    ElMessage.error('Failed to load sensor logs')
  }
  sensorLogsLoading.value = false
}

function protoName(p) {
  return { 1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP' }[p] || p
}

function formatTCPFlags(flags) {
  const names = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR']
  return names.filter((_, i) => flags & (1 << i)).join(',') || '...'
}

function formatBytes(b) {
  if (b == null) return '-'
  if (b < 1024) return b + ' B'
  if (b < 1048576) return (b / 1024).toFixed(1) + ' K'
  if (b < 1073741824) return (b / 1048576).toFixed(1) + ' M'
  return (b / 1073741824).toFixed(2) + ' G'
}

function aggregateTop(flows, field, n = 10) {
  const map = {}
  let total = 0
  for (const f of flows) {
    const key = String(f[field])
    map[key] = (map[key] || 0) + (f.packets || 0)
    total += (f.packets || 0)
  }
  return Object.entries(map)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([key, val]) => ({ key, pct: total > 0 ? ((val / total) * 100).toFixed(1) : '0' }))
}

const topSrcIps = computed(() => aggregateTop(sensorLogs.value, 'src_ip'))
const topSrcPorts = computed(() => aggregateTop(sensorLogs.value, 'src_port'))
const topDstPorts = computed(() => aggregateTop(sensorLogs.value, 'dst_port'))
const isGlobalAttack = computed(() => attack.value?.dst_ip === '0.0.0.0/0')

let timerPoll = null

async function refreshTimer() {
  if (!attack.value || attack.value.ended_at) return
  try {
    const res = await getAttack(route.params.id)
    attack.value = res.attack
    timer.value = res.timer || null
    actionsLog.value = res.actions_log || []
  } catch {}
}

onMounted(async () => {
  const res = await getAttack(route.params.id)
  attack.value = res.attack
  timer.value = res.timer || null
  actionsLog.value = res.actions_log || []
  loadActionLog()
  loadSensorLogs()
  // Poll timer for active attacks (every 3s)
  timerPoll = setInterval(refreshTimer, 3000)
})

onUnmounted(() => {
  if (timerPoll) clearInterval(timerPoll)
})
</script>
