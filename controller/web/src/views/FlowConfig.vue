<template>
  <div>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
      <h2>{{ $t('flow.title') }} — {{ nodeId }}</h2>
      <el-button type="primary" @click="editingListenerId = null; listenerForm.listen_address = ':2055'; listenerForm.protocol_mode = 'auto'; listenerForm.description = ''; showAddListener = true">{{ $t('flow.addListener') }}</el-button>
    </div>

    <!-- Flow Node Health Metrics -->
    <el-card v-if="nodeStatus" shadow="never" style="margin-bottom: 16px;">
      <div style="display: flex; align-items: center; gap: 24px; flex-wrap: wrap;">
        <span>
          <el-tag :type="nodeStatus.online ? 'success' : 'danger'" size="small">{{ nodeStatus.online ? 'Online' : 'Offline' }}</el-tag>
        </span>
        <span v-if="nodeStatus.flow_metrics" :style="{ fontSize: '13px', color: nodeStatus.online ? '#606266' : '#c0c4cc' }">
          {{ $t('flow.decodeErrors') }}:
          <el-tag :type="nodeStatus.online && nodeStatus.flow_metrics.decode_errors > 0 ? 'warning' : 'info'" size="small">{{ nodeStatus.flow_metrics.decode_errors }}</el-tag>
        </span>
        <span v-if="nodeStatus.flow_metrics" :style="{ fontSize: '13px', color: nodeStatus.online ? '#606266' : '#c0c4cc' }">
          {{ $t('flow.unknownExporter') }}:
          <el-tag :type="nodeStatus.online && nodeStatus.flow_metrics.unknown_exporter > 0 ? 'warning' : 'info'" size="small">{{ nodeStatus.flow_metrics.unknown_exporter }}</el-tag>
        </span>
        <span v-if="nodeStatus.flow_metrics" :style="{ fontSize: '13px', color: nodeStatus.online ? '#606266' : '#c0c4cc' }">
          {{ $t('flow.templateMisses') }}:
          <el-tag :type="nodeStatus.online && nodeStatus.flow_metrics.template_misses > 0 ? 'warning' : 'info'" size="small">{{ nodeStatus.flow_metrics.template_misses }}</el-tag>
        </span>
        <span v-if="nodeStatus.flow_metrics && !nodeStatus.online" style="font-size: 12px; color: #c0c4cc; font-style: italic;">
          (stale)
        </span>
        <span v-if="nodeStatus.uptime_seconds != null" style="font-size: 13px; color: #909399;">
          {{ $t('flow.uptime') }}: {{ formatUptime(nodeStatus.uptime_seconds) }}
        </span>
      </div>
    </el-card>

    <!-- Listeners table -->
    <el-table :data="listeners" stripe :empty-text="$t('common.noData')">
      <el-table-column prop="id" label="ID" width="60" />
      <el-table-column prop="listen_address" :label="$t('flow.listenAddress')" width="150">
        <template #default="{ row }">
          <el-link type="primary" @click="openEditListener(row)">{{ row.listen_address }}</el-link>
        </template>
      </el-table-column>
      <el-table-column prop="protocol_mode" :label="$t('flow.protocolMode')" width="120">
        <template #default="{ row }">
          <el-tag size="small">{{ row.protocol_mode }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="description" :label="$t('common.description')" />
      <el-table-column :label="$t('flow.recordsDecoded')" width="120">
        <template #default="{ row }">
          <span v-if="getListenerStatus(row)" style="font-size: 12px;">{{ formatNumber(getListenerStatus(row).records_decoded) }}</span>
          <span v-else style="color: #c0c4cc;">—</span>
        </template>
      </el-table-column>
      <el-table-column :label="$t('flow.sources')" width="80">
        <template #default="{ row }">{{ (row._sources || []).length }}</template>
      </el-table-column>
      <el-table-column :label="$t('common.enabled')" width="80">
        <template #default="{ row }">
          <el-switch v-model="row.enabled" size="small" @change="handleToggleListener(row)" />
        </template>
      </el-table-column>
      <el-table-column :label="$t('common.actions')" width="200">
        <template #default="{ row }">
          <el-button size="small" @click="openSources(row)">{{ $t('flow.manageSources') }}</el-button>
          <el-button size="small" type="danger" @click="handleDeleteListener(row.id)">{{ $t('common.delete') }}</el-button>
        </template>
      </el-table-column>
    </el-table>

    <!-- Add/Edit Listener dialog -->
    <el-dialog v-model="showAddListener" :title="editingListenerId ? $t('common.edit') : $t('flow.addListener')" width="450px">
      <el-form :model="listenerForm" label-width="120px">
        <el-form-item :label="$t('flow.listenAddress')"><el-input v-model="listenerForm.listen_address" placeholder=":2055" /></el-form-item>
        <el-form-item :label="$t('flow.protocolMode')">
          <el-select v-model="listenerForm.protocol_mode">
            <el-option label="Auto" value="auto" />
            <el-option label="sFlow" value="sflow" />
            <el-option label="NetFlow" value="netflow" />
            <el-option label="IPFIX" value="ipfix" />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('common.description')"><el-input v-model="listenerForm.description" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAddListener = false">{{ $t('common.cancel') }}</el-button>
        <el-button type="primary" @click="editingListenerId ? handleUpdateListener() : handleCreateListener()">{{ editingListenerId ? $t('common.save') : $t('common.create') }}</el-button>
      </template>
    </el-dialog>

    <!-- Sources dialog -->
    <el-dialog v-model="showSources" :title="$t('flow.sources') + ' — ' + (selectedListener?.listen_address || '')" width="700px">
      <div style="margin-bottom: 12px;">
        <el-button size="small" type="primary" @click="editingSourceId = null; sourceForm.name = ''; sourceForm.device_ip = ''; sourceForm.sample_mode = 'auto'; sourceForm.sample_rate = 1000; sourceForm.description = ''; showAddSource = true">{{ $t('flow.addSource') }}</el-button>
      </div>
      <el-table :data="sources" stripe size="small" :empty-text="$t('common.noData')">
        <el-table-column prop="name" :label="$t('common.name')" width="150">
          <template #default="{ row }">
            <el-link type="primary" @click="openEditSource(row)">{{ row.name }}</el-link>
          </template>
        </el-table-column>
        <el-table-column prop="device_ip" :label="$t('flow.deviceIp')" width="150" />
        <el-table-column :label="$t('flow.sourceStatus')" width="80">
          <template #default="{ row }">
            <el-tag v-if="getSourceStatus(row)" :type="getSourceStatus(row).active ? 'success' : 'danger'" size="small">
              {{ getSourceStatus(row).active ? 'Online' : 'Offline' }}
            </el-tag>
            <el-tag v-else type="info" size="small">—</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="sample_mode" :label="$t('flow.sampleMode')" width="100">
          <template #default="{ row }">
            <el-tag size="small">{{ row.sample_mode }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="sample_rate" :label="$t('flow.sampleRate')" width="100" />
        <el-table-column prop="description" :label="$t('common.description')" />
        <el-table-column :label="$t('common.enabled')" width="80">
          <template #default="{ row }">
            <el-switch v-model="row.enabled" size="small" @change="handleToggleSource(row)" />
          </template>
        </el-table-column>
        <el-table-column :label="$t('common.actions')" width="80">
          <template #default="{ row }">
            <el-button size="small" type="danger" @click="handleDeleteSource(row.id)">{{ $t('common.delete') }}</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-dialog>

    <!-- Add/Edit Source dialog -->
    <el-dialog v-model="showAddSource" :title="editingSourceId ? $t('common.edit') : $t('flow.addSource')" width="450px" append-to-body>
      <el-form :model="sourceForm" label-width="120px">
        <el-form-item :label="$t('common.name')"><el-input v-model="sourceForm.name" placeholder="Core Router" /></el-form-item>
        <el-form-item :label="$t('flow.deviceIp')"><el-input v-model="sourceForm.device_ip" placeholder="10.0.0.1" /></el-form-item>
        <el-form-item :label="$t('flow.sampleMode')">
          <el-select v-model="sourceForm.sample_mode">
            <el-option label="Auto" value="auto" />
            <el-option label="Force" value="force" />
            <el-option label="None" value="none" />
          </el-select>
        </el-form-item>
        <el-form-item v-if="sourceForm.sample_mode === 'force'" :label="$t('flow.sampleRate')">
          <el-input-number v-model="sourceForm.sample_rate" :min="1" />
        </el-form-item>
        <el-form-item :label="$t('common.description')"><el-input v-model="sourceForm.description" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAddSource = false">{{ $t('common.cancel') }}</el-button>
        <el-button type="primary" @click="editingSourceId ? handleUpdateSource() : handleCreateSource()">{{ editingSourceId ? $t('common.save') : $t('common.create') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, onUnmounted } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '../api'

const route = useRoute()
const nodeId = route.params.id

const listeners = ref([])
const sources = ref([])
const nodeStatus = ref(null)
const selectedListener = ref(null)
const showAddListener = ref(false)
const editingListenerId = ref(null)
const showSources = ref(false)
const showAddSource = ref(false)
const editingSourceId = ref(null)

const listenerForm = reactive({ listen_address: ':2055', protocol_mode: 'auto', description: '' })

// Match source row to its runtime status from Node health report
function getSourceStatus(row) {
  const statuses = nodeStatus.value?.source_statuses
  if (!statuses) return null
  const ip = (row.device_ip || '').replace(/\/\d+$/, '')
  return statuses.find(s => s.device_ip === ip) || null
}

// Match listener row to its runtime status
function getListenerStatus(row) {
  const statuses = nodeStatus.value?.listener_statuses
  if (!statuses) return null
  return statuses.find(s => s.listen_addr === row.listen_address) || null
}

function formatNumber(n) {
  if (n == null) return '—'
  if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M'
  if (n >= 1000) return (n / 1000).toFixed(1) + 'K'
  return String(n)
}

function formatUptime(seconds) {
  if (seconds == null) return '—'
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  if (d > 0) return `${d}d ${h}h ${m}m`
  if (h > 0) return `${h}h ${m}m`
  if (m > 0) return `${m}m`
  return `${seconds}s`
}
const sourceForm = reactive({ name: '', device_ip: '', sample_mode: 'auto', sample_rate: 1000, description: '' })

async function loadNodeStatus() {
  try {
    nodeStatus.value = await api.get(`/nodes/${nodeId}/status`)
  } catch (e) { console.error('Failed to load node status', e) }
}

async function loadListeners() {
  try {
    const data = await api.get('/flow-listeners', { params: { node_id: nodeId } })
    // Load source counts for each listener
    for (const l of data) {
      try {
        const detail = await api.get(`/flow-listeners/${l.id}`)
        l._sources = detail.sources || []
      } catch (e) { l._sources = [] }
    }
    listeners.value = data
  } catch (e) { console.error(e) }
}

async function handleCreateListener() {
  try {
    await api.post('/flow-listeners', { ...listenerForm, node_id: nodeId })
    ElMessage.success('Listener created')
    showAddListener.value = false
    listenerForm.listen_address = ':2055'
    listenerForm.protocol_mode = 'auto'
    listenerForm.description = ''
    loadListeners()
  } catch (e) { ElMessage.error(e?.error || e?.message || 'Failed') }
}

function openEditListener(row) {
  editingListenerId.value = row.id
  Object.assign(listenerForm, {
    listen_address: row.listen_address,
    protocol_mode: row.protocol_mode,
    description: row.description || '',
  })
  showAddListener.value = true
}

async function handleUpdateListener() {
  try {
    await api.put(`/flow-listeners/${editingListenerId.value}`, listenerForm)
    ElMessage.success('Updated')
    showAddListener.value = false
    editingListenerId.value = null
    loadListeners()
  } catch (e) { ElMessage.error(e?.error || e?.message || 'Failed') }
}

async function handleToggleListener(row) {
  try {
    await api.put(`/flow-listeners/${row.id}`, { listen_address: row.listen_address, protocol_mode: row.protocol_mode, enabled: row.enabled, description: row.description })
  } catch (e) {
    row.enabled = !row.enabled // revert on failure
    ElMessage.error(e?.error || e?.message || 'Failed to update')
  }
}

async function handleDeleteListener(id) {
  try {
    await ElMessageBox.confirm('Delete this listener and all its sources?', 'Confirm', { type: 'warning' })
    await api.delete(`/flow-listeners/${id}`)
    ElMessage.success('Deleted')
    loadListeners()
  } catch (e) { if (e !== 'cancel') ElMessage.error(e?.error || e?.message || 'Failed') }
}

async function openSources(listener) {
  selectedListener.value = listener
  showSources.value = true
  try {
    const data = await api.get('/flow-sources', { params: { listener_id: listener.id } })
    sources.value = data
  } catch (e) { sources.value = [] }
}

async function handleCreateSource() {
  try {
    await api.post('/flow-sources', {
      ...sourceForm,
      listener_id: selectedListener.value.id,
    })
    ElMessage.success('Source created')
    showAddSource.value = false
    sourceForm.name = ''
    sourceForm.device_ip = ''
    sourceForm.sample_mode = 'auto'
    sourceForm.sample_rate = 1000
    sourceForm.description = ''
    openSources(selectedListener.value)
    loadListeners()
  } catch (e) { ElMessage.error(e?.error || e?.message || 'Failed') }
}

function openEditSource(row) {
  editingSourceId.value = row.id
  Object.assign(sourceForm, {
    name: row.name,
    device_ip: row.device_ip?.replace(/\/\d+$/, '') || '',
    sample_mode: row.sample_mode,
    sample_rate: row.sample_rate || 1000,
    description: row.description || '',
  })
  showAddSource.value = true
}

async function handleUpdateSource() {
  try {
    await api.put(`/flow-sources/${editingSourceId.value}`, sourceForm)
    ElMessage.success('Updated')
    showAddSource.value = false
    editingSourceId.value = null
    openSources(selectedListener.value)
  } catch (e) { ElMessage.error(e?.error || e?.message || 'Failed') }
}

async function handleToggleSource(row) {
  try {
    await api.put(`/flow-sources/${row.id}`, { name: row.name, device_ip: row.device_ip, sample_mode: row.sample_mode, sample_rate: row.sample_rate, enabled: row.enabled, description: row.description })
  } catch (e) {
    row.enabled = !row.enabled
    ElMessage.error(e?.error || e?.message || 'Failed to update')
  }
}

async function handleDeleteSource(id) {
  try {
    await ElMessageBox.confirm('Delete this source?', 'Confirm', { type: 'warning' })
    await api.delete(`/flow-sources/${id}`)
    ElMessage.success('Deleted')
    openSources(selectedListener.value)
    loadListeners()
  } catch (e) { if (e !== 'cancel') ElMessage.error(e?.error || e?.message || 'Failed') }
}

let metricsTimer = null

onMounted(() => {
  loadListeners()
  loadNodeStatus()
  metricsTimer = setInterval(loadNodeStatus, 10000)
})

onUnmounted(() => {
  if (metricsTimer) clearInterval(metricsTimer)
})
</script>
