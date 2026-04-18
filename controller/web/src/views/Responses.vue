<template>
  <div>
    <!-- Response List View -->
    <div v-if="!editingResponse">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
        <h2>{{ $t('responses.title') }}</h2>
        <el-button type="primary" @click="showAdd = true">{{ $t('responses.addResponse') }}</el-button>
      </div>
      <el-table :data="responses" stripe :empty-text="$t('common.noData')" @row-click="openDetail">
        <el-table-column prop="id" :label="$t('common.id')" width="60" />
        <el-table-column prop="name" :label="$t('common.name')" />
        <el-table-column prop="description" :label="$t('common.description')" />
        <el-table-column :label="$t('responses.actions')" width="100">
          <template #default="{ row }">{{ row.action_count ?? '-' }}</template>
        </el-table-column>
        <el-table-column :label="$t('responses.boundTemplates')" width="140">
          <template #default="{ row }">{{ row.bound_template_count ?? '-' }}</template>
        </el-table-column>
        <el-table-column prop="enabled" :label="$t('common.enabled')" width="90">
          <template #default="{ row }">
            <el-tag :type="row.enabled !== false ? 'success' : 'info'" size="small">{{ row.enabled !== false ? $t('common.yes') : $t('common.no') }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" :label="$t('common.createdAt')" width="180">
          <template #default="{ row }">{{ new Date(row.created_at).toLocaleString() }}</template>
        </el-table-column>
        <el-table-column :label="$t('common.actions')" width="150">
          <template #default="{ row }">
            <el-button size="small" @click.stop="openDetail(row)">{{ $t('common.edit') }}</el-button>
            <el-button size="small" type="danger" @click.stop="handleDelete(row.id)">{{ $t('common.delete') }}</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- Response Detail/Edit View -->
    <div v-else>
      <el-page-header @back="closeDetail" :title="$t('responses.title')">
        <template #content>
          <span style="font-size: 18px; font-weight: bold;">{{ editingResponse.name }}</span>
          <el-tag v-if="editingResponse.enabled !== false" type="success" size="small" style="margin-left: 8px;">{{ $t('common.enabled') }}</el-tag>
          <el-tag v-else type="info" size="small" style="margin-left: 8px;">{{ $t('common.disabled') }}</el-tag>
        </template>
      </el-page-header>

      <!-- Response info edit -->
      <el-card style="margin-top: 16px;">
        <el-form :model="editForm" label-width="120px" inline>
          <el-form-item :label="$t('common.name')"><el-input v-model="editForm.name" style="width: 200px;" /></el-form-item>
          <el-form-item :label="$t('common.description')"><el-input v-model="editForm.description" style="width: 300px;" /></el-form-item>
          <el-form-item :label="$t('common.enabled')"><el-switch v-model="editForm.enabled" /></el-form-item>
          <el-form-item><el-button type="primary" @click="handleUpdateResponse">{{ $t('common.save') }}</el-button></el-form-item>
        </el-form>
      </el-card>

      <!-- On Detected Actions -->
      <el-card style="margin-top: 16px;">
        <template #header>
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <span style="font-weight: bold;">{{ $t('responses.onDetected') }}</span>
            <el-button size="small" @click="openActionEditor('on_detected')">+ {{ $t('responses.addAction') }}</el-button>
          </div>
        </template>
        <el-table :data="detectedActions" size="small" stripe :empty-text="$t('common.noData')" :row-class-name="actionRowClass">
          <el-table-column prop="priority" :label="$t('responses.priority')" width="80" />
          <el-table-column :label="$t('responses.actionType')" width="120">
            <template #default="{ row }">
              <span>{{ row.action_type }}</span>
              <span v-if="row.action_type !== 'webhook'" style="font-size: 11px; color: var(--xs-text-secondary); margin-left: 4px;">(first-match)</span>
            </template>
          </el-table-column>
          <el-table-column prop="connector_name" :label="$t('responses.connectorName')" />
          <el-table-column prop="run_mode" :label="$t('responses.runMode')" width="140" />
          <el-table-column :label="$t('responses.execution')" width="100">
            <template #default="{ row }">{{ row.execution || 'automatic' }}</template>
          </el-table-column>
          <el-table-column :label="$t('common.enabled')" width="80">
            <template #default="{ row }">
              <el-tag :type="row.enabled !== false ? 'success' : 'info'" size="small">{{ row.enabled !== false ? $t('common.yes') : $t('common.no') }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column :label="$t('common.actions')" width="140">
            <template #default="{ row }">
              <el-button size="small" link @click="openEditAction(row)">{{ $t('common.edit') }}</el-button>
              <el-button size="small" type="danger" link @click="handleDeleteAction(row.id)">{{ $t('common.delete') }}</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-card>

      <!-- On Expired Actions -->
      <el-card style="margin-top: 16px;">
        <template #header>
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <span style="font-weight: bold;">{{ $t('responses.onExpired') }}</span>
            <el-button size="small" @click="openActionEditor('on_expired')">+ {{ $t('responses.addAction') }}</el-button>
          </div>
        </template>
        <el-table :data="expiredActions" size="small" stripe :empty-text="$t('common.noData')" :row-class-name="actionRowClass">
          <el-table-column prop="priority" :label="$t('responses.priority')" width="80" />
          <el-table-column :label="$t('responses.actionType')" width="120">
            <template #default="{ row }">
              <span>{{ row.action_type }}</span>
              <span v-if="row.action_type !== 'webhook'" style="font-size: 11px; color: var(--xs-text-secondary); margin-left: 4px;">(first-match)</span>
            </template>
          </el-table-column>
          <el-table-column prop="connector_name" :label="$t('responses.connectorName')" />
          <el-table-column prop="run_mode" :label="$t('responses.runMode')" width="140" />
          <el-table-column :label="$t('responses.execution')" width="100">
            <template #default="{ row }">{{ row.execution || 'automatic' }}</template>
          </el-table-column>
          <el-table-column :label="$t('common.enabled')" width="80">
            <template #default="{ row }">
              <el-tag :type="row.enabled !== false ? 'success' : 'info'" size="small">{{ row.enabled !== false ? $t('common.yes') : $t('common.no') }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column :label="$t('common.actions')" width="140">
            <template #default="{ row }">
              <el-button size="small" link @click="openEditAction(row)">{{ $t('common.edit') }}</el-button>
              <el-button size="small" type="danger" link @click="handleDeleteAction(row.id)">{{ $t('common.delete') }}</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-card>
    </div>

    <!-- Create Response Dialog -->
    <el-dialog v-model="showAdd" :title="$t('responses.addResponse')" width="450px">
      <el-form :model="form" label-width="120px">
        <el-form-item :label="$t('common.name')"><el-input v-model="form.name" /></el-form-item>
        <el-form-item :label="$t('common.description')"><el-input v-model="form.description" type="textarea" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAdd = false">{{ $t('common.cancel') }}</el-button>
        <el-button type="primary" @click="handleCreate">{{ $t('common.create') }}</el-button>
      </template>
    </el-dialog>

    <!-- Action Editor Dialog -->
    <el-dialog v-model="showActionEditor" :title="actionEditorMode === 'edit' ? $t('responses.editAction') : $t('responses.addAction')" width="600px">
      <el-form :model="actionForm" label-width="140px">
        <el-form-item :label="$t('responses.actionType')">
          <el-select v-model="actionForm.action_type" @change="onActionTypeChange" style="width: 100%;">
            <el-option label="Webhook" value="webhook" />
            <el-option v-if="actionEditorPhase !== 'on_expired'" label="xDrop" value="xdrop" />
            <el-option label="Shell" value="shell" />
            <el-option v-if="actionEditorPhase !== 'on_expired'" label="BGP" value="bgp" />
          </el-select>
        </el-form-item>
        <!-- Connector selector: for webhook/shell/bgp (xDrop uses target nodes instead) -->
        <el-form-item v-if="actionForm.action_type === 'webhook' || actionForm.action_type === 'shell' || actionForm.action_type === 'bgp'" :label="$t('responses.connector')">
          <el-select v-model="actionForm.connector_id" style="width: 100%;" :placeholder="$t('responses.selectConnector')">
            <el-option v-for="c in availableConnectors" :key="c.id" :label="c.name" :value="c.id" />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('responses.priority')">
          <el-input-number v-model="actionForm.priority" :min="1" :max="10" />
        </el-form-item>
        <el-form-item :label="$t('responses.runMode')">
          <el-select v-model="actionForm.run_mode" style="width: 100%;">
            <el-option label="Once" value="once" />
            <el-option v-if="actionForm.trigger_phase !== 'on_expired'" label="Periodic" value="periodic" />
            <el-option v-if="actionForm.trigger_phase !== 'on_expired'" label="Retry Until Success" value="retry_until_success" />
          </el-select>
        </el-form-item>
        <el-form-item v-if="actionForm.run_mode === 'periodic'" :label="$t('responses.periodSeconds')">
          <el-input-number v-model="actionForm.period_seconds" :min="5" :max="86400" />
        </el-form-item>
        <el-form-item :label="$t('responses.execution')">
          <el-select v-model="actionForm.execution" style="width: 100%;">
            <el-option label="Automatic" value="automatic" />
            <el-option label="Manual" value="manual" />
          </el-select>
        </el-form-item>

        <!-- xDrop-specific fields -->
        <template v-if="actionForm.action_type === 'xdrop'">
          <!-- v1.2.1: surface the decoder compatibility gate at the action
               config point. Operators who bind this response to an `ip`-
               decoder threshold rule will see their xdrop action skipped
               at dispatch time; this note pre-empts the support ticket. -->
          <el-alert type="warning" :closable="false" show-icon style="margin-bottom: 14px;" :title="$t('responses.xdropDecoderScope')">
            <template #default>
              <div style="font-size: 12px;">{{ $t('responses.xdropDecoderScopeBody') }}</div>
            </template>
          </el-alert>
          <el-form-item :label="$t('responses.xdropAction')">
            <el-select v-model="actionForm.xdrop_action" style="width: 100%;">
              <el-option label="Filter L4" value="filter_l4" />
              <el-option label="Rate Limit" value="rate_limit" />
              <el-option label="Unblock" value="unblock" />
            </el-select>
          </el-form-item>
          <!-- Filter fields: checkboxes to select which 5-tuple fields to push to xDrop -->
          <el-form-item v-if="actionForm.xdrop_action === 'filter_l4' || actionForm.xdrop_action === 'rate_limit'" :label="$t('responses.filterFields')">
            <div>
              <el-checkbox-group v-model="actionForm.xdrop_fields">
                <el-checkbox label="dst_ip">Dst IP</el-checkbox>
                <el-checkbox label="src_ip">Src IP</el-checkbox>
                <el-checkbox label="dst_port">Dst Port</el-checkbox>
                <el-checkbox label="src_port">Src Port</el-checkbox>
                <el-checkbox label="protocol">Protocol</el-checkbox>
              </el-checkbox-group>
              <div style="font-size: 12px; color: var(--xs-text-secondary); margin-top: 4px;">{{ $t('responses.filterFieldsHint') }}</div>
            </div>
          </el-form-item>
          <!-- Rate limit PPS value -->
          <el-form-item v-if="actionForm.xdrop_action === 'rate_limit'" :label="$t('responses.rateLimitPPS')">
            <el-input-number v-model="actionForm.xdrop_rate_limit" :min="1" :max="100000000" :step="10000" />
            <span style="margin-left: 8px; font-size: 12px; color: var(--xs-text-secondary);">pps</span>
          </el-form-item>
          <el-form-item :label="$t('responses.targetNodes')">
            <div>
              <el-checkbox-group v-model="actionForm.target_node_ids">
                <el-checkbox v-for="c in xdropConnectorList" :key="c.id" :label="c.id">{{ c.name }}</el-checkbox>
              </el-checkbox-group>
              <div style="font-size: 12px; color: var(--xs-text-secondary); margin-top: 4px;">{{ $t('responses.targetNodesHint') }}</div>
            </div>
          </el-form-item>
        </template>

        <!-- BGP-specific fields -->
        <el-form-item v-if="actionForm.action_type === 'bgp' && actionEditorPhase === 'on_detected'" label="Route Map">
          <el-input v-model="actionForm.bgp_route_map" placeholder="RTBH" />
        </el-form-item>

        <!-- Shell-specific fields -->
        <el-form-item v-if="actionForm.action_type === 'shell'" :label="$t('responses.shellExtraArgs')">
          <el-input v-model="actionForm.shell_extra_args" :placeholder="$t('responses.shellExtraArgsPlaceholder')" />
        </el-form-item>

        <!-- Unblock delay: for on_detected xdrop filter/rate_limit actions -->
        <el-form-item v-if="actionForm.action_type === 'xdrop' && actionEditorPhase === 'on_detected' && (actionForm.xdrop_action === 'filter_l4' || actionForm.xdrop_action === 'rate_limit')" :label="$t('responses.unblockDelay')">
          <el-input-number v-model="actionForm.unblock_delay_minutes" :min="0" :max="1440" :step="5" />
          <div style="color: #909399; font-size: 12px; margin-top: 4px;">{{ $t('responses.unblockDelayHint') }}</div>
        </el-form-item>

        <!-- Withdraw delay: for on_detected bgp actions -->
        <el-form-item v-if="actionForm.action_type === 'bgp' && actionEditorPhase === 'on_detected'" :label="$t('responses.withdrawDelay')">
          <el-input-number v-model="actionForm.bgp_withdraw_delay_minutes" :min="0" :max="1440" :step="5" />
          <div style="color: #909399; font-size: 12px; margin-top: 4px;">{{ $t('responses.withdrawDelayHint') }}</div>
        </el-form-item>

        <el-form-item :label="$t('common.enabled')">
          <el-switch v-model="actionForm.enabled" />
        </el-form-item>

        <!-- Preconditions -->
        <el-form-item :label="$t('responses.preconditions')">
          <div style="width: 100%;">
            <div v-for="(cond, idx) in actionForm.preconditions" :key="idx" style="display: flex; gap: 8px; margin-bottom: 6px; align-items: center;">
              <el-select v-model="cond.attribute" style="width: 160px;" size="small" placeholder="Attribute">
                <el-option label="CIDR" value="cidr" />
                <el-option label="Decoder" value="decoder" />
                <el-option label="Attack Type" value="attack_type" />
                <el-option label="Severity" value="severity" />
                <el-option label="PPS" value="pps" />
                <el-option label="BPS" value="bps" />
                <el-option label="Node" value="node" />
                <el-option label="Domain" value="domain" />
                <el-option label="Dominant Src Port" value="dominant_src_port" />
                <el-option label="Dominant Src Port %" value="dominant_src_port_pct" />
                <el-option label="Dominant Dst Port" value="dominant_dst_port" />
                <el-option label="Dominant Dst Port %" value="dominant_dst_port_pct" />
                <el-option label="Unique Src IPs" value="unique_src_ips" />
              </el-select>
              <el-select v-model="cond.operator" style="width: 100px;" size="small" placeholder="Op">
                <el-option label="=" value="eq" />
                <el-option label="≠" value="neq" />
                <el-option label=">" value="gt" />
                <el-option label="≥" value="gte" />
                <el-option label="<" value="lt" />
                <el-option label="≤" value="lte" />
                <el-option label="in" value="in" />
                <el-option label="not in" value="not_in" />
              </el-select>
              <el-input v-model="cond.value" size="small" placeholder="Value" style="flex: 1;" />
              <el-button size="small" type="danger" :icon="Delete" circle @click="actionForm.preconditions.splice(idx, 1)" />
            </div>
            <el-button size="small" @click="actionForm.preconditions.push({ attribute: '', operator: 'eq', value: '' })">+ {{ $t('responses.addCondition') }}</el-button>
          </div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showActionEditor = false">{{ $t('common.cancel') }}</el-button>
        <el-button type="primary" @click="handleSaveAction">{{ $t('common.save') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Delete } from '@element-plus/icons-vue'
import api, {
  getResponses, createResponse, getResponse, updateResponse, deleteResponse,
  createAction, updateAction, deleteAction,
  getWebhookConnectors, getXDropConnectors, getShellConnectors,
} from '../api'

const responses = ref([])
const showAdd = ref(false)
const form = reactive({ name: '', description: '' })

// Detail view
const editingResponse = ref(null)
const editForm = reactive({ name: '', description: '', enabled: true })
const responseActions = ref([])

// Row class for action table — add border-top when action_type changes (visual grouping).
function actionRowClass({ row, rowIndex }) {
  // Detected and expired tables use same function; get the right data source
  const list = row.trigger_phase === 'on_expired' ? expiredActions.value : detectedActions.value
  if (rowIndex > 0 && list[rowIndex - 1]?.action_type !== row.action_type) {
    return 'action-type-divider'
  }
  return ''
}

// Sort actions by action_type then priority within each trigger_phase group.
// This groups same-type actions together for clarity (matches first-match execution model).
const actionTypeOrder = { xdrop: 0, shell: 1, webhook: 2 }
function sortActions(actions) {
  return [...actions].sort((a, b) => {
    const typeA = actionTypeOrder[a.action_type] ?? 9
    const typeB = actionTypeOrder[b.action_type] ?? 9
    if (typeA !== typeB) return typeA - typeB
    return (a.priority || 0) - (b.priority || 0)
  })
}
const detectedActions = computed(() => sortActions(responseActions.value.filter(a => a.trigger_phase === 'on_detected')))
const expiredActions = computed(() => sortActions(responseActions.value.filter(a => a.trigger_phase === 'on_expired' && !a.auto_generated)))

// Action editor
const showActionEditor = ref(false)
const actionEditorMode = ref('create') // 'create' or 'edit'
const actionEditorPhase = ref('on_detected')
const actionForm = reactive({
  id: null,
  action_type: 'webhook',
  connector_id: null,
  priority: 5,
  run_mode: 'once',
  period_seconds: 60,
  execution: 'automatic',
  xdrop_action: 'filter_l4',
  xdrop_fields: ['dst_ip'],
  xdrop_rate_limit: 100000,
  target_node_ids: [],
  shell_extra_args: '',
  bgp_route_map: '',
  bgp_withdraw_delay_minutes: 0,
  unblock_delay_minutes: 0,
  enabled: true,
  preconditions: [],
})

// Connector caches
const webhookConnectorList = ref([])
const xdropConnectorList = ref([])
const shellConnectorList = ref([])
const bgpConnectorList = ref([])

const availableConnectors = computed(() => {
  if (actionForm.action_type === 'webhook') return webhookConnectorList.value
  if (actionForm.action_type === 'xdrop') return xdropConnectorList.value
  if (actionForm.action_type === 'shell') return shellConnectorList.value
  if (actionForm.action_type === 'bgp') return bgpConnectorList.value
  return []
})

async function load() { responses.value = await getResponses() }
onMounted(load)

async function loadConnectors() {
  try { webhookConnectorList.value = await getWebhookConnectors() || [] } catch { webhookConnectorList.value = [] }
  try { xdropConnectorList.value = await getXDropConnectors() || [] } catch { xdropConnectorList.value = [] }
  try { shellConnectorList.value = await getShellConnectors() || [] } catch { shellConnectorList.value = [] }
  try { bgpConnectorList.value = await api.get('/settings/bgp-connectors') || [] } catch { bgpConnectorList.value = [] }
}

async function handleCreate() {
  await createResponse(form)
  ElMessage.success('Response created')
  showAdd.value = false
  Object.assign(form, { name: '', description: '' })
  load()
}

async function handleDelete(id) {
  await ElMessageBox.confirm('Delete this response?')
  try {
    await deleteResponse(id)
    ElMessage.success('Deleted')
    load()
  } catch (e) {
    ElMessage.error(e?.error || e?.message || 'Delete failed')
  }
}

async function openDetail(row) {
  try {
    const res = await getResponse(row.id)
    editingResponse.value = res.response || res
    responseActions.value = res.actions || []
    editForm.name = editingResponse.value.name
    editForm.description = editingResponse.value.description
    editForm.enabled = editingResponse.value.enabled !== false
    await loadConnectors()
  } catch (e) {
    ElMessage.error('Failed to load response detail')
  }
}

function closeDetail() {
  editingResponse.value = null
  responseActions.value = []
  load()
}

async function handleUpdateResponse() {
  await updateResponse(editingResponse.value.id, {
    name: editForm.name,
    description: editForm.description,
    enabled: editForm.enabled,
  })
  editingResponse.value.name = editForm.name
  editingResponse.value.description = editForm.description
  editingResponse.value.enabled = editForm.enabled
  ElMessage.success('Updated')
}

function resetActionForm() {
  Object.assign(actionForm, {
    id: null,
    action_type: 'webhook',
    connector_id: null,
    priority: 5,
    run_mode: 'once',
    period_seconds: 60,
    execution: 'automatic',
    xdrop_action: 'filter_l4',
    xdrop_fields: ['dst_ip'],
    xdrop_rate_limit: 100000,
    target_node_ids: [],
    shell_extra_args: '',
    bgp_withdraw_delay_minutes: 0,
    unblock_delay_minutes: 0,
    enabled: true,
  })
}

function openActionEditor(phase) {
  resetActionForm()
  actionEditorMode.value = 'create'
  actionEditorPhase.value = phase
  showActionEditor.value = true
}

async function openEditAction(action) {
  actionEditorMode.value = 'edit'
  actionEditorPhase.value = action.trigger_phase
  // Load preconditions from API
  let preconditions = []
  let precondsLoaded = false
  try {
    preconditions = await api.get(`/actions/${action.id}/preconditions`) || []
    precondsLoaded = true
  } catch (e) {
    ElMessage.warning('Failed to load preconditions. Editing is read-only for conditions.')
  }
  Object.assign(actionForm, {
    id: action.id,
    action_type: action.action_type || 'webhook',
    connector_id: action.connector_id,
    priority: action.priority || 5,
    run_mode: action.run_mode || 'once',
    period_seconds: action.period_seconds || 60,
    execution: action.execution || 'automatic',
    xdrop_action: action.xdrop_action || 'filter_l4',
    xdrop_fields: action.xdrop_fields || ['dst_ip'],
    xdrop_rate_limit: action.xdrop_rate_limit || 100000,
    target_node_ids: action.target_node_ids || [],
    shell_extra_args: action.shell_extra_args || '',
    bgp_route_map: action.bgp_route_map || '',
    bgp_withdraw_delay_minutes: action.bgp_withdraw_delay_minutes || 0,
    unblock_delay_minutes: action.unblock_delay_minutes || 0,
    enabled: action.enabled !== false,
    preconditions: preconditions.map(p => ({ attribute: p.attribute, operator: p.operator, value: p.value })),
  })
  showActionEditor.value = true
}

function onActionTypeChange() {
  actionForm.connector_id = null
}

async function handleSaveAction() {
  // Validate xDrop fields: filter_l4/rate_limit must have at least one match field
  if (actionForm.action_type === 'xdrop' && (actionForm.xdrop_action === 'filter_l4' || actionForm.xdrop_action === 'rate_limit')) {
    if (!actionForm.xdrop_fields || actionForm.xdrop_fields.length === 0) {
      ElMessage.warning($t('responses.filterFieldsRequired'))
      return
    }
    if (actionForm.xdrop_action === 'rate_limit' && (!actionForm.xdrop_rate_limit || actionForm.xdrop_rate_limit <= 0)) {
      ElMessage.warning($t('responses.rateLimitRequired'))
      return
    }
  }
  const payload = {
    action_type: actionForm.action_type,
    connector_id: actionForm.connector_id,
    priority: actionForm.priority,
    run_mode: actionForm.run_mode,
    period_seconds: actionForm.run_mode === 'periodic' ? actionForm.period_seconds : null,
    execution: actionForm.execution,
    trigger_phase: actionEditorPhase.value,
    enabled: actionForm.enabled,
  }
  if (actionForm.action_type === 'xdrop') {
    payload.xdrop_action = actionForm.xdrop_action
    payload.xdrop_fields = actionForm.xdrop_fields || []
    payload.xdrop_rate_limit = actionForm.xdrop_action === 'rate_limit' ? actionForm.xdrop_rate_limit : null
    payload.target_node_ids = actionForm.target_node_ids.length ? actionForm.target_node_ids : null
    // Build xdrop_custom_payload from checked fields
    if (actionForm.xdrop_action === 'filter_l4' || actionForm.xdrop_action === 'rate_limit') {
      const cp = {}
      const fields = actionForm.xdrop_fields || []
      if (fields.includes('dst_ip')) cp.dst_ip = '{dst_ip}'
      if (fields.includes('src_ip')) cp.src_ip = '{src_ip}'
      if (fields.includes('dst_port')) cp.dst_port = '{dominant_dst_port}'
      if (fields.includes('src_port')) cp.src_port = '{dominant_src_port}'
      if (fields.includes('protocol')) cp.protocol = '{decoder}'
      cp.action = actionForm.xdrop_action === 'rate_limit' ? 'rate_limit' : 'drop'
      if (actionForm.xdrop_action === 'rate_limit') cp.rate_limit = actionForm.xdrop_rate_limit
      cp.source = 'xsight'
      cp.comment = 'attack #{attack_id} {decoder}'
      payload.xdrop_custom_payload = cp
    }
  }
  if (actionForm.action_type === 'shell') {
    payload.shell_extra_args = actionForm.shell_extra_args || null
  }
  if (actionForm.action_type === 'bgp') {
    payload.bgp_route_map = actionForm.bgp_route_map || ''
  }
  // Unblock delay for on_detected xdrop filter/rate_limit actions
  if (actionForm.action_type === 'xdrop' && actionEditorPhase.value === 'on_detected' &&
      (actionForm.xdrop_action === 'filter_l4' || actionForm.xdrop_action === 'rate_limit')) {
    payload.unblock_delay_minutes = actionForm.unblock_delay_minutes || 0
  }

  let actionId
  if (actionEditorMode.value === 'edit') {
    await updateAction(actionForm.id, payload)
    actionId = actionForm.id
    ElMessage.success('Action updated')
  } else {
    const res = await createAction(editingResponse.value.id, payload)
    actionId = res?.id || res?.data?.id
    ElMessage.success('Action created')
  }
  // Save preconditions (treat as part of the same save operation)
  if (actionId) {
    const validConds = (actionForm.preconditions || []).filter(c => c.attribute && c.operator && c.value)
    try {
      await api.put(`/actions/${actionId}/preconditions`, { preconditions: validConds })
    } catch (e) {
      ElMessage.error('Action saved but preconditions failed to save. Please retry.')
      return // keep dialog open
    }
  }
  showActionEditor.value = false
  // Refresh actions
  const res = await getResponse(editingResponse.value.id)
  responseActions.value = res.actions || []
}

async function handleDeleteAction(actionId) {
  await ElMessageBox.confirm('Delete this action?')
  try {
    await deleteAction(actionId)
    ElMessage.success('Deleted')
    const res = await getResponse(editingResponse.value.id)
    responseActions.value = res.actions || []
  } catch (e) {
    ElMessage.error(e?.error || e?.message || 'Delete failed')
  }
}
</script>

<style>
/* Visual divider between action type groups in response action tables */
.el-table .action-type-divider td {
  border-top: 2px solid var(--el-border-color) !important;
}
</style>
