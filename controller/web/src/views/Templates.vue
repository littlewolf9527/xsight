<template>
  <div>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
      <h2>{{ $t('thresholds.templates') || 'Threshold Templates' }}</h2>
      <el-button type="primary" @click="showCreate = true">{{ $t('common.create') }}</el-button>
    </div>

    <!-- Template list table -->
    <el-table :data="templates" stripe :empty-text="$t('common.noData')" @row-click="openDetail">
      <el-table-column prop="id" :label="$t('common.id')" width="60" />
      <el-table-column prop="name" :label="$t('common.name')" />
      <el-table-column prop="description" :label="$t('common.description')" />
      <el-table-column prop="rule_count" :label="'Rules'" width="80" />
      <el-table-column prop="prefix_count" :label="'Prefixes'" width="80" />
      <el-table-column :label="$t('common.actions')" width="220">
        <template #default="{ row }">
          <el-button size="small" @click.stop="openDetail(row)">{{ $t('common.edit') }}</el-button>
          <el-button size="small" @click.stop="handleDuplicate(row)">{{ $t('common.duplicate') || 'Duplicate' }}</el-button>
          <el-button size="small" type="danger" @click.stop="handleDelete(row)">{{ $t('common.delete') }}</el-button>
        </template>
      </el-table-column>
    </el-table>

    <!-- Template detail modal (Wanguard style) -->
    <el-dialog v-model="showDetail" :title="detailTemplate?.name || ''" top="5vh" width="fit-content" class="template-detail-dialog">
      <template v-if="detailTemplate">
        <!-- Template info -->
        <div style="margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center;">
          <div>
            <span style="font-size: 13px; color: var(--xs-text-secondary);">{{ detailTemplate.description }}</span>
          </div>
          <el-button size="small" @click="startRename">{{ $t('common.edit') }} Name</el-button>
        </div>

        <!-- Default Response -->
        <div style="margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
          <span style="font-size: 13px; font-weight: bold;">{{ $t('thresholds.defaultResponse') }}:</span>
          <el-select v-model="detailTemplate.response_id" :placeholder="$t('thresholds.noResponse')" clearable size="small" style="width: 220px;" @change="handleTemplateResponseChange">
            <el-option :label="$t('thresholds.noResponse')" :value="null" />
            <el-option v-for="r in responseList" :key="r.id" :label="r.name" :value="r.id" />
          </el-select>
        </div>

        <!-- Prefixes using this template (collapsible) -->
        <div v-if="detailPrefixes.length" style="margin-bottom: 12px; font-size: 13px;">
          <span style="color: var(--xs-text-secondary);">{{ $t('thresholds.usedBy') || 'Used by' }} ({{ detailPrefixes.length }}): </span>
          <el-tag v-for="p in visiblePrefixes" :key="p.id" size="small" style="margin-right: 4px; margin-bottom: 4px;">{{ p.prefix }}</el-tag>
          <el-button v-if="detailPrefixes.length > 5 && !showAllPrefixes" type="primary" link size="small"
            @click="showAllPrefixes = true" style="margin-left: 4px;">
            +{{ detailPrefixes.length - 5 }} {{ $t('common.more') || 'more' }}...
          </el-button>
          <el-button v-if="showAllPrefixes && detailPrefixes.length > 5" type="info" link size="small"
            @click="showAllPrefixes = false" style="margin-left: 4px;">
            {{ $t('common.collapse') || 'collapse' }}
          </el-button>
        </div>

        <!-- Rules table -->
        <el-table :data="detailRules" size="small" stripe :empty-text="$t('common.noData')" border>
          <el-table-column prop="domain" :label="$t('thresholds.domain')" width="110" />
          <el-table-column prop="direction" :label="$t('thresholds.direction')" width="90" />
          <el-table-column prop="comparison" :label="$t('thresholds.comparison')" width="80" />
          <el-table-column :label="$t('thresholds.value')" width="100">
            <template #default="{ row }">{{ formatValue(row.value) }}</template>
          </el-table-column>
          <el-table-column prop="decoder" :label="$t('thresholds.decoder')" width="110" />
          <el-table-column prop="unit" :label="$t('thresholds.unit')" width="60" />
          <el-table-column :label="$t('thresholds.inheritable')" width="80">
            <template #default="{ row }">{{ row.inheritable ? '✓' : '✗' }}</template>
          </el-table-column>
          <el-table-column :label="$t('thresholds.response')" width="160">
            <template #default="{ row }">
              <el-select v-model="row.response_id" :placeholder="$t('thresholds.useDefault')" clearable size="small" @change="handleRuleResponseChange(row)">
                <el-option :label="$t('thresholds.useDefault')" :value="null" />
                <el-option v-for="r in responseList" :key="r.id" :label="r.name" :value="r.id" />
              </el-select>
            </template>
          </el-table-column>
          <el-table-column label="Recommend" width="140">
            <template #default="{ row }">
              <span v-if="recommendRange(row)" style="font-size: 12px; color: var(--xs-text-secondary);">
                {{ recommendRange(row) }}
              </span>
              <span v-else style="font-size: 11px; color: var(--xs-text-secondary);">⏳</span>
            </template>
          </el-table-column>
          <el-table-column :label="$t('common.actions')" width="120">
            <template #default="{ row }">
              <el-button size="small" link @click="startEditRule(row)">{{ $t('common.edit') }}</el-button>
              <el-button size="small" type="danger" link @click="handleDeleteRule(row.id)">{{ $t('common.delete') }}</el-button>
            </template>
          </el-table-column>
        </el-table>

        <el-button size="small" style="margin-top: 12px;" @click="editingRuleId = null; resetRuleForm(); showAddRule = true">+ {{ $t('thresholds.addRule') || 'Add Rule' }}</el-button>
      </template>
    </el-dialog>

    <!-- Create template dialog -->
    <el-dialog v-model="showCreate" :title="$t('common.create')" width="400px">
      <el-form :model="createForm" label-width="100px">
        <el-form-item :label="$t('common.name')"><el-input v-model="createForm.name" /></el-form-item>
        <el-form-item :label="$t('common.description')"><el-input v-model="createForm.description" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showCreate = false">{{ $t('common.cancel') }}</el-button>
        <el-button type="primary" @click="handleCreate">{{ $t('common.create') }}</el-button>
      </template>
    </el-dialog>

    <!-- Rename dialog -->
    <el-dialog v-model="showRename" title="Rename" width="400px">
      <el-form :model="renameForm" label-width="100px">
        <el-form-item :label="$t('common.name')"><el-input v-model="renameForm.name" /></el-form-item>
        <el-form-item :label="$t('common.description')"><el-input v-model="renameForm.description" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showRename = false">{{ $t('common.cancel') }}</el-button>
        <el-button type="primary" @click="handleRename">{{ $t('common.save') }}</el-button>
      </template>
    </el-dialog>

    <!-- Add/Edit rule dialog -->
    <el-dialog v-model="showAddRule" :title="editingRuleId ? ($t('common.edit') + ' Rule') : ($t('thresholds.addRule') || 'Add Rule')" width="500px">
      <el-form :model="ruleForm" label-width="110px">
        <el-form-item :label="$t('thresholds.domain')">
          <el-select v-model="ruleForm.domain">
            <el-option v-if="!isUsedByGlobalPrefix" label="internal_ip" value="internal_ip" />
            <el-option label="subnet" value="subnet" />
          </el-select>
          <div v-if="isUsedByGlobalPrefix" style="font-size: 12px; color: var(--el-color-warning);">{{ $t('thresholds.globalSubnetOnly') }}</div>
        </el-form-item>
        <el-form-item :label="$t('attacks.direction')">
          <el-select v-model="ruleForm.direction">
            <el-option label="Receives (Inbound)" value="receives" />
            <el-option label="Sends (Outbound)" value="sends" />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('thresholds.decoder')">
          <el-select v-model="ruleForm.decoder">
            <el-option v-for="d in decoders" :key="d" :label="d" :value="d" />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('thresholds.unit')">
          <el-select v-model="ruleForm.unit"><el-option label="pps" value="pps" /><el-option label="bps" value="bps" /><el-option label="pct (%)" value="pct" /></el-select>
        </el-form-item>
        <el-form-item :label="$t('thresholds.comparison')">
          <el-select v-model="ruleForm.comparison"><el-option label="over" value="over" /><el-option label="under" value="under" /></el-select>
        </el-form-item>
        <el-form-item :label="$t('thresholds.value')">
          <el-input-number v-model="ruleForm.value" :min="1" :max="ruleForm.unit === 'pct' ? 100 : undefined" />
          <span v-if="ruleForm.unit === 'pct'" style="margin-left:8px;color:#909399;font-size:12px;">{{ $t('thresholds.pctRange') || 'Valid range: 1–100' }}</span>
        </el-form-item>
        <el-form-item :label="$t('thresholds.inheritable')"><el-switch v-model="ruleForm.inheritable" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAddRule = false; editingRuleId = null; resetRuleForm()">{{ $t('common.cancel') }}</el-button>
        <el-button type="primary" @click="editingRuleId ? handleUpdateRule() : handleAddRule()">{{ editingRuleId ? $t('common.save') : $t('common.create') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import api, { getResponses } from '../api'

const { t } = useI18n()
const templates = ref([])
const responseList = ref([])
const showCreate = ref(false)
const showDetail = ref(false)
const showRename = ref(false)
const showAddRule = ref(false)
const editingRuleId = ref(null) // null = add mode, number = edit mode
const editingRuleOriginal = ref(null) // full row for merge on save
const detailTemplate = ref(null)
const detailRules = ref([])
const detailPrefixes = ref([])
const showAllPrefixes = ref(false)
const visiblePrefixes = computed(() =>
  showAllPrefixes.value ? detailPrefixes.value : detailPrefixes.value.slice(0, 5)
)
// Global prefix (0.0.0.0/0) only supports subnet rules — hide internal_ip when this template is used by global
const isUsedByGlobalPrefix = computed(() =>
  detailPrefixes.value.some(p => p.prefix === '0.0.0.0/0')
)
const baselineData = ref([])
const createForm = reactive({ name: '', description: '' })
const renameForm = reactive({ id: 0, name: '', description: '' })
const ruleForm = reactive({ domain: 'internal_ip', direction: 'receives', decoder: 'tcp_syn', unit: 'pps', comparison: 'over', value: 500, inheritable: true })
const decoders = ['ip', 'tcp', 'tcp_syn', 'udp', 'icmp', 'fragment']

// Auto-adjust value when switching to/from pct unit
watch(() => ruleForm.unit, (newUnit, oldUnit) => {
  if (newUnit === 'pct' && oldUnit !== 'pct') {
    ruleForm.value = 100
  } else if (newUnit !== 'pct' && oldUnit === 'pct') {
    ruleForm.value = 500
  }
})

function formatValue(v) {
  if (v >= 1000000000) return (v / 1000000000).toFixed(0) + 'G'
  if (v >= 1000000) return (v / 1000000).toFixed(0) + 'M'
  if (v >= 1000) return (v / 1000).toFixed(0) + 'K'
  return v
}

async function load() {
  // Single request — backend returns rule_count + prefix_count via LEFT JOIN (no N+1)
  templates.value = await api.get('/threshold-templates') || []
}
async function loadResponses() {
  try { responseList.value = await getResponses() || [] } catch { responseList.value = [] }
}
onMounted(() => { load(); loadResponses() })

function fmtPPS(v) {
  if (!v) return '0'
  if (v >= 1e9) return (v / 1e9).toFixed(1) + 'G'
  if (v >= 1e6) return (v / 1e6).toFixed(1) + 'M'
  if (v >= 1e3) return (v / 1e3).toFixed(0) + 'K'
  return String(v)
}

// For a rule (e.g. tcp_syn/pps), show the recommended range across all prefixes using this template
function recommendRange(rule) {
  if (!baselineData.value.length) return ''
  // Filter baselines for prefixes using this template
  const prefixCIDRs = (detailPrefixes.value || []).map(p => p.prefix)
  const relevant = baselineData.value.filter(b => prefixCIDRs.includes(b.prefix) && b.active)
  if (!relevant.length) return ''

  // Prefix-level baseline only — not decoder-specific
  if (rule.decoder && rule.decoder !== 'ip') return '(prefix-level)'
  const field = rule.unit === 'bps' ? 'recommend_bps' : 'recommend_pps'
  const values = relevant.map(b => b[field]).filter(v => v > 0)
  if (!values.length) return ''
  const min = Math.min(...values)
  const max = Math.max(...values)
  if (min === max) return '→ ' + fmtPPS(min)
  return '→ ' + fmtPPS(min) + '–' + fmtPPS(max)
}

async function openDetail(row) {
  try {
    const d = await api.get(`/threshold-templates/${row.id}`)
    detailTemplate.value = d.template
    detailRules.value = d.rules || []
    detailPrefixes.value = d.prefixes_using || []
    showAllPrefixes.value = false
    // Load baselines for recommendation display
    try { baselineData.value = await api.get('/baseline') || [] } catch {}
    showDetail.value = true
  } catch (e) { ElMessage.error('Failed to load template') }
}

async function handleCreate() {
  await api.post('/threshold-templates', createForm)
  ElMessage.success('Template created')
  showCreate.value = false
  Object.assign(createForm, { name: '', description: '' })
  load()
}

function startRename() {
  renameForm.id = detailTemplate.value.id
  renameForm.name = detailTemplate.value.name
  renameForm.description = detailTemplate.value.description
  showRename.value = true
}

async function handleRename() {
  await api.put(`/threshold-templates/${renameForm.id}`, { name: renameForm.name, description: renameForm.description })
  ElMessage.success('Updated')
  showRename.value = false
  detailTemplate.value.name = renameForm.name
  detailTemplate.value.description = renameForm.description
  load()
}

async function handleDuplicate(tpl) {
  const { value } = await ElMessageBox.prompt('New template name:', 'Duplicate', {
    inputValue: tpl.name + ' (Copy)', confirmButtonText: 'Duplicate',
  })
  await api.post(`/threshold-templates/${tpl.id}/duplicate`, { name: value })
  ElMessage.success('Duplicated')
  load()
}

async function handleDelete(tpl) {
  if (tpl.prefix_count > 0) {
    ElMessage.warning(`Template is used by ${tpl.prefix_count} prefix(es). Unbind them first.`)
    return
  }
  await ElMessageBox.confirm(`Delete "${tpl.name}"?`)
  try {
    await api.delete(`/threshold-templates/${tpl.id}`)
    ElMessage.success('Deleted')
    load()
  } catch (e) {
    ElMessage.error(e?.error || e?.message || 'Delete failed')
  }
}

async function handleAddRule() {
  if (ruleForm.unit === 'pct' && (ruleForm.value < 1 || ruleForm.value > 100)) {
    ElMessage.warning(t('thresholds.pctWarning'))
    return
  }
  await api.post(`/threshold-templates/${detailTemplate.value.id}/rules`, ruleForm)
  ElMessage.success('Rule added')
  showAddRule.value = false
  editingRuleId.value = null
  openDetail(detailTemplate.value) // refresh rules
}

// Reset rule form to defaults (for add mode)
function resetRuleForm() {
  const defaultDomain = isUsedByGlobalPrefix.value ? 'subnet' : 'internal_ip'
  Object.assign(ruleForm, { domain: defaultDomain, direction: 'receives', decoder: 'tcp_syn', unit: 'pps', comparison: 'over', value: 500, inheritable: true })
}

// Open rule edit dialog with existing rule values
function startEditRule(rule) {
  editingRuleId.value = rule.id
  editingRuleOriginal.value = { ...rule } // preserve full row for merge
  Object.assign(ruleForm, {
    domain: rule.domain || 'internal_ip',
    direction: rule.direction || 'receives',
    decoder: rule.decoder || 'tcp_syn',
    unit: rule.unit || 'pps',
    comparison: rule.comparison || 'over',
    value: rule.value || 500,
    inheritable: rule.inheritable !== false,
  })
  showAddRule.value = true
}

// Save edited rule — merge form fields into original row to avoid clearing unset fields
async function handleUpdateRule() {
  if (ruleForm.unit === 'pct' && (ruleForm.value < 1 || ruleForm.value > 100)) {
    ElMessage.warning(t('thresholds.pctWarning'))
    return
  }
  const payload = {
    ...editingRuleOriginal.value, // preserve template_id, response_id, enabled, etc.
    ...ruleForm,                   // overwrite editable fields
  }
  delete payload.id               // don't send id in body (it's in the URL)
  await api.put(`/threshold-rules/${editingRuleId.value}`, payload)
  ElMessage.success('Rule updated')
  showAddRule.value = false
  editingRuleId.value = null
  editingRuleOriginal.value = null
  openDetail(detailTemplate.value) // refresh rules
}

async function handleDeleteRule(ruleId) {
  await ElMessageBox.confirm('Delete this rule?')
  try {
    await api.delete(`/threshold-rules/${ruleId}`)
    ElMessage.success('Deleted')
    openDetail(detailTemplate.value)
  } catch (e) {
    ElMessage.error(e?.error || e?.message || 'Delete failed')
  }
}

async function handleTemplateResponseChange(val) {
  try {
    // clearable sets val to '' or undefined — normalize to null for backend
    const responseId = val || null
    await api.put(`/threshold-templates/${detailTemplate.value.id}`, { response_id: responseId })
    ElMessage.success('Default response updated')
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || 'Failed to update response')
  }
}

async function handleRuleResponseChange(rule) {
  try {
    // Send full row to avoid clearing other fields (backend is full-replace, not patch)
    const payload = { ...rule, response_id: rule.response_id }
    delete payload.id
    await api.put(`/threshold-rules/${rule.id}`, payload)
    ElMessage.success('Rule response updated')
  } catch { ElMessage.error('Failed to update rule response') }
}
</script>

<style>
.template-detail-dialog.el-dialog {
  width: fit-content !important;
  min-width: 800px;
  max-width: 95vw;
}
</style>
