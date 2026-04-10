<template>
  <div>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
      <h2>{{ $t('prefixes.title') }}</h2>
      <el-button type="primary" @click="openAdd">{{ $t('prefixes.addPrefix') }}</el-button>
    </div>
    <el-table :data="prefixes" stripe :empty-text="$t('common.noData')">
      <el-table-column prop="id" :label="$t('common.id')" width="60" />
      <el-table-column prop="prefix" :label="$t('prefixes.prefix')" width="180" />
      <el-table-column prop="name" :label="$t('common.name')" />
      <el-table-column prop="ip_group" :label="$t('prefixes.ipGroup')" width="120" />
      <el-table-column prop="parent_id" :label="$t('prefixes.parent')" width="100" />
      <el-table-column :label="$t('thresholds.templates') || 'Template'" width="160">
        <template #default="{ row }">
          <el-tag v-if="row.threshold_template_id && templateNames[row.threshold_template_id]" size="small" type="success">
            {{ templateNames[row.threshold_template_id] }}
          </el-tag>
          <span v-else style="color: var(--xs-text-secondary); font-size: 12px;">—</span>
        </template>
      </el-table-column>
      <el-table-column label="Baseline" width="180">
        <template #default="{ row }">
          <span v-if="baselineData[row.prefix]?.active" style="font-size: 12px;">
            P95: {{ formatPPS(baselineData[row.prefix].p95_pps) }}
            <br/><span style="color: var(--xs-text-secondary);">→ {{ formatPPS(baselineData[row.prefix].recommend_pps) }}</span>
          </span>
          <span v-else-if="baselineData[row.prefix]" style="font-size: 12px; color: var(--xs-text-secondary);">
            ⏳ {{ baselineData[row.prefix].data_points }}/3600
          </span>
          <span v-else style="color: var(--xs-text-secondary); font-size: 12px;">—</span>
        </template>
      </el-table-column>
      <el-table-column :label="$t('common.status')" width="100">
        <template #default="{ row }">
          <el-tag :type="row.enabled ? 'success' : 'info'" size="small">
            {{ row.enabled ? $t('common.enabled') : $t('common.disabled') }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="$t('common.actions')" width="150">
        <template #default="{ row }">
          <el-button size="small" @click="openEdit(row)">{{ $t('common.edit') }}</el-button>
          <el-button size="small" type="danger" @click="handleDelete(row.id)">{{ $t('common.delete') }}</el-button>
        </template>
      </el-table-column>
    </el-table>

    <!-- Add / Edit dialog (shared) -->
    <el-dialog v-model="showForm" :title="isEdit ? $t('common.edit') : $t('prefixes.addPrefix')" width="500px">
      <el-form :model="form" label-width="120px">
        <el-form-item :label="$t('prefixes.prefix')">
          <el-input v-model="form.prefix" placeholder="10.0.0.0/24" :disabled="isEdit" />
        </el-form-item>
        <el-form-item :label="$t('common.name')"><el-input v-model="form.name" /></el-form-item>
        <el-form-item :label="$t('prefixes.ipGroup')"><el-input v-model="form.ip_group" /></el-form-item>
        <el-form-item :label="$t('prefixes.parent')">
          <el-select v-model="form.parent_id" clearable placeholder="— None —">
            <el-option v-for="p in prefixes.filter(p => p.id !== form.id)" :key="p.id" :label="p.prefix + ' (' + p.name + ')'" :value="p.id" />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('thresholds.templates') || 'Template'">
          <el-select v-model="form.threshold_template_id" clearable placeholder="— None —">
            <el-option v-for="t in templateList" :key="t.id" :label="t.name" :value="t.id" />
          </el-select>
        </el-form-item>
        <el-form-item v-if="isEdit" :label="$t('common.status')">
          <el-switch v-model="form.enabled" :active-text="$t('common.enabled')" :inactive-text="$t('common.disabled')" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showForm = false">{{ $t('common.cancel') }}</el-button>
        <el-button type="primary" @click="handleSave">{{ isEdit ? $t('common.save') : $t('common.create') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { getPrefixes, createPrefix, updatePrefix, deletePrefix } from '../api'
import api from '../api'

const prefixes = ref([])
const showForm = ref(false)
const isEdit = ref(false)
const form = reactive({ id: 0, prefix: '', name: '', ip_group: '', parent_id: null, threshold_template_id: null, enabled: true })
const templateNames = ref({})
const templateList = ref([])
const baselineData = ref({})

function formatPPS(v) {
  if (!v) return '0'
  if (v >= 1000000000) return (v / 1000000000).toFixed(1) + 'G'
  if (v >= 1000000) return (v / 1000000).toFixed(1) + 'M'
  if (v >= 1000) return (v / 1000).toFixed(0) + 'K'
  return v
}

async function load() {
  prefixes.value = await getPrefixes()
  try {
    const tpls = await api.get('/threshold-templates') || []
    templateList.value = tpls
    const map = {}
    for (const t of tpls) { map[t.id] = t.name }
    templateNames.value = map
  } catch {}
  try {
    const baselines = await api.get('/baseline') || []
    const bMap = {}
    for (const b of baselines) { bMap[b.prefix] = b }
    baselineData.value = bMap
  } catch {}
}
onMounted(load)

function openAdd() {
  isEdit.value = false
  Object.assign(form, { id: 0, prefix: '', name: '', ip_group: '', parent_id: null, threshold_template_id: null, enabled: true })
  showForm.value = true
}

function openEdit(row) {
  isEdit.value = true
  Object.assign(form, {
    id: row.id,
    prefix: row.prefix,
    name: row.name,
    ip_group: row.ip_group,
    parent_id: row.parent_id,
    threshold_template_id: row.threshold_template_id,
    enabled: row.enabled,
  })
  showForm.value = true
}

async function handleSave() {
  if (isEdit.value) {
    await updatePrefix(form.id, form)
    ElMessage.success('Prefix updated')
  } else {
    await createPrefix(form)
    ElMessage.success('Prefix created')
  }
  showForm.value = false
  load()
}

async function handleDelete(id) {
  await ElMessageBox.confirm('Delete this prefix?')
  try {
    await deletePrefix(id)
    ElMessage.success('Deleted')
    load()
  } catch (e) {
    ElMessage.error(e?.error || e?.message || 'Delete failed')
  }
}
</script>
