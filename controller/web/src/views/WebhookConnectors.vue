<template>
  <div>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
      <h2>{{ t('webhookConnectors.title') }}</h2>
      <el-button type="primary" @click="openCreate">{{ t('webhookConnectors.add') }}</el-button>
    </div>
    <el-table :data="items" stripe :empty-text="t('common.noData')">
      <el-table-column prop="id" :label="t('common.id')" width="60" />
      <el-table-column prop="name" :label="t('common.name')" />
      <el-table-column prop="url" :label="t('webhookConnectors.url')" />
      <el-table-column prop="method" :label="t('webhookConnectors.method')" width="100" />
      <el-table-column :label="t('webhookConnectors.global')" width="100">
        <template #default="{ row }">
          <el-tag :type="row.global ? 'success' : 'info'" size="small">
            {{ row.global ? t('common.yes') : t('common.no') }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="t('common.status')" width="100">
        <template #default="{ row }">
          <el-tag :type="row.enabled ? 'success' : 'info'" size="small">
            {{ row.enabled ? t('common.enabled') : t('common.disabled') }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="t('common.actions')" width="220">
        <template #default="{ row }">
          <el-button size="small" @click="openEdit(row)">{{ t('common.edit') }}</el-button>
          <el-button size="small" type="success" @click="handleTest(row.id)" :loading="testing === row.id">{{ t('webhookConnectors.test') }}</el-button>
          <el-button size="small" type="danger" @click="handleDelete(row.id)">{{ t('common.delete') }}</el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-dialog v-model="showDialog" :title="isEdit ? t('webhookConnectors.edit') : t('webhookConnectors.add')" width="500px">
      <el-form :model="form" label-width="100px">
        <el-form-item :label="t('common.name')">
          <el-input v-model="form.name" />
        </el-form-item>
        <el-form-item :label="t('webhookConnectors.url')">
          <el-input v-model="form.url" placeholder="https://..." />
        </el-form-item>
        <el-form-item :label="t('webhookConnectors.method')">
          <el-select v-model="form.method" style="width: 100%;">
            <el-option label="POST" value="POST" />
            <el-option label="PUT" value="PUT" />
            <el-option label="PATCH" value="PATCH" />
          </el-select>
        </el-form-item>
        <el-form-item :label="t('webhookConnectors.headers')">
          <el-input v-model="form.headers" type="textarea" :rows="3" placeholder='{"Content-Type": "application/json"}' />
        </el-form-item>
        <el-form-item :label="t('webhookConnectors.global')">
          <el-switch v-model="form.global" />
        </el-form-item>
        <el-form-item :label="t('common.enabled')">
          <el-switch v-model="form.enabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showDialog = false">{{ t('common.cancel') }}</el-button>
        <el-button type="primary" @click="handleSave">{{ isEdit ? t('common.save') : t('common.create') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  getWebhookConnectors, createWebhookConnector,
  updateWebhookConnector, deleteWebhookConnector, testWebhookConnector,
} from '../api'

const { t } = useI18n()
const items = ref([])
const showDialog = ref(false)
const isEdit = ref(false)
const editId = ref(null)
const testing = ref(null)
const form = reactive({ name: '', url: '', method: 'POST', headers: '', global: false, enabled: true })

function resetForm() {
  Object.assign(form, { name: '', url: '', method: 'POST', headers: '', global: false, enabled: true })
}

function openCreate() {
  isEdit.value = false
  editId.value = null
  resetForm()
  showDialog.value = true
}

function openEdit(row) {
  isEdit.value = true
  editId.value = row.id
  Object.assign(form, {
    name: row.name,
    url: row.url,
    method: row.method || 'POST',
    headers: row.headers ? JSON.stringify(row.headers) : '',
    global: row.global || false,
    enabled: row.enabled,
  })
  showDialog.value = true
}

async function load() {
  items.value = await getWebhookConnectors()
}
onMounted(load)

async function handleSave() {
  const data = { ...form }
  if (data.headers) {
    try { data.headers = JSON.parse(data.headers) } catch { ElMessage.error('Invalid JSON for headers'); return }
  } else {
    data.headers = null
  }
  if (isEdit.value) {
    await updateWebhookConnector(editId.value, data)
    ElMessage.success(t('common.success'))
  } else {
    await createWebhookConnector(data)
    ElMessage.success(t('common.success'))
  }
  showDialog.value = false
  load()
}

async function handleDelete(id) {
  await ElMessageBox.confirm(t('webhookConnectors.confirmDelete'))
  try {
    await deleteWebhookConnector(id)
    ElMessage.success(t('common.success'))
    load()
  } catch (e) {
    ElMessage.error(e?.error || e?.message || 'Delete failed')
  }
}

async function handleTest(id) {
  testing.value = id
  try {
    const res = await testWebhookConnector(id)
    ElMessage.success(res.message || t('webhookConnectors.testSuccess'))
  } catch (e) {
    ElMessage.error(e.message || t('webhookConnectors.testFailed'))
  } finally {
    testing.value = null
  }
}
</script>
