<template>
  <div>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
      <h2>{{ t('xdropConnectors.title') }}</h2>
      <el-button type="primary" @click="openCreate">{{ t('xdropConnectors.add') }}</el-button>
    </div>
    <el-table :data="items" stripe :empty-text="t('common.noData')">
      <el-table-column prop="id" :label="t('common.id')" width="60" />
      <el-table-column prop="name" :label="t('common.name')" />
      <el-table-column prop="api_url" :label="t('xdropConnectors.apiUrl')" />
      <el-table-column :label="t('xdropConnectors.apiKey')" width="160">
        <template #default="{ row }">
          <span>{{ row.api_key ? '****' + row.api_key.slice(-4) : '****' }}</span>
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
          <el-button size="small" type="success" @click="handleTest(row.id)" :loading="testing === row.id">{{ t('xdropConnectors.test') }}</el-button>
          <el-button size="small" type="danger" @click="handleDelete(row.id)">{{ t('common.delete') }}</el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-dialog v-model="showDialog" :title="isEdit ? t('xdropConnectors.edit') : t('xdropConnectors.add')" width="500px">
      <el-form :model="form" label-width="100px">
        <el-form-item :label="t('common.name')">
          <el-input v-model="form.name" />
        </el-form-item>
        <el-form-item :label="t('xdropConnectors.apiUrl')">
          <el-input v-model="form.api_url" placeholder="https://xdrop.example.com:8000" />
        </el-form-item>
        <el-form-item :label="t('xdropConnectors.apiKey')">
          <el-input v-model="form.api_key" type="password" show-password :placeholder="isEdit ? t('xdropConnectors.apiKeyPlaceholder') : ''" />
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
  getXDropConnectors, createXDropConnector,
  updateXDropConnector, deleteXDropConnector, testXDropConnector,
} from '../api'

const { t } = useI18n()
const items = ref([])
const showDialog = ref(false)
const isEdit = ref(false)
const editId = ref(null)
const testing = ref(null)
const form = reactive({ name: '', api_url: '', api_key: '', enabled: true })

function resetForm() {
  Object.assign(form, { name: '', api_url: '', api_key: '', enabled: true })
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
    api_url: row.api_url,
    api_key: '',
    enabled: row.enabled,
  })
  showDialog.value = true
}

async function load() {
  items.value = await getXDropConnectors()
}
onMounted(load)

async function handleSave() {
  const data = { ...form }
  // When editing, omit api_key if left blank (don't overwrite)
  if (isEdit.value && !data.api_key) {
    delete data.api_key
  }
  if (isEdit.value) {
    await updateXDropConnector(editId.value, data)
    ElMessage.success(t('common.success'))
  } else {
    await createXDropConnector(data)
    ElMessage.success(t('common.success'))
  }
  showDialog.value = false
  load()
}

async function handleDelete(id) {
  await ElMessageBox.confirm(t('xdropConnectors.confirmDelete'))
  try {
    await deleteXDropConnector(id)
    ElMessage.success(t('common.success'))
    load()
  } catch (e) {
    ElMessage.error(e?.error || e?.message || 'Delete failed')
  }
}

async function handleTest(id) {
  testing.value = id
  try {
    const res = await testXDropConnector(id)
    ElMessage.success(res.message || t('xdropConnectors.testSuccess'))
  } catch (e) {
    ElMessage.error(e.message || t('xdropConnectors.testFailed'))
  } finally {
    testing.value = null
  }
}
</script>
