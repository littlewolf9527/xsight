<template>
  <div>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
      <h2>{{ t('shellConnectors.title') }}</h2>
      <el-button type="primary" @click="openCreate">{{ t('shellConnectors.add') }}</el-button>
    </div>
    <el-table :data="items" stripe :empty-text="t('common.noData')">
      <el-table-column prop="id" :label="t('common.id')" width="60" />
      <el-table-column prop="name" :label="t('common.name')" />
      <el-table-column prop="command" :label="t('shellConnectors.command')" />
      <el-table-column prop="default_args" :label="t('shellConnectors.defaultArgs')" />
      <el-table-column :label="t('common.status')" width="100">
        <template #default="{ row }">
          <el-tag :type="row.enabled ? 'success' : 'info'" size="small">
            {{ row.enabled ? t('common.enabled') : t('common.disabled') }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="t('common.actions')" width="180">
        <template #default="{ row }">
          <el-button size="small" @click="openEdit(row)">{{ t('common.edit') }}</el-button>
          <el-button size="small" type="danger" @click="handleDelete(row.id)">{{ t('common.delete') }}</el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-dialog v-model="showDialog" :title="isEdit ? t('shellConnectors.edit') : t('shellConnectors.add')" width="500px">
      <el-form :model="form" :rules="rules" ref="formRef" label-width="120px">
        <el-form-item :label="t('common.name')" prop="name">
          <el-input v-model="form.name" />
        </el-form-item>
        <el-form-item :label="t('shellConnectors.command')" prop="command">
          <el-input v-model="form.command" placeholder="/usr/local/bin/script.sh" />
          <div style="color: var(--xs-text-secondary, #909399); font-size: 12px; margin-top: 4px;">
            {{ t('shellConnectors.commandHint') }}
          </div>
        </el-form-item>
        <el-form-item :label="t('shellConnectors.defaultArgs')">
          <el-input v-model="form.default_args" placeholder="--flag value" />
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
  getShellConnectors, createShellConnector,
  updateShellConnector, deleteShellConnector,
} from '../api'

const { t } = useI18n()
const items = ref([])
const showDialog = ref(false)
const isEdit = ref(false)
const editId = ref(null)
const formRef = ref(null)
const form = reactive({ name: '', command: '', default_args: '', enabled: true })

const validateCommand = (rule, value, callback) => {
  if (!value || !value.startsWith('/')) {
    callback(new Error(t('shellConnectors.commandValidation')))
  } else {
    callback()
  }
}

const rules = {
  name: [{ required: true, message: () => t('shellConnectors.nameRequired'), trigger: 'blur' }],
  command: [
    { required: true, message: () => t('shellConnectors.commandRequired'), trigger: 'blur' },
    { validator: validateCommand, trigger: 'blur' },
  ],
}

function resetForm() {
  Object.assign(form, { name: '', command: '', default_args: '', enabled: true })
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
    command: row.command,
    default_args: row.default_args || '',
    enabled: row.enabled,
  })
  showDialog.value = true
}

async function load() {
  items.value = await getShellConnectors()
}
onMounted(load)

async function handleSave() {
  if (formRef.value) {
    try { await formRef.value.validate() } catch { return }
  }
  const data = { ...form }
  if (isEdit.value) {
    await updateShellConnector(editId.value, data)
    ElMessage.success(t('common.success'))
  } else {
    await createShellConnector(data)
    ElMessage.success(t('common.success'))
  }
  showDialog.value = false
  load()
}

async function handleDelete(id) {
  await ElMessageBox.confirm(t('shellConnectors.confirmDelete'))
  try {
    await deleteShellConnector(id)
    ElMessage.success(t('common.success'))
    load()
  } catch (e) {
    ElMessage.error(e?.error || e?.message || 'Delete failed')
  }
}
</script>
