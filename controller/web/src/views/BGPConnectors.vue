<template>
  <div>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
      <h2>{{ $t('bgpConnectors.title') }}</h2>
      <el-button type="primary" @click="openCreate">{{ $t('bgpConnectors.add') }}</el-button>
    </div>
    <el-table :data="items" stripe :empty-text="$t('common.noData')">
      <el-table-column prop="id" :label="$t('common.id')" width="60" />
      <el-table-column prop="name" :label="$t('common.name')" />
      <el-table-column prop="bgp_asn" :label="$t('bgpConnectors.bgpAsn')" width="100" />
      <el-table-column prop="vtysh_path" label="vtysh" width="180" />
      <el-table-column :label="$t('common.status')" width="100">
        <template #default="{ row }">
          <el-tag :type="row.enabled ? 'success' : 'info'" size="small">
            {{ row.enabled ? $t('common.enabled') : $t('common.disabled') }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="$t('common.actions')" width="220">
        <template #default="{ row }">
          <el-button size="small" @click="openEdit(row)">{{ $t('common.edit') }}</el-button>
          <el-button size="small" @click="handleRoutes(row.id)">{{ $t('bgpConnectors.routes') }}</el-button>
          <el-button size="small" type="success" @click="handleTest(row.id)" :loading="testing === row.id">{{ $t('bgpConnectors.test') }}</el-button>
          <el-button size="small" type="danger" @click="handleDelete(row.id)">{{ $t('common.delete') }}</el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-dialog v-model="showDialog" :title="isEdit ? $t('bgpConnectors.edit') : $t('bgpConnectors.add')" width="500px">
      <el-form :model="form" label-width="130px">
        <el-form-item :label="$t('common.name')">
          <el-input v-model="form.name" />
        </el-form-item>
        <el-form-item :label="$t('bgpConnectors.bgpAsn')">
          <el-input-number v-model="form.bgp_asn" :min="1" :max="4294967295" />
        </el-form-item>
        <el-form-item :label="$t('bgpConnectors.vtyshPath')">
          <el-input v-model="form.vtysh_path" />
        </el-form-item>
        <el-form-item :label="$t('common.description')">
          <el-input v-model="form.description" />
        </el-form-item>
        <el-form-item :label="$t('common.enabled')">
          <el-switch v-model="form.enabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showDialog = false">{{ $t('common.cancel') }}</el-button>
        <el-button type="primary" @click="handleSave">{{ isEdit ? $t('common.save') : $t('common.create') }}</el-button>
      </template>
    </el-dialog>

    <!-- Routes dialog -->
    <el-dialog v-model="showRoutes" :title="$t('bgpConnectors.bgpRoutes')" width="700px">
      <pre style="max-height: 400px; overflow: auto; background: #f5f5f5; padding: 12px; font-size: 12px; border-radius: 4px;">{{ routesOutput }}</pre>
      <template #footer>
        <el-button @click="showRoutes = false">{{ $t('common.close') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '../api'

const { t } = useI18n()

const items = ref([])
const showDialog = ref(false)
const isEdit = ref(false)
const editId = ref(null)
const testing = ref(null)
const showRoutes = ref(false)
const routesOutput = ref('')
const form = reactive({
  name: '', bgp_asn: 65000,
  vtysh_path: '/usr/bin/vtysh', description: '', enabled: true
})

async function load() {
  try { items.value = await api.get('/settings/bgp-connectors') } catch (e) { console.error(e) }
}

function openCreate() {
  isEdit.value = false; editId.value = null
  Object.assign(form, { name: '', bgp_asn: 65000, vtysh_path: '/usr/bin/vtysh', description: '', enabled: true })
  showDialog.value = true
}

function openEdit(row) {
  isEdit.value = true; editId.value = row.id
  Object.assign(form, { name: row.name, bgp_asn: row.bgp_asn, vtysh_path: row.vtysh_path, description: row.description || '', enabled: row.enabled })
  showDialog.value = true
}

async function handleSave() {
  try {
    if (isEdit.value) {
      await api.put(`/settings/bgp-connectors/${editId.value}`, form)
    } else {
      await api.post('/settings/bgp-connectors', form)
    }
    ElMessage.success(isEdit.value ? t('common.updated') : t('common.created'))
    showDialog.value = false
    load()
  } catch (e) { ElMessage.error(e?.error || e?.message || t('common.failed')) }
}

async function handleDelete(id) {
  try {
    await ElMessageBox.confirm(t('bgpConnectors.deleteConfirm'), t('common.confirm'), { type: 'warning' })
    await api.delete(`/settings/bgp-connectors/${id}`)
    ElMessage.success(t('common.deleted'))
    load()
  } catch (e) { if (e !== 'cancel') ElMessage.error(e?.error || e?.message || t('common.failed')) }
}

async function handleRoutes(id) {
  try {
    const res = await api.get(`/settings/bgp-connectors/${id}/routes`)
    routesOutput.value = res.output || t('common.noData')
    showRoutes.value = true
  } catch (e) {
    ElMessage.error(e?.error || t('bgpConnectors.fetchRoutesFailed'))
  }
}

async function handleTest(id) {
  testing.value = id
  try {
    await api.post(`/settings/bgp-connectors/${id}/test`)
    ElMessage.success({ message: t('bgpConnectors.connectionOk'), duration: 5000 })
  } catch (e) {
    ElMessage.error({ message: e?.error || t('bgpConnectors.testFailed'), duration: 8000 })
  } finally { testing.value = null }
}

onMounted(load)
</script>
