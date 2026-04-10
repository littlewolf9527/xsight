<template>
  <div>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
      <h2>{{ $t('nodes.title') }}</h2>
      <el-button type="primary" @click="showAdd = true">{{ $t('nodes.addNode') }}</el-button>
    </div>
    <el-table :data="nodes" stripe :empty-text="$t('common.noData')">
      <el-table-column prop="id" :label="$t('nodes.nodeId')" width="180" />
      <el-table-column :label="$t('nodes.mode')" width="90">
        <template #default="{ row }">
          <el-tag :type="row.mode === 'flow' ? 'warning' : 'primary'" size="small">
            {{ row.mode === 'flow' ? 'Flow' : 'XDP' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="description" :label="$t('common.description')" />
      <el-table-column :label="$t('common.status')" width="100">
        <template #default="{ row }">
          <el-tag :type="row.online ? 'success' : 'danger'" size="small">
            {{ row.online ? $t('nodes.online') : $t('nodes.offline') }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="$t('nodes.configStatus')" width="120">
        <template #default="{ row }">
          <el-tag :type="{ synced: 'success', pending: 'warning', failed: 'danger' }[row.config_status]" size="small">
            {{ $t('nodes.' + row.config_status) }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="$t('nodes.drift')" width="80">
        <template #default="{ row }">{{ row.delivery_version_current - row.delivery_version_applied }}</template>
      </el-table-column>
      <el-table-column :label="$t('common.actions')" width="200">
        <template #default="{ row }">
          <router-link v-if="row.mode === 'flow'" :to="`/nodes/${row.id}/flow`">
            <el-button size="small">{{ $t('flow.manageSources') || 'Flow Config' }}</el-button>
          </router-link>
          <el-button size="small" type="danger" @click="handleDelete(row.id)">{{ $t('common.delete') }}</el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-dialog v-model="showAdd" :title="$t('nodes.addNode')" width="450px">
      <el-form :model="form" label-width="100px">
        <el-form-item :label="$t('nodes.nodeId')"><el-input v-model="form.id" /></el-form-item>
        <el-form-item :label="$t('nodes.apiKey')"><el-input v-model="form.api_key" /></el-form-item>
        <el-form-item :label="$t('nodes.mode')">
          <el-select v-model="form.mode">
            <el-option label="XDP (Mirror)" value="xdp" />
            <el-option label="Flow (sFlow/NetFlow)" value="flow" />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('common.description')"><el-input v-model="form.description" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAdd = false">{{ $t('common.cancel') }}</el-button>
        <el-button type="primary" @click="handleCreate">{{ $t('common.create') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, onUnmounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { getNodes, createNode, deleteNode } from '../api'

const nodes = ref([])
const showAdd = ref(false)
const form = reactive({ id: '', api_key: '', description: '', mode: 'xdp' })

let loading = false
async function load() {
  if (loading) return
  loading = true
  try { nodes.value = await getNodes() } catch {}
  finally { loading = false }
}
let pollTimer = null
onMounted(() => { load(); pollTimer = setInterval(load, 3000) })
onUnmounted(() => { if (pollTimer) clearInterval(pollTimer) })

async function handleCreate() {
  await createNode(form)
  ElMessage.success('Node created')
  showAdd.value = false
  Object.assign(form, { id: '', api_key: '', description: '' })
  load()
}
async function handleDelete(id) {
  await ElMessageBox.confirm(`Delete node ${id}?`)
  try {
    await deleteNode(id)
    ElMessage.success('Deleted')
    load()
  } catch (e) {
    ElMessage.error(e?.error || e?.message || 'Delete failed')
  }
}
</script>
