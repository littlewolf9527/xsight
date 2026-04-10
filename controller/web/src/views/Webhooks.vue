<template>
  <div>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
      <h2>{{ $t('webhooks.title') }}</h2>
      <el-button type="primary" @click="showAdd = true">{{ $t('webhooks.addWebhook') }}</el-button>
    </div>
    <el-table :data="webhooks" stripe :empty-text="$t('common.noData')">
      <el-table-column prop="id" :label="$t('common.id')" width="60" />
      <el-table-column prop="url" :label="$t('webhooks.url')" />
      <el-table-column :label="$t('webhooks.events')" width="250">
        <template #default="{ row }">
          <el-tag v-for="e in (row.events || [])" :key="e" size="small" style="margin-right: 4px;">{{ e }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="$t('common.status')" width="100">
        <template #default="{ row }">
          <el-tag :type="row.enabled ? 'success' : 'info'" size="small">
            {{ row.enabled ? $t('common.enabled') : $t('common.disabled') }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="$t('common.actions')" width="120">
        <template #default="{ row }">
          <el-button size="small" type="danger" @click="handleDelete(row.id)">{{ $t('common.delete') }}</el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-dialog v-model="showAdd" :title="$t('webhooks.addWebhook')" width="500px">
      <el-form :model="form" label-width="80px">
        <el-form-item :label="$t('webhooks.url')"><el-input v-model="form.url" placeholder="https://..." /></el-form-item>
        <el-form-item :label="$t('webhooks.events')">
          <el-checkbox-group v-model="form.events">
            <el-checkbox label="attack_start" value="attack_start" />
            <el-checkbox label="attack_end" value="attack_end" />
            <el-checkbox label="attack_update" value="attack_update" />
          </el-checkbox-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAdd = false">{{ $t('common.cancel') }}</el-button>
        <el-button type="primary" @click="handleCreate">{{ $t('common.create') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { getWebhooks, createWebhook, deleteWebhook } from '../api'

const webhooks = ref([])
const showAdd = ref(false)
const form = reactive({ url: '', events: ['attack_start', 'attack_end'] })

async function load() { webhooks.value = await getWebhooks() }
onMounted(load)

async function handleCreate() {
  await createWebhook(form)
  ElMessage.success('Webhook created')
  showAdd.value = false
  Object.assign(form, { url: '', events: ['attack_start', 'attack_end'] })
  load()
}
async function handleDelete(id) {
  await ElMessageBox.confirm('Delete this webhook?')
  try {
    await deleteWebhook(id)
    ElMessage.success('Deleted')
    load()
  } catch (e) {
    ElMessage.error(e?.error || e?.message || 'Delete failed')
  }
}
</script>
