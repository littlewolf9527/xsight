<template>
  <div>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
      <h2>{{ $t('thresholds.title') }}</h2>
      <el-button type="primary" @click="showAdd = true">{{ $t('thresholds.addThreshold') }}</el-button>
    </div>
    <el-table :data="thresholds" stripe :empty-text="$t('common.noData')">
      <el-table-column prop="prefix_id" label="Prefix ID" width="90" />
      <el-table-column prop="domain" :label="$t('thresholds.domain')" width="110" />
      <el-table-column prop="decoder" :label="$t('thresholds.decoder')" width="100" />
      <el-table-column prop="unit" :label="$t('thresholds.unit')" width="60" />
      <el-table-column prop="comparison" :label="$t('thresholds.comparison')" width="80" />
      <el-table-column prop="value" :label="$t('thresholds.value')" width="100" />
      <el-table-column :label="$t('thresholds.inheritable')" width="90">
        <template #default="{ row }">{{ row.inheritable ? '✓' : '✗' }}</template>
      </el-table-column>
      <el-table-column prop="response_id" :label="$t('thresholds.response')" width="90" />
      <el-table-column :label="$t('common.actions')" width="120">
        <template #default="{ row }">
          <el-button size="small" type="danger" @click="handleDelete(row.id)">{{ $t('common.delete') }}</el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-dialog v-model="showAdd" :title="$t('thresholds.addThreshold')" width="500px">
      <el-form :model="form" label-width="120px">
        <el-form-item label="Prefix ID"><el-input-number v-model="form.prefix_id" :min="1" /></el-form-item>
        <el-form-item :label="$t('thresholds.domain')">
          <el-select v-model="form.domain"><el-option label="internal_ip" value="internal_ip" /><el-option label="subnet" value="subnet" /></el-select>
        </el-form-item>
        <el-form-item :label="$t('thresholds.decoder')">
          <el-select v-model="form.decoder">
            <el-option v-for="d in ['ip','tcp','tcp_syn','udp','icmp','fragment','tcp_ack','tcp_rst','tcp_fin','gre','esp','igmp','ip_other','bad_fragment','invalid']" :key="d" :label="d" :value="d" />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('thresholds.unit')">
          <el-select v-model="form.unit"><el-option label="pps" value="pps" /><el-option label="bps" value="bps" /></el-select>
        </el-form-item>
        <el-form-item :label="$t('thresholds.comparison')">
          <el-select v-model="form.comparison"><el-option label="over" value="over" /><el-option label="under" value="under" /></el-select>
        </el-form-item>
        <el-form-item :label="$t('thresholds.value')"><el-input-number v-model="form.value" :min="0" /></el-form-item>
        <el-form-item :label="$t('thresholds.inheritable')"><el-switch v-model="form.inheritable" /></el-form-item>
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
import { getThresholds, createThreshold, deleteThreshold } from '../api'

const thresholds = ref([])
const showAdd = ref(false)
const form = reactive({ prefix_id: 1, domain: 'internal_ip', direction: 'receives', decoder: 'tcp_syn', unit: 'pps', comparison: 'over', value: 500, inheritable: true })

async function load() { thresholds.value = await getThresholds() }
onMounted(load)

async function handleCreate() {
  await createThreshold(form)
  ElMessage.success('Threshold created')
  showAdd.value = false
  load()
}
async function handleDelete(id) {
  await ElMessageBox.confirm('Delete this threshold?')
  try {
    await deleteThreshold(id)
    ElMessage.success('Deleted')
    load()
  } catch (e) {
    ElMessage.error(e?.error || e?.message || 'Delete failed')
  }
}
</script>
