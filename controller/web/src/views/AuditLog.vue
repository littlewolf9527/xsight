<template>
  <div>
    <h2 style="margin-bottom: 16px;">{{ $t('audit.title') }}</h2>
    <el-table :data="logs" stripe :empty-text="$t('common.noData')">
      <el-table-column prop="id" :label="$t('common.id')" width="60" />
      <el-table-column prop="entity_type" :label="$t('audit.entityType')" width="130" />
      <el-table-column prop="entity_id" :label="$t('audit.entityId')" width="100" />
      <el-table-column prop="action" :label="$t('audit.action')" width="100">
        <template #default="{ row }">
          <el-tag :type="{ create: 'success', update: 'warning', delete: 'danger' }[row.action]" size="small">
            {{ row.action }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="delivery_version" :label="$t('audit.deliveryVersion')" width="120" />
      <el-table-column prop="created_at" :label="$t('common.createdAt')" width="180">
        <template #default="{ row }">{{ new Date(row.created_at).toLocaleString() }}</template>
      </el-table-column>
      <el-table-column :label="$t('audit.diff')">
        <template #default="{ row }">
          <span v-if="row.diff">{{ JSON.stringify(row.diff).substring(0, 100) }}</span>
          <span v-else>-</span>
        </template>
      </el-table-column>
    </el-table>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { getAuditLog } from '../api'

const logs = ref([])

onMounted(async () => {
  logs.value = (await getAuditLog({ limit: 50 })) || []
})
</script>
