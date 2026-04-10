<template>
  <div>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
      <h2>{{ $t('users.title') }}</h2>
      <el-button type="primary" @click="showAdd = true">{{ $t('users.addUser') }}</el-button>
    </div>
    <el-table :data="users" stripe :empty-text="$t('common.noData')">
      <el-table-column prop="id" :label="$t('common.id')" width="60" />
      <el-table-column prop="username" :label="$t('users.username')" />
      <el-table-column prop="role" :label="$t('users.role')" width="120">
        <template #default="{ row }">
          <el-tag :type="{ admin: 'danger', operator: 'warning', viewer: 'info' }[row.role]" size="small">{{ row.role }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="$t('common.status')" width="100">
        <template #default="{ row }">
          <el-tag :type="row.enabled ? 'success' : 'info'" size="small">
            {{ row.enabled ? $t('common.enabled') : $t('common.disabled') }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="$t('common.actions')" width="160">
        <template #default="{ row }">
          <el-button size="small" @click="openEdit(row)">{{ $t('common.edit') }}</el-button>
          <el-button size="small" type="danger" @click="handleDelete(row.id)">{{ $t('common.delete') }}</el-button>
        </template>
      </el-table-column>
    </el-table>

    <!-- Add User Dialog -->
    <el-dialog v-model="showAdd" :title="$t('users.addUser')" width="450px">
      <el-form :model="addForm" label-width="100px">
        <el-form-item :label="$t('users.username')"><el-input v-model="addForm.username" /></el-form-item>
        <el-form-item :label="$t('users.password')"><el-input v-model="addForm.password" type="password" show-password /></el-form-item>
        <el-form-item :label="$t('users.role')">
          <el-select v-model="addForm.role">
            <el-option label="admin" value="admin" />
            <el-option label="operator" value="operator" />
            <el-option label="viewer" value="viewer" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAdd = false">{{ $t('common.cancel') }}</el-button>
        <el-button type="primary" @click="handleCreate">{{ $t('common.create') }}</el-button>
      </template>
    </el-dialog>

    <!-- Edit User Dialog -->
    <el-dialog v-model="showEdit" :title="$t('common.edit') + ' — ' + editForm.username" width="450px">
      <el-form :model="editForm" label-width="120px">
        <el-form-item :label="$t('users.role')">
          <el-select v-model="editForm.role">
            <el-option label="admin" value="admin" />
            <el-option label="operator" value="operator" />
            <el-option label="viewer" value="viewer" />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('common.status')">
          <el-switch v-model="editForm.enabled" :active-text="$t('common.enabled')" :inactive-text="$t('common.disabled')" />
        </el-form-item>
        <el-form-item :label="$t('users.newPassword')">
          <el-input v-model="editForm.password" type="password" show-password :placeholder="$t('users.passwordPlaceholder')" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showEdit = false">{{ $t('common.cancel') }}</el-button>
        <el-button type="primary" @click="handleUpdate">{{ $t('common.save') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import { getUsers, createUser, updateUser, deleteUser } from '../api'

const { t } = useI18n()
const users = ref([])
const showAdd = ref(false)
const showEdit = ref(false)
const addForm = reactive({ username: '', password: '', role: 'viewer' })
const editForm = reactive({ id: 0, username: '', role: '', enabled: true, password: '' })

async function load() { users.value = await getUsers() }
onMounted(load)

async function handleCreate() {
  if (!addForm.username || !addForm.password) return
  try {
    await createUser(addForm)
    ElMessage.success(t('users.created'))
    showAdd.value = false
    Object.assign(addForm, { username: '', password: '', role: 'viewer' })
    load()
  } catch (e) {
    ElMessage.error(e?.error || e?.message || t('users.createFailed'))
  }
}

function openEdit(row) {
  Object.assign(editForm, { id: row.id, username: row.username, role: row.role, enabled: row.enabled, password: '' })
  showEdit.value = true
}

async function handleUpdate() {
  const data = { role: editForm.role, enabled: editForm.enabled }
  if (editForm.password) {
    data.password = editForm.password
  }
  try {
    await updateUser(editForm.id, data)
    ElMessage.success(t('users.updated'))
    showEdit.value = false
    load()
  } catch (e) {
    ElMessage.error(e?.error || e?.message || t('users.updateFailed'))
  }
}

async function handleDelete(id) {
  await ElMessageBox.confirm(t('users.confirmDelete'))
  try {
    await deleteUser(id)
    ElMessage.success(t('users.deleted'))
    load()
  } catch (e) {
    ElMessage.error(e?.error || e?.message || t('users.deleteFailed'))
  }
}
</script>
