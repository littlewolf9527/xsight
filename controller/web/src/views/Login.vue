<template>
  <div class="xs-login">
    <div class="xs-login-card">
      <div class="xs-login-brand">
        <span class="xs-login-icon">◆</span>
        <h1>xSight</h1>
        <p>{{ $t('login.subtitle') }}</p>
      </div>
      <el-form :model="form" @submit.prevent="handleLogin" label-position="top" class="xs-login-form">
        <el-form-item :label="$t('login.username')">
          <el-input v-model="form.username" :prefix-icon="User" size="large" placeholder="admin" />
        </el-form-item>
        <el-form-item :label="$t('login.password')">
          <el-input v-model="form.password" type="password" :prefix-icon="Lock" size="large" show-password placeholder="••••••••" />
        </el-form-item>
        <el-button type="primary" native-type="submit" size="large" class="xs-login-btn" :loading="loading">
          {{ $t('login.signIn') }}
        </el-button>
      </el-form>
      <div class="xs-login-footer">
        <el-dropdown @command="cmd => store.setTheme(cmd)" trigger="click">
          <span class="xs-login-link">
            {{ store.theme === 'amber' ? '🟠 Amber' : '☀️ Classic' }}
          </span>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="classic">☀️ Classic</el-dropdown-item>
              <el-dropdown-item command="amber">🟠 Amber</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </div>
    </div>
  </div>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { User, Lock } from '@element-plus/icons-vue'
import { useAppStore } from '../store'
import { login } from '../api'

const router = useRouter()
const store = useAppStore()
const loading = ref(false)
const form = reactive({ username: '', password: '' })

async function handleLogin() {
  if (!form.username || !form.password) return
  loading.value = true
  try {
    const res = await login(form)
    store.setAuth(res.token, res.user)
    router.push('/')
  } catch {
    ElMessage.error(store.locale === 'zh' ? '用户名或密码错误' : 'Invalid credentials')
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.xs-login {
  height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--xs-bg-primary);
}

.xs-login-card {
  width: 400px;
  background: var(--xs-card-bg);
  border: 1px solid var(--xs-card-border);
  border-radius: var(--xs-radius-lg);
  box-shadow: var(--xs-shadow-lg);
  padding: 40px 36px 32px;
}

.xs-login-brand {
  text-align: center;
  margin-bottom: 32px;
}
.xs-login-icon {
  color: var(--xs-accent);
  font-size: 28px;
  display: block;
  margin-bottom: 12px;
}
.xs-login-brand h1 {
  font-size: 26px;
  font-weight: 700;
  letter-spacing: 2px;
  color: var(--xs-text-primary);
  margin: 0;
}
.xs-login-brand p {
  color: var(--xs-text-secondary);
  font-size: 13px;
  margin-top: 6px;
}

.xs-login-form :deep(.el-form-item__label) {
  font-size: 13px;
  font-weight: 500;
}

.xs-login-btn {
  width: 100%;
  margin-top: 8px;
  font-weight: 600;
  letter-spacing: 0.02em;
}

.xs-login-footer {
  text-align: center;
  margin-top: 24px;
  padding-top: 20px;
  border-top: 1px solid var(--xs-border);
}
.xs-login-link {
  cursor: pointer;
  font-size: 12px;
  color: var(--xs-text-secondary);
  transition: color 0.2s;
}
.xs-login-link:hover {
  color: var(--xs-accent);
}
</style>
