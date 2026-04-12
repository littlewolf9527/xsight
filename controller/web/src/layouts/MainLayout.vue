<template>
  <el-container style="height: 100vh">
    <!-- Sidebar -->
    <el-aside :width="store.sidebarCollapsed ? '64px' : '240px'" class="xs-sidebar">
      <div class="xs-sidebar-brand" v-show="!store.sidebarCollapsed">
        <span class="xs-brand-icon">◆</span>
        <span class="xs-brand-text">xSight</span>
      </div>
      <div class="xs-sidebar-brand" v-show="store.sidebarCollapsed">
        <span class="xs-brand-icon">◆</span>
      </div>

      <el-menu
        :default-active="$route.path"
        :collapse="store.sidebarCollapsed"
        background-color="transparent"
        text-color="var(--xs-text-sidebar)"
        active-text-color="var(--xs-text-sidebar-active)"
        router
        class="xs-nav-menu"
      >
        <!-- Monitoring -->
        <div class="xs-nav-group" v-show="!store.sidebarCollapsed">{{ $t('common.monitoring') || 'MONITORING' }}</div>
        <el-menu-item index="/">
          <el-icon><Odometer /></el-icon>
          <template #title>{{ $t('nav.dashboard') }}</template>
        </el-menu-item>
        <el-menu-item index="/traffic-overview">
          <el-icon><TrendCharts /></el-icon>
          <template #title>{{ $t('nav.trafficOverview') }}</template>
        </el-menu-item>
        <el-menu-item index="/attacks">
          <el-icon><WarnTriangleFilled /></el-icon>
          <template #title>{{ $t('nav.attacks') }}</template>
        </el-menu-item>
        <el-menu-item index="/mitigations">
          <el-icon><CircleCheck /></el-icon>
          <template #title>{{ $t('nav.mitigations') }}</template>
        </el-menu-item>

        <!-- Infrastructure -->
        <div class="xs-nav-group" v-show="!store.sidebarCollapsed">{{ $t('common.infrastructure') || 'INFRASTRUCTURE' }}</div>
        <el-menu-item index="/nodes">
          <el-icon><Monitor /></el-icon>
          <template #title>{{ $t('nav.nodes') }}</template>
        </el-menu-item>
        <el-menu-item index="/prefixes">
          <el-icon><Connection /></el-icon>
          <template #title>{{ $t('nav.prefixes') }}</template>
        </el-menu-item>

        <!-- Detection -->
        <div class="xs-nav-group" v-show="!store.sidebarCollapsed">{{ $t('common.detection') || 'DETECTION' }}</div>
        <el-menu-item index="/templates">
          <el-icon><Files /></el-icon>
          <template #title>{{ $t('nav.templates') || 'Templates' }}</template>
        </el-menu-item>
        <el-menu-item index="/dynamic-detection">
          <el-icon><DataLine /></el-icon>
          <template #title>{{ $t('nav.dynamicDetection') }}</template>
        </el-menu-item>
        <el-menu-item index="/responses">
          <el-icon><SetUp /></el-icon>
          <template #title>{{ $t('nav.responses') }}</template>
        </el-menu-item>

        <!-- Settings -->
        <div class="xs-nav-group" v-show="!store.sidebarCollapsed">{{ $t('common.settings') || 'SETTINGS' }}</div>
        <el-sub-menu index="settings">
          <template #title>
            <el-icon><Setting /></el-icon>
            <span>{{ $t('nav.settings') }}</span>
          </template>
          <el-menu-item index="/settings/webhook-connectors">
            <template #title>{{ $t('nav.webhookConnectors') }}</template>
          </el-menu-item>
          <el-menu-item index="/settings/xdrop-connectors">
            <template #title>{{ $t('nav.xdropConnectors') }}</template>
          </el-menu-item>
          <el-menu-item index="/settings/shell-connectors">
            <template #title>{{ $t('nav.shellConnectors') }}</template>
          </el-menu-item>
          <el-menu-item index="/settings/bgp-connectors">
            <template #title>{{ $t('nav.bgpConnectors') }}</template>
          </el-menu-item>
        </el-sub-menu>
        <el-menu-item index="/users">
          <el-icon><User /></el-icon>
          <template #title>{{ $t('nav.users') }}</template>
        </el-menu-item>
        <el-menu-item index="/audit">
          <el-icon><Document /></el-icon>
          <template #title>{{ $t('nav.auditLog') }}</template>
        </el-menu-item>
      </el-menu>
    </el-aside>

    <el-container>
      <!-- Header -->
      <el-header class="xs-header">
        <div style="display: flex; align-items: center; gap: 12px;">
          <el-icon @click="store.toggleSidebar" style="cursor: pointer; font-size: 18px; color: var(--xs-text-secondary);"><Fold /></el-icon>
        </div>
        <div style="display: flex; align-items: center; gap: 20px;">
          <!-- Theme selector -->
          <el-dropdown @command="cmd => store.setTheme(cmd)" trigger="click">
            <span class="xs-header-action">
              <span :style="{ display: 'inline-block', width: '8px', height: '8px', borderRadius: '50%', background: 'var(--xs-accent)' }"></span>
              {{ store.theme === 'amber' ? '🟠 Amber' : '☀️ Classic' }}
            </span>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="classic">☀️ Classic</el-dropdown-item>
                <el-dropdown-item command="amber">🟠 Amber</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
          <!-- Language -->
          <el-dropdown @command="switchLang">
            <span class="xs-header-action">
              {{ locale === 'en' ? 'EN' : '中' }} <el-icon style="margin-left: 2px;"><ArrowDown /></el-icon>
            </span>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="en">English</el-dropdown-item>
                <el-dropdown-item command="zh">中文</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
          <!-- User -->
          <el-dropdown @command="handleUser">
            <span class="xs-header-action">
              <el-icon style="margin-right: 4px;"><User /></el-icon>
              {{ store.user?.username || 'admin' }}
            </span>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="logout">{{ $t('common.logout') }}</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </el-header>

      <!-- Main content -->
      <el-main class="xs-main">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup>
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import { useAppStore } from '../store'

const { locale } = useI18n()
const store = useAppStore()
const router = useRouter()

function switchLang(lang) {
  locale.value = lang
  store.setLocale(lang)
}

function handleUser(cmd) {
  if (cmd === 'logout') {
    store.logout()
    router.push('/login')
  }
}
</script>

<style scoped>
.xs-sidebar {
  background: var(--xs-bg-sidebar);
  transition: width 0.3s;
  overflow-y: auto;
  overflow-x: hidden;
}

.xs-sidebar-brand {
  padding: 20px 20px 12px;
  display: flex;
  align-items: center;
  gap: 10px;
  white-space: nowrap;
  overflow: hidden;
}
.xs-brand-icon {
  color: var(--xs-accent);
  font-size: 18px;
}
.xs-brand-text {
  color: #ffffff;
  font-size: 18px;
  font-weight: 700;
  letter-spacing: 1px;
}

.xs-nav-group {
  padding: 20px 20px 6px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.08em;
  color: rgba(255, 255, 255, 0.3);
  text-transform: uppercase;
}

.xs-nav-menu {
  border-right: none !important;
}

.xs-header {
  background: var(--xs-header-bg);
  border-bottom: 1px solid var(--xs-header-border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: 56px;
  padding: 0 24px;
}

.xs-header-action {
  cursor: pointer;
  color: var(--xs-text-secondary);
  font-size: 13px;
  font-weight: 500;
  display: flex;
  align-items: center;
  gap: 6px;
  transition: color 0.2s;
}
.xs-header-action:hover {
  color: var(--xs-text-primary);
}

.xs-main {
  background: var(--xs-bg-primary);
  padding: 24px 28px;
  overflow: auto;
}
</style>
