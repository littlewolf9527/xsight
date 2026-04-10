<template>
  <div>
    <h2 style="margin-bottom: 16px;">{{ $t('dynDetect.title') }}</h2>

    <!-- Section 1: Info banner (collapsible) -->
    <el-card style="margin-bottom: 16px;">
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <span><el-icon><InfoFilled /></el-icon> {{ $t('dynDetect.infoTitle') }}</span>
          <el-button type="primary" link @click="showInfo = !showInfo">
            {{ showInfo ? $t('common.collapse') : $t('common.more') }}
          </el-button>
        </div>
      </template>
      <div v-show="showInfo">
        <p style="margin: 0 0 8px 0; color: var(--xs-text-secondary); line-height: 1.8;">
          {{ $t('dynDetect.infoDesc') }}
        </p>
        <div style="display: flex; flex-direction: column; gap: 6px;">
          <span style="color: var(--xs-text-secondary);">
            <el-icon style="color: var(--el-color-warning);"><WarnTriangleFilled /></el-icon>
            {{ $t('dynDetect.infoEwma') }}
          </span>
          <span style="color: var(--xs-text-secondary);">
            <el-icon style="color: var(--el-color-warning);"><WarnTriangleFilled /></el-icon>
            {{ $t('dynDetect.infoSlots') }}
          </span>
          <span style="color: var(--xs-text-secondary);">
            <el-icon style="color: var(--el-color-warning);"><WarnTriangleFilled /></el-icon>
            {{ $t('dynDetect.infoDeviation') }}
          </span>
          <span style="color: var(--xs-text-secondary);">
            <el-icon style="color: var(--el-color-warning);"><WarnTriangleFilled /></el-icon>
            {{ $t('dynDetect.infoMinThreshold') }}
          </span>
        </div>
      </div>
    </el-card>

    <!-- Section 2: Config panel -->
    <el-card style="margin-bottom: 16px;">
      <template #header>
        <span>{{ $t('dynDetect.configTitle') }}</span>
      </template>
      <div style="margin-bottom: 16px; display: flex; align-items: center; gap: 12px;">
        <span style="font-weight: 500;">{{ $t('dynDetect.enabled') }}</span>
        <el-switch v-model="config.enabled" :active-text="$t('common.enabled')" :inactive-text="$t('common.disabled')" />
      </div>
      <el-form :model="config" label-width="180px" style="max-width: 600px;">
        <el-form-item>
          <template #label>
            {{ $t('dynDetect.deviationMax') }}
            <el-tooltip :content="$t('dynDetect.deviationMaxTip')" placement="top">
              <el-icon style="cursor: help; margin-left: 4px;"><QuestionFilled /></el-icon>
            </el-tooltip>
          </template>
          <el-input-number v-model="config.deviation_max" :min="50" :max="500" />
          <span style="margin-left: 8px; color: var(--xs-text-secondary);">%</span>
        </el-form-item>
        <el-form-item>
          <template #label>
            {{ $t('dynDetect.deviationMin') }}
            <el-tooltip :content="$t('dynDetect.deviationMinTip')" placement="top">
              <el-icon style="cursor: help; margin-left: 4px;"><QuestionFilled /></el-icon>
            </el-tooltip>
          </template>
          <el-input-number v-model="config.deviation_min" :min="10" :max="500" />
          <span style="margin-left: 8px; color: var(--xs-text-secondary);">%</span>
        </el-form-item>
        <el-form-item>
          <template #label>
            {{ $t('dynDetect.stableWeeks') }}
            <el-tooltip :content="$t('dynDetect.stableWeeksTip')" placement="top">
              <el-icon style="cursor: help; margin-left: 4px;"><QuestionFilled /></el-icon>
            </el-tooltip>
          </template>
          <el-input-number v-model="config.stable_weeks" :min="1" :max="12" />
        </el-form-item>
        <el-form-item>
          <template #label>
            {{ $t('dynDetect.minPps') }}
            <el-tooltip :content="$t('dynDetect.minPpsTip')" placement="top">
              <el-icon style="cursor: help; margin-left: 4px;"><QuestionFilled /></el-icon>
            </el-tooltip>
          </template>
          <el-input-number v-model="config.min_pps" :min="0" />
        </el-form-item>
        <el-form-item>
          <template #label>
            {{ $t('dynDetect.minBps') }}
            <el-tooltip :content="$t('dynDetect.minBpsTip')" placement="top">
              <el-icon style="cursor: help; margin-left: 4px;"><QuestionFilled /></el-icon>
            </el-tooltip>
          </template>
          <el-input-number v-model="config.min_bps" :min="0" />
        </el-form-item>
        <el-form-item>
          <template #label>
            {{ $t('dynDetect.ewmaAlpha') }}
            <el-tooltip :content="$t('dynDetect.ewmaAlphaTip')" placement="top">
              <el-icon style="cursor: help; margin-left: 4px;"><QuestionFilled /></el-icon>
            </el-tooltip>
          </template>
          <el-input-number v-model="config.ewma_alpha" :min="0.01" :max="0.99" :step="0.05" :precision="2" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="saveConfig" :loading="saving" :disabled="!configLoaded">{{ $t('common.save') }}</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <!-- Section 3: Profile Status table -->
    <el-card>
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <span>{{ $t('dynDetect.profileTitle') }}</span>
          <el-button type="primary" link @click="loadStatus">
            <el-icon><Refresh /></el-icon> {{ $t('dynDetect.refresh') }}
          </el-button>
        </div>
      </template>

      <!-- Slot info + summary -->
      <div v-if="status" style="margin-bottom: 12px; display: flex; gap: 24px; flex-wrap: wrap; font-size: 13px; color: var(--xs-text-secondary);">
        <span>{{ $t('dynDetect.currentSlot') }}: <b>{{ status.current_slot_label }}</b> (#{{ status.current_slot }})</span>
        <span>{{ $t('dynDetect.totalPrefixes') }}: <b>{{ status.total_prefixes }}</b></span>
        <span>{{ $t('dynDetect.activated') }}: <b style="color: var(--el-color-success);">{{ status.activated }}</b></span>
        <span>{{ $t('dynDetect.learning') }}: <b style="color: var(--el-color-primary);">{{ status.learning }}</b></span>
      </div>

      <el-table :data="profiles" stripe :empty-text="$t('common.noData')">
        <el-table-column prop="prefix" :label="$t('dynDetect.prefix')" min-width="160" />
        <el-table-column :label="$t('dynDetect.currentPps')" min-width="120">
          <template #default="{ row }">{{ fmtValue(row.current_pps) }}</template>
        </el-table-column>
        <el-table-column :label="$t('dynDetect.expectedPps')" min-width="120">
          <template #default="{ row }">{{ fmtValue(row.expected_pps) }}</template>
        </el-table-column>
        <el-table-column :label="$t('dynDetect.dynamicThreshold')" min-width="140">
          <template #default="{ row }">{{ fmtValue(row.thresh_pps) }}</template>
        </el-table-column>
        <el-table-column prop="sample_weeks" :label="$t('dynDetect.sampleWeeks')" width="120" />
        <el-table-column :label="$t('common.status')" width="100">
          <template #default="{ row }">
            <el-tag v-if="row.status === 'learning'" type="primary" size="small">{{ $t('dynDetect.statusLearning') }}</el-tag>
            <el-tag v-else-if="row.status === 'normal'" type="success" size="small">{{ $t('dynDetect.statusNormal') }}</el-tag>
            <el-tag v-else-if="row.status === 'exceeded'" type="danger" size="small">{{ $t('dynDetect.statusExceeded') }}</el-tag>
            <el-tag v-else size="small">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, onBeforeUnmount } from 'vue'
import { ElMessage } from 'element-plus'
import api from '../api'

const showInfo = ref(true)
const saving = ref(false)
const configLoaded = ref(false)
const config = reactive({
  enabled: false,
  deviation_min: 100,
  deviation_max: 200,
  stable_weeks: 4,
  min_pps: 100000,
  min_bps: 1000000000,
  ewma_alpha: 0.30,
})
const status = ref(null)
const profiles = ref([])
let refreshTimer = null

function fmtValue(v) {
  if (v == null || v === undefined) return '-'
  if (v >= 1e9) return (v / 1e9).toFixed(1) + 'G'
  if (v >= 1e6) return (v / 1e6).toFixed(1) + 'M'
  if (v >= 1e3) return (v / 1e3).toFixed(0) + 'K'
  return String(v)
}

async function loadConfig() {
  try {
    const data = await api.get('/dynamic-detection/config')
    Object.assign(config, data)
    configLoaded.value = true
  } catch (e) {
    // Config may not exist yet, use defaults
  }
}

async function saveConfig() {
  saving.value = true
  try {
    await api.put('/dynamic-detection/config', { ...config })
    ElMessage.success('Saved')
  } catch (e) {
    ElMessage.error(e?.message || 'Failed to save config')
  } finally {
    saving.value = false
  }
}

async function loadStatus() {
  try {
    const data = await api.get('/dynamic-detection/status')
    status.value = {
      current_slot: data.current_slot,
      current_slot_label: data.current_slot_label,
      total_prefixes: data.total_prefixes,
      activated: data.activated_count,
      learning: data.learning_count,
    }
    profiles.value = data.prefixes || []
  } catch (e) {
  }
}

onMounted(() => {
  loadConfig()
  loadStatus()
  refreshTimer = setInterval(loadStatus, 30000)
})

onBeforeUnmount(() => {
  if (refreshTimer) clearInterval(refreshTimer)
})
</script>
