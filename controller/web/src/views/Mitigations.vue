<template>
  <div>
    <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 20px;">
      <div>
        <h2 style="font-size: 22px;">{{ $t('nav.mitigations') }}</h2>
        <span style="font-size: 13px; color: var(--xs-text-secondary);">{{ $t('mitigations.subtitle') }}</span>
      </div>
    </div>

    <el-tabs v-model="tab" @tab-change="load">
      <el-tab-pane :label="$t('attacks.bgpRouting')" name="bgp" />
      <el-tab-pane :label="$t('attacks.xdropFiltering')" name="xdrop" />
    </el-tabs>

    <!-- BGP Orphan banner (v1.2 PR-5): FRR routes with no active attack.
         Operator must explicitly Force Withdraw or Dismiss — not treated as
         regular BGP artifacts because there's no attack_id/action_id. -->
    <el-alert
      v-if="tab === 'bgp' && bgpOrphans.length > 0"
      :title="$t('mitigations.orphanBannerTitle', { count: bgpOrphans.length })"
      type="warning"
      :closable="false"
      show-icon
      style="margin-bottom: 16px;">
      <template #default>
        <div style="margin-bottom: 8px; font-size: 13px;">{{ $t('mitigations.orphanBannerDesc') }}</div>
        <el-table :data="bgpOrphans" stripe size="small" :show-header="true" style="background: transparent;">
          <el-table-column prop="prefix" :label="$t('mitigations.prefix')" width="180" />
          <el-table-column prop="route_map" :label="$t('mitigations.routeMap')" width="140" />
          <el-table-column prop="connector_name" :label="$t('mitigations.bgpConnector')" min-width="140" />
          <el-table-column prop="created_at" :label="$t('attacks.announcedAt')" width="170">
            <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
          </el-table-column>
          <el-table-column :label="$t('common.actions')" width="240">
            <template #default="{ row }">
              <el-popconfirm :title="$t('mitigations.confirmOrphanForceWithdraw')" @confirm="orphanForceWithdraw(row)">
                <template #reference>
                  <el-button size="small" type="danger" plain>{{ $t('attacks.forceWithdraw') }}</el-button>
                </template>
              </el-popconfirm>
              <el-popconfirm :title="$t('mitigations.confirmOrphanDismiss')" @confirm="orphanDismiss(row)">
                <template #reference>
                  <el-button size="small" type="info" plain>{{ $t('mitigations.dismiss') }}</el-button>
                </template>
              </el-popconfirm>
            </template>
          </el-table-column>
        </el-table>
      </template>
    </el-alert>

    <!-- BGP Routing -->
    <div v-if="tab === 'bgp'" style="background: var(--xs-card-bg); border: 1px solid var(--xs-card-border); border-radius: var(--xs-radius-lg); box-shadow: var(--xs-shadow); overflow: hidden;">
      <el-table :data="bgpActive" stripe :empty-text="$t('common.noData')" :row-style="{ cursor: 'pointer' }" @row-click="openDetail">
        <el-table-column prop="attack_id" :label="$t('common.id')" width="80">
          <template #default="{ row }">
            <span class="attack-link" @click.stop="$router.push(`/attacks/${row.attack_id}`)">#{{ row.attack_id }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="prefix" :label="$t('mitigations.prefix')" width="180" />
        <el-table-column prop="route_map" :label="$t('mitigations.routeMap')" width="140" />
        <el-table-column prop="connector_name" :label="$t('mitigations.bgpConnector')" min-width="160" />
        <el-table-column prop="created_at" :label="$t('attacks.announcedAt')" width="180">
          <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column :label="$t('mitigations.timer')" width="120">
          <template #default="{ row }">
            <span v-if="row.status === 'delayed'" style="font-family: 'SF Mono', monospace; font-size: 12px; color: var(--xs-warning);">
              {{ formatCountdown(row.scheduled_for) }}
            </span>
            <span v-else-if="row.status === 'active'" style="font-family: 'SF Mono', monospace; font-size: 12px; color: var(--xs-accent);">
              {{ formatElapsed(row.created_at) }}
            </span>
            <span v-else style="color: var(--xs-text-secondary);">—</span>
          </template>
        </el-table-column>
        <el-table-column :label="$t('common.status')" width="120">
          <template #default="{ row }">
            <el-tag v-if="row.status === 'active'" type="success" size="small">{{ $t('attacks.statusActive') }}</el-tag>
            <el-tag v-else-if="row.status === 'delayed'" type="warning" size="small">{{ $t('attacks.statusDelayed') }}</el-tag>
            <el-tag v-else-if="row.status === 'pending'" type="warning" size="small">{{ $t('attacks.statusPending') }}</el-tag>
            <el-tag v-else-if="row.status === 'failed'" type="danger" size="small">{{ $t('attacks.statusFailed') }}</el-tag>
            <el-tag v-else-if="row.status === 'orphan'" type="warning" size="small" effect="plain">{{ row.status }}</el-tag>
            <el-tag v-else type="info" size="small">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="$t('common.actions')" width="130">
          <template #default="{ row }">
            <el-popconfirm :title="$t('attacks.confirmForceWithdraw')" @confirm="forceRemove(row)">
              <template #reference>
                <el-button size="small" type="danger" plain @click.stop>{{ $t('attacks.forceWithdraw') }}</el-button>
              </template>
            </el-popconfirm>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- Dismissed orphans collapsible (v1.2): audit view for orphans that
         operator dismissed OR that were auto-dismissed at first-upgrade
         bootstrap. Allows un-dismiss to re-surface in banner. -->
    <el-collapse
      v-if="tab === 'bgp'"
      v-model="dismissedExpanded"
      style="margin-top: 16px; background: var(--xs-card-bg); border: 1px solid var(--xs-card-border); border-radius: var(--xs-radius-lg); box-shadow: var(--xs-shadow); overflow: hidden;">
      <el-collapse-item name="dismissed">
        <template #title>
          <span style="padding-left: 16px; font-size: 13px; color: var(--xs-text-secondary);">
            {{ $t('mitigations.viewDismissedOrphans', { count: dismissedOrphans.length }) }}
          </span>
        </template>
        <el-table
          :data="dismissedOrphans"
          stripe
          size="small"
          :empty-text="$t('mitigations.noDismissedOrphans')"
          style="margin: 0 16px 12px 16px;">
          <el-table-column prop="prefix" :label="$t('mitigations.prefix')" width="180" />
          <el-table-column prop="route_map" :label="$t('mitigations.routeMap')" width="140" />
          <el-table-column prop="connector_name" :label="$t('mitigations.bgpConnector')" min-width="140" />
          <el-table-column :label="$t('common.type')" width="180">
            <template #default="{ row }">
              <el-tag
                :type="row.status === 'dismissed_on_upgrade' ? 'info' : ''"
                size="small"
                effect="plain">
                {{ row.status === 'dismissed_on_upgrade' ? $t('mitigations.dismissedOnUpgrade') : $t('mitigations.dismissed') }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="detected_at" :label="$t('mitigations.detectedAt')" width="170">
            <template #default="{ row }">{{ formatTime(row.detected_at) }}</template>
          </el-table-column>
          <el-table-column :label="$t('common.actions')" width="130">
            <template #default="{ row }">
              <el-popconfirm :title="$t('mitigations.confirmUndismiss')" @confirm="undismissOrphan(row)">
                <template #reference>
                  <el-button size="small" plain>{{ $t('mitigations.undismiss') }}</el-button>
                </template>
              </el-popconfirm>
            </template>
          </el-table-column>
        </el-table>
      </el-collapse-item>
    </el-collapse>

    <!-- xDrop Filtering -->
    <div v-if="tab === 'xdrop'" style="background: var(--xs-card-bg); border: 1px solid var(--xs-card-border); border-radius: var(--xs-radius-lg); box-shadow: var(--xs-shadow); overflow: hidden;">
      <el-table :data="xdropRules" stripe :empty-text="$t('common.noData')" :row-style="{ cursor: 'pointer' }" @row-click="openDetail">
        <el-table-column prop="attack_id" :label="$t('common.id')" width="80">
          <template #default="{ row }">
            <span class="attack-link" @click.stop="$router.push(`/attacks/${row.attack_id}`)">#{{ row.attack_id }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="dst_ip" :label="$t('attacks.dstIp')" width="160" />
        <el-table-column prop="external_rule_id" :label="$t('mitigations.ruleId')" width="120" />
        <el-table-column :label="$t('mitigations.action')" width="90">
          <template #default="{ row }">
            <el-tag :type="row.action === 'drop' ? 'danger' : 'warning'" size="small">{{ row.action || 'drop' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="protocol" :label="$t('attacks.protocol')" width="80" />
        <el-table-column prop="tcp_flags" :label="$t('attacks.tcpFlags')" width="100" />
        <el-table-column prop="connector_name" :label="$t('mitigations.xdropConnector')" min-width="140" />
        <el-table-column prop="created_at" :label="$t('common.createdAt')" width="170">
          <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column :label="$t('mitigations.timer')" width="120">
          <template #default="{ row }">
            <span v-if="row.status === 'delayed'" style="font-family: 'SF Mono', monospace; font-size: 12px; color: var(--xs-warning);">
              {{ formatCountdown(row.scheduled_for) }}
            </span>
            <span v-else-if="row.status === 'active'" style="font-family: 'SF Mono', monospace; font-size: 12px; color: var(--xs-accent);">
              {{ formatElapsed(row.created_at) }}
            </span>
            <span v-else style="color: var(--xs-text-secondary);">—</span>
          </template>
        </el-table-column>
        <el-table-column :label="$t('common.status')" width="120">
          <template #default="{ row }">
            <el-tag v-if="row.status === 'active'" type="success" size="small">{{ $t('attacks.statusActive') }}</el-tag>
            <el-tag v-else-if="row.status === 'delayed'" type="warning" size="small">{{ $t('attacks.statusDelayed') }}</el-tag>
            <el-tag v-else-if="row.status === 'pending'" type="warning" size="small">{{ $t('attacks.statusPending') }}</el-tag>
            <el-tag v-else-if="row.status === 'failed'" type="danger" size="small">{{ $t('attacks.statusFailed') }}</el-tag>
            <el-tag v-else-if="row.status === 'orphan'" type="warning" size="small" effect="plain">{{ row.status }}</el-tag>
            <el-tag v-else type="info" size="small">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="$t('common.actions')" width="130">
          <template #default="{ row }">
            <el-popconfirm :title="$t('attacks.confirmForceUnblock')" @confirm="forceRemove(row)">
              <template #reference>
                <el-button size="small" type="danger" plain @click.stop>{{ $t('attacks.forceUnblock') }}</el-button>
              </template>
            </el-popconfirm>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- Detail Drawer -->
    <el-drawer v-model="drawerVisible" :title="$t('mitigations.detail')" size="480px" direction="rtl">
      <template v-if="detail">
        <!-- Header -->
        <div style="margin-bottom: 20px;">
          <div style="font-size: 16px; font-weight: 600; margin-bottom: 8px;">
            {{ detail.action_type === 'bgp' ? $t('mitigations.bgpRoute') : $t('mitigations.xdropRule') }}
            <span style="font-family: 'SF Mono', monospace; font-weight: 400; margin-left: 6px;">{{ detail.external_rule_id }}</span>
          </div>
          <el-tag v-if="detail.status === 'active'" type="success" size="small">{{ $t('attacks.statusActive') }}</el-tag>
          <el-tag v-else-if="detail.status === 'delayed'" type="warning" size="small">{{ $t('attacks.statusDelayed') }}</el-tag>
          <el-tag v-else-if="detail.status === 'pending'" type="warning" size="small">{{ $t('attacks.statusPending') }}</el-tag>
          <el-tag v-else-if="detail.status === 'failed'" type="danger" size="small">{{ $t('attacks.statusFailed') }}</el-tag>
          <el-tag v-else type="info" size="small">{{ detail.status }}</el-tag>
        </div>

        <!-- Summary -->
        <div class="detail-section">
          <!-- BGP: show all attached attacks (shared announcement semantics).
               xDrop: still per-attack, show single id as before. -->
          <template v-if="detail.action_type === 'bgp' && detail.attached_attacks && detail.attached_attacks.length">
            <div class="detail-row">
              <span class="detail-label">{{ $t('mitigations.attachedAttacks', { count: detail.attached_attacks.length }) }}</span>
            </div>
            <div v-for="(a, idx) in detail.attached_attacks" :key="idx" class="attached-attack-row">
              <span class="attack-link" @click="$router.push(`/attacks/${a.attack_id}`); drawerVisible = false">#{{ a.attack_id }}</span>
              <span v-if="a.decoder" class="attached-chip">{{ a.decoder }}</span>
              <span v-if="a.response_name" class="attached-chip">{{ a.response_name }}</span>
              <span class="attached-chip">delay={{ a.delay_minutes }}m</span>
              <span v-if="a.detached_at" class="attached-chip attached-chip-muted">detached {{ formatTime(a.detached_at) }}</span>
              <span v-else class="attached-chip attached-chip-active">{{ $t('mitigations.attachedCurrent') }}</span>
            </div>
          </template>
          <div v-else class="detail-row">
            <span class="detail-label">{{ $t('mitigations.attack') }}</span>
            <span class="attack-link" @click="$router.push(`/attacks/${detail.attack_id}`); drawerVisible = false">#{{ detail.attack_id }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">{{ $t('mitigations.targetIp') }}</span>
            <span class="detail-value mono">{{ detail.attack_dst_ip || detail.dst_ip }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">{{ $t('mitigations.connector') }}</span>
            <span class="detail-value">{{ detail.connector_name }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">{{ $t('common.createdAt') }}</span>
            <span class="detail-value">{{ formatTime(detail.created_at) }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">{{ $t('mitigations.timer') }}</span>
            <span v-if="detail.status === 'delayed'" class="detail-value mono" style="color: var(--xs-warning);">{{ formatCountdown(detail.scheduled_for) }} {{ $t('mitigations.remaining') }}</span>
            <span v-else-if="detail.status === 'active'" class="detail-value mono" style="color: var(--xs-accent);">{{ formatElapsed(detail.created_at) }}</span>
            <span v-else class="detail-value" style="color: var(--xs-text-secondary);">—</span>
          </div>
        </div>

        <!-- Configuration -->
        <div class="detail-section">
          <div style="font-size: 13px; font-weight: 600; margin-bottom: 10px; color: var(--xs-text-secondary); text-transform: uppercase; letter-spacing: 0.05em;">{{ $t('mitigations.configuration') }}</div>
          <template v-if="detail.action_type === 'bgp'">
            <div class="detail-row"><span class="detail-label">{{ $t('mitigations.prefix') }}</span><span class="detail-value mono">{{ detail.prefix }}</span></div>
            <div class="detail-row"><span class="detail-label">{{ $t('mitigations.routeMap') }}</span><span class="detail-value mono">{{ detail.route_map }}</span></div>
          </template>
          <template v-else>
            <div class="detail-row"><span class="detail-label">{{ $t('mitigations.action') }}</span><el-tag :type="detail.action === 'drop' ? 'danger' : 'warning'" size="small">{{ detail.action || 'drop' }}</el-tag></div>
            <div class="detail-row"><span class="detail-label">{{ $t('attacks.protocol') }}</span><span class="detail-value mono">{{ detail.protocol || '—' }}</span></div>
            <div class="detail-row"><span class="detail-label">{{ $t('attacks.tcpFlags') }}</span><span class="detail-value mono">{{ detail.tcp_flags || '—' }}</span></div>
            <div class="detail-row"><span class="detail-label">{{ $t('attacks.dstIp') }}</span><span class="detail-value mono">{{ detail.dst_ip }}</span></div>
          </template>
        </div>

        <!-- Execution Timeline -->
        <div class="detail-section">
          <div style="font-size: 13px; font-weight: 600; margin-bottom: 10px; color: var(--xs-text-secondary); text-transform: uppercase; letter-spacing: 0.05em;">{{ $t('mitigations.timeline') }}</div>
          <div v-if="!timelineLogs.length" style="font-size: 13px; color: var(--xs-text-secondary);">{{ $t('mitigations.noTimeline') }}</div>
          <div v-else class="timeline">
            <div v-for="(log, idx) in timelineLogs" :key="idx" class="timeline-item">
              <div class="timeline-dot" :class="'dot-' + (log.trigger_phase === 'manual_override' ? 'override' : log.status)"></div>
              <div class="timeline-content">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                  <span class="timeline-phase">{{ log.trigger_phase }}</span>
                  <el-tag :type="log.status === 'success' ? 'success' : log.status === 'failed' ? 'danger' : log.status === 'scheduled' ? 'warning' : 'info'" size="small">{{ log.status }}</el-tag>
                </div>
                <div class="timeline-time">{{ formatTime(log.executed_at) }}</div>
                <div v-if="log.duration_ms > 0" style="font-size: 11px; color: var(--xs-text-secondary);">{{ log.duration_ms }}ms</div>
                <div v-if="log.error_message" style="font-size: 11px; color: var(--xs-danger); margin-top: 2px;">{{ log.error_message }}</div>
              </div>
            </div>
          </div>
        </div>

        <!-- Force Remove -->
        <div style="margin-top: 20px; padding-top: 16px; border-top: 1px solid var(--xs-card-border);">
          <el-popconfirm :title="detail.action_type === 'bgp' ? $t('attacks.confirmForceWithdraw') : $t('attacks.confirmForceUnblock')" @confirm="forceRemove(detail); drawerVisible = false">
            <template #reference>
              <el-button type="danger" plain style="width: 100%;">
                {{ detail.action_type === 'bgp' ? $t('attacks.forceWithdraw') : $t('attacks.forceUnblock') }}
              </el-button>
            </template>
          </el-popconfirm>
        </div>
      </template>
    </el-drawer>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import api from '../api'

const { t } = useI18n()

const tab = ref('bgp')
const bgpRoutes = ref([])
const xdropRules = ref([])
const dismissedOrphans = ref([])
const dismissedExpanded = ref([]) // collapse item names that are expanded

// v1.2 PR-5: split BGP rows into "active" (attached to attacks) and "orphan"
// (FRR route without active attack). Operator uses dedicated endpoints for
// orphans — they have no attack_id/action_id and the generic force-remove
// endpoint rejects them.
const bgpActive = computed(() => bgpRoutes.value.filter((r) => !r.is_orphan))
const bgpOrphans = computed(() => bgpRoutes.value.filter((r) => r.is_orphan))

// Detail drawer
const drawerVisible = ref(false)
const detail = ref(null)
const timelineLogs = ref([])

function formatTime(t) { return t ? new Date(t).toLocaleString() : '-' }
function formatCountdown(scheduledFor) {
  if (!scheduledFor) return ''
  const remaining = Math.max(0, (new Date(scheduledFor) - Date.now()) / 1000)
  const m = Math.floor(remaining / 60)
  const s = Math.floor(remaining % 60)
  return m > 0 ? `${m}m ${s}s` : `${s}s`
}
function formatElapsed(createdAt) {
  if (!createdAt) return ''
  const elapsed = Math.max(0, (Date.now() - new Date(createdAt)) / 1000)
  const h = Math.floor(elapsed / 3600)
  const m = Math.floor((elapsed % 3600) / 60)
  if (h > 0) return `${h}h ${m}m`
  const s = Math.floor(elapsed % 60)
  return m > 0 ? `${m}m ${s}s` : `${s}s`
}

let loading = false
async function load() {
  if (loading) return
  loading = true
  try {
    if (tab.value === 'bgp') {
      const [routes, dismissed] = await Promise.all([
        api.get('/active-actions/bgp'),
        api.get('/active-actions/bgp/dismissed-orphans'),
      ])
      bgpRoutes.value = routes || []
      dismissedOrphans.value = dismissed || []
    } else {
      xdropRules.value = await api.get('/active-actions/xdrop') || []
    }
  } catch (e) { console.error(e) }
  finally { loading = false }
}

async function openDetail(row) {
  detail.value = { ...row, action_type: tab.value }
  drawerVisible.value = true
  timelineLogs.value = []
  try {
    const params = new URLSearchParams({
      attack_id: row.attack_id,
      action_id: row.action_id || 0,
      connector_id: row.connector_id || 0,
      external_rule_id: row.external_rule_id,
    })
    const res = await api.get(`/active-actions/timeline?${params}`)
    timelineLogs.value = res?.logs || []
  } catch (e) { console.error(e) }
}

async function forceRemove(row) {
  // v1.2 PR-5: orphan rows must use dedicated endpoint (no attack_id/action_id).
  // Detail drawer may call forceRemove for orphan too — route accordingly.
  if (row.is_orphan && row.announcement_id) {
    return orphanForceWithdraw(row)
  }
  try {
    const resp = await api.post('/active-actions/force-remove', {
      attack_id: row.attack_id,
      action_id: row.action_id,
      connector_id: row.connector_id,
      external_rule_id: row.external_rule_id,
    })
    if (resp?.warning) {
      ElMessage.warning(resp.warning)
    } else {
      ElMessage.success(t('attacks.forceRemoved'))
    }
    load()
  } catch (e) {
    ElMessage.error(e?.error || e?.message || t('mitigations.forceFailed'))
  }
}

// v1.2 PR-5: orphan-specific operator actions.
// Backend returns 200 + {warning: ...} when the row was marked failed but
// vtysh couldn't confirm the FRR withdraw — this is the case the operator
// most needs to notice, so promote it to a warning toast rather than silently
// showing success (PR-6 audit P1).
async function orphanForceWithdraw(row) {
  try {
    const resp = await api.post('/active-actions/bgp/orphan-force-withdraw', {
      announcement_id: row.announcement_id,
    })
    if (resp?.warning) {
      ElMessage.warning(resp.warning)
    } else {
      ElMessage.success(t('attacks.forceRemoved'))
    }
    load()
  } catch (e) {
    ElMessage.error(e?.error || e?.message || t('mitigations.forceFailed'))
  }
}

async function orphanDismiss(row) {
  try {
    await api.post('/active-actions/bgp/orphan-dismiss', {
      announcement_id: row.announcement_id,
    })
    ElMessage.success(t('mitigations.dismissed'))
    load()
  } catch (e) {
    ElMessage.error(e?.error || e?.message || t('mitigations.forceFailed'))
  }
}

async function undismissOrphan(row) {
  try {
    await api.post('/active-actions/bgp/orphan-undismiss', {
      announcement_id: row.announcement_id,
    })
    ElMessage.success(t('mitigations.undismissed'))
    load()
  } catch (e) {
    ElMessage.error(e?.error || e?.message || t('mitigations.forceFailed'))
  }
}

let pollTimer = null
onMounted(() => { load(); pollTimer = setInterval(load, 3000) })
onUnmounted(() => { if (pollTimer) clearInterval(pollTimer) })
</script>

<style scoped>
.detail-section {
  margin-bottom: 20px;
  padding-bottom: 16px;
  border-bottom: 1px solid var(--xs-card-border);
}
.detail-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 6px 0;
  font-size: 13px;
}
.detail-label {
  color: var(--xs-text-secondary);
  font-weight: 500;
}
.attached-attack-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
  padding: 4px 0 4px 8px;
  font-size: 12px;
  border-left: 2px solid var(--xs-card-border);
  margin: 2px 0;
}
.attached-chip {
  font-family: 'SF Mono', monospace;
  font-size: 11px;
  padding: 2px 6px;
  border-radius: 3px;
  background: var(--xs-card-border);
  color: var(--xs-text-secondary);
}
.attached-chip-active {
  background: var(--xs-success, #22c55e);
  color: white;
}
.attached-chip-muted {
  opacity: 0.6;
}
.detail-value {
  font-weight: 500;
}
.mono {
  font-family: 'SF Mono', monospace;
  font-size: 12px;
}
.timeline {
  position: relative;
  padding-left: 20px;
}
.timeline-item {
  position: relative;
  padding-bottom: 16px;
  padding-left: 16px;
  border-left: 2px solid var(--xs-card-border);
}
.timeline-item:last-child {
  border-left-color: transparent;
}
.timeline-dot {
  position: absolute;
  left: -7px;
  top: 2px;
  width: 12px;
  height: 12px;
  border-radius: 50%;
  border: 2px solid var(--xs-card-bg);
}
.dot-success { background: var(--xs-success, #22c55e); }
.dot-failed { background: var(--xs-danger, #ef4444); }
.dot-scheduled { background: var(--xs-warning, #f59e0b); }
.dot-skipped { background: var(--xs-text-secondary, #64748b); }
.dot-override { background: #3b82f6; }
.attack-link {
  cursor: pointer;
  font-family: 'SF Mono', monospace;
  font-size: 12px;
  font-weight: 600;
  color: var(--xs-accent);
}
.attack-link:hover {
  text-decoration: underline;
}
.timeline-phase {
  font-size: 12px;
  font-weight: 600;
  font-family: 'SF Mono', monospace;
  text-transform: uppercase;
}
.timeline-time {
  font-size: 11px;
  color: var(--xs-text-secondary);
  margin-top: 2px;
}
.timeline-content {
  font-size: 13px;
}
</style>
