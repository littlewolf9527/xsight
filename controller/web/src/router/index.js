import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  {
    path: '/login',
    name: 'Login',
    component: () => import('../views/Login.vue'),
    meta: { public: true },
  },
  {
    path: '/',
    component: () => import('../layouts/MainLayout.vue'),
    children: [
      { path: '', name: 'Dashboard', component: () => import('../views/Dashboard.vue') },
      { path: 'traffic-overview', name: 'TrafficOverview', component: () => import('../views/TrafficOverview.vue') },
      { path: 'nodes', name: 'Nodes', component: () => import('../views/Nodes.vue') },
      { path: 'prefixes', name: 'Prefixes', component: () => import('../views/Prefixes.vue') },
      { path: 'templates', name: 'Templates', component: () => import('../views/Templates.vue') },
      { path: 'dynamic-detection', name: 'DynamicDetection', component: () => import('../views/DynamicDetection.vue') },
      { path: 'thresholds', name: 'Thresholds', component: () => import('../views/Thresholds.vue') },
      { path: 'responses', name: 'Responses', component: () => import('../views/Responses.vue') },
      { path: 'webhooks', name: 'Webhooks', component: () => import('../views/Webhooks.vue') },
      { path: 'attacks', name: 'Attacks', component: () => import('../views/Attacks.vue') },
      { path: 'mitigations', name: 'Mitigations', component: () => import('../views/Mitigations.vue') },
      { path: 'attacks/:id', name: 'AttackDetail', component: () => import('../views/AttackDetail.vue') },
      { path: 'settings/webhook-connectors', name: 'WebhookConnectors', component: () => import('../views/WebhookConnectors.vue') },
      { path: 'settings/xdrop-connectors', name: 'XDropConnectors', component: () => import('../views/XDropConnectors.vue') },
      { path: 'settings/shell-connectors', name: 'ShellConnectors', component: () => import('../views/ShellConnectors.vue') },
      { path: 'settings/bgp-connectors', name: 'BGPConnectors', component: () => import('../views/BGPConnectors.vue') },
      { path: 'nodes/:id/flow', name: 'FlowConfig', component: () => import('../views/FlowConfig.vue') },
      { path: 'users', name: 'Users', component: () => import('../views/Users.vue') },
      { path: 'audit', name: 'AuditLog', component: () => import('../views/AuditLog.vue') },
    ],
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach((to, from, next) => {
  if (to.meta.public) return next()
  const token = localStorage.getItem('token')
  if (!token) return next('/login')
  next()
})

export default router
