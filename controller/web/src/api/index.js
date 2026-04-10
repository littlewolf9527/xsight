import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 30000,
})

api.interceptors.request.use(config => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(
  res => res.data,
  err => {
    if (err.response?.status === 401) {
      localStorage.removeItem('token')
      window.location.href = '/login'
    }
    return Promise.reject(err.response?.data || err)
  }
)

export default api

// Auth
export const login = (data) => api.post('/login', data)

// Users
export const getUsers = () => api.get('/users')
export const createUser = (data) => api.post('/users', data)
export const updateUser = (id, data) => api.put(`/users/${id}`, data)
export const deleteUser = (id) => api.delete(`/users/${id}`)

// Nodes
export const getNodes = () => api.get('/nodes')
export const createNode = (data) => api.post('/nodes', data)
export const getNode = (id) => api.get(`/nodes/${id}`)
export const updateNode = (id, data) => api.put(`/nodes/${id}`, data)
export const deleteNode = (id) => api.delete(`/nodes/${id}`)
export const getNodeStatus = (id) => api.get(`/nodes/${id}/status`)

// Prefixes
export const getPrefixes = () => api.get('/prefixes')
export const createPrefix = (data) => api.post('/prefixes', data)
export const getPrefix = (id) => api.get(`/prefixes/${id}`)
export const updatePrefix = (id, data) => api.put(`/prefixes/${id}`, data)
export const deletePrefix = (id) => api.delete(`/prefixes/${id}`)

// Thresholds
export const getThresholds = (params) => api.get('/thresholds', { params })
export const createThreshold = (data) => api.post('/thresholds', data)
export const getThreshold = (id) => api.get(`/thresholds/${id}`)
export const updateThreshold = (id, data) => api.put(`/thresholds/${id}`, data)
export const deleteThreshold = (id) => api.delete(`/thresholds/${id}`)

// Responses
export const getResponses = () => api.get('/responses')
export const createResponse = (data) => api.post('/responses', data)
export const getResponse = (id) => api.get(`/responses/${id}`)
export const updateResponse = (id, data) => api.put(`/responses/${id}`, data)
export const deleteResponse = (id) => api.delete(`/responses/${id}`)
export const getActions = (respId) => api.get(`/responses/${respId}/actions`)
export const createAction = (respId, data) => api.post(`/responses/${respId}/actions`, data)
export const updateAction = (id, data) => api.put(`/actions/${id}`, data)
export const deleteAction = (id) => api.delete(`/actions/${id}`)

// Webhook Connectors
export const getWebhookConnectors = () => api.get('/settings/webhook-connectors')
export const createWebhookConnector = (data) => api.post('/settings/webhook-connectors', data)
export const updateWebhookConnector = (id, data) => api.put(`/settings/webhook-connectors/${id}`, data)
export const deleteWebhookConnector = (id) => api.delete(`/settings/webhook-connectors/${id}`)
export const testWebhookConnector = (id) => api.post(`/settings/webhook-connectors/${id}/test`)

// XDrop Connectors
export const getXDropConnectors = () => api.get('/settings/xdrop-connectors')
export const createXDropConnector = (data) => api.post('/settings/xdrop-connectors', data)
export const updateXDropConnector = (id, data) => api.put(`/settings/xdrop-connectors/${id}`, data)
export const deleteXDropConnector = (id) => api.delete(`/settings/xdrop-connectors/${id}`)
export const testXDropConnector = (id) => api.post(`/settings/xdrop-connectors/${id}/test`)

// Shell Connectors
export const getShellConnectors = () => api.get('/settings/shell-connectors')
export const createShellConnector = (data) => api.post('/settings/shell-connectors', data)
export const updateShellConnector = (id, data) => api.put(`/settings/shell-connectors/${id}`, data)
export const deleteShellConnector = (id) => api.delete(`/settings/shell-connectors/${id}`)

// Webhooks
export const getWebhooks = () => api.get('/webhooks')
export const createWebhook = (data) => api.post('/webhooks', data)
export const updateWebhook = (id, data) => api.put(`/webhooks/${id}`, data)
export const deleteWebhook = (id) => api.delete(`/webhooks/${id}`)

// Attacks
export const getAttacks = (params) => api.get('/attacks', { params })
export const getActiveAttacks = () => api.get('/attacks/active')
export const getAttack = (id) => api.get(`/attacks/${id}`)
export const getAttackActionLog = (id) => api.get(`/attacks/${id}/action-log`)
export const getAttackSensorLogs = (id, params) => api.get(`/attacks/${id}/sensor-logs`, { params })

// Dynamic Detection
export const getDynDetectConfig = () => api.get('/dynamic-detection/config')
export const updateDynDetectConfig = (data) => api.put('/dynamic-detection/config', data)
export const getDynDetectStatus = () => api.get('/dynamic-detection/status')

// Audit
export const getAuditLog = (params) => api.get('/audit-log', { params })

// Traffic Overview
export const getTrafficOverview = () => api.get('/stats/overview')
export const getTotalTimeseries = (params) => api.get('/stats/total-timeseries', { params })
