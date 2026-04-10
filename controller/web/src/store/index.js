import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

export const useAppStore = defineStore('app', () => {
  const token = ref(localStorage.getItem('token') || '')
  const user = ref(JSON.parse(localStorage.getItem('user') || 'null'))
  const savedTheme = localStorage.getItem('theme')
  const theme = ref((savedTheme === 'classic' || savedTheme === 'amber') ? savedTheme : 'classic')
  const locale = ref(localStorage.getItem('locale') || 'en')
  const sidebarCollapsed = ref(false)

  const isLoggedIn = computed(() => !!token.value)

  function setAuth(t, u) {
    token.value = t
    user.value = u
    localStorage.setItem('token', t)
    localStorage.setItem('user', JSON.stringify(u))
  }

  function logout() {
    token.value = ''
    user.value = null
    localStorage.removeItem('token')
    localStorage.removeItem('user')
  }

  function setTheme(t) {
    theme.value = t
    localStorage.setItem('theme', t)
    document.documentElement.setAttribute('data-theme', t)
  }

  function setLocale(l) {
    locale.value = l
    localStorage.setItem('locale', l)
  }

  function toggleSidebar() {
    sidebarCollapsed.value = !sidebarCollapsed.value
  }

  // Apply theme on load
  document.documentElement.setAttribute('data-theme', theme.value)

  return {
    token, user, theme, locale, sidebarCollapsed,
    isLoggedIn, setAuth, logout, setTheme, setLocale, toggleSidebar,
  }
})
