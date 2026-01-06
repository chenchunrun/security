/**
 * Authentication Context
 * Provides authentication state and methods throughout the app
 */

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react'
import type { AuthContextType, AuthUser, LoginCredentials } from '@/types'
import { api } from '@/lib/api'

const AuthContext = createContext<AuthContextType | undefined>(undefined)

/**
 * Auth Provider Component
 */
export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [token, setToken] = useState<string | null>(localStorage.getItem('access_token'))
  const [isLoading, setIsLoading] = useState(true)

  /**
   * Check if user has specific permission
   */
  const hasPermission = useCallback(
    (permission: string): boolean => {
      if (!user) return false
      if (user.role === 'admin') return true
      return user.permissions.includes(permission)
    },
    [user]
  )

  /**
   * Login function
   */
  const login = useCallback(async (credentials: LoginCredentials) => {
    setIsLoading(true)
    try {
      const authToken = await api.auth.login(credentials)

      // After successful login, fetch user info
      // For now, we'll use a mock user since we don't have a /me endpoint
      const mockUser: AuthUser = {
        id: '1',
        username: credentials.username,
        email: `${credentials.username}@example.com`,
        role: credentials.username === 'admin' ? 'admin' : 'operator',
        permissions: credentials.username === 'admin'
          ? ['alerts.create', 'alerts.update', 'alerts.delete', 'workflows.execute', 'config.update']
          : ['alerts.create', 'alerts.update', 'workflows.execute'],
      }

      setUser(mockUser)
      setToken(authToken.access_token)
    } finally {
      setIsLoading(false)
    }
  }, [])

  /**
   * Logout function
   */
  const logout = useCallback(async () => {
    try {
      await api.auth.logout()
    } finally {
      setUser(null)
      setToken(null)
    }
  }, [])

  /**
   * Initialize auth state from localStorage
   */
  useEffect(() => {
    const storedToken = localStorage.getItem('access_token')
    if (storedToken) {
      setToken(storedToken)
      // For demo purposes, create a mock user
      const mockUser: AuthUser = {
        id: '1',
        username: 'admin',
        email: 'admin@example.com',
        role: 'admin',
        permissions: ['alerts.create', 'alerts.update', 'alerts.delete', 'workflows.execute', 'config.update'],
      }
      setUser(mockUser)
    }
    setIsLoading(false)
  }, [])

  const value: AuthContextType = {
    user,
    token,
    login,
    logout,
    isAuthenticated: !!user,
    isLoading,
    hasPermission,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

/**
 * Hook to use auth context
 */
export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
