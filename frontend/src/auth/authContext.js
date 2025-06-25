'use client'

import { createContext, useContext, useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'

const AuthContext = createContext({})

export const useAuth = () => {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)
  const [token, setToken] = useState(null)
  const router = useRouter()

  // API base URL
  const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

  // Initialize auth state
  useEffect(() => {
    initializeAuth()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const initializeAuth = async () => {
    try {
      // Check both localStorage and sessionStorage for backward compatibility
      const storedToken = localStorage.getItem('access_token') || sessionStorage.getItem('token')
      const storedUser = localStorage.getItem('user')
      
      if (storedToken && storedUser) {
        setToken(storedToken)
        try {
          const userData = JSON.parse(storedUser)
          setUser(userData)
          // Optionally verify token validity by fetching fresh profile
          await fetchUserProfile(storedToken)
        } catch (error) {
          console.error('Error parsing stored user data:', error)
          logout()
        }
      }
    } catch (error) {
      console.error('Auth initialization error:', error)
      logout()
    } finally {
      setLoading(false)
    }
  }

  const fetchUserProfile = async (authToken) => {
    try {
      const response = await fetch(`${API_BASE_URL}/profile`, {
        headers: {
          'Authorization': `Bearer ${authToken}`,
          'Content-Type': 'application/json'
        }
      })

      if (response.ok) {
        const userData = await response.json()
        setUser(userData)
        localStorage.setItem('user', JSON.stringify(userData))
        return userData
      } else {
        throw new Error('Failed to fetch user profile')
      }
    } catch (error) {
      console.error('Failed to fetch user profile:', error)
      // If token is invalid, clear it
      logout()
      return null
    }
  }

  const login = async (email, password) => {
    try {
      const response = await fetch(`${API_BASE_URL}/auth/signin`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      })

      const data = await response.json()

      if (response.ok) {
        const { access_token, user: userData, token_type, expires_in } = data
        setToken(access_token)
        setUser(userData)
        
        // Store in localStorage for persistence
        localStorage.setItem('access_token', access_token)
        localStorage.setItem('user', JSON.stringify(userData))
        
        // Clean up old sessionStorage if it exists
        sessionStorage.removeItem('token')
        
        return { 
          success: true, 
          user: userData,
          token: access_token,
          tokenType: token_type,
          expiresIn: expires_in
        }
      } else {
        let errorMessage = 'Authentication failed'
        
        if (response.status === 401) {
          errorMessage = 'Invalid email or password'
        } else if (response.status === 403) {
          errorMessage = data.detail || 'Email not verified. Please verify your email first.'
        } else if (data.detail) {
          errorMessage = data.detail
        }
        
        return { 
          success: false, 
          error: errorMessage,
          needsVerification: response.status === 403
        }
      }
    } catch (error) {
      console.error('Login error:', error)
      return { 
        success: false, 
        error: 'Network error. Please check your connection and try again.' 
      }
    }
  }

  const signup = async (formData) => {
    try {
      const response = await fetch(`${API_BASE_URL}/signup`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: formData.email.toLowerCase(),
          first_name: formData.first_name.trim(),
          middle_name: formData.middle_name?.trim() || null,
          last_name: formData.last_name.trim(),
          date_of_birth: formData.date_of_birth,
          password: formData.password
        }),
      })

      const data = await response.json()

      if (response.ok) {
        return { 
          success: true, 
          message: data.message || 'Account created successfully! Please check your email for verification.',
          userId: data.id,
          email: data.email
        }
      } else {
        let errorMessage = 'Signup failed'
        
        if (response.status === 400) {
          if (data.detail && Array.isArray(data.detail)) {
            // Handle pydantic validation errors
            const validationErrors = {}
            data.detail.forEach(error => {
              if (error.loc && error.loc.length > 1) {
                validationErrors[error.loc[1]] = error.msg
              }
            })
            return { success: false, validationErrors }
          } else if (data.detail) {
            errorMessage = data.detail
          }
        } else if (data.detail) {
          errorMessage = data.detail
        }
        
        return { 
          success: false, 
          error: errorMessage
        }
      }
    } catch (error) {
      console.error('Signup error:', error)
      return { 
        success: false, 
        error: 'Network error. Please check your connection and try again.' 
      }
    }
  }

  const verifyEmail = async (email, verificationCode) => {
    try {
      const response = await fetch(`${API_BASE_URL}/verify-email`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
          email: email.toLowerCase(), 
          verification_code: verificationCode 
        }),
      })

      const data = await response.json()

      if (response.ok) {
        return { 
          success: true, 
          message: data.message || 'Email verified successfully!',
          userId: data.user_id
        }
      } else {
        let errorMessage = 'Email verification failed'
        
        if (response.status === 400) {
          if (data.detail && data.detail.includes('expired')) {
            errorMessage = 'Verification code has expired. Please request a new one.'
          } else if (data.detail && data.detail.includes('Invalid')) {
            errorMessage = 'Invalid verification code. Please check and try again.'
          } else if (data.detail) {
            errorMessage = data.detail
          }
        } else if (data.detail) {
          errorMessage = data.detail
        }
        
        return { 
          success: false, 
          error: errorMessage
        }
      }
    } catch (error) {
      console.error('Email verification error:', error)
      return { 
        success: false, 
        error: 'Network error. Please check your connection and try again.' 
      }
    }
  }

  const resendVerification = async (email) => {
    try {
      const response = await fetch(`${API_BASE_URL}/resend-verification`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email: email.toLowerCase() }),
      })

      const data = await response.json()

      if (response.ok) {
        return { 
          success: true, 
          message: data.message || 'Verification code resent successfully!'
        }
      } else {
        return { 
          success: false, 
          error: data.detail || 'Failed to resend verification code'
        }
      }
    } catch (error) {
      console.error('Resend verification error:', error)
      return { 
        success: false, 
        error: 'Network error. Please check your connection and try again.' 
      }
    }
  }

  const forgotPassword = async (email) => {
    try {
      const response = await fetch(`${API_BASE_URL}/forgot-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email: email.toLowerCase() }),
      })

      const data = await response.json()

      if (response.ok) {
        return { 
          success: true, 
          message: data.message || 'If the email exists in our system, a password reset code has been sent.'
        }
      } else {
        return { 
          success: false, 
          error: data.detail || 'Failed to send password reset code'
        }
      }
    } catch (error) {
      console.error('Forgot password error:', error)
      return { 
        success: false, 
        error: 'Network error. Please check your connection and try again.' 
      }
    }
  }

  const resetPassword = async (email, resetCode, newPassword) => {
    try {
      const response = await fetch(`${API_BASE_URL}/reset-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
          email: email.toLowerCase(), 
          reset_code: resetCode, 
          new_password: newPassword 
        }),
      })

      const data = await response.json()

      if (response.ok) {
        return { 
          success: true, 
          message: data.message || 'Password reset successfully!'
        }
      } else {
        let errorMessage = 'Password reset failed'
        
        if (response.status === 400) {
          if (data.detail && data.detail.includes('expired')) {
            errorMessage = 'Reset code has expired. Please request a new one.'
          } else if (data.detail && data.detail.includes('Invalid')) {
            errorMessage = 'Invalid reset code. Please check and try again.'
          } else if (data.detail) {
            errorMessage = data.detail
          }
        } else if (data.detail) {
          errorMessage = data.detail
        }
        
        return { 
          success: false, 
          error: errorMessage
        }
      }
    } catch (error) {
      console.error('Password reset error:', error)
      return { 
        success: false, 
        error: 'Network error. Please check your connection and try again.' 
      }
    }
  }

  const getDashboard = async () => {
    if (!token) return { success: false, error: 'Not authenticated' }
    
    try {
      const response = await fetch(`${API_BASE_URL}/dashboard`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      })

      if (response.ok) {
        const dashboardData = await response.json()
        return { success: true, data: dashboardData }
      } else {
        const data = await response.json()
        return { 
          success: false, 
          error: data.detail || 'Failed to fetch dashboard data'
        }
      }
    } catch (error) {
      console.error('Dashboard fetch error:', error)
      return { 
        success: false, 
        error: 'Network error. Please check your connection and try again.' 
      }
    }
  }

  const refreshProfile = async () => {
    if (!token) return { success: false, error: 'Not authenticated' }
    
    try {
      const userData = await fetchUserProfile(token)
      return { success: true, user: userData }
    } catch (error) {
      return { success: false, error: 'Failed to refresh profile' }
    }
  }

  const logout = () => {
    setUser(null)
    setToken(null)
    
    // Clear all stored auth data
    localStorage.removeItem('access_token')
    localStorage.removeItem('user')
    sessionStorage.removeItem('token') // Clean up old storage
    
    router.push('/signin')
  }

  // Helper function to make authenticated requests
  const makeAuthenticatedRequest = async (endpoint, options = {}) => {
    if (!token) {
      throw new Error('Not authenticated')
    }

    const defaultOptions = {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        ...options.headers
      }
    }

    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      ...defaultOptions
    })

    if (response.status === 401) {
      // Token expired or invalid
      logout()
      throw new Error('Authentication expired')
    }

    return response
  }

  const value = {
    user,
    token,
    loading,
    login,
    signup,
    verifyEmail,
    resendVerification,
    forgotPassword,
    resetPassword,
    getDashboard,
    refreshProfile,
    logout,
    makeAuthenticatedRequest,
    isAuthenticated: !!user && !!token,
    API_BASE_URL
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}