'use client'

import { Suspense, useState, useEffect } from 'react'
import Link from 'next/link'
import { useRouter, useSearchParams } from 'next/navigation'

function VerifyEmailInner() {
  const [formData, setFormData] = useState({
    email: '',
    verification_code: ''
  })
  const [errors, setErrors] = useState({})
  const [loading, setLoading] = useState(false)
  const [resendLoading, setResendLoading] = useState(false)
  const [success, setSuccess] = useState(false)
  const [resendMessage, setResendMessage] = useState('')
  const [showVerificationCode, setShowVerificationCode] = useState(false)
  
  const router = useRouter()
  const searchParams = useSearchParams()

  useEffect(() => {
    // Get email from URL parameters if available
    const emailParam = searchParams.get('email')
    if (emailParam) {
      setFormData(prev => ({
        ...prev,
        email: emailParam
      }))
    }
  }, [searchParams])

  const handleChange = (e) => {
    const { name, value } = e.target
    
    // For verification code, only allow digits and limit to 6 characters
    if (name === 'verification_code') {
      const sanitizedValue = value.replace(/\D/g, '').slice(0, 6)
      setFormData(prev => ({
        ...prev,
        [name]: sanitizedValue
      }))
    } else {
      setFormData(prev => ({
        ...prev,
        [name]: value
      }))
    }
    
    // Clear error for the specific field as user types
    if (errors[name]) {
      setErrors(prev => ({
        ...prev,
        [name]: ''
      }))
    }
    
    // Clear general errors when user starts typing
    if (errors.general) {
      setErrors(prev => ({
        ...prev,
        general: ''
      }))
    }
  }

  const validateForm = () => {
    const newErrors = {}

    // Email validation
    if (!formData.email.trim()) {
      newErrors.email = 'Email is required'
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      newErrors.email = 'Please enter a valid email address'
    }

    // Verification code validation (6 digits)
    if (!formData.verification_code.trim()) {
      newErrors.verification_code = 'Verification code is required'
    } else if (formData.verification_code.length !== 6) {
      newErrors.verification_code = 'Verification code must be 6 digits'
    } else if (!/^\d{6}$/.test(formData.verification_code)) {
      newErrors.verification_code = 'Verification code must contain only numbers'
    }

    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    
    if (!validateForm()) {
      return
    }

    setLoading(true)
    setErrors({})
    setResendMessage('')

    try {
      const response = await fetch('/verify-email', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: formData.email.toLowerCase(),
          verification_code: formData.verification_code
        }),
      })

      const data = await response.json()

      if (response.ok) {
        setSuccess(true)
        // Redirect to signin page after successful verification
        setTimeout(() => {
          router.push('/signin')
        }, 3000)
      } else {
        // Handle different types of errors from the backend
        if (response.status === 400) {
          if (data.detail) {
            if (data.detail.includes('expired')) {
              setErrors({ 
                verification_code: 'Verification code has expired. Please request a new one.',
                canResend: true 
              })
            } else if (data.detail.includes('Invalid')) {
              setErrors({ verification_code: 'Invalid verification code. Please check and try again.' })
            } else if (data.detail.includes('No pending')) {
              setErrors({ 
                general: 'No pending verification found for this email. Please sign up again.',
                shouldRedirect: true 
              })
            } else {
              setErrors({ general: data.detail })
            }
          } else {
            setErrors({ general: 'Verification failed. Please try again.' })
          }
        } else if (response.status === 422) {
          // Handle validation errors
          if (data.detail && Array.isArray(data.detail)) {
            const validationErrors = {}
            data.detail.forEach(error => {
              if (error.loc && error.loc.length > 1) {
                // Only use error.msg, which is a string
                validationErrors[error.loc[1]] = error.msg
              }
            })
            setErrors(validationErrors)
          } else if (typeof data.detail === 'string') {
            setErrors({ general: data.detail })
          } else {
            setErrors({ general: 'Validation error. Please check your input.' })
          }
        } else {
          setErrors({ general: data.detail || 'An error occurred during verification. Please try again.' })
        }
      }
    } catch (error) {
      if (error.name === 'TypeError' && error.message.includes('fetch')) {
        setErrors({ general: 'Unable to connect to the server. Please check if the backend is running.' })
      } else {
        setErrors({ general: 'Network error. Please check your connection and try again.' })
      }
    } finally {
      setLoading(false)
    }
  }

  const handleResendVerification = async () => {
    // Validate email before attempting to resend
    if (!formData.email.trim()) {
      setErrors({ email: 'Please enter your email address first.' })
      return
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      setErrors({ email: 'Please enter a valid email address to resend the code.' })
      return
    }

    setResendLoading(true)
    setResendMessage('')
    setErrors({})

    try {
      const email = encodeURIComponent(formData.email.toLowerCase());
      const response = await fetch(`/resend-verification?email=${email}`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
});

      const data = await response.json()

      if (response.ok) {
        setResendMessage('Verification code resent successfully! Please check your email.')
        setFormData(prev => ({ ...prev, verification_code: '' }))
        setTimeout(() => setResendMessage(''), 5000)
      } else {
        if (response.status === 400) {
          if (data.detail && data.detail.includes('No pending')) {
            setErrors({ 
              general: 'No pending verification found for this email. Please sign up again.',
              shouldRedirect: true 
            })
          } else {
            setErrors({ general: data.detail || 'Failed to resend verification code.' })
          }
        } else if (response.status === 422) {
          // Handle FastAPI validation errors (array of objects)
          if (data.detail && Array.isArray(data.detail)) {
            const validationErrors = {}
            data.detail.forEach(error => {
              if (error.loc && error.loc.length > 1) {
                validationErrors[error.loc[1]] = error.msg
              }
            })
            setErrors(validationErrors)
          } else if (typeof data.detail === 'string') {
            setErrors({ general: data.detail })
          } else {
            setErrors({ general: 'Validation error. Please check your input.' })
          }
        } else {
          setErrors({ general: data.detail || 'Failed to resend verification code. Please try again.' })
        }
      }
    } catch (error) {
      if (error.name === 'TypeError' && error.message.includes('fetch')) {
        setErrors({ general: 'Unable to connect to the server. Please check if the backend is running.' })
      } else {
        setErrors({ general: 'Network error. Please check your connection and try again.' })
      }
    } finally {
      setResendLoading(false)
    }
  }

  // Success state UI
  if (success) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-indigo-50 via-white to-cyan-50 flex items-center justify-center p-4">
        <div className="w-full max-w-md border border-black/20 rounded-2xl shadow-lg p-4">
          <div className="bg-white/80 backdrop-blur-sm rounded-2xl shadow-xl border border-black/20 p-8 text-center">
            <div className="mx-auto h-16 w-16 bg-gradient-to-r from-green-500 to-emerald-600 rounded-full flex items-center justify-center mb-6">
              <svg className="h-8 w-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
              </svg>
            </div>
            <h2 className="text-2xl font-bold text-gray-900 mb-4">
              Email Verified Successfully! 🎉
            </h2>
            <p className="text-gray-600 mb-8">
              Your email has been verified and your account is now active. You&apos;ll be redirected to the sign in page shortly.
            </p>
            <div className="flex items-center justify-center">
              <svg className="animate-spin h-5 w-5 text-indigo-600 mr-3" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              <span className="text-indigo-600 font-medium">Redirecting to sign in...</span>
            </div>
          </div>
        </div>
      </div>
    )
  }

  // Main verification form UI
  return (
    <div className="min-h-screen bg-gradient-to-br from-indigo-50 via-white to-cyan-50 flex items-center justify-center p-4 sm:p-6 lg:p-6">
      <div className="w-full max-w-md border border-black/20 rounded-2xl shadow-lg p-4">
        <div className="text-center mb-8">
          <div className="mx-auto w-16 h-16 bg-gradient-to-r from-indigo-600 to-purple-600 rounded-2xl flex items-center justify-center mb-4">
            <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
          </div>
          <h2 className="text-3xl font-bold text-gray-900 mb-2">Verify Your Email</h2>
          <p className="text-gray-600">
            Enter the 6-digit code sent to your email address
          </p>
        </div>

        <div className="bg-white/80 backdrop-blur-sm rounded-2xl shadow-xl border border-black/20 p-8">
          {(errors.general || resendMessage) && (
            <div className={`mb-6 p-4 rounded-xl border ${
              resendMessage 
                ? 'bg-green-50 border-green-200 text-green-800' 
                : 'bg-red-50 border-red-200 text-red-800'
            }`}>
              <div className="flex items-start">
                <div className="flex-shrink-0">
                  {resendMessage ? (
                    <svg className="h-5 w-5 text-green-400" viewBox="0 0 20 20" fill="currentColor">
                      <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                    </svg>
                  ) : (
                    <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                      <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                    </svg>
                  )}
                </div>
                <div className="ml-3">
                  <p className="text-sm font-medium">{resendMessage || errors.general}</p>
                  {errors.shouldRedirect && (
                    <div className="mt-2">
                      <Link 
                        href="/signup" 
                        className="inline-flex items-center text-sm font-medium text-red-600 hover:text-red-500 transition-colors"
                      >
                        Go to sign up
                        <svg className="ml-1 h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
                          <path fillRule="evenodd" d="M10.293 3.293a1 1 0 011.414 0l6 6a1 1 0 010 1.414l-6 6a1 1 0 01-1.414-1.414L14.586 11H3a1 1 0 110-2h11.586l-4.293-4.293a1 1 0 010-1.414z" clipRule="evenodd" />
                        </svg>
                      </Link>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label htmlFor="email" className="block text-sm font-semibold text-gray-700 mb-2">
                Email Address
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <svg className="h-5 w-5 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                  </svg>
                </div>
                <input
                  id="email"
                  name="email"
                  type="email"
                  value={formData.email}
                  onChange={handleChange}
                  className={`w-full pl-10 pr-4 py-3 border rounded-xl bg-white/50 backdrop-blur-sm transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent text-black ${
                    errors.email 
                      ? 'border-red-300 focus:ring-red-500' 
                      : 'border-gray-300 hover:border-gray-400'
                  }`}
                  placeholder="Enter your email address"
                />
              </div>
              {errors.email && (
                <p className="mt-2 text-sm text-red-600 flex items-center">
                  <svg className="h-4 w-4 mr-1" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                  </svg>
                  {errors.email}
                </p>
              )}
            </div>

            <div>
              <label htmlFor="verification_code" className="block text-sm font-semibold text-gray-700 mb-2">
                Verification Code
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <svg className="h-5 w-5 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <input
                  id="verification_code"
                  name="verification_code"
                  type={showVerificationCode ? 'text' : 'password'}
                  maxLength="6"
                  value={formData.verification_code}
                  onChange={handleChange}
                  className={`w-full pl-10 pr-12 py-3 border rounded-xl bg-white/50 backdrop-blur-sm transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent text-black text-center text-lg tracking-widest font-mono ${
                    errors.verification_code 
                      ? 'border-red-300 focus:ring-red-500' 
                      : 'border-gray-300 hover:border-gray-400'
                  }`}
                  placeholder="000000"
                />
                <button
                  type="button"
                  onClick={() => setShowVerificationCode(!showVerificationCode)}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-600 transition-colors"
                >
                  {showVerificationCode ? (
                    <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.878 9.878L3 3m6.878 6.878L21 21" />
                    </svg>
                  ) : (
                    <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                    </svg>
                  )}
                </button>
              </div>
              {errors.verification_code && (
                <p className="mt-2 text-sm text-red-600 flex items-center">
                  <svg className="h-4 w-4 mr-1" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                  </svg>
                  {errors.verification_code}
                </p>
              )}
              <div className="mt-2 flex items-center justify-between text-sm">
                <span className="text-gray-500">Code expires in 15 minutes</span>
                <button
                  type="button"
                  onClick={handleResendVerification}
                  disabled={resendLoading}
                  className={`font-medium transition-colors ${
                    resendLoading 
                      ? 'text-gray-400 cursor-not-allowed' 
                      : 'text-indigo-600 hover:text-indigo-500'
                  }`}
                >
                  {resendLoading ? (
                    <div className="flex items-center">
                      <svg className="animate-spin -ml-1 mr-1 h-4 w-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                      </svg>
                      Resending...
                    </div>
                  ) : (
                    'Resend code'
                  )}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-gradient-to-r from-indigo-600 to-purple-600 text-white font-semibold py-3 px-4 rounded-xl hover:from-indigo-700 hover:to-purple-700 disabled:from-gray-400 disabled:to-gray-500 disabled:cursor-not-allowed transition-all duration-200 transform hover:scale-[1.02] active:scale-[0.98] focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 shadow-lg"
            >
              {loading ? (
                <div className="flex items-center justify-center">
                  <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Verifying...
                </div>
              ) : (
                <div className="flex items-center justify-center">
                  <svg className="h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  Verify Email
                </div>
              )}
            </button>
          </form>

          <div className="mt-8 text-center">
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-gray-200"></div>
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="px-4 bg-white text-gray-500">Already verified?</span>
              </div>
            </div>
            <div className="mt-4">
              <Link 
                href="/signin" 
                className="inline-flex items-center justify-center w-full px-4 py-2 border border-gray-300 rounded-xl bg-white text-gray-700 font-medium hover:bg-gray-50 hover:border-gray-400 transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2"
              >
                <svg className="h-4 w-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1" />
                </svg>
                Sign in here
              </Link>
            </div>
          </div>
        </div>

        <div className="mt-8 text-center">
          <p className="text-xs text-gray-500">
            By continuing, you agree to our Terms of Service and Privacy Policy
          </p>
        </div>
      </div>
    </div>
  )
}

export default function VerifyEmail() {
  return (
    <Suspense fallback={<div className="flex justify-center items-center min-h-screen">Loading...</div>}>
      <VerifyEmailInner />
    </Suspense>
  )
}