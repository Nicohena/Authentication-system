import React, { useContext } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import Home from './pages/Home.jsx'
import Login from './pages/Login.jsx'
import ResetPassword from './pages/ResetPassword.jsx'
import EmailVerify from './pages/EmailVerify.jsx'
import { ToastContainer } from 'react-toastify'
import { AppContext } from './context/AppContext.jsx'

const App = () => {
  const { isLoggedIn, loading } = useContext(AppContext)

  // ✅ Wait until auth check completes
  if (loading) return null // or a spinner

  return (
    <div>
      <ToastContainer />
      <Routes>
        {/* Public routes */}
        <Route path='/login' element={isLoggedIn ? <Navigate to='/' /> : <Login />} />
        <Route path='/reset-password' element={<ResetPassword />} />
        <Route path='/email-verify' element={<EmailVerify />} />

        {/* Protected route */}
        <Route path='/' element={isLoggedIn ? <Home /> : <Navigate to='/login' />} />
      </Routes>
    </div>
  )
}

export default App
