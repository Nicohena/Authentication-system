import React, { useContext, useState } from 'react'
import { assets } from '../assets/assets'
import { useNavigate } from 'react-router-dom'
import { AppContext } from '../context/AppContext'
import axios from 'axios'
import { toast } from 'react-toastify'

const Login = () => {
  const navigate = useNavigate()
  const { backendUrl, setIsLoggedIn, getUserData } = useContext(AppContext)

  const [state, setState] = useState('Sign up')
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')

  const onSubmitHandler = async (e) => {
    e.preventDefault()
    axios.defaults.withCredentials = true

    try {
      let response

      if (state === 'Sign up') {
        response = await axios.post(`${backendUrl}/api/auth/register`, {
          name,
          email,
          password
        })
      } else {
        response = await axios.post(`${backendUrl}/api/auth/login`, {
          email,
          password
        })
      }

      if (response.data.success) {
        setIsLoggedIn(true)
        await getUserData()
        navigate('/')
      } else {
        toast.error(response.data.message)
      }

    } catch (err) {
      toast.error('Authentication failed')
    }
  }

  return (
    <div className='flex items-center justify-center min-h-screen px-6 sm:px-0 bg-gradient-to-br from-blue-200 to-purple-400'>
      <img
        onClick={() => navigate('/')}
        src={assets.logo}
        className='absolute left-5 sm:left-20 top-5 w-28 sm:w-32 cursor-pointer'
        alt=""
      />

      <div className='bg-slate-900 p-10 rounded-lg shadow-lg w-full sm:w-96 text-indigo-300 text-sm'>
        <h2 className='text-3xl font-semibold text-white text-center mb-3'>
          {state === 'Sign up' ? 'Create account' : 'Login'}
        </h2>

        <p className='text-center mb-6'>
          {state === 'Sign up'
            ? 'Create your account'
            : 'Login to your account'}
        </p>

        <form onSubmit={onSubmitHandler}>
          {state === 'Sign up' && (
            <div className='mb-4 flex items-center gap-3 px-5 py-2.5 rounded-full bg-[#333A5C]'>
              <img src={assets.person_icon} alt="" />
              <input
                type="text"
                placeholder="Full name"
                required
                onChange={(e) => setName(e.target.value)}
                className='bg-transparent outline-none w-full'
              />
            </div>
          )}

          <div className='mb-4 flex items-center gap-3 px-5 py-2.5 rounded-full bg-[#333A5C]'>
            <img src={assets.mail_icon} alt="" />
            <input
              type="email"
              placeholder="Email address"
              required
              onChange={(e) => setEmail(e.target.value)}
              className='bg-transparent outline-none w-full'
            />
          </div>

          <div className='mb-4 flex items-center gap-3 px-5 py-2.5 rounded-full bg-[#333A5C]'>
            <img src={assets.lock_icon} alt="" />
            <input
              type="password"
              placeholder="Password"
              required
              onChange={(e) => setPassword(e.target.value)}
              className='bg-transparent outline-none w-full'
            />
          </div>
              <p
            onClick={() => navigate("/reset-password")}
            className="mb-4 text-indigo-500 cursor-pointer text-right"
          >
            Forgot password?
          </p>
          

          <button className='w-full py-2.5 rounded-full bg-gradient-to-r from-indigo-500 to-indigo-900 text-white font-medium'>
            {state}
          </button>
        </form>

        {state === 'Sign up' ? (
          <p className='text-center text-xs mt-4'>
            Already have an account?{' '}
            <span
              onClick={() => setState('Login')}
              className='text-blue-400 cursor-pointer underline'
            >
              Login here
            </span>
          </p>
        ) : (
          <p className='text-center text-xs mt-4'>
            Don&apos;t have an account?{' '}
            <span
              onClick={() => setState('Sign up')}
              className='text-blue-400 cursor-pointer underline'
            >
              Sign up
            </span>
          </p>
        )}
      </div>
    </div>
  )
}

export default Login
