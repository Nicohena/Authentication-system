import axios from 'axios';

const backendUrl = 'http://localhost:3000'; // Port checked from .env
const email = 'testuser@example.com'; // Need a valid email in DB
const wrongOtp = '000000';
const newPassword = 'newPassword123';

async function testReset() {
  try {
     // 1. Send OTP (to ensure user exists and has an OTP set)
     console.log("Sending OTP...");
     await axios.post(`${backendUrl}/api/auth/send-reset-otp`, { email });
     console.log("OTP Sent.");

     // 2. Try to reset with WRONG OTP
     console.log("Attempting reset with WRONG OTP...");
     const response = await axios.post(`${backendUrl}/api/auth/reset-password`, {
       email,
       otp: wrongOtp,
       newPassword
     });

     console.log("Response:", response.data);
  } catch (error) {
    if (error.response) {
      console.log("Expected Error:", error.response.data);
    } else {
      console.error("Unexpected Error:", error.message);
    }
  }
}

testReset();
