import axios from 'axios';

const backendUrl = 'http://localhost:3000';
const email = `attacker${Date.now()}@example.com`;
const password = 'Password123!';
const wrongOtp = '000000';

async function testVulnerability() {
    try {
        console.log(`1. Registering user ${email}...`);
        await axios.post(`${backendUrl}/api/auth/register`, { name: 'Attacker', email, password });
        console.log("   Registered.");

        console.log("2. Requesting Reset OTP...");
        await axios.post(`${backendUrl}/api/auth/send-reset-otp`, { email });
        console.log("   OTP Requested.");

        console.log("3. Attempting reset with INVALID OTP '000000'...");
        const response = await axios.post(`${backendUrl}/api/auth/reset-password`, {
            email,
            otp: wrongOtp,
            newPassword: 'ByPassedPassword123!'
        });

        if (response.data.success) {
            console.error("CRITICAL: VULNERABILITY CONFIRMED. Password reset with WRONG OTP!");
        } else {
            console.log("SAFE: Server rejected wrong OTP with success=false (unexpected 200 OK with success=false?)");
        }

    } catch (error) {
        if (error.response) {
            if (error.response.status === 400) {
                console.log("PASS: Server returned 400 Bad Request for wrong OTP.");
                console.log("Message:", error.response.data.message);
            } else {
                console.log(`Failed with status ${error.response.status}:`, error.response.data);
            }
        } else {
            console.error("Error executing test:", error.message);
        }
    }
}

testVulnerability();
