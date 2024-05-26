// scripts.js

const BASE_URL = 'http://127.0.0.1:8000/v1/auth'; // Update with your backend URL

document.addEventListener('DOMContentLoaded', () => {
    const registerForm = document.getElementById('register-form');
    const loginForm = document.getElementById('login-form');
    const otpVerifyForm = document.getElementById('otp-verify-form');
    const signupOtpVerifyForm = document.getElementById('signup-otp-verify-form');
    const errorElement = document.getElementById('errorContainer')

    if (registerForm) {
        registerForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            errorElement.innerHTML = ""
            const first_name = document.getElementById('first_name').value;
            const last_name = document.getElementById('last_name').value;
            const email = document.getElementById('email').value;
            var phone = document.getElementById('phone').value;
            if (phone.startsWith('0')) {
                new_phone = phone.substring(1);
            }
            phone = '+234' + new_phone;
            const password1 = document.getElementById('password1').value;
            const password2 = document.getElementById('password2').value;
            console.log({ first_name, last_name, email, phone, password1, password2 });
            

            const response = await fetch(`${BASE_URL}/users/`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    first_name,
                    last_name, 
                    email,
                    phone,
                    role: 'user',
                    password: password1,
                    re_password: password2,
                }),
            });

            
            if (response.ok) {
                const data = await response.json();
                alert('Registration successful. Please check your email for OTP.');
                window.location.href = 'signup_otp_verify.html';
            } else {
                const errors = await response.json();
                // alert(`Error: ${JSON.stringify(data)}`);
                
                Object.values(errors).forEach(error => {
                    const p = document.createElement('p');
                    p.className = 'errorMessage capitalize';
                    p.textContent = error.toString();
                    errorElement.append(p)
                });

                // errorElement.innerHTML = '';

            }

        });
    }

    if (loginForm) {
        loginForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            errorElement.innerHTML = ""
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;

            const response = await fetch(`${BASE_URL}/login/`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email, password }),
            });

            const data = await response.json();
            if (response.ok) {
                console.log(data.access_token)
                // Save tokens to localStorage
                console.log(data.refresh_token)
                localStorage.setItem('accessToken', data.access_token);
                localStorage.setItem('refreshToken', data.refresh_token);
                alert('OTP sent to email. Please verify.');
                window.location.href = 'otp_verify.html';
            } else {
                const errors = await response.json();
                console.log(errors)
                if (errors?.detail) {
                    console.log("An error")
                    const p = document.createElement('p');
                    p.className = 'errorMessage capitalize';
                    p.textContent = errors.detail;
                    errorElement.append(p);

                } else {
                    Object.values(errors).forEach(error => {
                    const p = document.createElement('p');
                    p.className = 'errorMessage capitalize';
                    p.textContent = error.toString();
                    errorElement.append(p)
                });
            }
                // errorElement.innerHTML = '';

            }
        });
    }

    if (otpVerifyForm) {
        otpVerifyForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const otp = document.getElementById('otp').value;

            const response = await fetch(`${BASE_URL}/otp/verify/`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('accessToken')}`,
                },
                body: JSON.stringify({ otp }),
            });

            const data = await response.json();
            if (response.ok) {
                alert('OTP verified successfully. You are now logged in.');
                window.location.href = 'index.html';
                // Handle post-login actions, such as redirecting to a dashboard
            } else {
                alert(`Error: ${JSON.stringify(data)}`);
            }
        });
    }
    if (signupOtpVerifyForm) {
        signupOtpVerifyForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const otp = document.getElementById('otp').value;

            const response = await fetch(`${BASE_URL}/signup/otp/verify/`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ otp }),
            });

            const data = await response.json();
            if (response.ok) {
                alert('OTP verified successfully. You can now logged in.');
                window.location.href = 'login.html';
                // Handle post-login actions, such as redirecting to a dashboard
            } else {
                alert(`Error: ${JSON.stringify(data)}`);
            }
        });
    }
});
