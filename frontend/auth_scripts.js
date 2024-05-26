document.addEventListener('DOMContentLoaded', () => {
    const navDiv = document.getElementById('nav');
    
    const jwtToken = localStorage.getItem('jwt_token');
    
    if (jwtToken) {
        // User is logged in
        navDiv.innerHTML = `
            <a href="logout.html" id="logout-link">Logout</a>
        `;
    } else {
        // User is not logged in
        navDiv.innerHTML = `
            <a href="register.html">Register</a>
            <a href="login.html">Login</a>
        `;
    }
    
    const logoutLink = document.getElementById('logout-link');
    
    if (logoutLink) {
        logoutLink.addEventListener('click', () => {
            // Clear the JWT token from localStorage and redirect to the login page
            localStorage.removeItem('jwt_token');
            window.location.href = 'login.html';
        });
    }
});
