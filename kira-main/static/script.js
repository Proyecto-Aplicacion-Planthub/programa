function validateForm() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    if (username.trim() === '' || password.trim() === '') {
        alert('Todos los campos son obligatorios.');
        return false;
    }
    // Puedes agregar más validaciones aquí
    return true;
}
