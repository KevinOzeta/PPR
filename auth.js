// auth.js

// Lista blanca de correos permitidos
const allowedUsers = [
  "coordinaciongeneral@superaisp.org",
  "Sistematizacion@supera.mx"
  // añade más correos autorizados
];

// Esta función la invoca Google (data-callback="handleCredentialResponse")
function handleCredentialResponse(response) {
  try {
    const data = parseJwt(response.credential);

    // Validación simple por correo
    if (!allowedUsers.includes(data.email)) {
      alert("Acceso denegado: Usuario no autorizado.");
      return;
    }

    // Guardar datos como objeto en localStorage
    const usuario = {
      nombre: data.name || data.email,
      correo: data.email,
      foto: data.picture || ''
    };
    localStorage.setItem('usuario', JSON.stringify(usuario));

    // Evita autologin automático
    if (window.google?.accounts?.id) {
      window.google.accounts.id.disableAutoSelect();
    }

    // Redirigir a la página principal
    window.location.href = 'inicio.html';
  } catch (err) {
    console.error('Error procesando credencial:', err);
  }
}

// Función para decodificar JWT de Google
function parseJwt(token) {
  const base64Url = token.split('.')[1];
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  const jsonPayload = decodeURIComponent(
    atob(base64).split('').map(c =>
      '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
    ).join('')
  );

  return JSON.parse(jsonPayload);
}
