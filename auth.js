let allowedUsers = [];

// Normaliza cadenas: minúsculas, sin acentos, sin espacios extras
function normalize(str) {
  return str.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').trim();
}

// Cargar usuarios permitidos desde GAS
async function loadAllowedUsers() {
  try {
    const response = await fetch('https://script.google.com/macros/s/AKfycbzK_hkWCUOgDBSFG_zKRAIOxCDyWrGfyUVqqF4a4ik4Z0URa_gWEP3ZENZaudF2gfbmvg/exec?action=getUsers');
    allowedUsers = await response.json();
    console.log("Usuarios cargados:");
  } catch (err) {
    console.error('Error cargando usuarios permitidos:', err);
  }
}

// Llamar al cargar la página
loadAllowedUsers();

// Función que Google invoca tras login
async function handleCredentialResponse(response) {
  try {
    // Espera a que allowedUsers esté cargado
    if (allowedUsers.length === 0) {
      await loadAllowedUsers();
    }

    const data = parseJwt(response.credential);

    // Buscar usuario en la lista permitida
    const user = allowedUsers.find(u => normalize(u.email) === normalize(data.email));
    if (!user) {
      alert("Acceso denegado: Usuario no autorizado.");
      return;
    }

    // Guardar datos en localStorage
    const usuario = {
      nombre: user.nombre || data.email,
      correo: data.email,
      rol: user.rol,
      asociacion: user.asociacion || '(sin asociación)',
      foto: data.picture || ''
    };
    localStorage.setItem('usuario', JSON.stringify(usuario));

    // Evita autologin automático
    if (window.google?.accounts?.id) {
      window.google.accounts.id.disableAutoSelect();
    }

    // Redirigir a página principal
    window.location.href = 'Inicio.html';
  } catch (err) {
    console.error('Error procesando credencial:', err);
  }
}

// Función para parsear fechas en distintos formatos o como Date
function parseFecha(fechaStr) {
  if (!fechaStr) return null;

  if (fechaStr instanceof Date) {
    return fechaStr;
  }

  if (typeof fechaStr === 'string' && fechaStr.includes('/')) {
    const [d, m, a] = fechaStr.split('/').map(Number);
    return new Date(a, m - 1, d);
  }

  if (typeof fechaStr === 'string') {
    const meses = {
      enero:0, febrero:1, marzo:2, abril:3, mayo:4, junio:5,
      julio:6, agosto:7, septiembre:8, octubre:9, noviembre:10, diciembre:11
    };
    const match = fechaStr.match(/(\d{1,2}) de (\w+) de (\d{4})/i);
    if (match) {
      const dia = parseInt(match[1]);
      const mes = meses[match[2].toLowerCase()];
      const anio = parseInt(match[3]);
      if (!isNaN(dia) && mes !== undefined && !isNaN(anio)) {
        return new Date(anio, mes, dia);
      }
    }
  }

  return null;
}

// Función para obtener el cronograma
async function fetchCronograma() {
  try {
    const response = await fetch('https://script.google.com/macros/s/AKfycbzK_hkWCUOgDBSFG_zKRAIOxCDyWrGfyUVqqF4a4ik4Z0URa_gWEP3ZENZaudF2gfbmvg/exec?action=getCronograma');
    let cronograma = await response.json();

    cronograma.forEach(item => {
      item.fechaObj = parseFecha(item['Fecha de inicio']);
    });

    return cronograma;
  } catch (err) {
    console.error('Error cargando cronograma:', err);
    return [];
  }
}

// Decodificar JWT de Google
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
