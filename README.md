# Guía de Instalación y Ejecución de Passkeys Application

## Instalación y Ejecución Simplificada

El `package.json` incluye scripts que automatizan la compilación y ejecución del frontend y backend simultáneamente:

```json
"scripts": {
  "postinstall": "cd passkeys_frontend && npm i && npm run build",
  "start": "cd passkeys_frontend && ng build --configuration production && cd .. && node server.js"
}
```

### Pasos a seguir:
1. Instalar las dependencias:
   ```bash
   npm install
   ```
2. Iniciar la aplicación:
   ```bash
   npm start
   ```
3. Acceder a la aplicación en el navegador:
   - URL: [http://localhost:3000](http://localhost:3000)

---

## Instalación y Ejecución Separada

Si prefieres ejecutar el frontend y backend por separado, sigue estos pasos:

### Compilar el Frontend
```bash
cd passkeys_frontend
ng build --configuration production
```

### Ejecutar el Backend
```bash
cd ..
node server.js
```

Por defecto, la aplicación se ejecutará en el puerto 3000. Puedes modificar esto editando el archivo `server.js`:

```javascript
// Cambia el puerto aquí
app.listen( 3000, '0.0.0.0', err => {
    if (err) throw err;
    console.log('Server started on port', process.env.PORT || 3000);
});
```

---

## Ejecución en Servidor HTTPS de Cloudflare:

Podremos levantar un servidor que apunte hacia un puerto de nuestra red local para así permitir acceso a cualqueir usuario gracias a la siguiente extensión: 

![alt text](/images/captura1.png)
Una vez descargada realizaremos los siguientes pasos para levantar el tunel y poder acceder desde cualquier dispositivo en la misma u otra red:

1. Le damos a la opción de crear tunel en el output de abajo: ![alt text](/images/captura2.png)


2. Seleccionamos el puerto en el que vamos a abrir el tunel: ![alt text](/images/captura3.png)

3. Observamos que se crea correctamente el enlace a nuestro puerto local (si se quisiese parar el tunel en esa misma fila al final aparece un cuadrado con la opción STOP): ![alt text](/images/captura4.png)

4. Vamos al archivo `data.js` dentro de `/passkeys_application` y seguida de la línea de localhost indicamos el origen esperado por nuestra app para evitar otras conexiones no deseadas: 
```javascript
const expectedOrigin = ['http://localhost:3000', 'https://determine-hint-mines-juice.trycloudflare.com'];
```

5. Levantamos la applicación en nuestro puerto 3000 en la red local: 

```bash
PS C:\\passkeys_application> npm start

Server started on port 3000
```

6. Debería funcionar todo perfectamente:  ![alt text](/images/captura5.png)


# Usabilidad de la app: 
 
 El usuario al entrar en la app va a visualizar el inicio de sesión. En el con la opción `autofill`. Si se detecta que el usuario introducido no está registrado o tiene passkey te dará la opción de introducir una contraseña.

 Si se introduce la contraseña ya nos podemos registrar y en el campo `/profile` podremos crear las passkeys. 

 Tras crear las passkeys cada vez que volvamos a la página de inicio de sesión simplemente tendremos que indicar el usuario, si detecta que tienes passkey solo tienes que poner la huella digital entre otras. 

## Diferencias entre los tres tipos de login con passkeys

Esta aplicación implementa tres flujos distintos de autenticación con passkeys:

### 1. Login por Email (Username-first)

```javascript
router.post('/login/passkey/by-email', (req, res) => {
    const rpId = req.hostname;
    const { username } = req.body;
    
    // Genera un challenge específico para este usuario
    let challenge = getNewChallenge();
    challenges[username] = challenge;
    
    // Solo envía las credenciales de este usuario específico
    const userCredentials = users[username].credential.map(cred => ({
        type: 'public-key',
        id: cred.id,
        transports: ['internal', 'ble', 'nfc', 'usb'],
    }));
    
    res.json({
        challenge: challenge,
        rpId: rpId,
        allowCredentials: userCredentials,
        timeout: 60000,
        userVerification: 'preferred'
    });
});
```

- **Flujo de usuario:** El usuario introduce primero su email y luego usa la passkey
- **Características técnicas:**
  - Usa un desafío específico para cada usuario (`challenges[username]`)
  - Envía solo las credenciales asociadas a ese usuario
  - Timeout: 60 segundos
- **Ventajas:** Mayor seguridad al exponer solo las credenciales del usuario correcto
- **Caso de uso:** Usuario que conoce su email y quiere usar passkey en lugar de contraseña

### 2. Direct-Login (Login directo)
```javascript
router.post('/login/passkey/direct', (req, res) => {
    const rpId = req.hostname;
    const isConditional = req.body.isConditional === true;
    // isConditional = false para Direct Login
    
    // Usa un challenge global compartido
    if (!challenges['_direct']) {
        challenges['_direct'] = getNewChallenge();
        challenges['_direct_timestamp'] = Date.now();
    }
    const challenge = challenges['_direct'];
    
    // Envía TODAS las credenciales de TODOS los usuarios
    const allCredentials = [];
    for (const [username, userData] of Object.entries(users)) {
        if (userData.credential && userData.credential.length > 0) {
            userData.credential.forEach(cred => {
                if (cred && cred.id) {
                    allCredentials.push({
                        type: 'public-key',
                        id: cred.id,
                        transports: ['internal', 'ble', 'nfc', 'usb'],
                    });
                }
            });
        }
    }
    
    // Timeout estándar para direct login
    const timeout = 60000; // (isConditional ? 120000 : 60000)
    
    res.json({
        challenge: challenge,
        rpId: rpId,
        allowCredentials: allCredentials,
        timeout: timeout,
        userVerification: 'preferred'
    });
});
```

- **Flujo de usuario:** El usuario hace clic en un botón "Iniciar sesión con passkey"
- **Características técnicas:**
  - Usa un desafío global compartido (`challenges['_direct']`)
  - Envía todas las credenciales de todos los usuarios
  - Timeout: 60 segundos
  - `isConditional = false`
- **Ventajas:** Experiencia de usuario simplificada, sin necesidad de introducir email
- **Caso de uso:** Inicio de sesión rápido con un solo clic para usuarios frecuentes

### 3. Autofill (Autocompletado)
```javascript 
// Mismo endpoint que Direct Login pero con isConditional=true
router.post('/login/passkey/direct', (req, res) => {
    const rpId = req.hostname;
    const isConditional = req.body.isConditional === true;
    // isConditional = true para Autofill
    
    // Usa el mismo challenge global compartido
    if (!challenges['_direct']) {
        challenges['_direct'] = getNewChallenge();
        challenges['_direct_timestamp'] = Date.now();
    }
    const challenge = challenges['_direct'];
    
    // También envía TODAS las credenciales de TODOS los usuarios
    const allCredentials = [];
    // ...mismo código para recopilar credenciales...
    
    // Timeout extendido específico para autofill
    const timeout = 120000; // (isConditional ? 120000 : 60000)
    
    res.json({
        challenge: challenge,
        rpId: rpId,
        allowCredentials: allCredentials,
        timeout: timeout,
        userVerification: 'preferred'
    });
});
```

- **Flujo de usuario:** El navegador detecta un formulario de login y ofrece completarlo automáticamente
- **Características técnicas:**
  - Usa el mismo desafío global que Direct-Login
  - Envía todas las credenciales de todos los usuarios
  - Timeout: 120 segundos (mayor para dar tiempo a la interacción)
  - `isConditional = true`
- **Ventajas:** Experiencia "mágica" donde el navegador inicia el proceso automáticamente
- **Caso de uso:** Usuario que visita la página y recibe sugerencia automática de su navegador

### Comparativa técnica

| Característica | Login por Email | Direct-Login | Autofill |
|----------------|----------------|--------------|----------|
| Desafío | Específico por usuario | Global compartido | Global compartido |
| Credenciales | Solo del usuario | Todas | Todas |
| Timeout | 60 segundos | 60 segundos | 120 segundos |
| Iniciado por | Usuario (email) | Usuario (botón) | Navegador |
| Necesita username | Sí | No | No |
| isConditional | No aplica | false | true |

Todos los métodos convergen en el mismo endpoint final (`/login/passkey/fin`) que identifica al usuario según la credencial utilizada y completa la verificación.