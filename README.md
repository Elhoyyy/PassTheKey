# Guía de Instalación y Ejecución de Passkeys Application

## Instalación y Ejecución Simplificada

El `package.json` incluye scripts que automatizan la compilación y ejecución del frontend y backend simultáneamente:

```json
"scripts": {
  "postinstall": "cd passkeys_frontend && npm i && npm run build",
  "start": "cd passkeys_frontend && ng build --configuration production && cd .. && node index.js"
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
   - URL: [http://localhost:3000](http://localhost:3000) o utilizar: `https://<TU_IP_LOCAL>:3000`

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
node index.js
```

Por defecto, la aplicación se ejecutará en el puerto 3000. Puedes modificar esto editando el archivo `index.js`:

```javascript
const expectedOrigin = ['http://localhost:3000']; // Origen esperado

// Cambia el puerto aquí
const PORT = process.env.PORT || 4000;

app.listen(PORT, '0.0.0.0', err => {
    if (err) throw err;
    console.log('Server started on port', PORT);
});
```

---

## Ejecución en Red Local

Para probar la aplicación en múltiples dispositivos dentro de la misma red local:

### Opciones disponibles:

1. Desde tu móvil accede a `https://<TU_IP_LOCAL>`

2. Utilizando la siguiente línea para permitir acceso a toda la red local: 

```javascript
app.listen(process.env.PORT || 3000, '0.0.0.0', err => ...
```


# Usabilidad de la app: 
 
 El usuario al entrar en la app va a visualizar el inicio de sesión. En el con la opción `autofill`. Si se detecta que el usuario introducido no está registrado o tiene passkey te dará la opción de introducir una contraseña.

 Si se introduce la contraseña ya nos podemos registrar y en el campo `/profile` podremos crear las passkeys. 

 Tras crear las passkeys cada vez que volvamos a la página de inicio de sesión simplemente tendremos que indicar el usuario, si detecta que tienes passkey solo tienes que poner la huella digital entre otras. 

