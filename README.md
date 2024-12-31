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

