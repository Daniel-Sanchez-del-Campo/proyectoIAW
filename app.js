const mysql = require('mysql');
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const multer = require('multer');
const bcrypt = require('bcrypt');

const saltRounds = 10;
const upload = multer();
const app = express();

// Middlewares para parsear cuerpos de solicitud
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(upload.array());

// Configuración de la conexión a la base de datos MySQL
var mysqlConnection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'andel',
    multipleStatements: true
});

// Intento de conexión a la base de datos
mysqlConnection.connect((err) => {
    if (!err) {
        console.log('Conexion bbdd correcta...');
    } else {
        console.log('Connection Failed!' + JSON.stringify(err, undefined, 2));
    }
});

// Definición del puerto y puesta en marcha del servidor
const port = process.env.PORT || 8181;
app.listen(port, () => console.log(`Listening on port ${port}..`));

// Ruta principal que sirve la página de inicio
app.get('/', function(req, res) {
    res.sendFile(path.join(__dirname, 'inicio.html'));
});

// Ruta para mostrar la página de inicio de sesión
app.get('/login', function(req, res) {
    res.sendFile(path.join(__dirname, 'login.html'));
});

// Ruta para mostrar la página de registro
app.get('/registro', function(req, res) {
    res.sendFile(path.join(__dirname, 'registro.html'));
});

// Ruta para mostrar la página final
app.get('/final', function(req, res) {
    res.sendFile(path.join(__dirname, 'final.html'));
});

// Ruta para añadir un usuario (registro)
app.post('/registrarse', function(req, res) {
    const username = req.body.username;
    const password = req.body.password;

    bcrypt.hash(password, saltRounds, function(err, hash) {
        if (err) {
            console.log("Error al hashear la contraseña:", err);
            return res.status(500).send('Error al procesar la contraseña');
        }
        const sql = `INSERT INTO users (username, password) VALUES (?, ?)`;
        mysqlConnection.query(sql, [username, hash], (err) => {
            if (!err) {
                console.log("Usuario registrado exitosamente");
                res.redirect('/login'); // Cambiado para redirigir al usuario a la página de inicio de sesión
            } else {
                console.log("ERROR AL INSERTAR LOS DATOS: " + err);
                res.status(500).send('Error al registrar el usuario');
            }
        });
    });
});

// Ruta para manejar el inicio de sesión
app.post('/procesarlogin', function(req, res) {
    var username = req.body.username;
    var password = req.body.password;

    var sql = 'SELECT * FROM users WHERE username = ?';
    mysqlConnection.query(sql, [username], function(err, results, fields) {
        if (err) {
            console.log("Error al buscar el usuario: " + err);
            res.status(500).send('Error al buscar el usuario');
            return;
        }

        if (results.length > 0) {
            bcrypt.compare(password, results[0].password, function(err, isMatch) {
                if (err) {
                    console.log("Error al verificar la contraseña: " + err);
                    res.status(500).send('Error al verificar la contraseña');
                    return;
                }

                if (isMatch) {
                    console.log("Inicio de sesión exitoso para el usuario: " + username);
                    res.redirect('/final'); // Asegúrate de tener una ruta y página para '/final'
                } else {
                    console.log("Contraseña incorrecta para el usuario: " + username);
                    res.status(401).send('Contraseña incorrecta');
                }
            });
        } else {
            console.log("Usuario no encontrado: " + username);
            res.status(404).send('Usuario no encontrado');
        }
    });
});