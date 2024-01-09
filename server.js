const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cors = require('cors');  // Importa cors

const app = express();
const PORT = process.env.PORT || 5000;

// Configurar CORS para permitir solicitudes desde http://localhost:5173
app.use(cors({ origin: 'http://localhost:5173' }));


// Permitir solicitudes desde cualquier origen
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  next();
});


app.use(bodyParser.json());
app.use(cors()); 
// Conéctate a MongoDB (asegúrate de tener MongoDB instalado y ejecutándose)
mongoose.connect('mongodb://localhost:27017/your-database-name', { /* useNewUrlParser: true, useUnifiedTopology: true */ });

// Define el modelo de usuario con el nuevo campo phoneNumber y hashId
const User = mongoose.model('User', {
    username: String,
    password: String,
    phoneNumber: String,
    hashId: String, // Nuevo campo hashId
  });
  
  app.post('/api/register', async (req, res) => {
    try {
      const { username, password, confirmPassword, phoneNumber } = req.body;
  
      // Verificar si las contraseñas coinciden
      if (password !== confirmPassword) {
        return res.status(400).json({ error: 'Las contraseñas no coinciden' });
      }
  
      const existingUser = await User.findOne({ username });
  
      if (existingUser) {
        return res.status(400).json({ error: 'El nombre de usuario ya está en uso' });
      }
  
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Generar un hash de identificación único
      const hashId = crypto.createHash('sha256').update(username + Date.now().toString()).digest('hex');
      console.log(hashId)
  
      const newUser = new User({ username, password: hashedPassword, phoneNumber, hashId });
      await newUser.save();
  
      // Mostrar el hashId en la respuesta
      res.status(201).json({ message: 'Usuario registrado con éxito', hashId });
    } catch (error) {
      res.status(500).json({ error: 'Error al registrar el usuario' });
    }
  });
  
  
// Ruta para iniciar sesión y generar un token JWT
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(401).json({ error: 'Nombre de usuario o contraseña incorrectos' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Nombre de usuario o contraseña incorrectos' });
    }

    const token = jwt.sign({ username: user.username }, 'your-secret-key', { expiresIn: '1h' });

    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: 'Error al iniciar sesión' });
  }
});

// Rutas privadas
app.get('/api/private', (req, res) => {
  res.json({ message: 'Ruta privada' });
});


/* listen */
app.listen(PORT, () => {
  console.log(`Servidor en ejecución en http://localhost:${PORT}`);
});


