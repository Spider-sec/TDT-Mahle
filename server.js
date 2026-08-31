const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jwt-simple');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json());

const JWT_SECRET = 'sua_chave_secreta_super_segura_aqui';

// Banco de dados em memória (substitua por um banco relacional/NoSQL em produção)
const usersDB = [];

// Configuração do Transportador de E-mail para Envio de Relatórios
const transporter = nodemailer.createTransport({
    service: 'gmail', // ou o SMTP corporativo da empresa
    auth: {
        user: 'seu-email@dominio.com',
        pass: 'sua-senha-de-app'
    }
});

// Limite de 8 tentativas de login por IP
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // Janela de 15 minutos
    max: 8,
    message: { error: 'Número máximo de tentativas (8) excedido. Tente novamente após 15 minutos.' }
});

// Inicialização do usuário Administrador Padrão
async function initAdmin() {
    const hashedPassword = await bcrypt.hash('37051064', 10);
    usersDB.push({
        username: 'Mizael',
        password: hashedPassword,
        role: 'admin'
    });
    console.log('Usuário administrador (Mizael) inicializado com sucesso.');
}
initAdmin();

// Middleware de Autenticação de Rotas
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Acesso negado. Token não fornecido.' });

    try {
        const decoded = jwt.decode(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ error: 'Token inválido ou expirado.' });
    }
}

// Middleware Exclusivo de Administrador
function requireAdmin(req, res, next) {
    if (req.user.username !== 'Mizael' || req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Acesso negado. Apenas o usuário Mizael possui permissões administrativas.' });
    }
    next();
}

// ROTA 1: Login com limitação de 8 tentativas
app.post('/api/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    const user = usersDB.find(u => u.username === username);

    if (!user) {
        return res.status(401).json({ error: 'Usuário ou senha incorretos.' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
        return res.status(401).json({ error: 'Usuário ou senha incorretos.' });
    }

    // Gerar Token JWT com validade de 8 horas
    const payload = { username: user.username, role: user.role, exp: Math.floor(Date.now() / 1000) + (8 * 3600) };
    const token = jwt.encode(payload, JWT_SECRET);

    res.json({ token, role: user.role });
});

// ROTA 2: Criar novo usuário (Restrita ao usuário Mizael)
app.post('/api/users/create', authenticateToken, requireAdmin, async (req, res) => {
    const { newUsername, newPassword, role } = req.body;

    if (usersDB.find(u => u.username === newUsername)) {
        return res.status(400).json({ error: 'Usuário já existe.' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    usersDB.push({
        username: newUsername,
        password: hashedPassword,
        role: role || 'operator'
    });

    res.status(201).json({ message: `Usuário ${newUsername} criado com sucesso!` });
});

// ROTA 3: Envio do Relatório de Troca de Turno
app.post('/api/reports/submit', authenticateToken, async (req, res) => {
    const formData = req.body;
    const filledBy = req.user.username;

    // Estruturação do e-mail do relatório
    const mailOptions = {
        from: 'sistema-turno@empresa.com',
        to: 'supervisao@empresa.com', // E-mail do destinatário dos relatórios
        subject: `Relatório de Troca de Turno - Data: ${formData.data} - Turno: ${formData.deTurno} -> ${formData.paraTurno}`,
        html: `
            <h2>Relatório de Troca de Turno</h2>
            <p><strong>Preenchido por:</strong> ${filledBy}</p>
            <p><strong>Data:</strong> ${formData.data} | <strong>Departamento:</strong> ${formData.departamento}</p>
            <p><strong>Área:</strong> ${formData.areaProducao}</p>
            <p><strong>De:</strong> ${formData.deNome} (${formData.deTurno}) <strong>Para:</strong> ${formData.paraNome} (${formData.paraTurno})</p>
            <hr>
            <h3>Detalhamento do Turno</h3>
            <pre>${JSON.stringify(formData.secoes, null, 2)}</pre>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        res.json({ message: 'Relatório enviado com sucesso e e-mail disparado!' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao disparar o e-mail do relatório.' });
    }
});

app.listen(3000, () => console.log('Servidor rodando com segurança na porta 3000'));
