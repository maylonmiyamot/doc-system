const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const flash = require('express-flash');
const { Pool } = require('pg');
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
const app = express();
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'docpro',
    password: 'masterkey',
    port: 5432,
});
// Configuração de sessão
app.use(session({
    secret: 'seu_segredo_aqui',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Configuração do cookie, ajuste conforme necessário
}));
// Middleware do express-flash (deve vir depois do express-session)
app.use(flash());

// Middleware para disponibilizar mensagens flash para todas as views
app.use((req, res, next) => {
    res.locals.success_msg = req.flash('success_msg');
    res.locals.error_msg = req.flash('error_msg');
    next();
});

// Middleware para verificar se o usuário está autenticado
function ensureAuthenticated(req, res, next) {
    if (req.session.user) {
        // Se houver um usuário na sessão, significa que está autenticado
        return next();
    } else {
        // Caso contrário, redireciona para a página de login
        req.flash('error_msg', 'Faça login para acessar esta página');
        res.redirect('/login');
    }
}

// Rota para exibir o formulário de login
app.get('/login', (req, res) => {
    res.render('login');
});

// Rota para processar o formulário de login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    let errors = [];

    // Validar se username e password foram informados
    if (!username || !password) {
        errors.push({ msg: 'Por favor, preencha todos os campos' });
        res.render('login', { errors, username, password });
        return;
    }

    try {
        // Buscar usuário no banco de dados
        const query = 'SELECT * FROM users WHERE username = $1';
        const { rows } = await pool.query(query, [username]);

        if (rows.length === 0) {
            // Usuário não encontrado
            errors.push({ msg: 'Usuário não encontrado' });
            res.render('login', { errors, username, password });
            return;
        }

        const user = rows[0];
        // Comparar senha fornecida com a senha hashada no banco de dados
        const isMatch = await bcrypt.compare(password, user.password);

        if (isMatch) {
            // Senha correta, definir usuário na sessão
            req.session.user = user;
            req.flash('success_msg', 'Você está logado');
            res.redirect('/dashboard');
        } else {
            // Senha incorreta
            errors.push({ msg: 'Senha incorreta' });
            res.render('login', { errors, username, password });
        }
    } catch (error) {
        console.error('Erro ao buscar usuário:', error);
        req.flash('error_msg', 'Erro ao buscar usuário');
        res.redirect('/login');
    }
});

// Rota para exibir o formulário de registro
app.get('/register', (req, res) => {
    res.render('register');
});

// Rota para processar o formulário de registro
app.post('/register', async (req, res) => {
    const { username, password, isAdmin } = req.body;

    // Simples validação de campos
    if (!username || !password) {
        req.flash('error_msg', 'Por favor, preencha todos os campos');
        res.redirect('/register');
        return;
    }

    try {
        // Verifica se o usuário já existe no banco de dados
        const userExists = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

        if (userExists.rows.length > 0) {
            req.flash('error_msg', 'Usuário já registrado');
            res.redirect('/register');
            return;
        }

        // Hash da senha antes de salvar no banco de dados
        const hashedPassword = await bcrypt.hash(password, 10);

        // Determina se o usuário é administrador
        const isAdminValue = isAdmin === 'true'; // Converte para booleano

        // Insere o novo usuário no banco de dados
        await pool.query(
            'INSERT INTO users (username, password, is_admin) VALUES ($1, $2, $3)',
            [username, hashedPassword, isAdminValue]
        );

        req.flash('success_msg', 'Usuário registrado com sucesso');
        res.redirect('/login');
    } catch (err) {
        console.error('Erro ao registrar usuário:', err.message);
        req.flash('error_msg', 'Erro ao registrar usuário');
        res.redirect('/register');
    }
});

// Rota para exibir o dashboard após login
app.get('/dashboard', ensureAuthenticated, (req, res) => {
    pool.query('SELECT * FROM setores WHERE id = $1', [req.session.user.setor_id], (err, result) => {
        if (err) {
            req.flash('error_msg', 'Erro ao carregar setor');
            res.redirect('/login');
        } else {
            res.render('dashboard', { user: req.session.user, setor: result.rows[0] });
        }
    });
});
// Rota para deslogar usuário
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.redirect('/dashboard');
        }
        res.clearCookie('connect.sid');
        res.redirect('/');
    });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
