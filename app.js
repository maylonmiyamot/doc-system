const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const flash = require('connect-flash');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
const pool = new Pool({
    user: 'seu_usuario',
    host: 'localhost',
    database: 'sistema_permissoes',
    password: 'sua_senha',
    port: 5432,
});

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'secreto',
    resave: false,
    saveUninitialized: true
}));
app.use(flash());

// Middleware para definir mensagens flash globalmente
app.use((req, res, next) => {
    res.locals.success_msg = req.flash('success_msg');
    res.locals.error_msg = req.flash('error_msg');
    next();
});

// Rotas
app.get('/', (req, res) => {
    res.render('index');
});

// Exibir o formulário de login
app.get('/login', (req, res) => {
    res.render('login');
});

// Exibir o formulário de registro com a lista de setores
app.get('/register', (req, res) => {
    pool.query('SELECT * FROM setores', (err, result) => {
        if (err) {
            req.flash('error_msg', 'Erro ao carregar setores');
            res.redirect('/');
        } else {
            res.render('register', { setores: result.rows });
        }
    });
});

// Processar o formulário de registro
app.post('/register', async (req, res) => {
    const { username, password, setor_id } = req.body;
    let errors = [];

    if (!username || !password || !setor_id) {
        errors.push({ msg: 'Por favor, preencha todos os campos' });
    }

    if (errors.length > 0) {
        pool.query('SELECT * FROM setores', (err, result) => {
            if (err) {
                req.flash('error_msg', 'Erro ao carregar setores');
                res.redirect('/');
            } else {
                res.render('register', { errors, username, password, setores: result.rows });
            }
        });
    } else {
        const hashedPassword = await bcrypt.hash(password, 10);

        pool.query(
            'INSERT INTO users (username, password, setor_id) VALUES ($1, $2, $3) RETURNING id',
            [username, hashedPassword, setor_id],
            (err, result) => {
                if (err) {
                    req.flash('error_msg', 'Erro ao registrar usuário');
                    res.redirect('/register');
                } else {
                    req.flash('success_msg', 'Você está registrado e pode fazer login');
                    res.redirect('/login');
                }
            }
        );
    }
});

// Processar o formulário de login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    let errors = [];

    if (!username || !password) {
        errors.push({ msg: 'Por favor, preencha todos os campos' });
    }

    if (errors.length > 0) {
        res.render('login', { errors, username, password });
    } else {
        pool.query(
            'SELECT * FROM users WHERE username = $1',
            [username],
            async (err, result) => {
                if (err) {
                    req.flash('error_msg', 'Erro ao buscar usuário');
                    res.redirect('/login');
                } else {
                    if (result.rows.length > 0) {
                        const user = result.rows[0];

                        const isMatch = await bcrypt.compare(password, user.password);
                        if (isMatch) {
                            req.session.user = user;
                            req.flash('success_msg', 'Você está logado');
                            res.redirect('/dashboard');
                        } else {
                            req.flash('error_msg', 'Senha incorreta');
                            res.redirect('/login');
                        }
                    } else {
                        req.flash('error_msg', 'Usuário não encontrado');
                        res.redirect('/login');
                    }
                }
            }
        );
    }
});

// Exibir o dashboard após login
app.get('/dashboard', (req, res) => {
    if (!req.session.user) {
        req.flash('error_msg', 'Por favor, faça login para ver esta página');
        res.redirect('/login');
    } else {
        pool.query('SELECT * FROM setores WHERE id = $1', [req.session.user.setor_id], (err, result) => {
            if (err) {
                req.flash('error_msg', 'Erro ao carregar setor');
                res.redirect('/login');
            } else {
                res.render('dashboard', { user: req.session.user, setor: result.rows[0] });
            }
        });
    }
});

// Deslogar usuário
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.redirect('/dashboard');
        }
        res.clearCookie('connect.sid');
        res.redirect('/');
    });
});

// Gerenciar setores (exemplo: adicionar um novo setor)
app.get('/setores', (req, res) => {
    pool.query('SELECT * FROM setores', (err, result) => {
        if (err) {
            req.flash('error_msg', 'Erro ao carregar setores');
            res.redirect('/');
        } else {
            res.render('setores', { setores: result.rows });
        }
    });
});

app.post('/setores', (req, res) => {
    const { nome } = req.body;
    if (!nome) {
        req.flash('error_msg', 'Por favor, preencha o nome do setor');
        res.redirect('/setores');
    } else {
        pool.query(
            'INSERT INTO setores (nome) VALUES ($1) RETURNING id',
            [nome],
            (err, result) => {
                if (err) {
                    req.flash('error_msg', 'Erro ao adicionar setor');
                    res.redirect('/setores');
                } else {
                    req.flash('success_msg', 'Setor adicionado com sucesso');
                    res.redirect('/setores');
                }
            }
        );
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
