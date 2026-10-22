const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Pool } = require('pg');
const cors = require('cors');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const app = express();
const server = http.createServer(app);

app.set('trust proxy', 1);

// ==========================================
// CORS
// ==========================================
const FRONTEND_URL =
    process.env.FRONTEND_URL || 'https://nfc-avaliation.github.io';

const allowedOrigins = [
    'http://localhost:3000',
    'http://127.0.0.1:5500',
    'https://nfc-avaliation.github.io',
    FRONTEND_URL
];

const corsOptions = {
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Acesso bloqueado pelo CORS'));
        }
    },
    credentials: true
};

app.use(cors(corsOptions));
app.use(express.json());

// ==========================================
// LIMITE DE REQUISIÇÕES
// ==========================================
const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 100,
    message: {
        error: 'Muitas requisições originadas deste IP. Aguarde um minuto.'
    },
    validate: {
        trustProxy: false
    }
});

app.use('/api/', apiLimiter);

// ==========================================
// SOCKET.IO
// ==========================================
const io = new Server(server, {
    cors: {
        origin: allowedOrigins,
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        credentials: true
    }
});

// ==========================================
// BANCO DE DADOS
// ==========================================
const pool = new Pool({
    connectionString:
        process.env.DATABASE_URL ||
        'postgresql://postgres:JTSZTBKgDTGCZ5LF@db.jfyjrtllkqmvixosrtof.supabase.co:5432/postgres',
    ssl: {
        rejectUnauthorized: false
    },
    max: 20,
    idleTimeoutMillis: 30000
});

pool.on('error', err => {
    console.error('Erro inesperado no banco de dados:', err);
});

// ==========================================
// TABELA DE PAGAMENTOS
// ==========================================
async function initDB() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS comanda_pagamentos (
                id SERIAL PRIMARY KEY,
                comanda_id INT,
                caixa_id INT,
                forma_pagamento VARCHAR(50),
                valor DECIMAL(10,2),
                data_pagamento TIMESTAMP DEFAULT NOW()
            );
        `);

        console.log(
            "Tabela 'comanda_pagamentos' verificada/criada com sucesso."
        );
    } catch (err) {
        console.error(
            'Erro ao criar tabela de pagamentos múltiplos:',
            err
        );
    }
}

initDB();

// ==========================================
// CREDENCIAIS DO ADMINISTRADOR
// ==========================================
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin123';

const JWT_SECRET =
    process.env.JWT_SECRET || 'chave_super_secreta_restaurante_2026';

// ==========================================
// AUTENTICAÇÃO
// ==========================================
function verifyAdminToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({
            error: 'Acesso negado. Token ausente.'
        });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({
                error: 'Token inválido ou expirado. Faça login novamente.'
            });
        }

        req.user = user;
        next();
    });
}

// ==========================================
// CONEXÕES EM TEMPO REAL
// ==========================================
io.on('connection', socket => {
    console.log(`Cliente conectado: ${socket.id}`);

    socket.on('disconnect', () => {
        console.log(`Cliente desconectado: ${socket.id}`);
    });
});

function atualizarPainel() {
    io.emit('atualizacao_dados');
}

// ==========================================
// LOGIN DO PAINEL
// ==========================================
app.post('/api/admin/login', (req, res) => {
    const { user, pass } = req.body;

    if (user === ADMIN_USER && pass === ADMIN_PASS) {
        const token = jwt.sign(
            { role: 'admin' },
            JWT_SECRET,
            { expiresIn: '12h' }
        );

        return res.json({
            success: true,
            token
        });
    }

    return res.status(401).json({
        error: 'Utilizador ou senha incorretos!'
    });
});

// ==========================================
// ACESSAR MESA
// ==========================================
app.get('/api/mesa/acessar', async (req, res) => {
    const { mesa } = req.query;

    if (!mesa) {
        return res.status(400).send(
            'Número da mesa não especificado.'
        );
    }

    let client;

    try {
        client = await pool.connect();

        const mesaRes = await client.query(
            `
                SELECT id, status, token_sessao
                FROM mesas
                WHERE numero::text = $1
            `,
            [mesa]
        );

        if (mesaRes.rows.length === 0) {
            return res.status(404).send(
                'Mesa não encontrada no sistema.'
            );
        }

        const mesaObj = mesaRes.rows[0];
        let token = mesaObj.token_sessao;

        if (!token || mesaObj.status === 'livre') {
            token = 'tok_' + crypto.randomBytes(16).toString('hex');

            await client.query(
                `
                    UPDATE mesas
                    SET token_sessao = $1
                    WHERE id = $2
                `,
                [token, mesaObj.id]
            );
        }

        return res.redirect(
            `${FRONTEND_URL}/index.html?mesa=${mesa}&token=${token}`
        );
    } catch (error) {
        return res.status(500).send(
            'Erro interno ao acessar a mesa.'
        );
    } finally {
        if (client) client.release();
    }
});

// ==========================================
// INICIAR SESSÃO DA MESA
// ==========================================
app.post('/api/mesa/sessao', async (req, res) => {
    const { mesa_numero } = req.body;
    let client;

    try {
        client = await pool.connect();

        const mesaRes = await client.query(
            `
                SELECT id, status, token_sessao
                FROM mesas
                WHERE numero::text = $1
            `,
            [mesa_numero]
        );

        if (mesaRes.rows.length === 0) {
            return res.status(404).json({
                error: 'Mesa não encontrada'
            });
        }

        const mesa = mesaRes.rows[0];
        let token = mesa.token_sessao;

        if (!token || mesa.status === 'livre') {
            token = 'tok_' + crypto.randomBytes(16).toString('hex');

            await client.query(
                `
                    UPDATE mesas
                    SET token_sessao = $1
                    WHERE id = $2
                `,
                [token, mesa.id]
            );
        }

        return res.json({
            success: true,
            token_sessao: token
        });
    } catch (error) {
        return res.status(500).json({
            error: 'Erro ao iniciar sessão'
        });
    } finally {
        if (client) client.release();
    }
});

// ==========================================
// RECEBER PEDIDO DA MESA
// ==========================================
app.post('/api/pedidos', async (req, res) => {
    const { mesa_numero, cart, token_sessao } = req.body;

    if (!cart || !Array.isArray(cart) || cart.length === 0) {
        return res.status(400).json({
            error: 'Carrinho vazio'
        });
    }

    let client;

    try {
        client = await pool.connect();
        await client.query('BEGIN');

        const mesaRes = await client.query(
            `
                SELECT id, token_sessao, status
                FROM mesas
                WHERE numero::text = $1
                FOR UPDATE
            `,
            [mesa_numero]
        );

        if (mesaRes.rows.length === 0) {
            throw new Error('MESA_NOT_FOUND');
        }

        const mesa = mesaRes.rows[0];

        if (
            !mesa.token_sessao ||
            mesa.token_sessao !== token_sessao
        ) {
            throw new Error('INVALID_SESSION');
        }

        const comandaRes = await client.query(
            `
                SELECT id
                FROM comandas
                WHERE mesa_id = $1
                AND (
                    LOWER(status) = 'aberta'
                    OR status IS NULL
                )
            `,
            [mesa.id]
        );

        let comanda_id;

        if (comandaRes.rows.length === 0) {
            const codigo =
                `#${Math.floor(100 + Math.random() * 900)}`;

            const novaComanda = await client.query(
                `
                    INSERT INTO comandas (
                        codigo,
                        mesa_id,
                        status
                    )
                    VALUES ($1, $2, $3)
                    RETURNING id
                `,
                [codigo, mesa.id, 'aberta']
            );

            comanda_id = novaComanda.rows[0].id;

            await client.query(
                'UPDATE mesas SET status = $1 WHERE id = $2',
                ['ocupada', mesa.id]
            );
        } else {
            comanda_id = comandaRes.rows[0].id;
        }

        for (const item of cart) {
            await client.query(
                `
                    INSERT INTO comanda_itens (
                        comanda_id,
                        item_id_cache,
                        nome_item,
                        quantidade,
                        preco_unitario,
                        observacoes
                    )
                    VALUES ($1, $2, $3, $4, $5, $6)
                `,
                [
                    comanda_id,
                    item.dishId || 'item',
                    item.name,
                    item.quantity,
                    item.unitPrice,
                    item.notes || ''
                ]
            );
        }

        await client.query('COMMIT');

        atualizarPainel();

        io.emit('notificacao_painel', {
            titulo: 'Novo Pedido',
            msg: `Mesa ${mesa_numero} enviou um pedido.`,
            tipo: 'success'
        });

        return res.json({
            success: true,
            message: 'Pedido enviado!'
        });
    } catch (error) {
        if (client) await client.query('ROLLBACK');

        if (error.message === 'MESA_NOT_FOUND') {
            return res.status(404).json({
                error: 'Mesa não encontrada'
            });
        }

        if (error.message === 'INVALID_SESSION') {
            return res.status(403).json({
                error: 'Sessão inválida'
            });
        }

        console.error('Erro ao processar pedido da mesa:', error);

        return res.status(500).json({
            error: 'Erro ao processar pedido'
        });
    } finally {
        if (client) client.release();
    }
});

// ==========================================
// CHAMAR GARÇOM
// ==========================================
app.post('/api/garcom', async (req, res) => {
    const { mesa_numero, token_sessao } = req.body;
    let client;

    try {
        client = await pool.connect();

        const mesaRes = await client.query(
            `
                SELECT id, token_sessao
                FROM mesas
                WHERE numero::text = $1
            `,
            [mesa_numero]
        );

        if (mesaRes.rows.length === 0) {
            return res.status(404).json({
                error: 'Mesa não encontrada'
            });
        }

        const mesa = mesaRes.rows[0];

        if (
            !mesa.token_sessao ||
            mesa.token_sessao !== token_sessao
        ) {
            return res.status(403).json({
                error: 'Sessão inválida.'
            });
        }

        await client.query(
            `
                UPDATE mesas
                SET chamando_garcom = TRUE
                WHERE id = $1
            `,
            [mesa.id]
        );

        atualizarPainel();

        io.emit('chamada_garcom', {
            mesa: mesa_numero
        });

        return res.json({
            success: true
        });
    } catch (error) {
        console.error('Erro ao chamar garçom:', error);

        return res.status(500).json({
            error: 'Erro ao chamar garçom'
        });
    } finally {
        if (client) client.release();
    }
});

// ==========================================
// STATUS DO CAIXA
// ==========================================
app.get('/api/caixa/status', verifyAdminToken, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT *
            FROM caixas
            WHERE status = 'aberto'
            ORDER BY id DESC
            LIMIT 1
        `);

        if (result.rows.length > 0) {
            return res.json({
                aberto: true,
                caixa: result.rows[0]
            });
        }

        return res.json({
            aberto: false
        });
    } catch (error) {
        console.error('Erro ao verificar caixa:', error);

        return res.status(500).json({
            error: 'Erro ao verificar status do caixa.'
        });
    }
});

// ==========================================
// ABRIR CAIXA
// ==========================================
app.post('/api/caixa/abrir', verifyAdminToken, async (req, res) => {
    const { saldo_inicial } = req.body;

    try {
        const check = await pool.query(`
            SELECT id
            FROM caixas
            WHERE status = 'aberto'
        `);

        if (check.rows.length > 0) {
            return res.status(400).json({
                error: 'Já existe um caixa aberto.'
            });
        }

        const result = await pool.query(
            `
                INSERT INTO caixas (
                    status,
                    saldo_inicial,
                    data_abertura
                )
                VALUES ('aberto', $1, NOW())
                RETURNING *
            `,
            [saldo_inicial || 0]
        );

        return res.json({
            success: true,
            caixa: result.rows[0]
        });
    } catch (error) {
        console.error('Erro ao abrir caixa:', error);

        return res.status(500).json({
            error: 'Erro ao abrir caixa.'
        });
    }
});

// ==========================================
// FECHAR CAIXA
// ==========================================
app.post('/api/caixa/fechar', verifyAdminToken, async (req, res) => {
    try {
        const result = await pool.query(`
            UPDATE caixas
            SET
                status = 'fechado',
                data_fechamento = NOW()
            WHERE status = 'aberto'
            RETURNING *
        `);

        if (result.rowCount === 0) {
            return res.status(400).json({
                error: 'Nenhum caixa aberto encontrado.'
            });
        }

        return res.json({
            success: true,
            caixa: result.rows[0]
        });
    } catch (error) {
        console.error('Erro ao fechar caixa:', error);

        return res.status(500).json({
            error: 'Erro ao fechar caixa.'
        });
    }
});

// ==========================================
// RESUMO DO CAIXA
// ==========================================
app.get('/api/caixa/resumo', verifyAdminToken, async (req, res) => {
    try {
        const caixaAberto = await pool.query(`
            SELECT *
            FROM caixas
            WHERE status = 'aberto'
            ORDER BY id DESC
            LIMIT 1
        `);

        if (caixaAberto.rows.length === 0) {
            return res.json({
                aberto: false
            });
        }

        const caixa = caixaAberto.rows[0];

        const vendas = await pool.query(
            `
                SELECT
                    forma_pagamento,
                    SUM(valor) AS total
                FROM comanda_pagamentos
                WHERE caixa_id = $1
                GROUP BY forma_pagamento
            `,
            [caixa.id]
        );

        return res.json({
            aberto: true,
            caixa,
            vendas: vendas.rows
        });
    } catch (error) {
        console.error('Erro no resumo do caixa:', error);

        return res.status(500).json({
            error: 'Erro ao obter resumo do caixa.'
        });
    }
});

// ==========================================
// ATENDER CHAMADA DE GARÇOM
// ==========================================
app.post('/api/garcom/atender', verifyAdminToken, async (req, res) => {
    try {
        await pool.query(
            `
                UPDATE mesas
                SET chamando_garcom = FALSE
                WHERE id = $1
            `,
            [req.body.mesa_id]
        );

        atualizarPainel();

        return res.json({
            success: true
        });
    } catch (error) {
        return res.status(500).json({
            error: 'Erro ao atender garçom'
        });
    }
});

// ==========================================
// LISTAR MESAS E COMANDAS
// ==========================================
app.get('/api/mesas', verifyAdminToken, async (req, res) => {
    try {
        const query = `
            SELECT
                m.id AS mesa_id,
                m.numero,
                m.status,
                m.chamando_garcom,
                c.id AS comanda_id,
                c.codigo AS comanda_codigo,
                c.data_abertura,
                COALESCE(
                    (
                        SELECT json_agg(
                            json_build_object(
                                'id', ci.id,
                                'nome_item', ci.nome_item,
                                'preco_unitario', ci.preco_unitario,
                                'quantidade', ci.quantidade,
                                'observacoes', ci.observacoes
                            )
                        )
                        FROM comanda_itens ci
                        WHERE ci.comanda_id = c.id
                    ),
                    '[]'::json
                ) AS items
            FROM mesas m
            LEFT JOIN comandas c
                ON m.id = c.mesa_id
                AND (
                    LOWER(c.status) = 'aberta'
                    OR c.status IS NULL
                )
            ORDER BY m.numero ASC;
        `;

        const mesasRes = await pool.query(query);

        return res.json(mesasRes.rows);
    } catch (error) {
        return res.status(500).json({
            error: 'Erro ao buscar mesas'
        });
    }
});

// ==========================================
// CHECKOUT COM PAGAMENTOS MÚLTIPLOS
// ==========================================
app.post('/api/checkout', verifyAdminToken, async (req, res) => {
    const {
        comanda_id,
        mesa_id,
        pagamentos,
        subtotal,
        taxa,
        desconto
    } = req.body;

    let client;

    try {
        client = await pool.connect();
        await client.query('BEGIN');

        let comandaTargetId = comanda_id;

        if (mesa_id && !comanda_id) {
            const comandasAbertas = await client.query(
                `
                    SELECT id
                    FROM comandas
                    WHERE mesa_id = $1
                    AND (
                        LOWER(status) = 'aberta'
                        OR status IS NULL
                    )
                `,
                [mesa_id]
            );

            if (comandasAbertas.rows.length > 0) {
                comandaTargetId = comandasAbertas.rows[0].id;
            }
        }

        if (comandaTargetId) {
            let caixaId = null;

            const caixaAberto = await client.query(`
                SELECT id
                FROM caixas
                WHERE status = 'aberto'
                ORDER BY id DESC
                LIMIT 1
            `);

            if (caixaAberto.rows.length > 0) {
                caixaId = caixaAberto.rows[0].id;
            }

            const itensSum = await client.query(
                `
                    SELECT
                        SUM(quantidade * preco_unitario) AS soma
                    FROM comanda_itens
                    WHERE comanda_id = $1
                `,
                [comandaTargetId]
            );

            const comSubtotal =
                itensSum.rows[0]?.soma || subtotal || 0;

            const comFinal =
                comSubtotal - (desconto || 0) + (taxa || 0);

            const formaPagamentoPrincipal =
                req.body.forma_pagamento || 'MULTIPLOS';

            await client.query(
                `
                    UPDATE comandas
                    SET
                        status = 'fechada',
                        data_fechamento = NOW(),
                        forma_pagamento = $1,
                        subtotal = $2,
                        taxa_servico = $3,
                        desconto = $4,
                        valor_total_final = $5,
                        caixa_id = $6
                    WHERE id = $7
                `,
                [
                    formaPagamentoPrincipal,
                    comSubtotal,
                    taxa || 0,
                    desconto || 0,
                    comFinal,
                    caixaId,
                    comandaTargetId
                ]
            );

            if (pagamentos && pagamentos.length > 0) {
                for (const pagamento of pagamentos) {
                    await client.query(
                        `
                            INSERT INTO comanda_pagamentos (
                                comanda_id,
                                caixa_id,
                                forma_pagamento,
                                valor
                            )
                            VALUES ($1, $2, $3, $4)
                        `,
                        [
                            comandaTargetId,
                            caixaId,
                            pagamento.metodo,
                            pagamento.valor
                        ]
                    );
                }
            } else {
                await client.query(
                    `
                        INSERT INTO comanda_pagamentos (
                            comanda_id,
                            caixa_id,
                            forma_pagamento,
                            valor
                        )
                        VALUES ($1, $2, $3, $4)
                    `,
                    [
                        comandaTargetId,
                        caixaId,
                        formaPagamentoPrincipal,
                        comFinal
                    ]
                );
            }
        }

        if (mesa_id) {
            await client.query(
                `
                    UPDATE mesas
                    SET
                        status = $1,
                        chamando_garcom = FALSE,
                        token_sessao = NULL
                    WHERE id = $2
                `,
                ['livre', mesa_id]
            );
        }

        await client.query('COMMIT');

        atualizarPainel();

        return res.json({
            success: true
        });
    } catch (error) {
        if (client) await client.query('ROLLBACK');

        console.error('Erro no checkout:', error);

        return res.status(500).json({
            error: 'Erro ao fechar comanda'
        });
    } finally {
        if (client) client.release();
    }
});

// ==========================================
// CANCELAR MESA/COMANDA
// ==========================================
app.post(
    '/api/admin/mesa/cancelar',
    verifyAdminToken,
    async (req, res) => {
        let { mesa_id, comanda_id } = req.body;
        let client;

        try {
            client = await pool.connect();
            await client.query('BEGIN');

            if (!comanda_id && mesa_id) {
                const comRes = await client.query(
                    `
                        SELECT id
                        FROM comandas
                        WHERE mesa_id = $1
                        AND LOWER(status) = 'aberta'
                    `,
                    [mesa_id]
                );

                if (comRes.rows.length > 0) {
                    comanda_id = comRes.rows[0].id;
                }
            }

            if (comanda_id) {
                await client.query(
                    `
                        DELETE FROM comanda_pagamentos
                        WHERE comanda_id = $1
                    `,
                    [comanda_id]
                );

                await client.query(
                    `
                        DELETE FROM comanda_itens
                        WHERE comanda_id = $1
                    `,
                    [comanda_id]
                );

                await client.query(
                    'DELETE FROM comandas WHERE id = $1',
                    [comanda_id]
                );
            }

            if (mesa_id) {
                await client.query(
                    `
                        UPDATE mesas
                        SET
                            status = $1,
                            chamando_garcom = FALSE,
                            token_sessao = NULL
                        WHERE id = $2
                    `,
                    ['livre', mesa_id]
                );
            }

            await client.query('COMMIT');

            atualizarPainel();

            return res.json({
                success: true,
                message: 'Mesa cancelada.'
            });
        } catch (error) {
            if (client) await client.query('ROLLBACK');

            return res.status(500).json({
                error: 'Erro ao cancelar'
            });
        } finally {
            if (client) client.release();
        }
    }
);

// ==========================================
// ADICIONAR ITENS PELO PAINEL
// ==========================================
app.post(
    '/api/admin/mesa/adicionar-itens',
    verifyAdminToken,
    async (req, res) => {
        const { mesa_id, cart } = req.body;
        let client;

        try {
            client = await pool.connect();
            await client.query('BEGIN');

            const comandaRes = await client.query(
                `
                    SELECT id
                    FROM comandas
                    WHERE mesa_id = $1
                    AND LOWER(status) = 'aberta'
                `,
                [mesa_id]
            );

            let comanda_id;

            if (comandaRes.rows.length === 0) {
                const codigo =
                    `#${Math.floor(100 + Math.random() * 900)}`;

                const novaComanda = await client.query(
                    `
                        INSERT INTO comandas (
                            codigo,
                            mesa_id,
                            status
                        )
                        VALUES ($1, $2, $3)
                        RETURNING id
                    `,
                    [codigo, mesa_id, 'aberta']
                );

                comanda_id = novaComanda.rows[0].id;

                await client.query(
                    'UPDATE mesas SET status = $1 WHERE id = $2',
                    ['ocupada', mesa_id]
                );
            } else {
                comanda_id = comandaRes.rows[0].id;
            }

            for (const item of cart) {
                await client.query(
                    `
                        INSERT INTO comanda_itens (
                            comanda_id,
                            item_id_cache,
                            nome_item,
                            quantidade,
                            preco_unitario,
                            observacoes
                        )
                        VALUES ($1, $2, $3, $4, $5, $6)
                    `,
                    [
                        comanda_id,
                        item.dishId || 'item',
                        item.name,
                        item.quantity,
                        item.unitPrice,
                        item.notes || ''
                    ]
                );
            }

            await client.query('COMMIT');

            atualizarPainel();

            return res.json({
                success: true
            });
        } catch (error) {
            if (client) await client.query('ROLLBACK');

            return res.status(500).json({
                error: 'Erro ao adicionar'
            });
        } finally {
            if (client) client.release();
        }
    }
);

// ==========================================
// REMOVER ITEM DA COMANDA
// ==========================================
app.delete(
    '/api/admin/comanda-item/:id',
    verifyAdminToken,
    async (req, res) => {
        try {
            await pool.query(
                'DELETE FROM comanda_itens WHERE id = $1',
                [req.params.id]
            );

            atualizarPainel();

            return res.json({
                success: true
            });
        } catch (error) {
            return res.status(500).json({
                error: 'Erro ao apagar'
            });
        }
    }
);

// ==========================================
// HISTÓRICO
// ==========================================
app.get('/api/historico', verifyAdminToken, async (req, res) => {
    const { filtro } = req.query;

    try {
        let query = `
            SELECT
                c.id,
                c.codigo,
                c.status,
                c.data_abertura,
                c.data_fechamento,
                c.forma_pagamento,
                c.valor_total_final,
                COALESCE(m.numero, '0') AS mesa_numero,
                COALESCE(
                    (
                        SELECT json_agg(
                            json_build_object(
                                'nome_item', ci.nome_item,
                                'quantidade', ci.quantidade,
                                'preco_unitario', ci.preco_unitario,
                                'observacoes', ci.observacoes
                            )
                        )
                        FROM comanda_itens ci
                        WHERE ci.comanda_id = c.id
                    ),
                    '[]'::json
                ) AS items
            FROM comandas c
            LEFT JOIN mesas m ON c.mesa_id = m.id
            WHERE (
                LOWER(c.status) = 'fechada'
                OR c.data_fechamento IS NOT NULL
            )
        `;

        if (filtro === 'dia') {
            query += `
                AND c.data_fechamento >= NOW() - INTERVAL '1 day'
            `;
        } else if (filtro === 'semana') {
            query += `
                AND c.data_fechamento >= NOW() - INTERVAL '7 days'
            `;
        } else if (filtro === 'mes') {
            query += `
                AND c.data_fechamento >= NOW() - INTERVAL '30 days'
            `;
        }

        query += `
            ORDER BY c.data_fechamento DESC
            LIMIT 150
        `;

        const result = await pool.query(query);

        return res.json(result.rows);
    } catch (error) {
        return res.status(500).json({
            error: 'Erro no histórico'
        });
    }
});

// ==========================================
// ESTATÍSTICAS
// ==========================================
app.get('/api/estatisticas', verifyAdminToken, async (req, res) => {
    try {
        const fatDia = pool.query(`
            SELECT SUM(valor_total_final) AS total
            FROM comandas
            WHERE (
                LOWER(status) = 'fechada'
                OR data_fechamento IS NOT NULL
            )
            AND data_fechamento >= NOW() - INTERVAL '1 day'
        `);

        const fatSemana = pool.query(`
            SELECT SUM(valor_total_final) AS total
            FROM comandas
            WHERE (
                LOWER(status) = 'fechada'
                OR data_fechamento IS NOT NULL
            )
            AND data_fechamento >= NOW() - INTERVAL '7 days'
        `);

        const fatMes = pool.query(`
            SELECT SUM(valor_total_final) AS total
            FROM comandas
            WHERE (
                LOWER(status) = 'fechada'
                OR data_fechamento IS NOT NULL
            )
            AND data_fechamento >= NOW() - INTERVAL '30 days'
        `);

        const mediasQry = pool.query(`
            SELECT
                COALESCE(
                    SUM(valor_total_final) /
                    NULLIF(
                        COUNT(
                            DISTINCT DATE_TRUNC(
                                'day',
                                data_fechamento
                            )
                        ),
                        0
                    ),
                    0
                ) AS media_dia,
                COALESCE(
                    SUM(valor_total_final) /
                    NULLIF(
                        COUNT(
                            DISTINCT DATE_TRUNC(
                                'week',
                                data_fechamento
                            )
                        ),
                        0
                    ),
                    0
                ) AS media_semana,
                COALESCE(
                    SUM(valor_total_final) /
                    NULLIF(
                        COUNT(
                            DISTINCT DATE_TRUNC(
                                'month',
                                data_fechamento
                            )
                        ),
                        0
                    ),
                    0
                ) AS media_mes
            FROM comandas
            WHERE (
                LOWER(status) = 'fechada'
                OR data_fechamento IS NOT NULL
            )
        `);

        const itensVendidos = pool.query(`
            SELECT
                ci.nome_item,
                SUM(ci.quantidade) AS total_qtd
            FROM comanda_itens ci
            JOIN comandas c ON ci.comanda_id = c.id
            WHERE (
                LOWER(c.status) = 'fechada'
                OR c.data_fechamento IS NOT NULL
            )
            GROUP BY ci.nome_item
            ORDER BY total_qtd DESC
        `);

        const [
            rFatDia,
            rFatSemana,
            rFatMes,
            rMedias,
            rItens
        ] = await Promise.all([
            fatDia,
            fatSemana,
            fatMes,
            mediasQry,
            itensVendidos
        ]);

        return res.json({
            faturamento: {
                dia: rFatDia.rows[0]?.total || 0,
                semana: rFatSemana.rows[0]?.total || 0,
                mes: rFatMes.rows[0]?.total || 0
            },
            medias: {
                dia: rMedias.rows[0]?.media_dia || 0,
                semana: rMedias.rows[0]?.media_semana || 0,
                mes: rMedias.rows[0]?.media_mes || 0
            },
            itens: rItens.rows || []
        });
    } catch (error) {
        console.error('Erro nas estatísticas:', error);

        return res.status(500).json({
            error: 'Erro nas estatísticas'
        });
    }
});

// ==========================================
// DELIVERY: CRIAÇÃO AUTOMÁTICA DA TABELA
// ==========================================
// Guarda os dados preenchidos no formulário do cardápio,
// os itens do pedido e a etapa atual do atendimento.
const deliveryDBReady = pool.query(`
    CREATE TABLE IF NOT EXISTS pedidos_delivery (
        id SERIAL PRIMARY KEY,

        cliente JSONB NOT NULL,
        cliente_nome TEXT NOT NULL,
        endereco TEXT NOT NULL,

        itens JSONB NOT NULL,

        valor_total NUMERIC(12,2) NOT NULL
            CHECK (valor_total >= 0),

        origem TEXT NOT NULL
            DEFAULT 'WHATSAPP_DELIVERY',

        status TEXT NOT NULL DEFAULT 'novo'
            CHECK (
                status IN (
                    'novo',
                    'preparo',
                    'caminho',
                    'entregue'
                )
            ),

        data_criacao TIMESTAMPTZ NOT NULL
            DEFAULT NOW(),

        data_atualizacao TIMESTAMPTZ NOT NULL
            DEFAULT NOW()
    )
`).then(() => {
    return true;
}).catch(error => {
    console.error(
        'Erro ao inicializar tabela de delivery:',
        error
    );

    return false;
});

async function verificarDeliveryDB() {
    if (!await deliveryDBReady) {
        throw new Error(
            'Tabela de delivery indisponível'
        );
    }
}

// ==========================================
// DELIVERY: RECEBER NOVO PEDIDO
// ==========================================
app.post('/api/delivery/novo', async (req, res) => {
    const { cliente, itens, origem } = req.body || {};

    if (
        !cliente ||
        typeof cliente.nome !== 'string' ||
        !cliente.nome.trim() ||
        !Array.isArray(itens) ||
        itens.length === 0 ||
        itens.some(item =>
            !item ||
            !Number.isInteger(item.quantity) ||
            item.quantity <= 0 ||
            typeof item.unitPrice !== 'number' ||
            !Number.isFinite(item.unitPrice) ||
            item.unitPrice < 0
        )
    ) {
        return res.status(400).json({
            error: 'Informe o cliente e um carrinho válido.'
        });
    }

    // Calcula o total em centavos para evitar diferenças
    // de arredondamento ao somar os itens.
    const totalCentavos = itens.reduce(
        (total, item) =>
            total +
            Math.round(item.unitPrice * 100) * item.quantity,
        0
    );

    if (
        !Number.isSafeInteger(totalCentavos) ||
        totalCentavos > 999999999999
    ) {
        return res.status(400).json({
            error: 'Valor do pedido inválido.'
        });
    }

    // Endereço montado com os campos preenchidos pelo cliente.
    const endereco = [
        [cliente.rua, cliente.numero]
            .filter(Boolean)
            .join(', '),
        cliente.bairro,
        cliente.complemento
    ].filter(Boolean).join(' - ');

    try {
        await verificarDeliveryDB();

        const resultado = await pool.query(
            `
                INSERT INTO pedidos_delivery (
                    cliente,
                    cliente_nome,
                    endereco,
                    itens,
                    valor_total,
                    origem,
                    status
                )
                VALUES (
                    $1::jsonb,
                    $2,
                    $3,
                    $4::jsonb,
                    $5,
                    $6,
                    'novo'
                )
                RETURNING id, status
            `,
            [
                JSON.stringify(cliente),
                cliente.nome.trim(),
                endereco,
                JSON.stringify(itens),
                totalCentavos / 100,
                typeof origem === 'string' && origem.trim()
                    ? origem.trim()
                    : 'WHATSAPP_DELIVERY'
            ]
        );

        // Só confirma e notifica depois de salvar o pedido.
        io.emit('atualizacao_delivery');

        return res.status(201).json({
            sucesso: true,
            pedido: resultado.rows[0]
        });
    } catch (error) {
        console.error(
            'Erro ao salvar delivery:',
            error
        );

        return res.status(500).json({
            error: 'Não foi possível salvar o pedido.'
        });
    }
});

// ==========================================
// DELIVERY: LISTAR PEDIDOS ATIVOS
// ==========================================
// O objeto "cliente" inclui nome, telefone, endereço
// separado por campos e método de pagamento informado.
// Os itens incluem nome, quantidade, preço e observações.
app.get(
    '/api/delivery/listar',
    verifyAdminToken,
    async (req, res) => {
        try {
            await verificarDeliveryDB();

            const resultado = await pool.query(`
                SELECT
                    id,
                    cliente,
                    cliente_nome,
                    endereco,
                    itens,
                    valor_total,
                    origem,
                    status,
                    data_criacao
                FROM pedidos_delivery
                WHERE status IN (
                    'novo',
                    'preparo',
                    'caminho'
                )
                ORDER BY data_criacao ASC, id ASC
            `);

            return res.json(resultado.rows);
        } catch (error) {
            console.error(
                'Erro ao listar delivery:',
                error
            );

            return res.status(500).json({
                error: 'Não foi possível carregar os pedidos.'
            });
        }
    }
);

// ==========================================
// DELIVERY: ATUALIZAR ETAPA
// ==========================================
// Fluxo permitido:
// novo -> preparo -> caminho -> entregue
app.post(
    '/api/delivery/status',
    verifyAdminToken,
    async (req, res) => {
        const { id, status } = req.body || {};

        const anterior = {
            preparo: 'novo',
            caminho: 'preparo',
            entregue: 'caminho'
        };

        if (
            !Number.isSafeInteger(id) ||
            id <= 0 ||
            !Object.hasOwn(anterior, status)
        ) {
            return res.status(400).json({
                error: 'Pedido ou status inválido.'
            });
        }

        try {
            await verificarDeliveryDB();

            const resultado = await pool.query(
                `
                    UPDATE pedidos_delivery
                    SET
                        status = $1,
                        data_atualizacao = NOW()
                    WHERE id = $2
                    AND status = $3
                    RETURNING id, status
                `,
                [status, id, anterior[status]]
            );

            if (!resultado.rows.length) {
                return res.status(409).json({
                    error:
                        'Pedido não encontrado ou já mudou de status. Atualize a lista.'
                });
            }

            io.emit('atualizacao_delivery');

            return res.json({
                sucesso: true,
                pedido: resultado.rows[0]
            });
        } catch (error) {
            console.error(
                'Erro ao atualizar delivery:',
                error
            );

            return res.status(500).json({
                error: 'Não foi possível atualizar o pedido.'
            });
        }
    }
);

// ==========================================
// INICIAR SERVIDOR
// ==========================================
const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
    console.log(
        `Servidor rodando protegido na porta ${PORT}`
    );
});
