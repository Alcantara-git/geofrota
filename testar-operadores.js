const crypto = require('crypto');
process.env.CTT_SHEETS_SYNC_ENABLED = 'false';
const app = require('./server');
const pool = require('./database');

async function main() {
    const nome = `TESTE OPERADOR ${Date.now()}`;
    const senha = 'Ab#1';
    let re, id, server;
    try {
        for (let tentativa = 0; tentativa < 20 && !id; tentativa++) {
            re = String(900000 + crypto.randomInt(100000));
            try {
                id = (await pool.query(`INSERT INTO usuarios (nome,cargo,re,setor,senha_hash)
                    VALUES ($1,$2,$2,'CTT',NULL) RETURNING id`, [nome, re])).rows[0].id;
            } catch (e) {
                if (e?.code !== '23505') throw e;
            }
        }
        if (!id) throw new Error('Não foi possível reservar um RE temporário');
        server = await new Promise((resolve, reject) => { const s=app.listen(0,'127.0.0.1',()=>resolve(s)); s.on('error',reject); });
        const base = `http://127.0.0.1:${server.address().port}`;
        const chamar = (rota, body, cookie) => fetch(base + rota, { method:'POST', headers:{'Content-Type':'application/json',...(cookie?{cookie}:{})}, body:JSON.stringify(body) });

        const formatoInvalido = await chamar('/api/operadores/primeiro-acesso', { re:'12345', senha });
        if (formatoInvalido.status !== 400) throw new Error(`RE inválido retornou ${formatoInvalido.status}`);
        const primeiro = await chamar('/api/operadores/primeiro-acesso', { re, senha });
        if (!primeiro.ok) throw new Error(`Primeiro acesso falhou: ${primeiro.status}`);
        const cookie = primeiro.headers.get('set-cookie')?.split(';')[0];
        if (!cookie) throw new Error('Cookie do operador não foi criado');
        const repetido = await chamar('/api/operadores/primeiro-acesso', { re, senha });
        if (repetido.status !== 409) throw new Error(`Primeiro acesso repetido retornou ${repetido.status}`);
        const incorreto = await chamar('/api/login', { tipo:'oper', re, senha:'Err0' });
        if (incorreto.status !== 401) throw new Error(`Senha incorreta retornou ${incorreto.status}`);
        const login = await chamar('/api/login', { tipo:'oper', re, senha });
        if (!login.ok) throw new Error(`Login correto falhou: ${login.status}`);
        const loginCookie = login.headers.get('set-cookie')?.split(';')[0];
        const sessaoRes = await fetch(base+'/api/session',{headers:{cookie:loginCookie}}), sessao=await sessaoRes.json();
        if (!sessaoRes.ok || sessao.nome !== nome || sessao.re !== re || sessao.setor !== 'CTT') throw new Error('Identidade da sessão operacional incorreta');
        const usuarios = await fetch(base+'/api/usuarios',{headers:{cookie:loginCookie}});
        if (usuarios.status !== 403) throw new Error(`Operador acessou lista administrativa: ${usuarios.status}`);
        const hash = (await pool.query('SELECT senha_hash FROM usuarios WHERE id=$1',[id])).rows[0]?.senha_hash;
        if (!hash?.startsWith('scrypt$') || hash.includes(senha)) throw new Error('Senha operacional não foi armazenada corretamente como hash');
        console.log('Teste de operadores concluído: primeiro acesso, hash, login, sessão individual e bloqueio administrativo validados.');
    } finally {
        if (server) await new Promise(resolve=>server.close(resolve));
        if (id) await pool.query('DELETE FROM usuarios WHERE id=$1',[id]).catch(()=>{});
        await pool.end();
    }
}

main().catch(error=>{console.error('Falha no teste de operadores:',error.message);process.exitCode=1;});
