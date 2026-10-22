const crypto = require('crypto');
process.env.CTT_SHEETS_SYNC_ENABLED = 'false';
const app = require('./server');
const pool = require('./database');

async function main() {
    const nome = `TESTE OPERADOR ${Date.now()}`;
    const nomeResponsavel = `TESTE RESPONSAVEL ${Date.now()}`;
    const prefixo = `OPDIA${Date.now().toString().slice(-8)}`;
    const senha = 'Ab#1';
    let re, id, reResponsavel, responsavelId, viaturaId, server;
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
        for (let tentativa = 0; tentativa < 20 && !responsavelId; tentativa++) {
            reResponsavel = String(700000 + crypto.randomInt(100000));
            try {
                responsavelId = (await pool.query(`INSERT INTO usuarios (nome,cargo,re,setor,senha_hash)
                    VALUES ($1,$2,$2,'2° CIA',NULL) RETURNING id`, [nomeResponsavel, reResponsavel])).rows[0].id;
            } catch (e) {
                if (e?.code !== '23505') throw e;
            }
        }
        if (!responsavelId) throw new Error('Não foi possível criar o responsável temporário');
        viaturaId = (await pool.query(`INSERT INTO viaturas (prefixo,placa,modelo,km,km_revisao,status,ultimo_usuario,motivo,setor)
            VALUES ($1,'DIA-0001','MODELO TESTE',100,5000,'Operante','Teste','','CTT') RETURNING id`, [prefixo])).rows[0].id;
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
        if (!sessaoRes.ok || sessao.nome !== nome || sessao.re !== re || sessao.setor !== 'CTT' || sessao.servico_dia !== false) throw new Error('Identidade da sessão operacional incorreta');
        const usuarios = await fetch(base+'/api/usuarios',{headers:{cookie:loginCookie}});
        if (usuarios.status !== 403) throw new Error(`Operador acessou lista administrativa: ${usuarios.status}`);
        const listaBloqueada = await fetch(base+'/api/operacional/responsaveis',{headers:{cookie:loginCookie}});
        if (listaBloqueada.status !== 403) throw new Error(`Operador comum acessou responsáveis: ${listaBloqueada.status}`);
        const tentativaDelegada = await fetch(base+`/api/operacional/viaturas/${viaturaId}`,{method:'PUT',headers:{'Content-Type':'application/json',cookie:loginCookie},body:JSON.stringify({km:101,baixa:false,motivo:'',categoria_baixa:null,responsavel_id:responsavelId})});
        if (tentativaDelegada.status !== 403) throw new Error(`Operador comum lançou por terceiro: ${tentativaDelegada.status}`);

        await pool.query('UPDATE usuarios SET servico_dia=TRUE WHERE id=$1',[id]);
        const loginServico = await chamar('/api/login', { tipo:'oper', re, senha });
        if (!loginServico.ok) throw new Error(`Login de serviço de dia falhou: ${loginServico.status}`);
        const cookieServico = loginServico.headers.get('set-cookie')?.split(';')[0];
        const sessaoServicoRes = await fetch(base+'/api/session',{headers:{cookie:cookieServico}}), sessaoServico=await sessaoServicoRes.json();
        if (!sessaoServicoRes.ok || sessaoServico.servico_dia !== true) throw new Error('Permissão de serviço de dia não entrou na nova sessão');
        const listaRes = await fetch(base+'/api/operacional/responsaveis',{headers:{cookie:cookieServico}}), lista=await listaRes.json();
        if (!listaRes.ok || !lista.some(p=>p.id===responsavelId && p.re===reResponsavel)) throw new Error('Serviço de dia não recebeu policial cadastrado em outra subunidade');
        const lancamento = await fetch(base+`/api/operacional/viaturas/${viaturaId}`,{method:'PUT',headers:{'Content-Type':'application/json',cookie:cookieServico},body:JSON.stringify({km:101,baixa:false,motivo:'',categoria_baixa:null,responsavel_id:responsavelId})});
        if (!lancamento.ok) throw new Error(`Lançamento de serviço de dia falhou: ${lancamento.status}`);
        const registro = (await pool.query('SELECT usuario,autor_conta FROM historico WHERE prefixo=$1 ORDER BY id DESC LIMIT 1',[prefixo])).rows[0];
        if (!registro?.usuario?.includes(reResponsavel) || !registro?.autor_conta?.includes(re)) throw new Error('Histórico não registrou responsável e lançador separadamente');
        const hash = (await pool.query('SELECT senha_hash FROM usuarios WHERE id=$1',[id])).rows[0]?.senha_hash;
        if (!hash?.startsWith('scrypt$') || hash.includes(senha)) throw new Error('Senha operacional não foi armazenada corretamente como hash');
        console.log('Teste de operadores concluído: login individual, bloqueio comum, serviço de dia entre subunidades e histórico duplo validados.');
    } finally {
        if (server) await new Promise(resolve=>server.close(resolve));
        await pool.query('DELETE FROM historico WHERE prefixo=$1',[prefixo]).catch(()=>{});
        if (viaturaId) await pool.query('DELETE FROM viaturas WHERE id=$1',[viaturaId]).catch(()=>{});
        if (responsavelId) await pool.query('DELETE FROM usuarios WHERE id=$1',[responsavelId]).catch(()=>{});
        if (id) await pool.query('DELETE FROM usuarios WHERE id=$1',[id]).catch(()=>{});
        await pool.end();
    }
}

main().catch(error=>{console.error('Falha no teste de operadores:',error.message);process.exitCode=1;});
