const crypto = require('crypto');
process.env.CTT_SHEETS_SYNC_ENABLED = 'false';
const app = require('./server');
const pool = require('./database');
const { hashPassword } = require('./auth');

async function main() {
    const sufixo = Date.now().toString().slice(-8);
    const usuario = `TESTE${sufixo}`;
    const senha = `Teste-${crypto.randomBytes(8).toString('hex')}9`;
    const prefixoProprio = `AUTHEM${sufixo}`;
    const prefixoCriado = `AUTHNOVO${sufixo}`;
    const usuarioProprio = `Militar Teste EM ${sufixo}`;
    const usuarioOutro = `Militar Teste CTT ${sufixo}`;
    let server;
    try {
        const senhaHash = await hashPassword(senha);
        await pool.query(`INSERT INTO administradores (usuario,nome,setor,papel,senha_hash,ativo,trocar_senha)
            VALUES ($1,'Conta de teste automatizado','EM','admin',$2,TRUE,TRUE)`, [usuario, senhaHash]);
        await pool.query(`INSERT INTO viaturas (prefixo,placa,modelo,km,km_revisao,status,ultimo_usuario,motivo,setor)
            VALUES ($1,'TST-0001','MODELO TESTE',100,5000,'Operante','Teste','','EM')`, [prefixoProprio]);
        await pool.query(`INSERT INTO usuarios (nome,cargo,setor) VALUES ($1,'TESTE','CTT')`, [usuarioOutro]);

        server = await new Promise((resolve, reject) => { const s=app.listen(0,'127.0.0.1',()=>resolve(s)); s.on('error',reject); });
        const base = `http://127.0.0.1:${server.address().port}`;
        const login = await fetch(base+'/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tipo:'admin',usuario,senha})});
        if(!login.ok) throw new Error(`Login da conta de teste falhou: ${login.status}`);
        const loginBody = await login.json();
        if(loginBody.redirect!=='trocar-senha.html') throw new Error('Primeiro acesso não exigiu troca de senha');
        let cookie = login.headers.get('set-cookie')?.split(';')[0];
        let headers = {'Content-Type':'application/json',cookie};

        const bloqueadoAntesDaTroca=await fetch(base+'/api/viaturas',{method:'POST',headers,body:JSON.stringify({prefixo:'NAOCRIAR',placa:'TST-9999',modelo:'TESTE',km:0,km_revisao:5000,status:'Operante',setor:'EM'})});
        if(bloqueadoAntesDaTroca.status!==428) throw new Error(`Senha temporária permitiu alteração: ${bloqueadoAntesDaTroca.status}`);
        const novaSenha=`Nova-${crypto.randomBytes(8).toString('hex')}8`;
        const troca=await fetch(base+'/api/minha-senha',{method:'POST',headers,body:JSON.stringify({senha_atual:senha,nova_senha:novaSenha})});
        if(!troca.ok) throw new Error(`Troca obrigatória de senha falhou: ${troca.status}`);
        const loginAntigo=await fetch(base+'/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tipo:'admin',usuario,senha})});
        if(loginAntigo.status!==401) throw new Error('Senha temporária continuou válida após a troca');
        const novoLogin=await fetch(base+'/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tipo:'admin',usuario,senha:novaSenha})});
        const novoBody=await novoLogin.json();
        if(!novoLogin.ok||novoBody.redirect!=='index.html') throw new Error('Nova senha não autenticou diretamente no dashboard');
        cookie=novoLogin.headers.get('set-cookie')?.split(';')[0];
        headers={'Content-Type':'application/json',cookie};

        const paginaAdministradores=await fetch(base+'/administradores.html',{headers:{cookie},redirect:'manual'});
        if(paginaAdministradores.status!==303 || paginaAdministradores.headers.get('location')!=='/index.html?aviso=administradores')
            throw new Error('A página de administradores não redirecionou o administrador comum para o aviso do painel');

        const frotaRes = await fetch(base+'/api/viaturas',{headers:{cookie}}), frota=await frotaRes.json();
        if(!frotaRes.ok || !frota.some(v=>v.setor!=='EM')) throw new Error('A conta EM não conseguiu visualizar outras subunidades');
        const propria=frota.find(v=>v.prefixo===prefixoProprio), outra=frota.find(v=>v.setor!=='EM');
        if(!propria||!outra) throw new Error('Viaturas de teste/referência não encontradas');

        const proibido=await fetch(base+`/api/viaturas/${outra.id}`,{method:'PUT',headers,body:JSON.stringify({km:outra.km,km_revisao:outra.km_revisao,status:outra.status,setor:outra.setor})});
        if(proibido.status!==403) throw new Error(`Alteração de outra subunidade retornou ${proibido.status}, esperado 403`);

        const permitido=await fetch(base+`/api/viaturas/${propria.id}`,{method:'PUT',headers,body:JSON.stringify({km:101,km_revisao:5000,status:'Operante',setor:'EM'})});
        if(!permitido.ok) throw new Error(`Alteração da própria subunidade falhou: ${permitido.status}`);

        const antes91=await fetch(base+`/api/operacional/viaturas/${propria.id}`,{method:'PUT',headers,body:JSON.stringify({km:4524,ultimo_usuario:'Teste 91%',baixa:false})});
        if(!antes91.ok) throw new Error(`Atualização antes de 91% falhou: ${antes91.status}`);
        let status91=(await pool.query('SELECT status FROM viaturas WHERE id=$1',[propria.id])).rows[0]?.status;
        if(status91!=='Operante') throw new Error(`Status antes de 91% incorreto: ${status91}`);
        const em91=await fetch(base+`/api/operacional/viaturas/${propria.id}`,{method:'PUT',headers,body:JSON.stringify({km:4525,ultimo_usuario:'Teste 91%',baixa:false})});
        if(!em91.ok) throw new Error(`Atualização em 91% falhou: ${em91.status}`);
        status91=(await pool.query('SELECT status FROM viaturas WHERE id=$1',[propria.id])).rows[0]?.status;
        if(status91!=='Troca de Óleo') throw new Error(`Status em 91% incorreto: ${status91}`);
        await pool.query("UPDATE viaturas SET status='Operante' WHERE id=$1",[propria.id]);
        const listaRecalculada=await fetch(base+'/api/viaturas',{headers:{cookie}}), dadosRecalculados=await listaRecalculada.json();
        if(!listaRecalculada.ok||dadosRecalculados.find(v=>v.id===propria.id)?.status!=='Troca de Óleo')
            throw new Error('A listagem não corrigiu uma viatura antiga que já estava em 91%');

        const criar=await fetch(base+'/api/viaturas',{method:'POST',headers,body:JSON.stringify({prefixo:prefixoCriado,placa:'TST-0002',modelo:'BMW F 850 GS',km:2715,km_revisao:3000,status:'Operante',setor:'CTT'})});
        if(!criar.ok) throw new Error(`Criação de viatura falhou: ${criar.status}`);
        const criada=(await pool.query('SELECT id,setor,status FROM viaturas WHERE prefixo=$1',[prefixoCriado])).rows[0];
        if(!criada||criada.setor!=='EM') throw new Error('Servidor não forçou a subunidade EM na criação');
        if(criada.status!=='Troca de Óleo') throw new Error(`BMW em 91% ficou com status incorreto: ${criada.status}`);

        const criarUsuario=await fetch(base+'/api/usuarios',{method:'POST',headers,body:JSON.stringify({nome:usuarioProprio,cargo:'TESTE',setor:'CTT'})});
        if(!criarUsuario.ok) throw new Error(`Criação de militar falhou: ${criarUsuario.status}`);
        const militar=(await pool.query('SELECT id,setor FROM usuarios WHERE nome=$1',[usuarioProprio])).rows[0];
        if(!militar||militar.setor!=='EM') throw new Error('Servidor não forçou a subunidade EM no militar');
        const outroMilitar=(await pool.query('SELECT id FROM usuarios WHERE nome=$1',[usuarioOutro])).rows[0];
        const excluirOutro=await fetch(base+`/api/usuarios/${outroMilitar.id}`,{method:'DELETE',headers:{cookie}});
        if(excluirOutro.status!==404) throw new Error(`Exclusão de militar de outra subunidade retornou ${excluirOutro.status}, esperado 404`);
        const excluirProprio=await fetch(base+`/api/usuarios/${militar.id}`,{method:'DELETE',headers:{cookie}});
        if(!excluirProprio.ok) throw new Error('Exclusão do militar da própria subunidade falhou');

        const admins=await fetch(base+'/api/administradores',{headers:{cookie}});
        if(admins.status!==403) throw new Error(`Gestão de administradores retornou ${admins.status}, esperado 403`);
        console.log('Teste concluído: troca obrigatória validada; status de troca de óleo ativado quando a barra entra em 91% nos ciclos de 5.000 e 3.000 km; leitura global permitida; escrita limitada à subunidade; criação forçada no setor; gestão de contas bloqueada para admin comum.');
    } finally {
        if(server) await new Promise(resolve=>server.close(resolve));
        await pool.query('DELETE FROM historico WHERE prefixo IN ($1,$2)',[prefixoProprio,prefixoCriado]).catch(()=>{});
        await pool.query('DELETE FROM viaturas WHERE prefixo IN ($1,$2)',[prefixoProprio,prefixoCriado]).catch(()=>{});
        await pool.query('DELETE FROM usuarios WHERE nome IN ($1,$2)',[usuarioProprio,usuarioOutro]).catch(()=>{});
        await pool.query('DELETE FROM administradores WHERE usuario=$1',[usuario]).catch(()=>{});
        const restos = (await pool.query(`SELECT
            (SELECT count(*) FROM administradores WHERE usuario=$1)::int AS administradores,
            (SELECT count(*) FROM viaturas WHERE prefixo IN ($2,$3))::int AS viaturas,
            (SELECT count(*) FROM usuarios WHERE nome IN ($4,$5))::int AS usuarios,
            (SELECT count(*) FROM historico WHERE prefixo IN ($2,$3))::int AS historico`,
            [usuario,prefixoProprio,prefixoCriado,usuarioProprio,usuarioOutro])).rows[0];
        if (Object.values(restos).some(Number)) throw new Error(`Limpeza incompleta: ${JSON.stringify(restos)}`);
        console.log('Limpeza verificada: nenhum registro temporário permaneceu no banco.');
        await pool.end();
    }
}

main().catch(error=>{console.error('Falha no teste de permissões:',error.message);process.exitCode=1;});

