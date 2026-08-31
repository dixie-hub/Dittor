# Dittor — Resultados dos Testes e Experiências

Registo cumulativo dos resultados das 6 categorias de teste definidas para a secção
"Testes e Experiências" da tese. Dados em bruto em `raw/*.csv`; este ficheiro tem os
resumos/estatísticas para transcrição direta.

**Ambiente:** Windows 11 + WSL2 (Ubuntu), Java (mclwrap/BLS12-381, sem biblioteca MCL
nativa compilada — usa o binário pré-compilado "maximum-compatibility", pelo que os
tempos aqui são um limite superior; podem melhorar com a MCL compilada localmente).

---

## Categoria 1 — Rejeição de prova inválida

### Teste 1.1 — Nível Bridge (payload corrompido enviado direto ao `DAServer`)

**Metodologia:** payload válido gerado por um registo real (nó `000a`, fluxo Babel
completo), depois o campo `dleqResponse` (índice 7 do payload pipe-delimited)
corrompido num único dígito hex via `PayloadCorruptor` (dígito `4`→`5` na posição 68
do campo). Enviado 30 vezes ao `DAServer` (porta 8081) via `BridgeTestClient`, com o
`Main`/DA/3 CAs já a correr (DKG completo antes do teste).

**Resultado:** 30/30 execuções devolveram `INVALID` — 100% de deteção da prova
corrompida, zero falsos positivos (nenhum `VALID` incorreto).

**Latência (ms), N=30:**

| Estatística | Valor |
|---|---|
| Média | 17,88 ms |
| Mediana | 16,78 ms |
| Mínimo | 15,35 ms |
| Máximo | 34,18 ms |
| Média sem outliers (excl. as 2 execuções a 34,18ms) | 16,71 ms |

As duas execuções a 34,18ms (corridas #1 e #25) destoam claramente das restantes 28
(que ficam todas entre 15,35 e 18,82ms) — provavelmente efeito de warm-up de JIT/JVM
na primeira ligação de cada `mvn exec:java` novo (a corrida #25 coincide com o início
de um novo lote dentro da mesma execução do cliente, o que sugere um GC pause pontual
em vez de warm-up puro — vale a pena voltar a correr com mais repetições para
confirmar se este segundo pico se repete). Dados em bruto:
`raw/1.1_bridge_invalid_proof.csv`.

### Teste 1.2 — Nível Completo (Chutney real)

**Setup:** topologia `networks/basic-min` (autoridades `000a`/`001a` + relay `002r`,
apesar do nome só precisamos do `000a` para este teste), 3 CAs (`CAMain`) + `Main.java`
a correr em processos WSL separados, item 9 (imposição real em `routerparse.c`) já
aplicado e compilado no binário `tor` usado pelo Chutney. `DITTOR_NODES='000a'` (só
este nó, para isolar o resultado de ruído de outros nós).

**Nota de metodologia — correção de índice de campo:** o `dittor_proof.txt` tem a
palavra-chave literal `dittor-proof` como primeiro token (delimitado por espaço),
o que desloca todos os índices de campo em +1 relativamente ao `bridge_payload.txt`
(que começa logo em `context`). Índices corretos para `dittor_proof.txt`:
`0=dittor-proof(literal) 1=context 2=pk 3=nym 4=zkp 5=g1x 6=credential 7=dleqChallenge 8=dleqResponse`.
Isto é diferente da tabela documentada no cabeçalho do `PayloadCorruptor.java`, que
assume o formato do `bridge_payload.txt` (sem o prefixo `dittor-proof`).

**Bug encontrado e corrigido no `PayloadCorruptor.java`:** a função `flipHexDigit`
não tratava o caso `9→a` (só tratava `f→0`), pelo que corromper um dígito `9`
produzia `:` (ASCII seguinte a `9`), inválido em hex. Corrigido adicionando o caso
`lower == '9' → 'a'`.

#### Teste 1.2a — Payload malformado (encontrado antes da correção do bug acima)

**Metodologia (não intencional):** corrupção do campo 6 (então pensado ser
`dleqChallenge`, na realidade `credential` — ver nota de índice acima) resultou,
devido ao bug do `flipHexDigit`, num caracter `:` inválido em hex inserido no meio
da string JSON do campo.

**Resultado:** o `DAServer` não conseguiu desserializar o campo e lançou
`NumberFormatException: For input string: "4c8be9:" under radix 16` em
`JSONConverter.deserializeBigInteger` (chamado a partir de `DAServer.java:82`). A
exceção foi apanhada sem crashar o servidor (`[DA-Server] Pseudonym rejected`
seguido de recuperação normal, continuou a servir pedidos seguintes). O Tor real
recebeu `INVALID` e rejeitou o descriptor (`Rejecting descriptor` em
`notice.log`).

**Interpretação:** confirma robustez extra — mesmo um payload malformado (não só
semanticamente errado mas sintaticamente inválido) é tratado de forma segura,
sem crashar o `DAServer`, e continua a resultar em rejeição correta do lado Tor.

#### Teste 1.2b — Payload semanticamente inválido, bem formado (`dleqChallenge` corrompido, índice correto)

**Metodologia:** payload válido gerado por um registo real (nó `000a`, fluxo Babel
completo via `Main.java`), campo `dleqChallenge` (índice **7**, delimitador espaço)
corrompido num único dígito hex válido (`7→8`, posição 67) via `PayloadCorruptor`
(já com o bug do wraparound corrigido). O Tor real reinjeta o `dittor_proof.txt`
periodicamente (~a cada 60s, ou mais cedo — neste caso ~10s depois da corrupção) e
resubmete à bridge sem necessidade de reiniciar o Chutney.

**Resultado:**

```
[DA-Crypto] Running Dodis-Yampolskiy VRF validation checks...
[DA-Crypto] VRF Evaluation Outcome: PASS
[DA-Crypto] Verifying DLEQ credential linkage proof...
[DA-Crypto] DLEQ Eval Result: FAIL
[DA-Server] VRF Evaluation Outcome: PASS
[DA-Server] Credential Linkage Outcome: FAIL
[DA-Server] Pseudonym rejected
```

```
Aug 30 21:05:47.397 [warn] [Tor-Dittor] Verification REJECTED by backend for
'test000a'. Response: INVALID. Rejecting descriptor.
```

A confirmação cruzada com o `notice.log` mostra o valor corrompido já embutido na
linha do descriptor (`...c4e21538` em vez do original `...c4e21537`), provando que
foi mesmo o payload corrompido que a bridge avaliou.

**Interpretação:** demonstra o caminho ponta-a-ponta completo (Tor real →
`dittor_proxy.c` → `DAServer` → deteção específica da corrupção **na verificação
DLEQ**, não incidentalmente noutra verificação → `INVALID` → imposição real do
item 9 em `routerparse.c` → `goto err` → descriptor rejeitado). É o resultado mais
"limpo" para citar na tese como confirmação do item 9 + item 4 (ligação DLEQ)
combinados, via o caminho C real (não simulado).

**Achado bónus (não planeado, relevante para o teste 4.3):** em várias tentativas
anteriores a esta (antes da corrupção fazer efeito, com o payload ainda válido), o
`DAServer` rejeitou consistentemente por **colisão de pseudónimo**:
```
[DA] REJECTED: node <fingerprint real> reused a pseudonym without shared family ids
```
Isto acontece porque o `Main.java` regista o nó simulado (`000a`, string literal)
via Babel com um pseudónimo, e o mesmo ficheiro `dittor_proof.txt` é depois lido e
resubmetido pelo processo Tor real do mesmo nó, mas com o `nodeId` real (fingerprint
hex de 20 bytes), diferente da string `"000a"`. A DA trata-os como dois nós
diferentes a reivindicar o mesmo pseudónimo sem família partilhada — rejeição
correta. Confirmado com fingerprints diferentes em execuções diferentes (ex.
`75A8250C3F8AA8869C85669E2CDADC5A723CC91B`, `143FA8313B915301D099CB6D1C8B9CEE487AF641`).
Serve como pré-validação parcial do teste 4.3 (nível Completo) — a repetir de forma
controlada (com dois nós reais deliberados, um com família partilhada e um sem)
quando fizermos a categoria 4/5.

**Nota para investigar depois (não bloqueia mais testes):** numa das execuções
apareceu também `RuntimeException: EcT:load` na parser nativa do MCL
(`MclGroup1Impl.getInternalObjectFromString`, chamado de `DAServer.java:82`),
sugerindo uma string de grupo malformada/truncada vinda de uma submissão real
distinta. Possível suspeito: o buffer `char buffer[2048]` em `dittor_proxy.c`, que
já tínhamos identificado como podendo precisar de crescer agora que o payload tem
10 campos (ver plano do item 6). A confirmar/reproduzir de forma controlada mais
tarde.

---

## Categoria 2 — Ausência de prova

### Teste 2.1 — Nível Completo (Chutney real)

**Metodologia:** só nível Completo — não há variante Bridge/Babel (não há nada
para enviar quando a prova está simplesmente ausente). O token `dittor-proof`
está registado como opcional na gramática de descriptors do Tor
(`T01("dittor-proof", K_OPT_DITTOR_PROOF, GE(8), NO_OBJ)`,
[parsecommon/routerparse.c:132](tor/src/feature/dirparse/routerparse.c:132)), por
isso a sua ausência não é um erro de parsing — só é apanhada explicitamente pelo
bloco Dittor. Removido o `dittor_proof.txt` do nó `000a`
(`rm /tmp/dittor_chutney/nodes/000a/dittor_proof.txt`) com o `Main.java`/`DAServer`
a continuar a correr mas sem ser contactado — a rejeição acontece inteiramente do
lado do Tor, antes de qualquer ligação à bridge:

```c
tok = find_opt_by_keyword(tokens, K_OPT_DITTOR_PROOF);
...
} else {
  log_warn(LD_DIR, "[Tor-Dittor] Descriptor for '%s' has no dittor-proof token. "
           "Rejecting.", ...);
  goto err;
}
```

**Resultado:** rejeição confirmada e repetida em dois ciclos periódicos
consecutivos de geração de descriptor (~60s de intervalo, sem intervenção
manual entre eles):

```
Aug 30 22:05:47.591 [warn] [Tor-Dittor] Descriptor for 'test000a' has no dittor-proof token. Rejecting.
Aug 30 22:06:47.598 [warn] [Tor-Dittor] Descriptor for 'test000a' has no dittor-proof token. Rejecting.
```

**Interpretação:** confirma que o item 9 cobre corretamente os dois casos de
rejeição incondicional que desenhámos (prova presente mas inválida — teste 1.2 —
e prova totalmente ausente — este teste), e que o caso de ausência nunca chega a
contactar o `DAServer`/bridge (comportamento mais eficiente e correto, já que não
há nada para a bridge verificar). Nota: a mensagem do lado da geração do
descriptor (`"No local dittor_proof.txt found. Building normal descriptor"`,
[router.c:3234](tor/src/feature/relay/router.c:3234)) é `log_info`, abaixo do
nível capturado por omissão em `notice.log` — não apareceu no log, como esperado;
não afeta a validade do resultado.

---

## Categoria 3 — Backend Java offline/crash

### Teste 3.1a — Nível Bridge (backend nunca chegou a arrancar)

**Metodologia:** `Main.java` (que aloja o `DAServer` na porta 8081) interrompido
antes do teste, porta 8081 confirmada livre. Payload válido (`bridge_payload.txt`
do nó `000a`, gerado num registo real anterior) enviado 30 vezes via
`BridgeTestClient` diretamente à porta 8081.

**Resultado:** 30/30 execuções devolveram `CONNECTION_ERROR: Connection refused`
— falha limpa e tratada (`catch IOException` em
[BridgeTestClient.java:37](demo/src/main/java/dittor/testing/BridgeTestClient.java:37)),
sem exceções não apanhadas.

**Latência (ms), N=30:**

| Estatística | Valor |
|---|---|
| Média | 1,12 ms |
| Mediana | 0,45 ms |
| Mínimo | 0,30 ms |
| Máximo | 20,58 ms |
| Média sem outlier (excl. a 1ª execução, 20,58ms) | 0,45 ms |

**Interpretação:** a rejeição é quase instantânea (~0,45ms) — muito mais rápida
que qualquer um dos casos VALID/INVALID (57,60ms / 17,88ms), porque é uma recusa
de ligação TCP ao nível do SO (`ECONNREFUSED`), sem sequer chegar a haver um
handshake de aplicação. O único outlier (#1, 20,58ms) segue o mesmo padrão de
warm-up de JIT/JVM observado no teste 1.1. Dados em bruto:
`raw/3.1a_bridge_backend_offline.csv`.

### Teste 3.1b — Nível Bridge (backend cai a meio da ligação)

**Metodologia (nota sobre a primeira tentativa falhada):** a primeira abordagem
usou o `BridgeTestClient` em background com um `sleep 0.05` antes de matar o
`Main.java`, mas o resultado foi sempre `CONNECTION_ERROR: Connection refused`
— indistinguível do 3.1a. Causa: o arranque de uma JVM nova para o cliente
(tipicamente >50ms) é da mesma ordem de grandeza que o próprio tempo de resposta
do servidor (~17-57ms), por isso não há janela fiável para "matar depois de
ligar, antes de responder" usando um cliente que precisa de arrancar uma JVM de
cada vez. Corrigido usando o redirecionamento `/dev/tcp` do próprio bash (sem
arranque de processo nenhum): a ligação é aberta e o pedido enviado em
comandos de shell, e só depois o `Main.java` é morto.

```bash
PAYLOAD=$(cat /tmp/dittor_chutney/nodes/000a/bridge_payload.txt)
exec 3<>/dev/tcp/127.0.0.1/8081
echo "VALIDATE $PAYLOAD" >&3
pkill -9 -f dittor.Main
RESPONSE=$(timeout 2 head -n1 <&3)
```

**Resultado:** a ligação TCP foi aceite com sucesso (não houve erro no
`exec 3<>/dev/tcp/...`, ao contrário do que aconteceria se o backend já
estivesse em baixo), o pedido foi enviado, e a resposta lida foi **vazia**
(EOF imediato) — o servidor morreu antes de escrever qualquer linha de
resposta.

**Interpretação:** confirmado no código C consumidor real da bridge
([dittor_proxy.c:25-38](tor/src/feature/dirparse/dittor_proxy.c:25)) que os
casos "nunca ligou" (3.1a) e "ligou mas morreu antes de responder" (3.1b) são
**tratados de forma idêntica**: `connect()` a falhar devolve `NULL`; e se a
ligação for aceite mas `read()` devolver `0` ou erro, a condição
`valread > 0` também falha e devolve `NULL` na mesma. Ou seja, do ponto de
vista do Tor (`routerparse.c`), o 3.1a e o 3.1b acionam exatamente o mesmo
caminho fail-open, indistinguíveis um do outro — resultado relevante para a
tese, mostra que a implementação não precisa de distinguir os dois modos de
falha para se comportar corretamente em ambos.

### Teste 3.2 — Nível Completo (Tor real com backend offline)

**Metodologia:** `dittor_proof.txt` válido regenerado para o nó `000a` (via
`Main.java`, CAs a correr), `Main.java` interrompido deliberadamente logo após
confirmar a escrita do ficheiro, **antes** de qualquer submissão do Tor real
chegar à bridge — para garantir que o token `dittor-proof` está presente
(diferente do teste 2.1) mas a porta 8081 está inacessível (mesma condição do
3.1a/3.1b, desta vez pelo caminho C real completo).

**Nota de metodologia — filtro de log incorreto:** `grep -i "dittor"` apanha
também as linhas de exportação periódica de "consensus transparency" (o caminho
`/tmp/dittor_chutney/...` contém a substring "dittor"), que acontecem a cada
~20s — muito mais frequentes que os eventos reais do Dittor (~60s) — afogando-os
num `tail` curto. Corrigido filtrando por `"Tor-Dittor"` (a tag usada em todas as
mensagens de log reais do bloco Dittor), que não apanha essas linhas de ruído.

**Resultado:**

```
Aug 31 10:37:08.111 [notice] [Tor-Dittor] Successfully injected local dittor_proof.txt into descriptor!
Aug 31 10:37:08.111 [notice] [Tor-Dittor] Passing real descriptor payload to loopback proxy...
Aug 31 10:37:08.111 [warn]   [Tor-Dittor] Loopback connection to port 8081 failed. Keeping node alive.
Aug 31 10:37:39.548 [notice] [Tor-Dittor] Successfully injected local dittor_proof.txt into descriptor!
Aug 31 10:37:39.548 [notice] [Tor-Dittor] Passing real descriptor payload to loopback proxy...
Aug 31 10:37:39.548 [warn]   [Tor-Dittor] Loopback connection to port 8081 failed. Keeping node alive.
```

Sem nenhuma linha `Rejecting descriptor` a seguir a qualquer um destes dois
eventos — confirma o comportamento fail-open do item 9 (o `goto err` só existe
nos ramos "token ausente" e "resposta explícita não-VALID"; a falha de ligação à
bridge cai num terceiro ramo que só regista o aviso e deixa o resto do parsing
continuar normalmente).

**Confirmação indireta adicional (achado não planeado):** comparando com os
ciclos de retry observados nos testes 1.2/2.1 (reinjeção agressiva a cada ~60s
enquanto o descriptor continua a ser rejeitado), aqui o Tor **parou de tentar
republicar** logo depois destes dois eventos (nenhum evento `Tor-Dittor`
seguinte no log, apesar de o `notice.log` continuar ativo com outras mensagens
periódicas). Isto sugere que a cadência agressiva de republicação nos testes
anteriores era o comportamento de retry normal do Tor perante uma publicação de
descriptor falhada — e a sua ausência aqui é evidência indireta de que o
descriptor foi de facto tratado como aceite, não só "não explicitamente
rejeitado".

**Interpretação:** confirma a Categoria 3 por completo — nos três níveis
testados (3.1a, 3.1b, 3.2), uma falha do backend Java nunca resulta em bloqueio
do nó; é uma escolha de desenho deliberada (documentada no item 9) para que uma
falha de infraestrutura do sidecar Java não derrube a rede Tor, ao custo de,
durante essa janela, não haver imposição real da resistência a Sybil — um
trade-off a discutir explicitamente na tese.

---

## Categoria 4 — Reutilização de pseudónimo sem família partilhada

### Teste 4.1 — Nível Babel (registo simulado interno, sem Tor/bridge)

**Metodologia:** alteração temporária em `Main.java` (revertida logo a seguir a
este teste) — em vez de um `User` (com `secretX` aleatório) novo por nó
simulado, os dois nós da lista `DITTOR_NODES` partilharam o mesmo `User`
(logo, o mesmo pseudónimo VRF), com `familyIds` vazio para ambos (já era o
comportamento por omissão do `Main.java`). `DITTOR_NODES='000a,001a'`, CAs a
correr, registo feito através do protocolo Babel real (`UserProtocol` →
`DAProtocol` → `DA.registerNode`), sem tocar em Tor/Chutney/bridge.

**Resultado:** o nó `000a` registou com sucesso (primeiro a reivindicar o
pseudónimo). O nó `001a`, com o mesmo pseudónimo e sem família partilhada:

```
[DA-Crypto] VRF Evaluation Outcome: PASS
[DA-Crypto] DLEQ Eval Result: PASS
[DA-Crypto] Credential Bilinear Check Result: PASS
[DA] REJECTED: node 001a reused a pseudonym without shared family ids
[DA] Verification FAILURE. Pseudonym is being reused without a shared family!
Registration denied: Unauthorized: pseudonym already claimed by another node.
[User] Execution cycle failed, shutting down system
```

**Interpretação:** as três verificações criptográficas (VRF, DLEQ, credencial)
passam individualmente para o `001a` — a credencial e a prova são
matematicamente válidas, tal como seriam para um atacante Sybil real a usar o
mesmo segredo subjacente sob duas identidades de nó diferentes. A rejeição vem
exclusivamente da lógica de unicidade de pseudónimo + interseção de
`family_ids` (item 3), isolando bem a propriedade de resistência a Sybil que
este teste valida (não é confundível com uma simples falha de prova inválida,
categoria 1).

**Achado sobre o harness de teste (não é uma falha de segurança):** uma
rejeição no caminho Babel faz o `UserProtocol` chamar `System.exit(1)`
([UserProtocol.java:214](demo/src/main/java/dittor/protocols/UserProtocol.java:214)),
terminando todo o processo `Main.java` (incl. a bridge `DAServer`) assim que um
nó é recusado. É uma limitação do harness de demonstração/simulação, não do
protocolo em si — a DA responde corretamente com `false`/negação; é só o lado
cliente simulado que não foi pensado para continuar depois de uma rejeição.
Relevante para o desenho dos testes 5.x (só o *último* nó de uma lista pode
testar um cenário de rejeição, já que o processo termina a seguir).

### Teste 4.2 — Nível Bridge (payloads diretos à porta 8081, `nodeId` diferente)

**Metodologia:** `Main.java` relançado com um único nó (`DITTOR_NODES='000a'`),
registando `000a` via Babel normalmente (estado limpo, um só pseudónimo na
tabela da DA). Duplicado o `bridge_payload.txt` gerado, alterando só o campo
`nodeId` (índice 9, `awk -F'|' -v OFS='|' '{$9="999z"; print}'`) — pseudónimo e
todas as provas criptográficas mantidas exatamente iguais. Ambos os payloads
enviados diretamente à porta 8081 via `BridgeTestClient`, sem Tor/Chutney.

**Nota de desenho descoberta no código:** [DA.java:107-108](demo/src/main/java/dittor/crypto/DA.java:107)
trata um `nodeId` já registado a reenviar o mesmo pseudónimo como idempotente
(`if (existing.containsKey(nodeId)) return true;`, sem exigir família
partilhada) — só rejeita quando o `nodeId` é diferente do(s) já associado(s)
àquele pseudónimo. Por isso o payload original, embora reenviado pela bridge
depois de já ter sido registado via Babel, continua a dar `VALID`.

**Resultado:**

```
--- Original (nodeId=000a, já registado via Babel) ---
[1/1] 47.10ms -> VALID
--- Duplicado (nodeId=999z, mesmo pseudonimo) ---
[1/1] 39.84ms -> INVALID
```

Confirmado no console do `Main.java`/`DAServer`:
```
[DA] REJECTED: node 999z reused a pseudonym without shared family ids
[DA-Server] Pseudonym rejected
```

**Interpretação:** confirma a Categoria 4 ao nível Bridge — a lógica de
unicidade de pseudónimo funciona corretamente mesmo quando o pedido chega
diretamente à bridge (sem passar pelo caminho Babel/simulado), reforçando que
a proteção está implementada na própria `DA` (item 3), não depende de nenhum
comportamento específico do transporte Babel.

### Teste 4.3 — Nível Completo (Tor real, via `routerparse.c`/`dittor_proxy.c`)

**Metodologia:** `Main.java` relançado com um único nó (`DITTOR_NODES='000a'`),
gerando um pseudónimo fresco e registando-o via Babel sob o `nodeId` simulado
`"000a"` (string literal). O mesmo `dittor_proof.txt` foi depois copiado
manualmente também para a pasta do nó real `001a`
(`cp .../000a/dittor_proof.txt .../001a/dittor_proof.txt`), para que o processo
Tor real do `001a` o injetasse e submetesse à bridge com a sua própria
identidade real.

**Nota de metodologia importante:** o processo Tor real do `000a` **não
resubmeteu** o novo ficheiro dentro da janela deste teste — o seu último
descriptor já tinha sido aceite (fail-open) numa sessão de testes anterior
(`10:37:39`), e o Tor só regenera descriptors com pouca frequência depois de
um aceite, ao contrário do ciclo agressivo de retry (~60s) que se vê enquanto
um descriptor continua a ser rejeitado (o mesmo padrão já documentado no teste
3.2). Por isso, o "outro lado" da colisão observada nesta execução é a entrada
Babel simulada (`nodeId="000a"`, string literal), não o processo Tor real do
`000a`. A propriedade de segurança demonstrada é a mesma — a `DA.registerNode`
usa exatamente a mesma lógica independentemente de quem já detém o pseudónimo
([DA.java:96-122](demo/src/main/java/dittor/crypto/DA.java:96)) — mas por
rigor não se deve descrever este resultado como "dois nós Tor reais a
colidir entre si"; é "um nó Tor real, através do caminho C completo,
corretamente barrado por colidir com um pseudónimo já reivindicado".

**Resultado:** confirmado no console do `Main.java`/`DAServer`, repetido em
cada ciclo periódico de resubmissão do `001a`:

```
[DA] New pseudonym registered for node 000a
...
[DA] REJECTED: node FD68816E5E77D8A44D47B113401272204D8BDC6C reused a pseudonym without shared family ids
[DA-Server] Pseudonym rejected
```

`FD68816E5E77D8A44D47B113401272204D8BDC6C` é o `identity_digest` real (40
carateres hex) do nó `001a` — confirma que é mesmo o processo Tor real, através
do caminho C completo (`routerparse.c` → `dittor_proxy.c` → `DAServer` →
`DA.registerNode`), a ser barrado, e não uma string simulada.

**Interpretação:** completa a Categoria 4 nos três níveis (4.1 Babel, 4.2
Bridge, 4.3 Completo) — a resistência a reutilização de pseudónimo sem família
partilhada funciona de forma consistente em toda a pilha, incluindo através do
caminho Tor real com uma identidade de nó genuína. Complementa (de forma
deliberada e documentada) o achado acidental equivalente já registado no teste
1.2b.

---

## Categoria 5 — Aceitação legítima multi-nó com família partilhada

### Teste 5.1 — Nível Babel (registo simulado interno, sem Tor/bridge)

**Metodologia:** mesma alteração temporária do teste 4.1 (um só `User`
partilhado entre `DITTOR_NODES='000a,001a'`, logo o mesmo pseudónimo VRF), mas
desta vez com `familyIds=["familyXYZ"]` não-vazio e igual para os dois nós, em
vez da lista vazia por omissão do `Main.java`.

**Resultado:** os dois nós registaram com sucesso:

```
[DA] New pseudonym registered for node 000a
[DA] Verification SUCCESS. Adding to Tor Consensus list.
...
[DA] Node 001a accepted under existing pseudonym (shared family)!
[DA] Verification SUCCESS. Adding to Tor Consensus list.
```

**Interpretação:** confirma o caso positivo simétrico ao teste 4.1 — a mesma
lógica de colisão de pseudónimo ([DA.java:107-121](demo/src/main/java/dittor/crypto/DA.java:107))
que rejeita reutilização sem família partilhada aceita corretamente a
reutilização quando há sobreposição de `family_ids`, permitindo que um operador
legítimo registe vários nós sem ser incorretamente marcado como Sybil.

**Nota:** o output desta execução inclui também, no fim, uma rejeição
`[DA] REJECTED: node FD68816E5E77D8A44D47B113401272204D8BDC6C reused a
pseudonym...` — ruído de fundo do processo Tor real do `001a` (ainda em
execução de testes anteriores, sem nenhuma família real configurada) a
resubmeter pelo caminho C, sem relação com este teste Babel. Não afeta o
resultado.

### Teste 5.2 — Nível Bridge (payloads diretos à porta 8081, família partilhada)

**Bug encontrado e corrigido antes deste teste, em
[DAServer.java:98](demo/src/main/java/dittor/tor/DAServer.java:98):**
`familyIdsRaw.split(".")` usa `.` como regex ("qualquer caracter"), não como
caracter literal — `"familyXYZ".split(".")` devolve um array **vazio**, não
`["familyXYZ"]` (gotcha clássico do Java). Ou seja, antes desta correção,
qualquer `family_ids` não-vazio recebido pela bridge era sempre interpretado
como conjunto vazio — o mecanismo de família nunca teria funcionado por este
caminho. Corrigido para `familyIdsRaw.split(",")`.

**Metodologia:** alteração temporária em `Main.java` (só a lista de
`familyIds` do nó simulado passa a `["familyXYZ"]` em vez de vazia — variante
mais simples da alteração do teste 4.1/5.1, um só nó, sem partilhar `User`).
`Main.java` relançado com `DITTOR_NODES='000a'`, registando `000a` via Babel
com família `["familyXYZ"]`. Duplicado o `bridge_payload.txt` resultante,
desta vez alterando **dois** campos — `nodeId` (índice 9) e `familyIds`
(índice 10) — com `awk -F'|' -v OFS='|' '{$9="999z"; $10="familyXYZ"; print}'`.
Enviado à porta 8081 via `BridgeTestClient`.

**Resultado:**
```
[1/1] 42.78ms -> VALID
```
Confirmado no console do `Main.java`/`DAServer`:
```
[DA] Node 999z accepted under existing pseudonym (shared family)!
[DA-Server] Pseudonym verified successfully!
```

**Interpretação:** confirma a Categoria 5 ao nível Bridge, e valida a correção
do bug de parsing acima — sem ela, este teste teria dado `INVALID` mesmo com
`family_ids` genuinamente partilhado, o que teria sido um falso negativo grave
(bloquear operadores legítimos de multi-relay por um bug de parsing, não por
desenho). Reforça, tal como no 4.2, que a lógica de família está corretamente
implementada na própria `DA`, independente do transporte usado para lá chegar.

### Teste 5.3 — Nível Completo (Tor real, com certificado de família real)

**Metodologia — configuração da família real do Tor** (mecanismo `K_FAMILY_CERT`,
não o `MyFamily` clássico):

1. `tor --keygen-family <ficheiro-base>` gera `<base>.secret_family_key` e
   imprime diretamente a linha a colar no torrc: `FamilyId <valor-base64>`.
2. Copiar `<base>.secret_family_key` para o `KeyDirectory` de cada relay que
   partilha a família (por omissão, `<node_dir>/keys/`; não é preciso definir
   `FamilyKeyDirectory` explicitamente).
3. Acrescentar `FamilyId <valor>` ao torrc de cada relay.
4. Reiniciar o Tor (`FamilyKeyDirectory` é `VAR_IMMUTABLE`, não recarrega via
   HUP) — cada relay gera então um `family-cert` assinado com a chave
   partilhada + a sua própria chave de identidade, verificado por
   `check_family_certs`/`check_one_family_cert`
   ([routerparse.c:1410](tor/src/feature/dirparse/routerparse.c:1410)) tanto
   por si próprio como por quem lhe analisa o descriptor.

Configurado para os dois nós reais `000a` e `001a` (mesma chave de família
copiada para ambos), com o mesmo `dittor_proof.txt` (mesmo pseudónimo)
copiado para os dois, tal como no teste 4.3.

**Armadilha encontrada (erro de metodologia, não bug de produção):** o
`family_ids` real extraído pelo Tor vem com o prefixo `ed25519:` (ex.
`ed25519:tFNOVZ6ClGUkHg4Bimy9UesMqCw6+G5acJiBFxixWvc`), confirmado por um
diagnóstico temporário em `DAServer.java` a imprimir o valor bruto recebido.
A entrada Babel simulada (mesmo truque dos testes 4.1/5.1/5.2, usada aqui
para evitar que o registo automático do `Main.java` "envenenasse" o
pseudónimo com família vazia) tinha sido configurada só com o valor
base64 sem o prefixo — nunca coincidia com o valor real, causando rejeição
permanente até isto ser corrigido. Corrigido ao incluir o prefixo
`"ed25519:"` na string da família simulada.

**Resultado, depois da correção — console `DAServer`/`Main.java`:**
```
[DA] New pseudonym registered for node 0738F207067BC55F8931A0FF0A1AFB94369F2515
[DA] Node FD68816E5E77D8A44D47B113401272204D8BDC6C accepted under existing pseudonym (shared family)!
[DA] Node 0738F207067BC55F8931A0FF0A1AFB94369F2515 accepted under existing pseudonym (shared family)!
```

`notice.log` de ambos os nós reais (`000a` e `001a`), sem nenhuma rejeição:
```
[notice] [Tor-Dittor] Verification SUCCESS for 'test000a'!
[notice] [Tor-Dittor] Verification SUCCESS for 'test001a'!
```

**Interpretação:** completa a Categoria 5 nos três níveis (5.1 Babel, 5.2
Bridge, 5.3 Completo) — confirma, através do mecanismo real e completo de
certificados de família do Tor (não simulado), que um operador legítimo pode
registar múltiplos relays sob o mesmo pseudónimo/segredo sem ser rejeitado
como Sybil, desde que prove a relação de família através do certificado
assinado. Fecha o par com a Categoria 4 (mesmo mecanismo de deteção de
colisão, mas aqui com a exceção correta a funcionar ponta-a-ponta).

---

## Categoria 6 — Desempenho (dados parciais, acumulados à medida que os outros testes correm)

### 6.2 — Overhead do socket bridge (isolado)

**Metodologia (caso `VALID`, N=30):** o mesmo `bridge_payload.txt` válido do
nó `000a` (já registado) enviado 30x via `BridgeTestClient` — dá sempre
`VALID` por idempotência ([DA.java:107-108](demo/src/main/java/dittor/crypto/DA.java:107)),
mas a verificação criptográfica completa (VRF+DLEQ+par bilinear) corre por
inteiro em cada envio, já que essa verificação acontece em
[DAServer.java:92-93](demo/src/main/java/dittor/tor/DAServer.java:92), antes
de `registerNode` sequer ser chamado — por isso mede o custo real e completo
do caminho `VALID`, não um atalho.

| Cenário | N | Média | Mediana | Mín | Máx | Média sem outliers |
|---|---|---|---|---|---|---|
| Payload válido (`VALID`) | 30 | 22,84 ms | 20,01 ms | 17,95 ms | 66,87 ms | 20,74 ms (excl. #1 e #29) |
| Payload inválido (`INVALID`) | 30 | 17,88 ms | 16,78 ms | 15,35 ms | 34,18 ms | 16,71 ms — ver Categoria 1, Teste 1.1 |

Dados em bruto: `raw/6.2_bridge_valid_proof.csv`.

**Nota — correção de uma hipótese anterior:** a amostra única original do
caminho `VALID` (57,60ms, teste inicial antes da Categoria 1) sugeria uma
diferença grande entre `VALID` e `INVALID`, atribuída à verificação bilinear
completa só acontecer no caminho `VALID`. Com N=30 em regime estacionário, a
diferença real é muito menor (~21ms vs ~17ms, sem outliers) — a amostra
original de 57,60ms era provavelmente um outlier de arranque (primeira
ligação/JIT, mesmo padrão dos outliers #1 vistos em quase todos os testes
repetidos desta secção), não representativo do custo em regime normal. A
verificação bilinear tem, sim, um custo adicional mensurável (~4ms), mas
muito mais modesto do que a amostra única isolada sugeria — vale a pena usar
os números de N=30 na tese, não a amostra original.

### 6.1 / 6.4 — Latência de registo ponta-a-ponta (custo recorrente por nó)

**Metodologia:** instrumentação temporária em `UserProtocol.java` — timestamp
no início de `startRegistration` (contacto às 3 CAs) e no recebimento da
resposta final da DA (`handleRegisterRelayReply`). Mede o intervalo completo
do registo de **um** nó (abertura de ligação às 3 CAs, `CredentialRequestMsg`,
combinação threshold das assinaturas, prova DLEQ, registo na DA), com as CAs
já com o DKG completo (não inclui o custo de setup do DKG — esse é o 6.3). O
`Main.java` foi relançado 5 vezes seguidas (`DITTOR_NODES='000a'`), as 3 CAs
mantidas a correr sem reiniciar entre execuções.

**Resultado, N=5:** 201, 157, 160, 161, 158 ms.

| Estatística | Valor |
|---|---|
| Média | 167,4 ms |
| Mediana | 160 ms |
| Mínimo | 157 ms |
| Máximo | 201 ms |
| Média sem outlier (excl. #1, 201ms) | 159 ms |

**Interpretação:** ~160ms é o custo recorrente, em regime estacionário, para
registar um novo nó (Sybil-check completo incluído) depois do DKG das CAs já
estar feito. O outlier #1 (201ms) segue o mesmo padrão de warm-up de JIT/JVM
observado em quase todos os testes desta secção. Este número cobre tanto o
6.1 (latência ponta-a-ponta) como o 6.4 (custo por registo recorrente), já
que ambos medem exatamente a mesma operação quando o DKG já está feito — a
distinção só importa se se quiser separar explicitamente o custo do 6.3
(setup único do DKG) do custo por-nó, o que se faz comparando este número
com o do 6.3 a seguir.

### 6.3 — Custo do DKG (setup único, 3 CAs)

**Metodologia:** instrumentação temporária em `CAProtocol.java` — timestamp
no início do DKG de cada CA (`startRegistration`-equivalente, logo antes de
abrir ligações aos pares) e na conclusão (`DKG COMPLETE`). As 3 CAs (mortas e
relançadas de raiz a cada ronda, para evitar o artefacto de *retry backoff*
de TCP descrito abaixo) lançadas em sequência rápida nos Terminais 1/2/3, 4
rondas completas.

**Nota de metodologia — 1ª tentativa invalidada:** a primeira tentativa
testou cada CA isoladamente (relançada várias vezes sozinha, com as outras
duas já de pé há muito tempo ou também a reiniciar de forma descoordenada) e
deu valores completamente inconsistentes (223ms-6191ms, quase 30x de
variação) — dominados pelo *backoff* fixo de "retry em dois segundos" da
ligação TCP entre pares, não pelo custo real do protocolo. Descartados.

**Resultado (4 rondas, todas as 3 CAs relançadas de raiz em cada ronda):**

| CA | Amostras (ms) | Média | Mediana | Mín | Máx |
|---|---|---|---|---|---|
| CA-1 (lançada 1ª) | 1413, 2140, 1408, 1326 | 1571,8 ms | 1410,5 ms | 1326 ms | 2140 ms |
| CA-2 (lançada 2ª) | 887, 1017, 574, 726 | 801,0 ms | 806,5 ms | 574 ms | 1017 ms |
| CA-3 (lançada 3ª) | 118, 442, 104, 104 | 192,0 ms | 111,0 ms | 104 ms | 442 ms |

**Interpretação:** cada CA mede o seu próprio DKG a partir do instante em que
o **seu próprio** processo arranca — como as 3 CAs são lançadas em sucessão
rápida mas não perfeitamente simultânea (arranque de JVM + Maven + Bilinear
group de cada uma), a CA-1 (lançada primeiro) "vê" o relógio a começar mais
cedo, e por isso o seu tempo medido inclui a espera pelas outras duas
arrancarem, além do protocolo DKG em si. A CA-3 (lançada por último) já
encontra as outras duas prontas, por isso o seu número (~100-440ms) é o que
mais se aproxima do custo *intrínseco* do protocolo DKG (troca de hashes de
compromisso, revelação, distribuição de shares) uma vez que todas as ligações
já estão estabelecidas. O número da CA-1 (~1,3-2,1s) é mais representativo do
tempo de setup *operacional* completo, do ponto de vista de quem arranca a
rede pela primeira vez (inclui arranque das 3 JVMs). Para a tese, vale a pena
citar os dois: "~100-450ms de custo intrínseco do protocolo DKG" e "~1,3-2,1s
de tempo de setup operacional ponta-a-ponta, incluindo arranque das 3 JVMs".

### 6.5 — Comparação com Tor Metrics

**Valores de referência** (fornecidos pelo utilizador, tabela já usada na
tese, retirada do [Tor Metrics](https://metrics.torproject.org/torperf.html)):

| Métrica | Resultados na Rede Tor |
|---|---|
| Tempo de download de ficheiros | 0,5-7 segundos |
| Timeouts e falhas de download | Timeouts: 0%-50%; Falhas: 0% |
| Tempo de construção de Tor Circuits | 1º salto: até 300ms; 2º salto: até 400ms; 3º salto: até 500ms |
| Latência de round-trip de circuitos | Em média, 250ms-1s |
| Throughput no download de ficheiros | Mediana entre 4-20 Mbps |

**Nota de verificação:** tentei confirmar estes valores diretamente no site
do Tor Metrics (`WebFetch` e o browser da sessão) sem sucesso — os gráficos
são renderizados em JavaScript e os endpoints CSV tentados não responderam;
a navegação direta ao site também foi bloqueada pela política de navegação
desta sessão. Consegui confirmar que a estrutura e as categorias de métricas
da tabela (`torperf.html` para download/timeouts, páginas `onionperf-*.html`
para construção de circuitos/latência/throughput) correspondem à estrutura
real do site — não os valores numéricos exatos. Recomenda-se confirmar
visualmente no site antes de fechar a tese, caso os valores tenham mudado
desde a captura original.

**O argumento central da comparação:** a verificação Dittor acontece
inteiramente no **caminho de publicação do descriptor** — entre o processo
Tor de um relay e as autoridades de diretório (via `routerparse.c` →
`dittor_proxy.c` → `DAServer`), tipicamente uma vez a cada ciclo de
republicação do descriptor (na rede Tor real, da ordem das horas, não a cada
circuito). As 5 métricas do Tor Metrics acima medem o **caminho de dados do
utilizador** — construção de circuitos, pedidos HTTP, downloads — que nunca
passa pelo código Dittor. Por desenho, a verificação Dittor não está no
caminho crítico de nenhuma destas métricas: um utilizador a navegar através
de relays já publicados não sofre nenhum overhead adicional, porque a
verificação já aconteceu antes, na publicação do descriptor desse relay.

**Os nossos números, para contexto (nenhum deles é comparável célula-a-célula
com a tabela acima, mas servem para argumentar a ordem de grandeza):**

| Operação Dittor | Custo medido | Frequência na rede real |
|---|---|---|
| Verificação de um descriptor na bridge (`VALID`) | ~21-23ms (mediana ~20ms, N=30 — Teste 6.2) | uma vez por ciclo de republicação de descriptor por relay (~horas) |
| Registo completo de um novo relay (CAs+DA) | ~160ms em regime estacionário (Teste 6.1/6.4) | uma vez por relay, ao entrar na rede |
| Setup do DKG das 3 CAs | ~100-450ms (custo intrínseco) / ~1,3-2,1s (operacional, N=4 — Teste 6.3) | uma vez, no arranque da infraestrutura Dittor |

**Interpretação:** mesmo o maior destes números (~2,1s, setup do DKG) é um
custo **único e de infraestrutura**, nunca repetido por circuito nem por
download — comparável em ordem de grandeza a um único tempo de construção de
circuito da rede real (até 500ms por salto, ~1,2s para um circuito de 3
saltos), mas pago uma única vez, não por cada interação do utilizador. O
custo recorrente mais relevante (~160ms por registo de relay, ~20ms por
verificação de descriptor) acontece a uma cadência de horas, nunca no caminho
de um pedido HTTP do utilizador. Por desenho, a diferença de performance
para o utilizador final é zero, não apenas "insignificante" — o Dittor não
adiciona nenhum passo ao caminho de dados que as métricas do Tor Metrics
medem. Este é o argumento a usar na tese para justificar que o requisito de
performance (diferença insignificante para a experiência do utilizador) está
cumprido.

---

## Índice de testes por fazer

- [x] 1.1 — Bridge, prova inválida
- [x] 1.2 — Completo, prova inválida (1.2a payload malformado + 1.2b DLEQ inválido bem formado)
- [x] 2.1 — Completo, ausência de prova
- [x] 3.1a — Bridge, backend offline (nunca arrancou)
- [x] 3.1b — Bridge, backend crasha a meio da ligação
- [x] 3.2 — Completo, backend offline
- [x] 4.1 — Babel, reutilização de pseudónimo
- [x] 4.2 — Bridge, reutilização de pseudónimo
- [x] 4.3 — Completo, reutilização de pseudónimo
- [x] 5.1 — Babel, família partilhada
- [x] 5.2 — Bridge, família partilhada
- [x] 5.3 — Completo, família partilhada
- [x] 6.1 — Latência de registo ponta-a-ponta
- [x] 6.2 — Overhead do socket (repetir caso VALID 30x)
- [x] 6.3 — Custo do DKG (setup único)
- [x] 6.4 — Custo por registo (recorrente)
- [x] 6.5 — Comparação com Tor Metrics
