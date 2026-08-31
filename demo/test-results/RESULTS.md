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

## Categoria 6 — Desempenho (dados parciais, acumulados à medida que os outros testes correm)

### 6.2 — Overhead do socket bridge (isolado)

| Cenário | N | Latência |
|---|---|---|
| Payload válido (`VALID`) | 1 | 57,60 ms |
| Payload inválido (`INVALID`) | 30 | média 17,88 ms (16,71 ms sem outliers) — ver Categoria 1, Teste 1.1 |

**Nota:** só há 1 amostra do caminho `VALID` até agora — vale a pena repetir esse
caso também 30x (mesmo formato do teste 1.1) antes de reportar isto como número
final, para ter uma média comparável. A diferença entre os dois casos (57,60ms vs
~17ms) é esperada: o caminho `VALID` faz a verificação bilinear completa (par de
emparelhamentos), enquanto o `INVALID` falha mais cedo, na verificação DLEQ, antes
de chegar ao passo bilinear — por isso é mais rápido. Vale a pena confirmar isto
explicitamente como parte da análise na tese.

---

## Índice de testes por fazer

- [x] 1.1 — Bridge, prova inválida
- [x] 1.2 — Completo, prova inválida (1.2a payload malformado + 1.2b DLEQ inválido bem formado)
- [x] 2.1 — Completo, ausência de prova
- [x] 3.1a — Bridge, backend offline (nunca arrancou)
- [x] 3.1b — Bridge, backend crasha a meio da ligação
- [x] 3.2 — Completo, backend offline
- [ ] 4.1 — Babel, reutilização de pseudónimo
- [ ] 4.2 — Bridge, reutilização de pseudónimo
- [ ] 4.3 — Completo, reutilização de pseudónimo
- [ ] 5.1 — Babel, família partilhada
- [ ] 5.2 — Bridge, família partilhada
- [ ] 5.3 — Completo, família partilhada
- [ ] 6.1 — Latência de registo ponta-a-ponta
- [ ] 6.2 — Overhead do socket (repetir caso VALID 30x)
- [ ] 6.3 — Custo do DKG (setup único)
- [ ] 6.4 — Custo por registo (recorrente)
- [ ] 6.5 — Comparação com Tor Metrics (precisa dos valores de referência do utilizador)
