# Metodologia de avaliação

Este documento descreve como o huehue avalia uma senha. A avaliação segue o modelo do [zxcvbn](https://github.com/dropbox/zxcvbn) e do [nbvcxz](https://github.com/GoSimpleLLC/nbvcxz), com algumas partes próprias. As diferenças entre os três e as limitações do huehue estão na seção 7. Os arquivos de código citados ficam em `src/password_analyzer/`.

## 1. Visão geral

O huehue calcula o **número de tentativas** (*guesses*) que um atacante precisaria para acertar a senha. O atacante é modelado como alguém que testa primeiro as senhas mais prováveis: senhas comuns, nomes, palavras, datas, sequências e linhas de teclado. A nota e o tempo de quebra são calculados a partir desse número.

Etapas da avaliação:

1. Consulta de vazamentos (HIBP).
2. Verificação das regras (lista proibida e composição).
3. Detecção de padrões na senha.
4. Cálculo do número de tentativas de cada padrão.
5. Escolha da decomposição da senha com menor número de tentativas.
6. Conversão do total em nota (0 a 4) e em tempo de quebra.

O huehue também informa `entropy_bits`, que é `log₂(tentativas)`. É apenas outra escala para o mesmo número: cada bit dobra o número de tentativas.

## 2. Consulta de vazamentos

O huehue consulta a API Pwned Passwords do Have I Been Pwned. Apenas os 5 primeiros caracteres do hash SHA-1 da senha são enviados, e a comparação do restante é feita localmente (k-anonimato). O funcionamento está em [`hibp.md`](hibp.md).

Uma senha encontrada em vazamento recebe nota 0, independentemente do tamanho ou da composição. Se a consulta falhar (por exemplo, sem internet), o resultado de vazamento fica como desconhecido e a análise local continua.

Esta etapa é própria do huehue.

## 3. Regras

- **Lista proibida** (`rules/blacklist.py`): senhas presentes na lista recebem nota 0.
- **Composição** (`rules/composition.py`): verifica tamanho mínimo (8) e presença de maiúscula, minúscula, número e caractere especial (incluindo espaço). As violações geram avisos e **não alteram a nota**.


## 4. Padrões e número de tentativas

Cada padrão encontrado é um trecho da senha, com posição inicial e final. O número de tentativas do trecho é a quantidade de candidatos que o atacante testaria, em ordem de probabilidade, até chegar nele. O cálculo fica em `core/entropy.py`; a detecção, em `matchers/`.

| Padrão | O que detecta | Número de tentativas | Origem da fórmula |
|---|---|---|---|
| Dicionário | Trecho de 3+ caracteres presente em uma lista | posição na lista × variações de maiúsculas | zxcvbn |
| Sequência | `123`, `987` | base × tamanho | zxcvbn |
| Teclado | `qwerty`, `asdf`, `1234567890` | soma sobre os tamanhos possíveis (4.3) | zxcvbn |
| Repetição | `aaa`, `!!!!` | custo do caractere × nº de repetições | zxcvbn |
| Data | `31122026`, `31/12/26` | anos de distância × 365 | zxcvbn |
| Força bruta | Trecho sem padrão | tamanho do alfabeto ^ tamanho do trecho | nbvcxz |

### 4.0 Valor mínimo de um trecho

Um trecho que **não** cobre a senha inteira nunca conta menos de **10** tentativas (1 caractere) ou **50** tentativas (2 ou mais caracteres). Sem esse mínimo, um trecho como `Maria` (posição 1 na lista) contaria 2 tentativas e reduziria demais o total. O trecho de força bruta usa um mínimo uma unidade acima (11 e 51), para que, em empate na mesma região, o padrão de dicionário, sequência etc. seja o escolhido.

Origem: zxcvbn -> Constantes em `scoring.coffee`:

`MIN_SUBMATCH_GUESSES_SINGLE_CHAR` (10)

`MIN_SUBMATCH_GUESSES_MULTI_CHAR` (50), em `scoring.coffee`.

### 4.1 Dicionário

**Detecção.** Para cada dataset, o huehue procura na senha qualquer trecho de 3 ou mais caracteres que seja uma entrada do dataset. Se a senha inteira for uma entrada, esse é o resultado. Caso contrário, entre os trechos encontrados, a escolha segue esta ordem:

1. Trecho com frequência conhecida;
2. Maior frequência;
3. Maior comprimento.

Como a busca devolve um único trecho por dataset, o huehue repete a procura no texto à esquerda e à direita do trecho encontrado, para que a escolha da decomposição (seção 5) tenha todos os candidatos.

Datasets usados (`data/`):

| Dataset | Conteúdo | Ordem do arquivo | Compara ignorando maiúsculas |
|---|---|---|---|
| `common_passwords` | Senhas comuns | Mais para menos comum | Não |
| `names_brazil` | Nomes brasileiros | Mais para menos comum | Sim |
| `surnames_brazil` | Sobrenomes brasileiros | Mais para menos comum | Sim |
| `names_english` | Nomes em inglês | Mais para menos comum | Sim |
| `surnames_english` | Sobrenomes em inglês | Mais para menos comum | Sim |
| `english` | Palavras do inglês | Mais para menos comum | Não |
| `eff_large` | Lista de palavras para passphrases | Alfabética | Não |

**Fórmula.**

```text
tentativas = posição_na_lista × variações_de_maiúsculas
```

- **Posição na lista (rank).** Um atacante que testa as entradas da mais para a menos comum e chega à entrada de posição *n* após *n* tentativas. Em datasets cuja posição não indica frequência, o rank é o tamanho da lista inteira.
- **Variações de maiúsculas.** Representa as formas de escrever a mesma palavra com letras maiúsculas e minúsculas:

| Formato da palavra | Fator |
|---|---|
| Tudo minúsculo (`maria`) | 1 |
| Só a primeira letra (`Maria`), só a última (`mariA`) ou todas (`MARIA`) em maiúscula | 2 |
| Outras combinações (`pAsswOrd`) | necessário cálculo |

Para as outras combinações (terceira linha da tabela), a fórmula é:

```text
variações = Σ C(U + L, i), para i de 1 até m
```

Variáveis:

- `U`: quantidade de letras maiúsculas na palavra.
- `L`: quantidade de letras minúsculas na palavra. `U + L` é o total de letras.
- `m = mín(U, L)`: o menor entre `U` e `L`.
- `i`: quantidade de letras em maiúscula em cada caso contado, de 1 até `m`.
- `C(n, i)`: coeficiente binomial, o número de formas de escolher `i` letras entre `n`. Calcula-se `C(n, i) = n! ÷ (i! × (n − i)!)`.

Exemplo com `pAsswOrd`: `U = 2` (A, O), `L = 6` (p, s, s, w, r, d), `U + L = 8` e `m = 2`.

```text
variações = C(8, 1) + C(8, 2)
          = 8 + 28
          = 36
```

Os três formatos comuns da tabela (primeira letra, última letra ou todas em maiúscula) têm seu valor inspirado pelo zxcvbn e recebem o fator de 2 por serem variações comuns.

Exemplo: `Maria` → 1 × 2 = 2, que o mínimo do trecho (4.0) eleva a 50.

Origem: zxcvbn, `dictionary_guesses` e `uppercase_variations`, em `scoring.coffee`.

### 4.2 Sequência

**Detecção.** O huehue procura sequências numéricas de 3 dígitos consecutivos, crescentes (`012`, `123`, ..., `789`) ou decrescentes (`987`, `876`, ..., `210`). Apenas a primeira ocorrência na senha é considerada. Sequências maiores, como `123456`, são tratadas pelo detector de teclado (4.3).

**Fórmula.**

```text
tentativas = base × tamanho_do_trecho
```

| Primeiro caractere | Base |
|---|---|
| `a`, `A`, `z`, `Z`, `0`, `1` ou `9` | 4 |
| Outro dígito | 10 |
| Qualquer outro | 26 |

Se a sequência é decrescente, a base é multiplicada por 2, porque o atacante precisa testar também o sentido inverso. As bases pequenas correspondem a pontos de partida que as pessoas costumam escolher (início ou fim do alfabeto, `0`, `1`, `9`).

Exemplos: `123` → 4 × 3 = **12**. `987` → (4 × 2) × 3 = **24**. `456` → 10 × 3 = **30**.

Origem: zxcvbn, `sequence_guesses`, em `scoring.coffee`.

### 4.3 Teclado

**Detecção.** O huehue procura trechos de 3 ou mais teclas consecutivas em uma das quatro fileiras do teclado QWERTY, em ordem direta ou inversa, sem diferenciar maiúsculas de minúsculas:

```text
1234567890
qwertyuiop
asdfghjkl
zxcvbnm
```

**Fórmula.**

```text
tentativas = (L − 1) × s × d
```

- `L`: tamanho do trecho, em teclas. O atacante testa trechos de todos os tamanhos de 2 até `L`, e cada tamanho contribui com `s × d` tentativas. Por isso o fator é `L − 1`.
- `s`: número de teclas em que um trecho pode começar (47 no QWERTY).
- `d`: número médio de teclas vizinhas de uma tecla (≈ 4,6 no QWERTY). Representa as opções do atacante para a próxima tecla.

Exemplo: um trecho de 5 teclas seguidas (`L = 5`) → 4 × 216 = **864**.

**Letras maiúsculas (Shift).** Se o trecho tiver letras maiúsculas, o resultado é multiplicado por um fator:

```text
se todas as teclas estão com Shift:  fator = 2
senão:                               fator = C(S + N, 1) + ... + C(S + N, m)

onde m = mínimo entre S e N
```

- `S`: quantidade de teclas com Shift (letras maiúsculas) no trecho.
- `N`: quantidade de teclas sem Shift (`N = L − S`).
- `C(n, i)`: número de formas de escolher `i` teclas entre `n`, como em 4.1.

Exemplo: `asDfg` tem `S = 1` e `N = 4`, então `m = 1` e o fator é `C(5, 1) = 5`. O resultado é 864 × 5 = **4.320**.

Origem: zxcvbn, `spatial_guesses`, em `scoring.coffee`. Os valores 47 e ≈ 4,6 vêm do grafo de adjacência do teclado do zxcvbn (`adjacency_graphs.coffee`, gerado por `scripts/build_keyboard_adjacency_graph.py`).

### 4.4 Repetição

**Detecção.** O huehue procura o mesmo caractere repetido 3 ou mais vezes seguidas (`aaa`, `111`, `!!!!`). Apenas a primeira ocorrência é considerada.

**Fórmula.**

```text
tentativas = custo_do_caractere × número_de_repetições
```

O custo do caractere é o de adivinhar um único caractere: o tamanho do alfabeto do caractere (4.6), com mínimo de 11. O atacante adivinha o caractere uma vez e depois só precisa escolher quantas vezes ele se repete.

Exemplos: `aaaa` → 26 × 4 = **104**. `!!!!!` → 33 × 5 = **165**. `1111` → 11 × 4 = **44** (o alfabeto dos dígitos tem 10, e o mínimo é 11).

Origem: zxcvbn, `repeat_guesses`, em `scoring.coffee`. No zxcvbn, o custo base é o do bloco que se repete, que pode ter mais de um caractere. No huehue, o bloco é sempre um caractere (seção 7).

### 4.5 Data

**Detecção.** O huehue procura datas no formato dia, mês e ano, com ano de 2 ou 4 dígitos, sem dígitos colados antes ou depois:

| Formato | Exemplo |
|---|---|
| `DDMMAA` | `311226` |
| `DDMMAAAA` | `31122026` |
| `DD/MM/AA` | `31/12/26` |
| `DD/MM/AAAA` | `31/12/2026` |

Apenas a primeira data da senha é considerada. Anos de dois dígitos são convertidos: `00–49` viram 2000–2049 e `50–99` viram 1950–1999.

A detecção considera os intervalos numéricos de dia (01–31) e mês (01–12), mas não verifica se a data existe no calendário. Portanto, combinações como `31/02/26` também podem ser reconhecidas.

**Fórmula.**

```text
tentativas = máx(|ano − ano_atual|, 20) × 365
se há separador: tentativas × 4
```

- `|ano − ano_atual|`: distância do ano da data até o ano atual. Datas próximas do presente são as mais prováveis, então têm menos tentativas.
- `máx(..., 20)`: o atacante testa pelo menos uma janela de 20 anos, mesmo que a data seja do ano atual.
- `× 365`: dias do ano.
- `× 4`: representa a escolha do separador, quando existe.

Exemplos (em 2026): `31122026` → 20 × 365 = **7.300**. `31/12/2026` → 7.300 × 4 = **29.200**. `31/12/1990` → 36 × 365 × 4 = **52.560**. O ano atual entra no cálculo, então os valores mudam de um ano para o outro.

Origem: zxcvbn, `date_guesses`, com as constantes `MIN_YEAR_SPACE` (20) e `REFERENCE_YEAR`, em `scoring.coffee`.

### 4.6 Força bruta

Os trechos da senha que nenhum padrão cobre são preenchidos com matches de força bruta durante a escolha da decomposição (seção 5).

**Fórmula.**

```text
tentativas = tamanho_do_alfabeto ^ tamanho_do_trecho
```

O trecho pode ser qualquer combinação dos caracteres do alfabeto, então existem `tamanho_do_alfabeto` opções para cada posição. O **tamanho do alfabeto** é a soma dos grupos de caracteres presentes no trecho:

| Grupo | Tamanho |
|---|---|
| Letras minúsculas (a–z) | 26 |
| Letras maiúsculas (A–Z) | 26 |
| Dígitos (0–9) | 10 |
| Símbolos ASCII (inclui espaço) | 33 |
| Qualquer outro caractere (acentos, outros alfabetos) | 100 |

Exemplos:

- `xqzvjkpmw`: 9 letras minúsculas → 26⁹ = **5.429.503.678.976** (≈ 10¹²·⁷).
- `Zx9!`: maiúscula, minúscula, dígito e símbolo → 26 + 26 + 10 + 33 = 95 → 95⁴ = **81.450.625**.
- `!`: 1 símbolo → 33¹ = **33**.

Por padrão, o alfabeto é calculado separadamente para cada trecho de força bruta (`bruteforce_scope="token"`). Com `bruteforce_scope="password"`, usa-se o alfabeto da senha inteira, o que aumenta o valor quando a senha mistura vários grupos de caracteres.

Origem: nbvcxz (classe `BruteForceUtil`). A fórmula `alfabeto ^ tamanho` e o valor mínimo do trecho vêm do zxcvbn (`bruteforce_guesses`, em `scoring.coffee`).

## 5. Escolha da decomposição da senha

Os padrões encontrados podem se sobrepor. O huehue escolhe o conjunto de trechos que cobre a senha inteira, sem sobreposição, com o **menor valor** de:

```text
g = l! × (produto das tentativas dos trechos) + 10000^(l − 1)
```

onde `l` é o número de trechos. A função é `most_guessable_match_sequence`, em `core/scoring.py`.

- **Produto:** as escolhas de cada trecho são independentes, então os valores se multiplicam.
- **`l!`:** representa as ordens possíveis dos `l` trechos.
- **`10000^(l − 1)`:** penaliza sequências com mais trechos. Com isso, dividir a senha em muitos trechos pequenos não reduz o total artificialmente.

Trechos que nenhum padrão cobre são preenchidos com força bruta. A busca é feita por programação dinâmica: para cada posição da senha e cada número de trechos, guarda-se a melhor sequência encontrada e reaproveita-se esse resultado nas posições seguintes.

### Exemplo: `pedro123`

| Trecho | Padrão | Cálculo | Tentativas |
|---|---|---|---|
| `pedro` | dicionário (`names_brazil`, rank 9) | 9 × 1 = 9; mínimo de 50 | 50 |
| `123` | sequência | 4 × 3 = 12; mínimo de 50 | 50 |

Com `l = 2`:

```text
g = 2! × (50 × 50) + 10000¹ = 5.000 + 10.000 = 15.000  (≈ 10^4,2)
```

Resultado: nota bruta 1 (entre 10³ e 10⁶ tentativas).

## 6. Nota, tempo de quebra e avisos

### 6.1 Nota

A nota bruta (`raw_score`) é definida pelo número de tentativas:

| Tentativas | Nota bruta |
|---|---|
| < 10³ | 0 |
| < 10⁶ | 1 |
| < 10⁸ | 2 |
| < 10¹⁰ | 3 |
| ≥ 10¹⁰ | 4 |

Os limites da tabela são comparados com um acréscimo de 5, por exemplo, a nota 0 vale para menos de 1.005 tentativas, e não para menos de 1.000. Isso mantém na mesma faixa os números que ficam logo acima de uma potência exata de 10.

Essas faixas e o acréscimo de 5 (`SCORE_DELTA`) vêm do zxcvbn (`guesses_to_score`).

A nota final (`score`) é:

- **0**, se a senha foi encontrada em vazamento ou está na blacklist;
- `máx(nota bruta, 1)`, nos demais casos (para a nota 0 ser exclusiva de casos de vazamento ou blacklist).

Rótulos:

| Pontuação | Rótulo |
|---|---|
| 0 | muito fraca |
| 1 | fraca |
| 2 | razoável |
| 3 | forte |
| 4 | muito forte |


Junto da nota, é apresentados avisos e sugestões dependendo de quais padrões foram detectados na senha. Por exemplo, caso a senha possua um nome próprio ela recebe o aviso em relação a nomes próprios, caso a senha possua menos de 12
caractéres, a senha recebe uma sugestão para ser mais longa.

### 6.2 Tempo de quebra

O tempo é `tentativas ÷ velocidade do ataque`. O huehue usa os quatro cenários do zxcvbn:

| Cenário | Velocidade |
|---|---|
| `online_throttling_100_per_hour` | 100 por hora |
| `online_no_throttling_10_per_second` | 10 por segundo |
| `offline_slow_hashing_1e4_per_second` | 10⁴ por segundo |
| `offline_fast_hashing_1e10_per_second` | 10¹⁰ por segundo |

Essas velocidades são hipóteses utilizadas pelo zxcvbn como valores de referência. Para consultá-las, veja `scenario_definitions` em `src/time_estimates.coffee`, no [repositório oficial do zxcvbn](https://github.com/dropbox/zxcvbn/blob/master/src/time_estimates.coffee).

Exemplo: 15.000 tentativas a 10 por segundo → 1.500 s ≈ 25 minutos.

O arquivo `core/scoring.py` também define `GUESS_TYPES`, com velocidades de referência por tipo de hash, inspiradas no nbvcxz. A tabela abaixo apresenta os valores definidos no código:

| Tipo | Velocidade (tentativas por segundo) |
|---|---:|
| `OFFLINE_MD5` | 250.375.000.000 |
| `OFFLINE_SHA1` | 85.963.750.000 |
| `OFFLINE_SHA512` | 10.780.875.000 |
| `OFFLINE_BCRYPT_5` | 130.875 |
| `OFFLINE_BCRYPT_10` | 4.129 |
| `OFFLINE_BCRYPT_12` | 1.033 |
| `OFFLINE_BCRYPT_14` | 259 |
| `ONLINE_UNTHROTTLED` | 100 |
| `ONLINE_THROTTLED` | 2 |

Esses valores são referências utilizadas pelo `time_to_crack()` e podem ser ajustados conforme o hardware. 

A função `analyze()` utiliza os quatro cenários de `ATTACK_SCENARIOS` descritos anteriormente, e não esses valores por tipo de hash.

## 7. Diferenças entre os avaliadores e limitações do huehue

### 7.1 Comparação

O huehue é baseado no zxcvbn e no nbvcxz e não reimplementa nenhum dos dois por completo. O README do nbvcxz informa que a compatibilidade estrita com o zxcvbn não é um objetivo dele.

| Aspecto | zxcvbn | nbvcxz | huehue |
|---|---|---|---|
| Linguagem | CoffeeScript / JavaScript | Java | Python |
| Resultado principal | Número de tentativas e nota de 0 a 4 | Entropia, com valor mínimo configurável | Número de tentativas e nota de 0 a 4 |
| Dicionários | Senhas comuns, nomes e palavras do inglês | Vários, configuráveis, ranqueados ou não | Senhas comuns, nomes e sobrenomes (BR e EN), palavras do inglês |
| Casamento aproximado (distância de Levenshtein) | Não | Sim, configurável | Não |
| Substituição de letras (`p4ssw0rd`) e palavras invertidas | Sim | — | Não |
| Teclado | Caminhos pelo teclado, com curvas | Sim | Apenas linhas retas |
| Repetição | Caractere e blocos (`abcabc`) | Caracteres e conjuntos de caracteres | Apenas um caractere |
| Datas | Várias formas, com separadores | Datas e anos | `DDMMAA` e `DDMMAAAA`, com ou sem `/` |
| Força bruta | Alfabeto fixo de 10 | Alfabeto por grupos de caracteres | Alfabeto por grupos de caracteres |
| Busca da decomposição | `l! × produto + D^(l−1)` | Combinação de menor entropia | Igual ao zxcvbn |
| Tempo de quebra | 4 cenários de ataque | Tipos de hash configuráveis | 4 cenários do zxcvbn; tipos de hash opcionais |
| Consulta de vazamentos (HIBP) | Não | — | Sim |
| Lista proibida e regras de composição | Não | Dicionários de exclusão e entropia mínima | Sim |

"—" indica que a informação não foi identificada na documentação consultada do projeto.

### 7.2 Limitações do huehue

**Padrões não detectados**

- Substituição de letras por números e símbolos (`p4ssw0rd`, `s3nh@`).
- Palavras escritas ao contrário.
- Palavras com erro de digitação ou pequenas variações.
- Sequências de letras (`abc`, `xyz`). Apenas sequências numéricas de 3 dígitos são detectadas.
- Repetição de blocos (`abcabc`).
- Teclado em diagonal ou com curvas. Apenas linhas retas das 4 fileiras (`1234567890`, `qwertyuiop`, `asdfghjkl`, `zxcvbnm`).
- Datas em outros formatos, por exemplo, com `-` ou `.` como separador, ou `AAAAMMDD`.

**Detecção**

- Os detectores de data, repetição, sequência e teclado retornam **uma única ocorrência** por senha.
- Os dicionários contêm nomes e sobrenomes brasileiros e de língua inglesa, mas apenas palavras comuns do **inglês**. Palavras do português não são reconhecidas como palavras e entram como força bruta.
- A análise de padrões e a estimativa de tentativas consideram apenas os primeiros 128 caracteres da senha.
- A consulta ao HIBP, a verificação da blacklist e as regras de composição utilizam a senha inteira.
