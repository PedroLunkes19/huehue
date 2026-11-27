# Arquitetura

## 1. Visão geral

O `huehue` é organizado em módulos com responsabilidades distintas. O pacote `core` coordena a análise de senhas, `matchers` identificam padrões previsíveis, `rules` aplicam verificações independentes e `models` definem as estruturas de dados utilizadas para representar os resultados da análise.

## 2. Estrutura do projeto

A estrutura relevante do projeto está organizada da seguinte forma:

```text
huehue/
├── src/
│   └── password_analyzer/
│       ├── api/
│       │   └── hibp.py
│       ├── core/
│       │   ├── analyzer.py
│       │   ├── entropy.py
│       │   └── scoring.py
│       ├── matchers/
│       │   ├── dates.py
│       │   ├── dictionary.py
│       │   ├── keyboard.py
│       │   ├── patterns.py
│       │   └── repetition.py
│       ├── rules/
│       │   ├── blacklist.py
│       │   └── composition.py
│       ├── models/
│       │   └── result.py
│       ├── data/
│       └── main.py
├── tests/
├── examples/
├── docs/
├── pyproject.toml
└── requirements.txt
```

## 3. Responsabilidades dos módulos

### `api/`

Gerencia a comunicação com serviços externos. A implementação atual integra a API Pwned Passwords do Have I Been Pwned (HIBP) para verificar se uma senha já apareceu em vazamentos de dados conhecidos.

### `core/`

Contém o fluxo principal de análise de senhas e os cálculos utilizados para avaliar sua força.

- **`analyzer.py`** coordena a análise. Realiza a verificação de vazamento, aplica as regras de senha, aciona os módulos de detecção, reúne as correspondências candidatas, chama a busca de pontuação e monta o objeto `PasswordResult`. Também gera avisos e sugestões.
- **`entropy.py`** estima o número de tentativas associado a cada tipo de correspondência, calcula a cardinalidade dos conjuntos de caracteres utilizados na força bruta, constrói tabelas de classificação dos dicionários e converte as estimativas de tentativas em bits de entropia.
- **`scoring.py`** busca a sequência de correspondências não sobrepostas mais fácil de adivinhar, utilizando programação dinâmica. Também converte a estimativa total de tentativas em uma pontuação e estima o tempo necessário para quebrar a senha em cenários predefinidos.

`scoring.py` e `entropy.py` trabalham em conjunto: a busca de pontuação chama `estimate_guesses()` de `entropy.py` para obter o custo de cada correspondência candidata. O primeiro é responsável por selecionar a decomposição e calcular a pontuação geral; o segundo estima o custo de cada padrão individual.

### `matchers/`

Contém as funções responsáveis por identificar estruturas previsíveis em uma senha.

- **`dictionary.py`** procura palavras, senhas comuns, nomes e sobrenomes nos conjuntos de dados carregados. As comparações não diferenciam maiúsculas de minúsculas apenas nos conjuntos de dados configurados para normalização de capitalização.
- **`dates.py`** procura sequências semelhantes a datas nos formatos reconhecidos pelo módulo. Retorna a primeira ocorrência encontrada.
- **`repetition.py`** detecta repetições consecutivas do mesmo caractere e retorna a primeira ocorrência encontrada.
- **`patterns.py`** detecta sequências numéricas em ordem crescente ou decrescente. O analisador utiliza a primeira sequência numérica retornada por esse módulo. Outros padrões identificados por ele, como uma única letra maiúscula no início ou números e caracteres especiais no final da senha, não são adicionados como correspondências independentes pelo analisador.
- **`keyboard.py`** detecta sequências lineares nas linhas horizontais QWERTY suportadas, em ambas as direções. Quando mais de um candidato é encontrado, mantém o mais longo. Caminhos diagonais do teclado não são contemplados.

O analisador converte as saídas dos módulos de detecção em objetos `Match`, que fornecem uma estrutura comum para a busca de sequências.

### `rules/`

Contém verificações aplicadas independentemente da detecção de padrões.

- **`composition.py`** verifica o comprimento mínimo e a presença de letras maiúsculas, letras minúsculas, números e caracteres especiais. As violações geram avisos, mas, isoladamente, não forçam a pontuação final a zero.
- **`blacklist.py`** verifica se a senha completa está presente na lista de bloqueio integrada. O código-fonte atual contém as entradas de exemplo `12345`, `admin` e `password`. Uma correspondência na lista força a pontuação final a zero.

A lista de bloqueio é definida no código-fonte e atualmente não está disponível como opção de configuração em tempo de execução.

### `models/`

Define as estruturas de dados utilizadas durante a análise e na representação do resultado final.

- **`Match`** representa um padrão detectado, incluindo seu tipo, posição, token e metadados específicos do padrão. Seus campos `guesses` armazenam a estimativa calculada por `entropy.py`.
- **`PasswordResult`** armazena a pontuação final, a pontuação bruta, as estimativas de tentativas e entropia, as informações sobre vazamentos, as violações de regras, a sequência de correspondências selecionada, as estimativas de tempo de ataque, os avisos e as sugestões. Seu método `to_dict()` converte o resultado em um dicionário para serialização em JSON.

Embora `PasswordResult` não possua um campo específico contendo a senha completa, seu campo `sequence` pode reter objetos `Match` cujos valores de `token` contêm partes da senha. O campo `rule_violations` também pode conter valores originais. Como `to_dict()` serializa os campos da classe de dados (*dataclass*), esses valores podem ser incluídos na saída JSON. Esse é um risco conhecido de exposição de informações; portanto, a afirmação de que o resultado não armazena a senha não deve ser interpretada como garantia de que ele esteja livre de fragmentos sensíveis.

### `data/`

Contém os conjuntos de dados utilizados pelo módulo de detecção por dicionário. A coleção atual inclui senhas comuns, palavras em inglês, nomes próprios brasileiros e ingleses e sobrenomes brasileiros e ingleses. Os conjuntos de dados são carregados quando uma instância de `PasswordAnalyzer` é inicializada e são utilizados para construir as respectivas tabelas de classificação.

### `main.py`

Fornece a interface de linha de comando. Aceita um argumento opcional de senha e oferece opções para desabilitar a verificação HIBP (`--no-hibp`) ou imprimir o resultado completo em JSON (`--json`). O caminho atual de entrada interativa utiliza `input()`, portanto, os caracteres digitados são exibidos no terminal. O fornecimento de uma senha como argumento de linha de comando também pode expô-la por meio do histórico do shell ou da listagem de processos, dependendo do ambiente.

### `tests/` e `examples/`

`tests/` contém testes automatizados da aplicação. `examples/` contém scripts que demonstram sua utilização.

## 4. Fluxo de análise

O método `PasswordAnalyzer.analyze()` coordena as seguintes etapas:

1. **Verificação de vazamento:** quando habilitada, a senha completa é processada localmente por meio de hash e verificada pela API de intervalo do HIBP. Se a verificação estiver desabilitada ou não puder ser concluída, o estado de vazamento é registrado como desconhecido (`None`) e a análise local continua.
2. **Aplicação das regras:** as regras da lista de bloqueio e de composição são avaliadas com base na senha completa. Uma correspondência na lista de bloqueio é registrada separadamente das violações de composição.
3. **Limitação da entrada para análise local:** por padrão, a análise de padrões considera apenas os primeiros 128 caracteres da senha. Esse limite pode ser alterado por meio do argumento `max_length` do construtor.
4. **Detecção de padrões:** os módulos de detecção procuram padrões na parte analisada da senha. Os resultados são convertidos em objetos `Match`.
5. **Busca de sequência:** `scoring.py` avalia as correspondências candidatas e solicita suas estimativas individuais a `entropy.py`. Trechos não correspondidos são representados por correspondências de força bruta.
6. **Montagem do resultado:** o analisador reúne a pontuação, o estado de vazamento, as violações de regras, as correspondências selecionadas, as estimativas de tempo de ataque, os avisos e as sugestões em um objeto `PasswordResult`.

Uma solicitação HIBP malsucedida ou indisponível não interrompe a análise: a aplicação continua com as verificações locais e registra o estado de vazamento como desconhecido. Uma senha encontrada no HIBP ou na lista de bloqueio recebe uma pontuação final de `0/4`. Caso contrário, a pontuação final é baseada na estimativa de tentativas, com valor mínimo de `1/4`. Os critérios matemáticos por trás das estimativas de tentativas e da pontuação são descritos em `methodology.md`.

```text
                         Entrada da senha
                               |
                               v
                 Verificação HIBP (se habilitada)
                               |
                               v
                      Regras de senha
                (lista de bloqueio e composição)
                               |
                               v
                       Análise local
                 (até 128 caracteres por padrão)
                               |
                  +------------+------------+
                  |            |            |
                  v            v            v
                Busca      Detecção de   Outros módulos
             em dicionários  padrões      de detecção
                  |            |            |
                  +------------+------------+
                               |
                               v
                    Objetos de correspondência
                               |
                               v
                  Busca de sequência (scoring.py)
                               |
                               | solicita estimativas
                               v
                Estimativa de tentativas (entropy.py)
                               |
                               | retorna estimativas
                               v
                    Continuação da busca
                               |
                               v
                  Seleção da melhor sequência
                               |
                               v
                Estimativa de tentativas e pontuação bruta
                               |
                  +------------+------------+
                  |                         |
                  v                         v
       Encontrada em vazamento ou       Sem sobrescrita
          na lista de bloqueio?
                  |                         |
             Sim  |                         | Não
                  v                         v
              Pontuação 0/4          Pontuação final 1-4/4
                  |                         |
                  +------------+------------+
                               |
                               v
                  Tempos de ataque e feedback
                               |
                               v
                         PasswordResult
```

## 5. Decisões arquiteturais

### Separação de responsabilidades

A detecção de padrões, a estimativa de custos das correspondências, a seleção de sequências, as regras de senha e a representação dos resultados são tratadas por módulos separados. Isso mantém cada componente concentrado em uma responsabilidade específica e facilita a compreensão do fluxo de análise.

### Representação comum de correspondências

As funções dos módulos de detecção retornam diferentes tipos de dados. O analisador converte essas saídas em objetos `Match` antes de encaminhá-las para a busca de sequências. Isso fornece uma representação consistente, independentemente do módulo que identificou o padrão.

### Detecção por dicionário baseada em conjuntos de dados

As entradas dos dicionários são mantidas em arquivos de dados externos, em vez de serem incorporadas à lógica dos módulos de detecção. O analisador carrega os conjuntos de dados e constrói as tabelas de classificação quando uma instância de `PasswordAnalyzer` é inicializada. Conjuntos de dados personalizados também podem ser fornecidos por meio do construtor público.

### Dependência configurável para verificação de vazamentos

O `PasswordAnalyzer` aceita um objeto chamável (*callable*) `breach_checker`. Isso permite utilizar a integração padrão com o HIBP, substituí-la por outra função compatível ou desabilitá-la passando `None`. Se uma verificação de vazamento não puder ser concluída, a análise local ainda poderá prosseguir.

### Separação entre regras e pontuação

As verificações de composição e de lista de bloqueio são implementadas separadamente da detecção de padrões e da estimativa de tentativas. As violações de composição geram feedback, enquanto uma correspondência na lista de bloqueio pode sobrescrever a pontuação final. Os critérios detalhados de avaliação estão documentados em `methodology.md`.

## 6. Configuração e interface pública

O construtor de `PasswordAnalyzer` disponibiliza os seguintes parâmetros:

- `datasets`: conjuntos de dados personalizados para o dicionário. Quando omitido, os conjuntos de dados integrados são carregados.
- `breach_checker`: objeto chamável utilizado para a verificação de vazamentos. Por padrão, utiliza o verificador HIBP; passar `None` o desabilita.
- `max_length`: número máximo de caracteres considerados pela busca local de padrões. O valor padrão é 128.
- `bruteforce_scope`: determina se a cardinalidade do conjunto de caracteres da força bruta é calculada por trecho não correspondido (`"token"`, o padrão) ou com base na senha completa (`"password"`).

O principal método público é `analyze(password, check_breach=True)`, que retorna um `PasswordResult`. O módulo também fornece a função de conveniência `analyze_password()`, que reutiliza um analisador padrão inicializado sob demanda.

A interface de linha de comando oferece suporte a:

```bash
password-analyzer --no-hibp
password-analyzer --json --no-hibp
password-analyzer "password-to-check"
```

O comando `huehue` é um alias para `password-analyzer`. As implicações de segurança relacionadas à entrada interativa, aos argumentos de linha de comando e à saída JSON são descritas na Seção 7.1.

## 7. Limitações conhecidas e considerações de segurança

Os pontos a seguir descrevem limitações e riscos da implementação atual. Eles esclarecem o comportamento desta versão e identificam aspectos que podem ser considerados em revisões futuras; não implicam que o código atual tenha sido modificado.

### 7.1 Informações sensíveis nos resultados e no uso da linha de comando

A senha completa não é armazenada em um campo específico de `PasswordResult`. No entanto, os objetos `Match` selecionados mantêm o texto correspondente em `token`, e as entradas de violações de regras podem reter valores originais. Esses objetos fazem parte do resultado e podem ser serializados por `to_dict()` e pela opção `--json` da CLI. Como consequência, a saída JSON pode conter partes da senha e, em alguns casos, valores correspondentes à senha completa.

A CLI atual utiliza `input()` para a entrada interativa da senha, o que exibe os caracteres digitados no terminal. Senhas fornecidas como argumentos posicionais de linha de comando também podem ficar visíveis no histórico do shell ou na listagem de processos. Esses comportamentos representam riscos potenciais de exposição quando a aplicação é utilizada em terminais compartilhados, sessões gravadas, scripts ou ambientes nos quais as informações dos processos podem ser acessadas.

Python não oferece uma garantia geral de que dados armazenados em strings imutáveis possam ser apagados da memória com segurança e de forma imediata. Portanto, reduzir as referências a valores sensíveis e limitar sua serialização pode diminuir a retenção não intencional, mas isso não deve ser descrito como uma garantia de apagamento seguro da memória.

**Possíveis melhorias futuras:** evitar a retenção de fragmentos da senha nas correspondências e de valores originais das violações de regras no resultado público quando eles não forem necessários; oferecer uma forma de serializar resultados sem valores sensíveis; e utilizar um método de entrada de senha que não exiba os caracteres digitados no terminal. Essas melhorias são apenas possibilidades e não estão implementadas na versão atual.

### 7.2 Lista de bloqueio integrada

A lista de bloqueio atual contém três entradas de exemplo (`12345`, `admin` e `password`) diretamente no código-fonte. Ela está ativa durante a análise, e uma correspondência exata força a pontuação final a zero. Atualmente, não é possível configurá-la por meio do construtor público ou da interface de linha de comando.