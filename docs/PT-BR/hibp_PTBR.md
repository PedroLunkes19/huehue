# Integração com o Have I Been Pwned

## Visão geral

O projeto utiliza a API Pwned Passwords do Have I Been Pwned para verificar se uma senha apareceu em vazamentos de dados conhecidos.

A implementação utiliza o modelo de k-anonimato para evitar o envio da senha original.

## Processo de verificação

1. A senha é convertida localmente em um hash SHA-1.
2. Os primeiros 5 caracteres do hash são enviados à API.
3. A API retorna todos os hashes que possuem o mesmo prefixo.
4. A aplicação pesquisa localmente pelo sufixo restante do hash.
5. Se o sufixo for encontrado, a senha é considerada comprometida.

## Exemplo

Senha:

```text
123456
```

SHA-1:

```text
7C4A8D09CA3762AF61E59520943DC26494F8941B
```

Prefixo enviado:

```text
7C4A8
```

Sufixo verificado localmente:

```text
D09CA3762AF61E59520943DC26494F8941B
```
