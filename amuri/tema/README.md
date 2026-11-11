# Amuri Cursos

## Requerimentos
* Node versão 18.16.0

## Instalação

Rodar a partir da pasta do projeto: 

```
npm install
```

## Compilar o arquivo CSS

```
gulp css
```

## Browser sync com watch para o navegador
Recarrega o navegador ao salvar arquivos PHP, JS ou CSS.
Para configurar o proxy do Browser sync deve-se criar um arquivo chamado `gulp-config.json` na raiz do tema e configurá-lo com a URL que está rodando o projeto, exemplo:
```
{
    "proxyURL": "http://localhost:8888/"
}
```

Em seguida rodar o watch com o comando:

```
gulp
```