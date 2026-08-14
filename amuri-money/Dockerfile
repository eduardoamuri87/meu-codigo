FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN DATABASE_URL=file:/tmp/build.db npx next build --webpack
# A convergência de schema roda aqui, e não em release_command, porque máquinas
# de release do Fly não montam o volume onde o SQLite vive. Se o schema estiver
# defasado o boot falha e o deploy é abortado — melhor que 500 em toda request.
CMD ["sh", "-c", "node scripts/ensure-schema.mjs && npm start"]
