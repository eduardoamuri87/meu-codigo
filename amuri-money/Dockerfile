FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN DATABASE_URL=file:/tmp/build.db npx next build --webpack
CMD ["npm", "start"]
