FROM node:18

WORKDIR /var/www/

COPY package*.json ./

RUN npm ci --legacy-peer-deps -q

COPY config ./config
COPY tsconfig.build.json ./
COPY tsconfig.json ./
COPY nest-cli.json ./
COPY .env ./
COPY src ./src

RUN npm run build
RUN npm prune --production --legacy-peer-deps

RUN chown -R node:node /var/www/*

USER node

ENV NODE_ENV=production

EXPOSE 3000
EXPOSE 5000

CMD ["npm", "run", "start:prod"]
