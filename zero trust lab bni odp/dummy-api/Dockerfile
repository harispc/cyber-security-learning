FROM node:20-alpine

WORKDIR /app

# install build deps if needed (small), then cleanup
RUN apk add --no-cache tini

COPY package*.json ./
RUN npm install --production

COPY . .

EXPOSE 3000

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "server.js"]
