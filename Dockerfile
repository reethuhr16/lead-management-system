FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN apk add --no-cache python3 make g++ && npm install --omit=dev
COPY . .
ENV NODE_ENV=production DB_PATH=/data/leads.db
VOLUME /data
EXPOSE 3000
CMD ["node","server.js"]
