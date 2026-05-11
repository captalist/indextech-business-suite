# API + SQLite + static UI — persist /app/data for the database
FROM node:20-bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y python3 make g++ \
  && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json* ./
RUN npm install --omit=dev
COPY server.js index.html ./
ENV NODE_ENV=production
ENV PORT=8080
EXPOSE 8080
VOLUME ["/app/data"]
CMD ["node", "server.js"]
