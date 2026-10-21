# syntax=docker/dockerfile:1
FROM node:20-alpine AS base
WORKDIR /app

# No dependencies to install, but keep the layer honest for future additions.
COPY package.json ./

COPY src ./src
COPY public ./public

ENV NODE_ENV=production
ENV PORT=3000

# Run unprivileged.
USER node

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "src/server.js"]
