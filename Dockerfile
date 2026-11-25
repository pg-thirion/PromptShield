FROM node:22-bookworm-slim
ENV NODE_ENV=production PORT=3000 PS_BIND=0.0.0.0
WORKDIR /app
COPY --chown=node:node package.json server.mjs index.html ./
COPY --chown=node:node src ./src
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s CMD node -e "const h=process.env.PS_ALLOWED_HOSTS.split(',')[0].trim();fetch('http://127.0.0.1:3000/healthz',{headers:{host:h}}).then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node","server.mjs"]
