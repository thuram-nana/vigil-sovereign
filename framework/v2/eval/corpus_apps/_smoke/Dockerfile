# Corpus DOCKER smoke image — built from a cached node base (no registry pull).
# Proves the real DockerLauncher lifecycle against a live daemon.
FROM node:22-bookworm
WORKDIR /app
COPY app.js .
EXPOSE 8080
ENV PORT=8080
CMD ["node", "app.js"]
