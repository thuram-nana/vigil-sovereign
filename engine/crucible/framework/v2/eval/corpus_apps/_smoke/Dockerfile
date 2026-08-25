# Corpus DOCKER smoke image — built from a cached node base (no registry pull).
# Proves the real DockerLauncher lifecycle against a live daemon.
# A14: digest-pinned so the corpus app the launcher lifecycle is proven against is the SAME
# image every run — a floating tag would silently change the thing under test.
# node:22-bookworm, resolved 2026-08-12.
FROM node:22-bookworm@sha256:fbe64f0a038c6117d58d6a160c52994ee586cab9e36812802b564ac2d464bb24
WORKDIR /app
COPY app.js .
EXPOSE 8080
ENV PORT=8080
CMD ["node", "app.js"]
