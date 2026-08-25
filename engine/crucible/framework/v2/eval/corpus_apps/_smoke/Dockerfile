# Corpus DOCKER smoke image — built from a cached node base (no registry pull).
# Proves the real DockerLauncher lifecycle against a live daemon.
# A14: digest-pinned so the corpus app the launcher lifecycle is proven against is the SAME
# image every run — a floating tag would silently change the thing under test.
# node:22-bookworm, resolved 2026-08-12.
FROM node:22-bookworm@sha256:8a34c4ab3ea2c5cd194f07e317b2a8f09461d3c8b05c4e34c8ccd56d56024c4d
WORKDIR /app
COPY app.js .
EXPOSE 8080
ENV PORT=8080
CMD ["node", "app.js"]
