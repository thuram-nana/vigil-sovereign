# Corpus DOCKER smoke image — built from a cached node base (no registry pull).
# Proves the real DockerLauncher lifecycle against a live daemon.
# A14: digest-pinned so the corpus app the launcher lifecycle is proven against is the SAME
# image every run — a floating tag would silently change the thing under test.
# node:22-bookworm, resolved 2026-08-12.
FROM node:22-bookworm@sha256:0557ac14e0d45d02ed563067b82856ca5e7aa3437fa28d98d4350ea9c3d9494a
WORKDIR /app
COPY app.js .
EXPOSE 8080
ENV PORT=8080
CMD ["node", "app.js"]
