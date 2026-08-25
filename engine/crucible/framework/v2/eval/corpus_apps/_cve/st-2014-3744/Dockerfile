# A14: digest-pinned. This corpus app is GROUND TRUTH for a CVE reproduction — if the base
# image drifts, the ground truth drifts with it and the benchmark silently stops measuring the
# same thing. node:22-bookworm, resolved 2026-08-12.
FROM node:22-bookworm@sha256:fbe64f0a038c6117d58d6a160c52994ee586cab9e36812802b564ac2d464bb24
WORKDIR /app
COPY . .
ENV PORT=8080
EXPOSE 8080
CMD ["node","app.js"]
