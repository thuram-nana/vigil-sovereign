# A14: digest-pinned. This corpus app is GROUND TRUTH for a CVE reproduction — if the base
# image drifts, the ground truth drifts with it and the benchmark silently stops measuring the
# same thing. node:22-bookworm, resolved 2026-08-12.
FROM node:22-bookworm@sha256:8a34c4ab3ea2c5cd194f07e317b2a8f09461d3c8b05c4e34c8ccd56d56024c4d
WORKDIR /app
COPY . .
ENV PORT=8080
EXPOSE 8080
CMD ["node","app.js"]
