# A14: digest-pinned. This corpus app is GROUND TRUTH for a CVE reproduction — if the base
# image drifts, the ground truth drifts with it and the benchmark silently stops measuring the
# same thing. node:22-bookworm, resolved 2026-08-12.
FROM node:22-bookworm@sha256:0557ac14e0d45d02ed563067b82856ca5e7aa3437fa28d98d4350ea9c3d9494a
WORKDIR /app
COPY . .
ENV PORT=8080
EXPOSE 8080
CMD ["node","app.js"]
