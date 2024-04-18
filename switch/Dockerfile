FROM --platform=$TARGETPLATFORM denoland/deno:distroless

COPY --link . switch

EXPOSE 3478/tcp

CMD ["run", "--allow-net", "--allow-env", "--no-prompt", "switch/serve.js"]
