FROM nginx

COPY --link ./frontend/nginx.conf /etc/nginx/

# TODO: Replace with certbot and use configure docker compose to use a volume for keys
COPY --link ./frontend/fullchain.pem /etc/keys/local.evan-brass.net.pem
COPY --link ./frontend/privkey.pem /etc/keys/local.evan-brass.net.key.pem

# Static content
COPY --link ./frontend/static /data/www
COPY --link ./src /data/www/swbrd
