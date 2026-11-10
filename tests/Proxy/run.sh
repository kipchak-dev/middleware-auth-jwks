#!/usr/bin/env bash
# Runs tests/Proxy against a real outbound proxy, in Docker, and removes everything it started:
#  - jwks.test, an nginx serving the key set over HTTPS and HTTP, on a network the host cannot resolve, so a fetch
#    that succeeds came through a proxy; it is also published on 127.0.0.1:18443 for the no_proxy test;
#  - an open tinyproxy on 127.0.0.1:18888, and one requiring Basic credentials on 127.0.0.1:18889.
#
#   bash tests/Proxy/run.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

name=jwks-proxy-test
work="$(mktemp -d)"
cleanup() {
	docker rm -f "${name}-idp" "${name}-open" "${name}-auth" > /dev/null 2>&1 || true
	docker network rm "${name}" > /dev/null 2>&1 || true
	docker rmi "${name}-tinyproxy" > /dev/null 2>&1 || true
	rm -rf "${work}"
}
trap cleanup EXIT

# A CA and a certificate for jwks.test and localhost, which PHP is told to trust for this run only.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=jwks proxy test CA' \
	-keyout "${work}/ca.key" -out "${work}/ca.pem" 2> /dev/null
openssl req -newkey rsa:2048 -nodes -subj '/CN=jwks.test' -keyout "${work}/idp.key" -out "${work}/idp.csr" 2> /dev/null
printf 'subjectAltName=DNS:jwks.test,DNS:localhost,IP:127.0.0.1\n' > "${work}/san.ext"
openssl x509 -req -in "${work}/idp.csr" -CA "${work}/ca.pem" -CAkey "${work}/ca.key" -CAcreateserial -days 1 \
	-extfile "${work}/san.ext" -out "${work}/idp.pem" 2> /dev/null

mkdir -p "${work}/www"
cat > "${work}/nginx.conf" <<'EOF'
server {
	listen 80;
	listen 443 ssl;
	server_name jwks.test localhost;
	ssl_certificate /etc/nginx/certs/idp.pem;
	ssl_certificate_key /etc/nginx/certs/idp.key;
	location / { root /www; default_type application/json; }
}
EOF

cat > "${work}/Dockerfile" <<'EOF'
FROM alpine:3.24
RUN apk add --no-cache tinyproxy
COPY tinyproxy.conf /etc/tinyproxy/tinyproxy.conf
ENTRYPOINT ["tinyproxy", "-d", "-c", "/etc/tinyproxy/tinyproxy.conf"]
EOF
printf 'Port 8888\nListen 0.0.0.0\nTimeout 30\nMaxClients 20\nAllow 0.0.0.0/0\nConnectPort 443\nConnectPort 80\nLogLevel Info\n' > "${work}/tinyproxy.conf"
docker build -q -t "${name}-tinyproxy" "${work}" > /dev/null

docker network create "${name}" > /dev/null
docker run -d --name "${name}-idp" --network "${name}" --network-alias jwks.test -p 127.0.0.1:18443:443 \
	-v "${work}/nginx.conf:/etc/nginx/conf.d/default.conf:ro" -v "${work}:/etc/nginx/certs:ro" -v "${work}/www:/www:ro" \
	nginx:alpine > /dev/null
docker run -d --name "${name}-open" --network "${name}" -p 127.0.0.1:18888:8888 "${name}-tinyproxy" > /dev/null
docker run -d --name "${name}-auth" --network "${name}" -p 127.0.0.1:18889:8888 \
	--entrypoint sh "${name}-tinyproxy" -c 'cp /etc/tinyproxy/tinyproxy.conf /tmp/t.conf && echo "BasicAuth jwks-user s3cret-proxy-pass" >> /tmp/t.conf && exec tinyproxy -d -c /tmp/t.conf' > /dev/null

for _ in $(seq 1 30); do
	curl -s -o /dev/null --cacert "${work}/ca.pem" https://localhost:18443/ && nc -z 127.0.0.1 18888 && nc -z 127.0.0.1 18889 && break
	sleep 1
done

JWKS_PROXY_TEST_WWW="${work}/www" php -d "openssl.cafile=${work}/ca.pem" vendor/bin/phpunit --testsuite Proxy "$@"
