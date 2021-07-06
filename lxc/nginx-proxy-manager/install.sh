#!/usr/bin/env sh
set -euo pipefail

trap trapexit EXIT SIGTERM

TEMPDIR=$(mktemp -d)
TEMPLOG="$TEMPDIR/tmplog"
TEMPERR="$TEMPDIR/tmperr"
LASTCMD=""
WGETOPT="-t 1 -T 15 -q"
DEVDEPS="jq npm g++ make gcc git python3-dev musl-dev libffi-dev openssl-dev"

cd $TEMPDIR
touch $TEMPLOG

# Helpers
log() { logs=$(cat $TEMPLOG | sed -e "s/34/32/g" | sed -e "s/info/success/g"); clear && printf "\033c\e[3J$logs\n\e[34m[info] $*\e[0m\n" | tee $TEMPLOG; }
runcmd() { 
  LASTCMD=$(grep -n "$*" "$0" | sed "s/[[:blank:]]*runcmd//");
  if [[ "$#" -eq 1 ]]; then
    eval "$@" 2>$TEMPERR;
  else
    $@ 2>$TEMPERR;
  fi
}
trapexit() {
  status=$?
  
  if [[ $status -eq 0 ]]; then
    logs=$(cat $TEMPLOG | sed -e "s/34/32/g" | sed -e "s/info/success/g")
    clear && printf "\033c\e[3J$logs\n";
  elif [[ -s $TEMPERR ]]; then
    logs=$(cat $TEMPLOG | sed -e "s/34/31/g" | sed -e "s/info/error/g")
    err=$(cat $TEMPERR | sed $'s,\x1b\\[[0-9;]*[a-zA-Z],,g' | rev | cut -d':' -f1 | rev | cut -d' ' -f2-) 
    clear && printf "\033c\e[3J$logs\e[33m\n$0: line $LASTCMD\n\e[33;2;3m$err\e[0m\n"
  else
    printf "\e[33muncaught error occurred\n\e[0m"
  fi
  # Cleanup
  rm -rf $TEMPDIR
  apk del $DEVDEPS &>/dev/null
}

# Check for previous install
if [ -f /etc/init.d/npm ]; then
  log "Stopping services"
  rc-service npm stop &>/dev/null
  rc-service openresty stop &>/dev/null
  sleep 2

  log "Cleaning old files"
  # Cleanup for new install
  rm -rf /app \
  /var/www/html \
  /etc/nginx \
  /var/log/nginx \
  /var/lib/nginx \
  /var/cache/nginx &>/dev/null

  log "Removing old dependencies"
  apk del certbot $DEVDEPS &>/dev/null
fi

log "Checking for latest openresty repository"
. /etc/os-release
_alpine_version=${VERSION_ID%.*}
_npm_url="https://github.com/jc21/nginx-proxy-manager"
# add openresty public key
if [ ! -f /etc/apk/keys/admin@openresty.com-5ea678a6.rsa.pub ]; then
  runcmd 'wget $WGETOPT -P /etc/apk/keys/ http://openresty.org/package/admin@openresty.com-5ea678a6.rsa.pub'
fi

# Get the latest openresty repository
_repository_version=$(wget $WGETOPT "http://openresty.org/package/alpine/" -O - | grep -Eo "[0-9]{1}\.[0-9]{1,2}" | sort -uVr | head -n1)
_repository_version=$(printf "$_repository_version\n$_alpine_version" | sort -V | head -n1)
_repository="http://openresty.org/package/alpine/v$_repository_version/main"

# Update/Insert openresty repository
grep -q 'openresty.org' /etc/apk/repositories && 
  sed -i "/openresty.org/c\\$_repository/" /etc/apk/repositories || echo $_repository >> /etc/apk/repositories

# Update container OS
log "Updating container OS"
runcmd apk update
runcmd apk upgrade
echo "fs.file-max = 65535" > /etc/sysctl.conf

# Install dependancies
log "Installing dependencies"
runcmd 'apk add python3 openresty nodejs yarn openssl apache2-utils $DEVDEPS'

# Setup python env and PIP
log "Setting up python"
ln -sf /usr/bin/python3 /usr/bin/python
python -m venv /opt/certbot/
runcmd 'wget $WGETOPT -c https://bootstrap.pypa.io/get-pip.py -O - | python'
# Install certbot and python dependancies
runcmd pip install --no-cache-dir -U cryptography==3.3.2
runcmd pip install --no-cache-dir cffi certbot
ln -sf /usr/bin/certbot /opt/certbot/bin/certbot

log "Checking for latest NPM version"
# Get latest version information for nginx-proxy-manager
runcmd 'wget $WGETOPT -O ./_latest_release $_npm_url/releases/latest'
_latest_version=$(basename $(cat ./_latest_release | grep -wo "jc21/.*.tar.gz") .tar.gz | cut -d'v' -f2)

# Download nginx-proxy-manager source
log "Downloading NPM v$_latest_version"
runcmd 'wget $WGETOPT -c https://github.com/PUP-Loki/nginx-proxy-manager/archive/refs/tags/v2.9.4.tar.gz -O - | tar -xz'

cd ./nginx-proxy-manager-$_latest_version
# Copy runtime files
_rootfs=docker/rootfs
mkdir -p /var/www/html && cp -r $_rootfs/var/www/html/* /var/www/html
mkdir -p /etc/nginx/logs && cp -r $_rootfs/etc/nginx/* /etc/nginx
rm -f /etc/nginx/conf.d/dev.conf
cp $_rootfs/etc/letsencrypt.ini /etc/letsencrypt.ini

# Update NPM version in package.json files
echo "`jq --arg _latest_version $_latest_version '.version=$_latest_version' backend/package.json`" > backend/package.json
echo "`jq --arg _latest_version $_latest_version '.version=$_latest_version' frontend/package.json`" > frontend/package.json

# Create required folders
mkdir -p /tmp/nginx/body \
/run/nginx \
/var/log/nginx \
/data/nginx \
/data/custom_ssl \
/data/logs \
/data/access \
/data/nginx/default_host \
/data/nginx/default_www \
/data/nginx/proxy_host \
/data/nginx/redirection_host \
/data/nginx/stream \
/data/nginx/dead_host \
/data/nginx/temp \
/var/lib/nginx/cache/public \
/var/lib/nginx/cache/private \
/var/cache/nginx/proxy_temp

touch /var/log/nginx/error.log && chmod 777 /var/log/nginx/error.log && chmod -R 777 /var/cache/nginx
chown root /tmp/nginx

# Dynamically generate resolvers file, if resolver is IPv6, enclose in `[]`
# thanks @tfmm
echo resolver "$(awk 'BEGIN{ORS=" "} $1=="nameserver" {print ($2 ~ ":")? "["$2"]": $2}' /etc/resolv.conf);" > /etc/nginx/conf.d/include/resolvers.conf

# Generate dummy self-signed certificate.
if [ ! -f /data/nginx/dummycert.pem ] || [ ! -f /data/nginx/dummykey.pem ]
then
  log "Generating dummy SSL certificate"
  runcmd 'openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -subj "/O=Nginx Proxy Manager/OU=Dummy Certificate/CN=localhost" -keyout /data/nginx/dummykey.pem -out /data/nginx/dummycert.pem'
fi

# Copy app files
mkdir -p /app/global
cp -r backend/* /app
cp -r global/* /app/global

# Build the frontend
log "Building frontend"
mkdir -p /app/frontend/images
cd ./frontend
runcmd yarn install
runcmd yarn build
cp -r dist/* /app/frontend
cp -r app-images/* /app/frontend/images

log "Initializing backend"
rm -rf /app/config/default.json &>/dev/null
if [ ! -f /app/config/production.json ]; then
cat << 'EOF' > /app/config/production.json
{
  "database": {
    "engine": "knex-native",
    "knex": {
      "client": "sqlite3",
      "connection": {
        "filename": "/data/database.sqlite"
      }
    }
  }
}
EOF
fi
runcmd cd /app && yarn install

# Create required folders
mkdir -p /data

# Update openresty config
log "Configuring openresty"
cat << 'EOF' > /etc/conf.d/openresty
# Configuration for /etc/init.d/openresty

cfgfile=/etc/nginx/nginx.conf
app_prefix=/etc/nginx
EOF
rc-update add openresty boot &>/dev/null
rc-service openresty stop &>/dev/null

if [ -f /usr/sbin/nginx ]; then
  rm /usr/sbin/nginx
fi
ln -sf /usr/local/openresty/nginx/sbin/nginx /usr/sbin/nginx

# Create NPM service
log "Creating NPM service"
cat << 'EOF' > /etc/init.d/npm
#!/sbin/openrc-run
description="Nginx Proxy Manager"

command="/usr/bin/node" 
command_args="index.js --abort_on_uncaught_exception --max_old_space_size=250"
command_background="yes"
directory="/app"

pidfile="/var/run/npm.pid"
output_log="/var/log/npm.log"
error_log="/var/log/npm.err"

depends () {
  before openresty
}

start_pre() {
  mkdir -p /tmp/nginx/body \
  /data/letsencrypt-acme-challenge

  export NODE_ENV=production
}

stop() {
  pkill -9 -f node
  return 0
}

restart() {
  $0 stop
  $0 start
}
EOF
chmod a+x /etc/init.d/npm
rc-update add npm boot &>/dev/null

# Start services
log "Starting services"
runcmd rc-service openresty start
runcmd rc-service npm start
