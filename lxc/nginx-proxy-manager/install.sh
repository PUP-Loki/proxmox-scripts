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
runcmd 'wget $WGETOPT -c $_npm_url/archive/v$_latest_version.tar.gz -O - | tar -xz'

cat << EOF > /app/global/certbot-dns-plugins.js
/**
 * This file contains info about available Certbot DNS plugins.
 * This only works for plugins which use the standard argument structure, so:
 * --authenticator <plugin-name> --<plugin-name>-credentials <FILE> --<plugin-name>-propagation-seconds <number>
 *
 * File Structure:
 *
 *  {
 *    cloudflare: {
 *      display_name: "Name displayed to the user",
 *      package_name: "Package name in PyPi repo",
 *      package_version: "Package version in PyPi repo",
 *      dependencies: "Additional dependencies, space separated (as you would pass it to pip install)",
 *      credentials: `Template of the credentials file`,
 *      full_plugin_name: "The full plugin name as used in the commandline with certbot, including prefixes, e.g. 'certbot-dns-njalla:dns-njalla'",
 *    },
 *    ...
 *  }
 *
 */

module.exports = {
	//####################################################//
	acmedns: {
		display_name:    'ACME-DNS',
		package_name:    'certbot-dns-acmedns',
		package_version: '0.1.0',
		dependencies:    '',
		credentials:     `certbot_dns_acmedns:dns_acmedns_api_url = http://acmedns-server/
certbot_dns_acmedns:dns_acmedns_registration_file = /data/acme-registration.json`,
		full_plugin_name: 'certbot-dns-acmedns:dns-acmedns',
	},
	aliyun: {
		display_name:    'Aliyun',
		package_name:    'certbot-dns-aliyun',
		package_version: '0.38.1',
		dependencies:    '',
		credentials:     `certbot_dns_aliyun:dns_aliyun_access_key = 12345678
certbot_dns_aliyun:dns_aliyun_access_key_secret = 1234567890abcdef1234567890abcdef`,
		full_plugin_name: 'certbot-dns-aliyun:dns-aliyun',
	},
	//####################################################//
	azure: {
		display_name:    'Azure',
		package_name:    'certbot-dns-azure',
		package_version: '1.2.0',
		dependencies:    '',
		credentials:     `# This plugin supported API authentication using either Service Principals or utilizing a Managed Identity assigned to the virtual machine.
# Regardless which authentication method used, the identity will need the “DNS Zone Contributor” role assigned to it.
# As multiple Azure DNS Zones in multiple resource groups can exist, the config file needs a mapping of zone to resource group ID. Multiple zones -> ID mappings can be listed by using the key dns_azure_zoneX where X is a unique number. At least 1 zone mapping is required.

# Using a service principal (option 1)
dns_azure_sp_client_id = 912ce44a-0156-4669-ae22-c16a17d34ca5
dns_azure_sp_client_secret = E-xqXU83Y-jzTI6xe9fs2YC~mck3ZzUih9
dns_azure_tenant_id = ed1090f3-ab18-4b12-816c-599af8a88cf7

# Using used assigned MSI (option 2)
# dns_azure_msi_client_id = 912ce44a-0156-4669-ae22-c16a17d34ca5

# Using system assigned MSI (option 3)
# dns_azure_msi_system_assigned = true

# Zones (at least one always required)
dns_azure_zone1 = example.com:/subscriptions/c135abce-d87d-48df-936c-15596c6968a5/resourceGroups/dns1
dns_azure_zone2 = example.org:/subscriptions/99800903-fb14-4992-9aff-12eaf2744622/resourceGroups/dns2`,
		full_plugin_name: 'dns-azure',
	},
	//####################################################//
	cloudflare: {
		display_name:    'Cloudflare',
		package_name:    'certbot-dns-cloudflare',
		package_version: '1.8.0',
		dependencies:    'cloudflare',
		credentials:     `# Cloudflare API token
dns_cloudflare_api_token = 0123456789abcdef0123456789abcdef01234567`,
		full_plugin_name: 'dns-cloudflare',
	},
	//####################################################//
	cloudns: {
		display_name:    'ClouDNS',
		package_name:    'certbot-dns-cloudns',
		package_version: '0.4.0',
		dependencies:    '',
		credentials:     `# Target user ID (see https://www.cloudns.net/api-settings/)
	dns_cloudns_auth_id=1234
	# Alternatively, one of the following two options can be set:
	# dns_cloudns_sub_auth_id=1234
	# dns_cloudns_sub_auth_user=foobar 
	
	# API password
	dns_cloudns_auth_password=password1`,
		full_plugin_name: 'dns-cloudns',
	},
	//####################################################//
	cloudxns: {
		display_name:    'CloudXNS',
		package_name:    'certbot-dns-cloudxns',
		package_version: '1.8.0',
		dependencies:    '',
		credentials:     `dns_cloudxns_api_key = 1234567890abcdef1234567890abcdef
dns_cloudxns_secret_key = 1122334455667788`,
		full_plugin_name: 'dns-cloudxns',
	},
	//####################################################//
	corenetworks: {
		display_name:    'Core Networks',
		package_name:    'certbot-dns-corenetworks',
		package_version: '0.1.4',
		dependencies:    '',
		credentials:     `certbot_dns_corenetworks:dns_corenetworks_username = asaHB12r
certbot_dns_corenetworks:dns_corenetworks_password = secure_password`,
		full_plugin_name: 'certbot-dns-corenetworks:dns-corenetworks',
	},
	//####################################################//
	cpanel: {
		display_name:    'cPanel',
		package_name:    'certbot-dns-cpanel',
		package_version: '0.2.2',
		dependencies:    '',
		credentials:     `certbot_dns_cpanel:cpanel_url = https://cpanel.example.com:2083
certbot_dns_cpanel:cpanel_username = user
certbot_dns_cpanel:cpanel_password = hunter2`,
		full_plugin_name: 'certbot-dns-cpanel:cpanel',
	},
	//####################################################//
	duckdns: {
		display_name:     'DuckDNS',
		package_name:     'certbot-dns-duckdns',
		package_version:  '0.6',
		dependencies:     '',
		credentials:      'dns_duckdns_token=your-duckdns-token',
		full_plugin_name: 'dns-duckdns',
	},
	//####################################################//
	digitalocean: {
		display_name:     'DigitalOcean',
		package_name:     'certbot-dns-digitalocean',
		package_version:  '1.8.0',
		dependencies:     '',
		credentials:      'dns_digitalocean_token = 0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff',
		full_plugin_name: 'dns-digitalocean',
	},
	//####################################################//
	directadmin: {
		display_name:    'DirectAdmin',
		package_name:    'certbot-dns-directadmin',
		package_version: '0.0.20',
		dependencies:    '',
		credentials:     `directadmin_url = https://my.directadminserver.com:2222
directadmin_username = username
directadmin_password = aSuperStrongPassword`,
		full_plugin_name: 'certbot-dns-directadmin:directadmin',
	},
	//####################################################//
	dnsimple: {
		display_name:     'DNSimple',
		package_name:     'certbot-dns-dnsimple',
		package_version:  '1.8.0',
		dependencies:     '',
		credentials:      'dns_dnsimple_token = MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw',
		full_plugin_name: 'dns-dnsimple',
	},
	//####################################################//
	dnsmadeeasy: {
		display_name:    'DNS Made Easy',
		package_name:    'certbot-dns-dnsmadeeasy',
		package_version: '1.8.0',
		dependencies:    '',
		credentials:     `dns_dnsmadeeasy_api_key = 1c1a3c91-4770-4ce7-96f4-54c0eb0e457a
dns_dnsmadeeasy_secret_key = c9b5625f-9834-4ff8-baba-4ed5f32cae55`,
		full_plugin_name: 'dns-dnsmadeeasy',
	},
	//####################################################//
	dnspod: {
		display_name:    'DNSPod',
		package_name:    'certbot-dns-dnspod',
		package_version: '0.1.0',
		dependencies:    '',
		credentials:     `certbot_dns_dnspod:dns_dnspod_email = "DNSPOD-API-REQUIRES-A-VALID-EMAIL"
certbot_dns_dnspod:dns_dnspod_api_token = "DNSPOD-API-TOKEN"`,
		full_plugin_name: 'certbot-dns-dnspod:dns-dnspod',
	},
	//####################################################//
	dynu: {
		display_name:     'Dynu',
		package_name:     'certbot-dns-dynu',
		package_version:  '0.0.1',
		dependencies:     '',
		credentials:      'certbot_dns_dynu:dns_dynu_auth_token = YOUR_DYNU_AUTH_TOKEN',
		full_plugin_name: 'certbot-dns-dynu:dns-dynu',
	},
	//####################################################//
	eurodns: {
		display_name:    'EuroDNS',
		package_name:    'certbot-dns-eurodns',
		package_version: '0.0.4',
		dependencies:    '',
		credentials:     `dns_eurodns_applicationId = myuser
dns_eurodns_apiKey = mysecretpassword
dns_eurodns_endpoint = https://rest-api.eurodns.com/user-api-gateway/proxy`,
		full_plugin_name: 'certbot-dns-eurodns:dns-eurodns',
	},
	//####################################################//
	gandi: {
		display_name:     'Gandi Live DNS',
		package_name:     'certbot_plugin_gandi',
		package_version:  '1.2.5',
		dependencies:     '',
		credentials:      'certbot_plugin_gandi:dns_api_key = APIKEY',
		full_plugin_name: 'certbot-plugin-gandi:dns',
	},
	//####################################################//
	godaddy: {
		display_name:    'GoDaddy',
		package_name:    'certbot-dns-godaddy',
		package_version: '0.2.0',
		dependencies:    '',
		credentials:     `dns_godaddy_secret = 0123456789abcdef0123456789abcdef01234567
dns_godaddy_key = abcdef0123456789abcdef01234567abcdef0123`,
		full_plugin_name: 'dns-godaddy',
	},
	//####################################################//
	google: {
		display_name:    'Google',
		package_name:    'certbot-dns-google',
		package_version: '1.8.0',
		dependencies:    '',
		credentials:     `{
"type": "service_account",
...
}`,
		full_plugin_name: 'dns-google',
	},
	//####################################################//
	hetzner: {
		display_name:     'Hetzner',
		package_name:     'certbot-dns-hetzner',
		package_version:  '1.0.4',
		dependencies:     '',
		credentials:      'certbot_dns_hetzner:dns_hetzner_api_token = 0123456789abcdef0123456789abcdef',
		full_plugin_name: 'certbot-dns-hetzner:dns-hetzner',
	},
	//####################################################//
	infomaniak: {
		display_name:     'Infomaniak',
		package_name:     'certbot-dns-infomaniak',
		package_version:  '0.1.12',
		dependencies:     '',
		credentials:      'certbot_dns_infomaniak:dns_infomaniak_token = XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
		full_plugin_name: 'certbot-dns-infomaniak:dns-infomaniak',
	},
	//####################################################//
	inwx: {
		display_name:    'INWX',
		package_name:    'certbot-dns-inwx',
		package_version: '2.1.2',
		dependencies:    '',
		credentials:     `certbot_dns_inwx:dns_inwx_url = https://api.domrobot.com/xmlrpc/
certbot_dns_inwx:dns_inwx_username = your_username
certbot_dns_inwx:dns_inwx_password = your_password
certbot_dns_inwx:dns_inwx_shared_secret = your_shared_secret optional`,
		full_plugin_name: 'certbot-dns-inwx:dns-inwx',
	},
	//####################################################//
	ionos: {
		display_name:    'IONOS',
		package_name:    'certbot-dns-ionos',
		package_version: '0.0.7',
		dependencies:    '',
		credentials:     `certbot_dns_ionos:dns_ionos_prefix = myapikeyprefix
certbot_dns_ionos:dns_ionos_secret = verysecureapikeysecret
certbot_dns_ionos:dns_ionos_endpoint = https://api.hosting.ionos.com`,
		full_plugin_name: 'certbot-dns-ionos:dns-ionos',
	},
	//####################################################//
	ispconfig: {
		display_name:    'ISPConfig',
		package_name:    'certbot-dns-ispconfig',
		package_version: '0.2.0',
		dependencies:    '',
		credentials:     `certbot_dns_ispconfig:dns_ispconfig_username = myremoteuser
certbot_dns_ispconfig:dns_ispconfig_password = verysecureremoteuserpassword
certbot_dns_ispconfig:dns_ispconfig_endpoint = https://localhost:8080`,
		full_plugin_name: 'certbot-dns-ispconfig:dns-ispconfig',
	},
	//####################################################//
	isset: {
		display_name:    'Isset',
		package_name:    'certbot-dns-isset',
		package_version: '0.0.3',
		dependencies:    '',
		credentials:     `certbot_dns_isset:dns_isset_endpoint="https://customer.isset.net/api"
certbot_dns_isset:dns_isset_token="<token>"`,
		full_plugin_name: 'certbot-dns-isset:dns-isset',
	},
	//####################################################//
	joker: {
		display_name:    'Joker',
		package_name:    'certbot-dns-joker',
		package_version: '1.1.0',
		dependencies:    '',
		credentials:     `certbot_dns_joker:dns_joker_username = USERNAME
certbot_dns_joker:dns_joker_password = PASSWORD
certbot_dns_joker:dns_joker_domain = DOMAIN`,
		full_plugin_name: 'certbot-dns-joker:dns-joker',
	},
	//####################################################//
	linode: {
		display_name:    'Linode',
		package_name:    'certbot-dns-linode',
		package_version: '1.8.0',
		dependencies:    '',
		credentials:     `dns_linode_key = 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ64
dns_linode_version = [<blank>|3|4]`,
		full_plugin_name: 'dns-linode',
	},
	//####################################################//
	luadns: {
		display_name:    'LuaDNS',
		package_name:    'certbot-dns-luadns',
		package_version: '1.8.0',
		dependencies:    '',
		credentials:     `dns_luadns_email = user@example.com
dns_luadns_token = 0123456789abcdef0123456789abcdef`,
		full_plugin_name: 'dns-luadns',
	},
	//####################################################//
	netcup: {
		display_name:    'netcup',
		package_name:    'certbot-dns-netcup',
		package_version: '1.0.0',
		dependencies:    '',
		credentials:     `certbot_dns_netcup:dns_netcup_customer_id  = 123456
certbot_dns_netcup:dns_netcup_api_key      = 0123456789abcdef0123456789abcdef01234567
certbot_dns_netcup:dns_netcup_api_password = abcdef0123456789abcdef01234567abcdef0123`,
		full_plugin_name: 'certbot-dns-netcup:dns-netcup',
	},
	//####################################################//
	njalla: {
		display_name:     'Njalla',
		package_name:     'certbot-dns-njalla',
		package_version:  '1.0.0',
		dependencies:     '',
		credentials:      'certbot_dns_njalla:dns_njalla_token = 0123456789abcdef0123456789abcdef01234567',
		full_plugin_name: 'certbot-dns-njalla:dns-njalla',
	},
	//####################################################//
	nsone: {
		display_name:     'NS1',
		package_name:     'certbot-dns-nsone',
		package_version:  '1.8.0',
		dependencies:     '',
		credentials:      'dns_nsone_api_key = MDAwMDAwMDAwMDAwMDAw',
		full_plugin_name: 'dns-nsone',
	},
	//####################################################//
	ovh: {
		display_name:    'OVH',
		package_name:    'certbot-dns-ovh',
		package_version: '1.8.0',
		dependencies:    '',
		credentials:     `dns_ovh_endpoint = ovh-eu
dns_ovh_application_key = MDAwMDAwMDAwMDAw
dns_ovh_application_secret = MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw
dns_ovh_consumer_key = MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw`,
		full_plugin_name: 'dns-ovh',
	},
	//####################################################//
	porkbun: {
		display_name:    'Porkbun',
		package_name:    'certbot-dns-porkbun',
		package_version: '0.2',
		dependencies:    '',
		credentials:     `dns_porkbun_key=your-porkbun-api-key
dns_porkbun_secret=your-porkbun-api-secret`,
		full_plugin_name: 'dns-porkbun',
	},
	//####################################################//
	powerdns: {
		display_name:    'PowerDNS',
		package_name:    'certbot-dns-powerdns',
		package_version: '0.2.0',
		dependencies:    '',
		credentials:     `certbot_dns_powerdns:dns_powerdns_api_url = https://api.mypowerdns.example.org
certbot_dns_powerdns:dns_powerdns_api_key = AbCbASsd!@34`,
		full_plugin_name: 'certbot-dns-powerdns:dns-powerdns',
	},
	//####################################################//
	regru: {
		display_name:    'reg.ru',
		package_name:    'certbot-regru',
		package_version: '1.0.2',
		dependencies:    '',
		credentials:     `certbot_regru:dns_username=username
certbot_regru:dns_password=password`,
		full_plugin_name: 'certbot-regru:dns',
	},
	//####################################################//
	rfc2136: {
		display_name:    'RFC 2136',
		package_name:    'certbot-dns-rfc2136',
		package_version: '1.8.0',
		dependencies:    '',
		credentials:     `# Target DNS server
dns_rfc2136_server = 192.0.2.1
# Target DNS port
dns_rfc2136_port = 53
# TSIG key name
dns_rfc2136_name = keyname.
# TSIG key secret
dns_rfc2136_secret = 4q4wM/2I180UXoMyN4INVhJNi8V9BCV+jMw2mXgZw/CSuxUT8C7NKKFs AmKd7ak51vWKgSl12ib86oQRPkpDjg==
# TSIG key algorithm
dns_rfc2136_algorithm = HMAC-SHA512`,
		full_plugin_name: 'dns-rfc2136',
	},
	//####################################################//
	route53: {
		display_name:    'Route 53 (Amazon)',
		package_name:    'certbot-dns-route53',
		package_version: '1.8.0',
		dependencies:    '',
		credentials:     `[default]
aws_access_key_id=AKIAIOSFODNN7EXAMPLE
aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`,
		full_plugin_name: 'dns-route53',
	},
	//####################################################//
	transip: {
		display_name:    'TransIP',
		package_name:    'certbot-dns-transip',
		package_version: '0.3.3',
		dependencies:    '',
		credentials:     `certbot_dns_transip:dns_transip_username = my_username
certbot_dns_transip:dns_transip_key_file = /etc/letsencrypt/transip-rsa.key`,
		full_plugin_name: 'certbot-dns-transip:dns-transip',
	},
	//####################################################//
	vultr: {
		display_name:     'Vultr',
		package_name:     'certbot-dns-vultr',
		package_version:  '1.0.3',
		dependencies:     '',
		credentials:      'certbot_dns_vultr:dns_vultr_key = YOUR_VULTR_API_KEY',
		full_plugin_name: 'certbot-dns-vultr:dns-vultr',
	},
};

EOF

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
