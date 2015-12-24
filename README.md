# How to configure & deploy a modular Nginx web server + Naxsi Web Application Firewall on Ubuntu 14.04.2 LTS

### Introduction

We thought it was a good idea to write a tutorial about Nginx + Naxsi on Ubuntu because it is a popular product combination and the Ubuntu repositories typically do not contain recent versions of the Nginx web server with the Naxsi security module. This means that you cannot simply install a recent stable Nginx+Naxsi release with a single `apt-get install` command. You need to make and build the binaries, and configure everything yourself (such as the service).

This tutorial explains in simple terms how to configure and deploy a modular Nginx + Naxsi web server. The tutorial also addresses specific needs such as security and administration.

The setup includes various security measures such as the Naxsi Web Application Firewall, a system to exclude Spamhaus IP sources (to reject the worst spammers) and a system for connection throttling.

The setup includes various administration features such as the Nginx Stats page and a system to allow/reject specific client IP addresses.

Note that Nginx does not support .htaccess files and that the modules can only be loaded/specified at compile time of the Nginx binary.

The end result will be a robust modular Nginx web server for serving your static files with the following latest stable versions: Nginx V1.8.0 of Apr2015, Naxsi 0.53-2 of 2014. This baseline configuration can very easily be customized by you so it fits your specific needs. A future tutorial might cover the setup to serve PHP scripts as well using PHP-FPM.

Methodology:
1. Perform a standard Ubuntu apt-get install (or reinstall) of nginx. Note that this will install the older nginx v1.4.6. This install ensures the overall setup is done correctly: the /etc/nginx/ directory and subdirectories, the service nginx, etc.
2. Build, make and install the latest stable Nginx v1.8.0 including Naxsi 0.53-2.
3. Modify the config files for a modular setup of the Nginx server and the sits it will serve.

Prerequisites:
* A droplet configured for Ubuntu 14.04.2 LTS.
* SSH access to your droplet.
* A user with sudo privileges, <^>sammy<^> in this tutorial.
* A web server name for which you want to configure the website, <^>www.example.com<^> in this tutorial.

## Step 1 — Installing the required Ubuntu packages

Install the Ubuntu packages that are required for this tutorial.
```
sudo apt-get install build-essential libpcre3-dev make mcrypt
```

## Step 2222 — Installing Nginx using APT

This step installs the Nginx Ubuntu package using APT.

Update the Package Index on your droplet.
```
sudo apt-get update
```

Install the package `nginx`.
```
sudo apt-get install nginx
```
```
[secondary label Output]
The following NEW packages will be installed:
    nginx nginx-common nginx-core
```

Put the installed packages of the previous step on hold in APT because we will manually install newer versions of the software. Putting them on hold means they will never be upgraded again.
```
sudo apt-mark hold nginx nginx-common nginx-core
```

Verify that Nginx has been installed.
```
nginx -v
```
```
[secondary label Output]
nginx version: nginx/1.4.6
```

## Step 2 — Download the latest Nginx and Naxsi sources

This step downloads the correct sources and saves them in an appropriate directory.

Prepare the target directories for the downloads.
```
rm -r           ~/nginx-naxsi-1.8.0-buildfromsource/
mkdir --parents ~/nginx-naxsi-1.8.0-buildfromsource/
cd              ~/nginx-naxsi-1.8.0-buildfromsource/
```

Download the sources.
```
wget http://nginx.org/download/nginx-1.8.0.tar.gz
wget https://github.com/nbs-system/naxsi/archive/0.53-2.tar.gz
```

Unzip and extract the sources in the current directory.
```
tar -xvzf nginx-1.8.0.tar.gz
tar -xvzf 0.53-2.tar.gz
```

## Step 3 — Make and install the new binaries

This step will compile, make and install the Nginx-Naxsi environment.

Notes:
* Nginx will decide the order of modules according the order of the module's directive in the ./configure command. It is important to always put the naxsi module first.
* The options of the .configure command have been taken mainly from the Ubuntu package for Nginx V1.4.6
* The `make install` command will deploy the binary and the config files to the correct directories. Note that the service is not installed by this command because it is Ubuntu specific.

Configure the make.
```
cd nginx-1.8.0
./configure \
	--add-module=../naxsi-0.53-2/naxsi_src/ \
	--with-cc-opt='-g -O2 -fstack-protector --param=ssp-buffer-size=4 -Wformat -Werror=format-security -D_FORTIFY_SOURCE=2' \
	--with-ld-opt='-Wl,-Bsymbolic-functions -Wl,-z,relro' \
	--prefix=/usr/share/nginx \
	--sbin-path=/usr/sbin/nginx \
	--conf-path=/etc/nginx/nginx.conf \
	--error-log-path=/var/log/nginx/error.log \
	--http-log-path=/var/log/nginx/access.log \
	--pid-path=/run/nginx.pid \
	--lock-path=/var/lock/nginx.lock \
	--http-client-body-temp-path=/var/lib/nginx/body \
	--http-proxy-temp-path=/var/lib/nginx/proxy --http-fastcgi-temp-path=/var/lib/nginx/fastcgi \
	--http-scgi-temp-path=/var/lib/nginx/scgi --http-uwsgi-temp-path=/var/lib/nginx/uwsgi \
	--with-debug --with-pcre-jit --with-ipv6 \
	--with-http_ssl_module --with-http_stub_status_module --with-http_realip_module \
	--without-http_scgi_module --without-http_uwsgi_module \
	--without-mail_imap_module --without-mail_pop3_module --without-mail_smtp_module
```

Execute the make. This will create the binary and the config files.
```
make
```

Execute the make install. This will deploy the binary and the config files to the specified directories.
```
sudo make install
```
```
[secondary label Output]
    make -f objs/Makefile install
    make[1]: Entering directory `~/nginx-naxsi-1.8.0-buildfromsource/nginx-1.8.0'
    test -d '/usr/share/nginx' || mkdir -p '/usr/share/nginx'
    test -d '/usr/sbin'             || mkdir -p '/usr/sbin'
    test ! -f '/usr/sbin/nginx'             || mv '/usr/sbin/nginx'                         '/usr/sbin/nginx.old'
    cp objs/nginx '/usr/sbin/nginx'
    test -d '/etc/nginx'            || mkdir -p '/etc/nginx'
    cp conf/koi-win '/etc/nginx'
    cp conf/koi-utf '/etc/nginx'
    cp conf/win-utf '/etc/nginx'
    test -f '/etc/nginx/mime.types'                 || cp conf/mime.types '/etc/nginx'
    cp conf/mime.types '/etc/nginx/mime.types.default'
    test -f '/etc/nginx/fastcgi_params'             || cp conf/fastcgi_params '/etc/nginx'
    cp conf/fastcgi_params          '/etc/nginx/fastcgi_params.default'
    test -f '/etc/nginx/fastcgi.conf'               || cp conf/fastcgi.conf '/etc/nginx'
    cp conf/fastcgi.conf '/etc/nginx/fastcgi.conf.default'
    test -f '/etc/nginx/uwsgi_params'               || cp conf/uwsgi_params '/etc/nginx'
    cp conf/uwsgi_params            '/etc/nginx/uwsgi_params.default'
    test -f '/etc/nginx/scgi_params'                || cp conf/scgi_params '/etc/nginx'
    cp conf/scgi_params             '/etc/nginx/scgi_params.default'
    test -f '/etc/nginx/nginx.conf'                 || cp conf/nginx.conf '/etc/nginx/nginx.conf'
    cp conf/nginx.conf '/etc/nginx/nginx.conf.default'
    test -d '/run'          || mkdir -p '/run'
    test -d '/var/log/nginx' ||             mkdir -p '/var/log/nginx'
    test -d '/usr/share/nginx/html'                 || cp -R html '/usr/share/nginx'
    test -d '/var/log/nginx' ||             mkdir -p '/var/log/nginx'
    make[1]: Leaving directory `~/nginx-naxsi-1.8.0-buildfromsource/nginx-1.8.0'
```

Verify that correct version of Nginx has been installed. The output must refer to version `1.8.0`.
```
nginx -v
```
```
[secondary label Output]
nginx version: nginx/1.8.0
```

## Step 4 — Create the global Nginx configuration file

This step will create the Nginx main HTTP config file. Note that this config file refers to other config files that will be created in later steps. The various settings are clearly documented within the config file.

```
read -r -d '' FILECONTENT <<'ENDFILECONTENT'

# The Linux user that will be used by the worker processes.
user www-data;

# The number of worker processes are automatically determined. The value is typically the number of CPU's on your droplet.
worker_processes auto;

pid /run/nginx.pid;
events {
        ## Set the maximum number of simultaneous connections that can be opened by a worker process.
        #   Each browser uses 4 connections.
        worker_connections 512;
}
http {
        #
        ## Security: Deny all except me (HTTP level).
        # 		Uncomment this include to quickly block public access to all the Nginx sites of this Nginx HTTP server (except me). This feature becomes handy when preparing a website but you do not want it to be available to the public.
        #####include /etc/nginx/my_deny_all_except_me.conf;

        #
        ## Security: Banned IP addresses (HTTP level).
        #       This include configures the HTTP server to ban certain IP addresses that you have defined.
        include /etc/nginx/my_banip_http.conf;

        #
        ## Security: Spamhaus Drop list (HTTP level).
        #       This include configures the HTTP server to ban all IP addresses that are marked as spammers by the Spamhaus service.
        include /etc/nginx/my_spamhaus_http.conf;

        #
        ## Stability: Connection throttler (HTTP level)
        #       This include configures the HTTP server to throttle the number of requests by one client.
        limit_conn_zone $binary_remote_addr zone=zone-addr:10m;

        #
        ## Basic Settings
        #       These are some typical network settings for Nginx.
        sendfile on;
        tcp_nopush on;
        tcp_nodelay on;
        server_names_hash_bucket_size 64;
        types_hash_max_size 2048;
        keepalive_timeout 5;
        underscores_in_headers on;

        #
        ## Security:
        #       Do not generate the Nginx version in the error messages and the HTTP headers.
        server_tokens off;

        #
        ## MIME Types
        include /etc/nginx/mime.types;
        default_type application/octet-stream;

        #
        ## Logging Settings
        #       These are the log files for the main HTTP server. Note that the virtual servers (your websites) will have their own log files.
        access_log /var/log/nginx/access.log;
        error_log  /var/log/nginx/error.log warn;

        #
        ## Gzip Settings
        # 		The gzip_type text/html is gzipped by default, no need to add it here.
        gzip on;

        gzip_comp_level 6;
        gzip_disable "msie6";
        gzip_proxied any;
        gzip_types text/plain text/css application/json application/javascript application/x-javascript text/javascript text/xml application/xml application/rss+xml application/atom+xml application/rdf+xml;
        gzip_vary on;

        #
        ## nginx-naxsi rules (HTTP level)
        #       Include the standard rule set of Naxsi and your custom rule set.
        include /etc/nginx/naxsi_core.rules;
        include /etc/nginx/my_naxsi_custom_rules_http.conf;

        #
        ## Virtual Host definitions and extra Config files
        #       Include the extra config files in the conf.d directory and the config files that contain the definition of your sites.
        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/*;
}
ENDFILECONTENT
sudo echo "$FILECONTENT" > /etc/nginx/nginx.conf
```

## Step 5 — Configure the Nginx Status page

This step will configure the Nginx Status page. It displays some statistics of your Nginx server. The access to this web page should be restricted.

Remember to specify your client IP address and your server IP address to the allow list. Your client IP address is typically that of the active SSH connection that you are using right now to connect to the server.

Create the configuration file for the Nginx Status
```
read -r -d '' FILECONTENT <<'ENDFILECONTENT'
	#
	## Server Status page (restricted access)
	location /nginx-status {

		# The stub_status command triggers the display of the Nginx status information at this location.
		stub_status;

		#
		## Security: DENY ALL EXCEPT MYSELF.
		# 		BLOCK PUBLIC ACCESS to this location (except me and my servers).
		include /etc/nginx/my_deny_all_except_me.conf;
	}
ENDFILECONTENT
sudo echo "$FILECONTENT" > /etc/nginx/my_nginxstatus_server.conf
```

## Step 6 — Configure the MIME Types

This step will configure the MIME Types. This standard file is referenced in the nginx GLOBAL config file. You need to copy the default file to the current file because the current config file is the one that belongs to the older Nginx version (which was installed using `apt-get`).

Copy the default config file of Nginx v1.8.0.
```
sudo cp /etc/nginx/mime.types.default /etc/nginx/mime.types
```

## Step 7 — Configure the include file that restricts access to the web server

This include file is referenced in the main Nginx config file, in which it is disabled by default. You can enable the include in case of security breaches and system upgrades. Secondly, it is also included in the Nginx Status page.

Remember to specify your client IP address and your server IP address in the allow list. Your client IP address is typically that of the active SSH connection that you are using right now to connect to the server.

You can determine the public IP address of your droplet server as follows:
```
echo $(ip route get 8.8.8.8 | awk '{print $NF; exit}')
```

You can determine your client IP address as follows:
```
echo $(who | awk '{print $NF; exit}')
```

Create the config file `/etc/nginx/my_deny_all_except_me.conf`
```
#
## Security: Deny all except my client IP and my server IP.
#       You can add more 'allow' lines if needed, but remember that the line 'deny all' must always be the last line.
#       You can also specify IP masks.
#       Examples:
#           1.2.3.4;
#	        1.2.3.0/24;
#           1.2.0.0/16;
#           1.0.0.0/8;
allow       <^>your_client_ip<^>;
allow       <^>your_server_ip<^>;
deny  all;
```


## Step 8  — Configure the include file that bans certain IP addresses

The configuration file set consists of 3 files:
1. A config file containing the list of banned IP addresses or IP blocks.
2. A config file to be included in the main nginx HTTP config file (`/etc/nginx/nginx.conf`).
3. A config file to be included in each Nginx site config file.

Create the config file `/etc/nginx/my_banip_list_http.conf`. It contains the list of banned IP addresses.
```
## Banned IP addresses list
#    Examples:
#      255.255.255.255 1;
#	   1.2.3.0/24 1;
#      1.2.0.0/16 1;
#      1.0.0.0/8 1;
## Test: ban my home ip address
#####<^>your_client_ip<^>;
## Ban Listing:
#####a.b.c.d 1;
```

Create the Nginx HTTP include file `/etc/nginx/my_banip_http.conf`.
```
## Banned IP addresses
#		The ngx_http_geo_module module creates variables with values depending on the client IP address.
geo $is_banned_ip {
    default 0;
    # Including my list.
    include /etc/nginx/my_banip_list_http.conf;
}
```

Create the Nginx site include file `/etc/nginx/my_banip_server.conf`.
```
## Banned IP addresses (it refers to a variable in the HTTP section).
# 		HTTP status code 444 = No Response (Nginx).
if ($is_banned_ip) {
        return 444;
}
```


## Step 9  — Configure drop access & deny access to specific web files

This step makes sure that the access logs do not mention trivial web files such as `favicon.ico` and `robots.txt`. This is typically called 'dropping'.

The step also denies access to specific web files such as backups and Wordpress configuration files (if any).

Create the config file `/etc/nginx/my_drops_server.conf`
```
# [Drop = No logging at all.]
# 1. Drop access logs for these files: favicon robots.txt
# 2. Deny access to the ".*" files (including .htaccess); a good one when you migrate from Apache to Nginx.
# 3. Deny access to typical backup directories and files.
# 4. Deny access to typical Wordpress files.
location =  /favicon.ico { access_log off; log_not_found off; }
location =  /robots.txt  { access_log off; log_not_found off; }
location ~*  /\.         { deny all; }
location ~*  /backup     { deny all; }
location ~* ~$           { deny all; }
location ~* .bak$        { deny all; }
location ~* .old$        { deny all; }
location ~* .save$       { deny all; }
location ~* (wp-config.php|readme.html) { deny all; }
```

## Step 10  — Configure the Naxsi WAF (Web Application Firewall)

This step configures the Naxsi WAF. It protects you from malicious attacks on your web server.

The Naxsi core rules are defined in the config file `/etc/nginx/naxsi_core.rules`.

You can also define your own rules. We typically reserve the range 9000-9099 of rule ID's for our own rules.

Add your specific Naxsi rules in the config file `/etc/nginx/my_naxsi_custom_rules_http.conf`. This include file is referenced later in the Nginx sites config file(s).
```
## My own rules for my sites (HTTP Level).
MainRule "str:bash -c" "msg:shellshock bash -c" "mz:HEADERS" "s:$MJD:1" id:9001;
```

Create the config file `/etc/nginx/my_naxsi_custom_rules_server.conf` which contains your own rules.
```
## My rules for my servers (server site Level).

## Disable LearningMode once, and only once, you have done some testing and created some whitelist rules.
#####LearningMode;

SecRulesEnabled;
#####SecRulesDisabled;

DeniedUrl "/request-denied";

## Check Rules
CheckRule "$MJD >= 1" BLOCK;
CheckRule "$SQL >= 8" BLOCK;
CheckRule "$RFI >= 8" BLOCK;
CheckRule "$TRAVERSAL >= 4" BLOCK;
CheckRule "$EVADE >= 4" BLOCK;
CheckRule "$XSS >= 8" BLOCK;
```


## Step 10  — Configure the Spamhaus security rules

This step configures the Spamhaus rules. The Spamhaus rules contains IP addresses that are marked as spammers. We use the Github project `nginx-spamhaus-drop` to generate the IP address list.

Clone the Github project
```
cd /usr/local/sbin
sudo git clone git://github.com/perusio/nginx-spamhaus-drop.git
```

Verify the correct operation of this script.
```
sudo cd /usr/local/sbin/nginx-spamhaus-drop/
sudo ./nginx-drop-fetch  /etc/nginx/my_spamhaus_drop_list.conf
sudo cat /etc/nginx/my_spamhaus_drop_list.conf
```

Create the include file `/etc/nginx/my_spamhaus_http.conf` for the Nginx HTTP config file.
```
## Spamhaus Drop list: part http.
geo $is_spamhaus_drop {
    default 0;
    ## Including the list.
    include /etc/nginx/my_spamhaus_drop_list.conf;
}
```

Create the include file `/etc/nginx/my_spamhaus_server.conf` for the Nginx site(s) config file.
```
## Spamhaus server - Drop list: part server (it refers to a variable from the http section).
if ($is_spamhaus_drop) {
    return 444;
}
```

Create a cron job which refreshes the Spamhaus IP address list weekly.
```
sudo mkdir --parents /etc/rolf
read -r -d '' FILECONTENT <<'ENDFILECONTENT'
#!/bin/sh
    #	TIP The first line may not be indented!
    exec > /var/log/`basename $0`.log 2>&1
    echo Start of ${0}
    date
    rm -f /etc/nginx/my_spamhaus_drop_list.conf
    cd /usr/local/sbin/nginx-spamhaus-drop/
    ./nginx-drop-fetch  /etc/nginx/my_spamhaus_drop_list.conf
    service nginx reload
    echo End of ${0}
ENDFILECONTENT
sudo echo "$FILECONTENT" > /etc/rolf/mjd-nginx-spamhaus-cron.sh
```

Mark it as eXecutable.
```
chmod +x /etc/rolf/mjd-nginx-spamhaus-cron.sh
```

Test the cron job script. The config file `my_spamhaus_drop_list.conf` should contain a list of IP addresses.
```
sudo /etc/rolf/mjd-nginx-spamhaus-cron.sh
sudo cat /var/log/mjd-nginx-spamhaus-cron.sh.log
sudo ll /etc/nginx/my_spamhaus_drop_list.conf
sudo tail /etc/nginx/my_spamhaus_drop_list.conf
```

Define the cron job.
```
read -r -d '' FILECONTENT <<'ENDFILECONTENT'
#Production: Every Saturday (6) at 04:00h am
00 04 * * 6 root /etc/rolf/mjd-nginx-spamhaus-cron.sh
#Testing my jobs. Every 1 minute.
#####*/1 * * * * root /etc/rolf/mjd-nginx-spamhaus-cron.sh
ENDFILECONTENT
sudo echo "$FILECONTENT" > /etc/cron.d/nginx-spamhaus
```

Reload the cron service so that the new cron job is validated and activated.
```
sudo service cron reload
```


## Step 10  — Configure the default Nginx site for port 80

This step creates a specific default site config file for port 80 to make sure that improper access to the server on that port 80 is denied, except for the Nginx sites that we have configured.

The Nginx environment contains a default site/server config file. We will keep this config file as a reference but we will not enable it.

Disable the "default" site definition.
```
sudo rm /etc/nginx/sites-enabled/default
sudo mv /etc/nginx/sites-available/default /etc/nginx/sites-available/default.original-from-install
```

Create the default Nginx site config file `/etc/nginx/sites-available/default-server-for-port-80.conf` for port 80.
```
    ## Deny undeclared server names (also by IP) by declaring this "default server" for this port.
    # 	TIP: Specify ipv6only=on in here once, but NEVER AGAIN in the specific nginx sites config files later on, else Nginx will not start.
    # 	Returns HTTP 444 (No Response). It is used in the Nginx logs to indicate that the server has returned no information to the client and has closed the connection.
    server {
        listen       80        default_server;
        listen       [::]:80   default_server ipv6only=on;
        server_name  _;
        return       444;
    }
```

Enable the default Nginx site config file for port 80.
```
sudo ln -s /etc/nginx/sites-available/default-server-for-port-80.conf /etc/nginx/sites-enabled/default-server-for-port-80.conf
```


## Step 12 — Create the directory that will contain the files of the Nginx site <^>www.example.com<^> on port 80

This step creates the directory for your web files. The files must be accessible by the Linux user `www-data`. The directory name clearly indicates by which web server it is used.

```
sudo mkdir <^>/var/nginx-www-example-com-80<^>
sudo chown --changes --recursive www-data:www-data <^>/var/nginx-www-example-com-80<^>
```

## Step 13  — Configure the Nginx site <^>www.example.com<^> for port 80

This step configures an actual Nginx site. An Nginx site or Nginx server is the equivalent of an Apache Virtual Host. We will start with the site <^>www.example.com<^>.

Create our default Nginx site config file `/etc/nginx/sites-available/<^>www-example-com-80.conf<^>`  for port 80.
```
read -r -d '' FILECONTENT <<'ENDFILECONTENT'
	server {
		listen 80;
		listen [::]:80;

		#
		## Make site accessible from (_=any servername)
		server_name <^>www.example.com<^>;

		#
		## Document Root
		root <^>/var/nginx-www-example-com-80<^>;

		#
		## Security Server Level: DENY ALL EXCEPT MYSELF.
		# 		Uncomment this (http)-include to quickly BLOCK PUBLIC ACCESS to THIS SERVER SITE (except me).
		#
		#####include /etc/nginx/my_deny_all_except_me.conf;

		#
		## Banned IP addresses: server part.
		include /etc/nginx/my_banip_server.conf;

		#
		## Spamhaus server - Drop list: server part (it refers to a variable from the http section).
		include /etc/nginx/my_spamhaus_server.conf;

		#
		## Connection throttler (Part 2)
		# 		Limit to max. 25 simultaneous connections per IP adres.
		limit_conn zone-addr 25;

		#
		## Main Location.
		# 		Includes the nginx-naxsi rules (server part)
		location / {
			# My Naxsi rules
			include /etc/nginx/my_naxsi_custom_rules_server.conf;

			# First attempt to serve the request as file, then as directory, then fall back to displaying the 404-not-found page.
			try_files $uri $uri/ =404;
		}

		#
		## nginx-naxsi debugging (SERVER part)
		# 		Enable nginx-naxsi extensive logging to get more information in the error log.
		#   	Add the flag in your server {} section but out of your location.
		#   	[Activate it only temporarily as it blows up the error log!].
		#####set $naxsi_extensive_log 1;

		#
		## Cache control for static files. 4 weeks.
		# 		The ?: prefix is a 'non-capturing' mark, meaning we do not require the pattern to be captured into $1 which improves performance.
		location ~ \.(?:ico|css|js|gif|jpe?g|pdf|png|txt)$ {
			expires 4w;
			add_header Pragma public;
			add_header Cache-Control "public, must-revalidate, proxy-revalidate";
		}

		#
		## Naxsi /request-denied location
		# 		Returns HTTP 418. I'm a teapot (RFC 2324), defined as one of the traditional IETF April Fools' jokes.
		# 		INFO DO not return 444 (HTTP Nginx No Response) as it does not work!
		location /request-denied {
			return 418;
		}

		#
		## Deny access to ALL scripts (security hole: else their source could be downloaded!)
		location ~* \.(perl|php|py)$ {
			deny all;
		}

		#
		## Drop these files
		include /etc/nginx/my_drops_server.conf;

		#
		## Server Status page
		include /etc/nginx/my_nginxstatus_server.conf;

		#
		## Logging Settings
		# 		error_log: defaultlevel=warn is good (=info is not sufficient).
		# 		error_log: defaultlevel=debug for all details.

		access_log /var/log/nginx/<^>access-www-example-com-80.log<^>;

		error_log /var/log/nginx/<^>error-www-example-com-80.log<^> warn;
		#####error_log /var/log/nginx/<^>error-www-example-com-80.log<^> debug;

	}
ENDFILECONTENT
sudo echo "$FILECONTENT" > /etc/nginx/sites-available/<^>www-example-com-80.conf<^>

```

Enable the Nginx site config file for port 80.
```
sudo ln -s /etc/nginx/sites-available/<^>www-example-com-80.conf<^> /etc/nginx/sites-enabled/<^>www-example-com-80.conf<^>
```


## Step 14 — Validate the Nginx config files

This step verifies that all config files are valid.

```
nginx -t
```
```
[secondary_label Expected Output]
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```


## Step 15 — Reload the service configurations of the Upstart daemon

The Upstart daemon manages all services on your system. We have changed the service definition of the Nginx service. It is therefore necessary to restart the Upstart daemon. We will also verify the correct configuration of the Nginx service.

Reload the Upstart services configuration
```
sudo initctl check-config
sudo initctl reload-configuration
```

## Step 16 — Test the correct system operation of the Nginx-powered website <^>http://www.example.com/<^>

Restart the nginx Upstart service
```
sudo service nginx restart
```

Check that the Nginx Linux process(es) are running.
```
ps -eF --sort=+comm  | grep "UID\|nginx"
```

Check that the Nginx daemon is listening on port 80
```
netstat -tap | grep nginx
```

Check the Nginx server log for problems.
```
sudo tail /var/log/nginx/error.log
```

## Step 17 — Test some web files of the Nginx-powered website <^>http://www.example.com/<^>

Create the web file `<^>/var/nginx-www-example-com-80/index.html<^>`
```
<!DOCTYPE html>
<html lang="nl-BE">
<head>
<title>index.html</title>
</head>
<body>
<p>Hello, this is the index.html</p>
</body></html>
```

The web files must be owned by the Linux user `www-data`.
```
sudo chown --changes --recursive www-data:www-data <^>/var/nginx-www-example-com-80<^>
```

Point your browser to this web file <^>http://www.example.com/<^>index.html
```
[secondary_label Expected Output]
Hello, this is the index.html
```


## How to manage the Nginx service?

The Nginx service which is defined within the Upstart system of Ubuntu can be managed with the standard Upstart service commands. The Nginx binary `nginx` also provides command-line options to manage the daemon.

This section list the commands . Please do not execute them right now one after the other. We have listed them here for future use.

Stopping the Nginx server
```
sudo service nginx stop
sudo service nginx status
ps -eF --sort=+comm | egrep "UID|nginx" ; netstat -tap | grep nginx
```

Starting the Nginx service
```
sudo service nginx status
sudo service nginx start
sudo service nginx status
ps -eF --sort=+comm | egrep "UID|nginx" ; netstat -tap | grep nginx
```

Restarting the nginx configuration file
```
sudo service nginx restart
sudo service nginx status
ps -eF --sort=+comm | egrep "UID|nginx" ; netstat -tap | grep nginx
```

Reloading gracefully the Nginx configuration file(s)
```
sudo service nginx reload
sudo service nginx status
ps -eF --sort=+comm | egrep "UID|nginx" ; netstat -tap | grep nginx
```

Controlling the Nginx daemon directly can be achieved by using the following Nginx command-line options.

Stop the Nginx daemon
```
sudo nginx -s stop
```

Start the Nginx daemon
```
sudo nginx -g 'daemon on; master_process on;'
```


## Congratulations

You have successfully configured a modular Nginx server with an initial static website configuration for <^>http://www.example.com/<^>


--------------------------------------------------------------------------------
LEMP - Post Action: NGINX FILE PERMISSIONS and OWNERSHIP.

- Pre Tests
	find /var/nginx-common          -user root

- *CRUCIAL* Ownership (Phase 1 - FTP typically nullifies the user-owner of the files and directories...)
	chown --changes --recursive www-data:www-data /var/nginx-cloud-12220
