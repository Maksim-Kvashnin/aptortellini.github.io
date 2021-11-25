---
layout: post
title: Carrying the Tortellini's golf sticks	
subtitle: Using Caddy to spin up fast and reliable C2 redirectors.
image: /img/tortellinicaddy.jpg
published: true
author:
- Her0
- Electroxero
---
### Giving Caddy redirectors some love

The consultant's life is a difficult one. New business, new setup and sometimes you gotta do everything in a hurry. We are not a top notch security company with a fully automated infra. We are poor, rookies and always learning from the best.

We started by reading several blogposts that can be found on the net, written by people much more experienced than us, realizing that redirectors are almost always based on apache and nginx, which are great solutions! but we wanted to explore other territories...

just to name a few:

https://www.praetorian.com/blog/praetorians-approach-to-red-team-infrastructure/
https://www.mdsec.co.uk/2020/02/testing-your-redteam-infrastructure/
https://www.netspi.com/blog/technical/adversary-simulation/modern-red-team-infrastructure/
https://bluescreenofjeff.com/2017-12-05-designing-effective-covert-red-team-attack-infrastructure/

and many others...

despite the posts described above that are seriously top notch level, we decided to proceed taking inspiration from our fellow countryman Marcello aka byt3bl33d3r which came to the rescue!

https://byt3bl33d3r.substack.com/p/taking-the-pain-out-of-c2-infrastructure

As you can see from his post, Marcello makes available to us mere mortals a quick configuration, which prompted us to want to deepen the argument

### Why Caddy Server ?

Caddy was born as an opensource webserver specifically created to be easy to use and safe. it is written in go and runs on almost every platform.

The added value of Caddy is the automatic system that supports the ability to generate and renew certificates automatically through let's encrypt with basically no effort at all.

Another important factor is the configurative side that is very easy to understand and more minimalist, just what we need!




### Let's Configure!
[![1]({{site.baseurl}}/img/01.jpg)]({{site.baseurl}}/img/01.jpg)


do you remember byt3bl33d3r's post listed just above ? (Of course, you wrote it 4 lines higher...) let's take a cue from it!

First of all let's install Caddy Server with the following commands:

(We are installing it on a AWS EC2 instance)

```bash
sudo yum update
```

```bash
yum install yum-plugin-copr
yum copr enable @caddy/caddy
yum install caddy
```

Once installed, let's go under `/opt` and create a folder named `/caddy` or whatever you like

And inside create the  `Caddyfile`

At this point let's populate the`/caddy` with our own `Caddyfile` and relative folder structure and configurations

To make things clearer, here we have a tree of the structure we are going to implement:

1) The actual `Caddyfile`
2) The `filters` folder, which will contain our countermeasures and defensive mechanisms ( wtf are you talking about there is a bunch of crap inside here)
3) the `sites` folder, which will contain the domains for our red team operation and relative logfiles
4) the `upstreams` folder, which will contain the entire upstreams part
5) the `www` folder, which will contain the sites if we want to farm a categorization for our domains, like hosting a custom index.html or simply clone an exsiting one because we are terrible individuals.

```
.
├── Caddyfile
├── filters
│   ├── allow_ips.caddy
│   ├── bad_ips.caddy
│   ├── bad_ua.caddy
│   └── headers_standard.caddy
├── sites
│   ├── cdn.aptortellini.cloud.caddy
│   └── logs
│       └── cdn.aptortellini.cloud.log 
├── upstreams
│   ├── cobalt_proxy_upstreams.caddy
│   └── reverse_proxy
│       └── cobalt.caddy
└── www
    └── cdn.aptortellini.cloud
        └── index.html
```
### CADDYFILE

This is the default configuration file for Caddy

```
# This are the default ports which instruct caddy to respond where all other configuration are not matched
:80, :443 {
	# Default security headers and custom header to mislead fingerprinting
    header {
        import filters/headers_standard.caddy
    }
	# Just respond "OK" in the body and put the http status code 200 (change this as you desire)
    respond "OK" 200
}

#Import all upstreams configuration files (only with .caddy extension)
import upstreams/*.caddy

#Import all sites configuration files (only with .caddy extension)
import sites/*.caddy
```
[![2]({{site.baseurl}}/img/02.jpg)]({{site.baseurl}}/img/02.jpg)

We decided to keep the Caddyfile as clean as possible, spending some more time structuring and modulating the `.caddy` files

### FILTERS folder

This folder contain all basic configuration for the web server, for example:

* list of IP to block
* list of User Agents (UA) to block
* default implementation of security headers

##### bad_ips.caddy

```
remote_ip mal.ici.ous.ips
```

Still incomplete but usable list we crafted can be found here: https://github.com/her0ness/av-edr-urls/blob/main/AV-EDR-Netblocks

##### bad_ua.caddy
This will block all User-Agent we don't want to visit our domain.
```
header User-Agent curl*
header User-Agent *bot*
```
A very well done bad_ua list can be found, for example, here: https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/blob/master/_generator_lists/bad-user-agents.list

##### headers_standard.caddy

```
# Add a custom fingerprint signature
Server "Apache/2.4.50 (Unix) OpenSSL/1.1.1d"

X-Robots-Tag "noindex, nofollow, nosnippet, noarchive"
X-Content-Type-Options "nosniff"

# disable FLoC tracking
Permissions-Policy interest-cohort=()

# enable HSTS
Strict-Transport-Security max-age=31536000;

# disable clients from sniffing the media type
X-Content-Type-Options nosniff

# clickjacking protection
X-Frame-Options DENY

# keep referrer data off of HTTP connections
Referrer-Policy no-referrer-when-downgrade

# Do not allow to cache the response
Cache-Control no-cache
```
We decided to hardly customize the response `Server` header to mislead any detection based on response headers.

### SITES folder

You may see this folder similar to `sites-available` and `sites-enabled` in nginx; where you store the whole host configuration.

#### Example front-end redirector (cdn.aptortellini.cloud.caddy)

From our experience ( false, we are rookies) this file should contain a single host because we have decided to uniquely identify each individual host, but feel free to add as many as you want, You messy!

```
https://cdn.aptortellini.cloud {

	# Import the proxy upstream for the cobalt beacon
    import cobalt_proxy_upstream

    # Default security headers and custom header to mislead fingerprinting
    header {
            import ../filters/headers_standard.caddy
    }
	
	# Put caddy logs to a specified location
    log {
	    output file sites/logs/cdn.aptortellini.cloud.log
	    format console
	}
		
	# Define the root folder for the content of the website if you want to serve one
	root * www/cdn.aptortellini.cloud
    file_server
}
```

#### UPSTREAMS folder

the file contains the entire upstream part, the inner part of the reverse proxy has been voluntarily detached because it often requires individual ad-hoc configurations



#### cobalt_proxy_upstreams

```Handle Directive```: Evaluates a group of directives mutually exclusively from other `handle` blocks at the same level of nesting.

The `handle` directive is kind of similar to the `location` directive from nginx config: the first matching `handle` block will be evaluated. Handle blocks can be nested if needed.

To make things more comprehensive, here we have the sample of `http-get` block adopted in the Cobalt Strike malleable profile:

[![3]({{site.baseurl}}/img/03.jpg)]({{site.baseurl}}/img/03.jpg)

```
# Just a fancy name
(cobalt_proxy_upstream) {
    
	# This directive instruct caddy to handle only request which begins with /ms/ (http-get block config pre-defined in the malleable profile for testing purposes)
    handle /ms/* {
       
	    # This is our list of User Agents we want to block
		@ua_denylist {
			import ../filters/bad_ua.caddy
		}

		# This is our list of IPs we want to block
		@ip_denylist {
			import ../filters/bad_ips.caddy
		}

		header {
			import ../filters/headers_standard.caddy
		}

		# Respond 403 to blocked User-Agents
		route @ip_denylist {

             redir https://cultofthepartyparrot.com/ #redir to another site like, for example, an external supplier site which provides services for the company you are targeting ( sneaky move I know..)
        }

		
		# Respond 403 to blocked IPs
		route @ip_denylist {

             redir https://cultofthepartyparrot.com/ #redir to another site like, for example, an external supplier website which provides services for the company you are targeting ( sneaky move I know..) 
        }

	 	# Reverse proxy to our cobalt strike server on port 443 https
    	import reverse_proxy/cobalt.caddy
	}
}
```

#### REVERSE PROXY folder

The reverse proxy directly instruct the https stream connection to forward the request to the teamserver if the rules above are respected.

#### Cobalt Strike redirector to HTTPS endpoint

```
reverse_proxy https://<cobalt_strike_endpoint> {
    
	# This directive put the original X-Forwarded-for header value in the upstream X-Forwarded-For header, you need to use this configuration for example if you are behind cloudfront in order to obtain the correct external ip of the machine you just compromised
    header_up X-Forwarded-For {http.request.header.X-Forwarded-For}
	
	# Standard reverse proxy upstream headers
	header_up Host {upstream_hostport}
    header_up X-Forwarded-Host {host}
    header_up X-Forwarded-Port {port}
    
	# Caddy will not check for SSL certificate to be valid if we are defining the <cobalt_strike_endpoint> with an ip address instead of a domain
	transport http {
        tls
        tls_insecure_skip_verify
    }
}
```
#### WWW

 This folder is reserved if you want to put a website in here and manually categorize it
 
 Or..
 
 take a cue from those who do things better than we do:
 
 https://github.com/mdsecactivebreach/Chameleon
 
#### Starting Caddy

Once started, caddy will automatically obtain the SSL certificate. Remember to start Caddy in the same folder where you placed your `Caddyfile`!

```bash
sudo caddy start
```

[![4]({{site.baseurl}}/img/04.jpg)]({{site.baseurl}}/img/04.jpg)

To reload the configuration, you can just run the following command in the root configuration folder of Caddy

```bash
sudo caddy reload
```
#### Getting a CS Beacon

Everything worked as expected and the beacon is obtained

[![5]({{site.baseurl}}/img/05.jpg)]({{site.baseurl}}/img/05.jpg)

### A final thought

This blogpost is just the beginning of a series focused on making infrastructures for offensive security purposes, in the upcoming months we will expand the section with additional components.

With this we just wanted to try something we never tried before, and we know there are multiple ways to expand the configuration or make it even better, so,  if you are not satisfied with what we just wrote, feel free to offend us: we won't take it personally, promise.
