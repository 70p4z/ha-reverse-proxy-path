# ha-reverse-proxy-path
Home assistant reverse proxy script to allow for sub path chrooting (http://acme.com/ha/). Which was not possible with bare home assistant

## Overview
```
web-bro <==SSL+BasicAuth==> nginx <--HTTP--> hacs-reverse-proxy.py <---HTTP---> Home Assistant
                [Docker]                                                          [Docker]
            linuxserver/swag                                     ghcr.io/home-assistant/home-assistant:stable
```
NOTES:
- Nginx is responsible for rewrite of webrooted URLs incoming from the web browser. This is the standard way of performing reverse proxy.
- hacs-reverse-proxy rewrites content sent by the HA server to inject webroot

## Setup
. git clone
. python hacs-reverse-proxy.py --webroot <WEBROOT> --upstream <HA server and port>

### Example
https://acme.com/ha => http://server:8123/
$config nginx here to redirect acme.com/ha toward localhost:8124 (see commited script)
python hacs-reverse-proxy.py --webroot /ha --upstream http://server:8123

## Disclaimer
This setup relies on the security model of nginx using basic authentication in my case.
From the HA server point of view, the reverse proxy script IS a proxy, and therefore, it must by authorized as such in home assistant. Without additional authentication or too lazy trusted host configuration, take care not drilling security holes in your configuration.
