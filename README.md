Passe partout v0.1
==================

passe-partout is a tool to extract SSL private keys from process memory written by Nicolas Collignon and Jean-Baptiste Aviat (passe-partout@hsc.fr).

More information may be found at the following URLs:

* http://www.hsc.fr/ressources/breves/passe-partout.html.en
* http://www.hsc.fr/ressources/breves/passe-partout.html.fr

Tested to work with:
* sshd and ssh-agent (from OpenSSH 7.4p1 running on Fedora 24)
* sshd and ssh-agent (from OpenSSH 6.1)
* ssh-agent running on macOS Sierra (System Integrity Protection needs to be turned off)
* Apache httpd 2.2.23
* Nginx 1.2.6
* Node.js v0.8.15
* Thin web server (v1.5.0 codename Knife)
* Tomcat 7.0.34 + apr 1.4.6 + jdk7-openjdk 7.u9
* CherryPy 3.2.2 + Python 2.7.3 (load generation is required to catch live SSL_CTX objects)
* Tornado 2.4.1 + Python 2.7.3 (load generation is required to catch live SSL_CTX objects)
* Tornado 2.4.1 + Python 3.3.0 (load generation is required to catch live SSL_CTX objects)

Test Platform (if not specified): Arch Linux 64-bit, OpenSSL 1.0.1c

License: Beerware

Authors: Nicolas Collignon and Jean-Baptiste Aviat


