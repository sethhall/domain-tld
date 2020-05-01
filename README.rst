Domain-TLD
==========

This package is a Zeek script library that give developers the ability to efficiently 
discover if a given domain name is effectively a TLD. It was created to help
Zeek developers easily discover if domains like `google.uk.co` are effectively TLDs. 
It avoids the trouble of splitting on periods and making the incorrect assumption
that `uk` is the interesting component of the name. It also has functionality to 
extract the domain and subdomain from the FQDN.

Installation
------------

::

	zkg install sethhall/domain-tld

API
---

For now, refer to the inline documentation in the `scripts/main.zeek` script.
