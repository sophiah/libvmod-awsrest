===================
vmod_awsrest
===================

-------------------------------
Varnish AWS REST API module
-------------------------------
Copy from 
https://github.com/xcir/libvmod-awsrest

SYNOPSIS
========

import awsrestv2;

DESCRIPTION
===========
Purpose for the changes
  * Validate the client requests for the cached objects with standard AWS APIs 
  * Changing url for some requirements at proxy level, using `v4_validate` with previous token, and re-issue with `v4_generic` 

FUNCTIONS
============

v4_validate
------------------
Prototype
        ::

                v4_validate(
                    STRING access_key,            // [your access key]
                    STRING secret_key,            // [your secret key]
                )
Return value
	Bool
