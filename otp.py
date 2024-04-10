#! /usr/bin/env python3
#
# Python module example file
# Miguel A.L. Paraz <mparaz@mparaz.com>
#
# $Id: 5d437f446e8938beb1d458dc332e4081bf3d5144 $

#
#            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
#                    Version 2, December 2004
#
# Copyright (C) 2021 Ho Phuong Nam <hophuongnam@gmail.com>
#
# Everyone is permitted to copy and distribute verbatim or modified
# copies of this license document, and changing it is allowed as long
# as the name is changed.
#
#            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
#   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
#
#  0. You just DO WHAT THE FUCK YOU WANT TO.

# REDIS keys:
# username => otp key
# username_token => token
# username_email => email address
# username_nootp => 1 (this key exists to signify that this user is not eligible to OTP authen)
# username_attributes => additional RADIUS attributes

import radiusd
import yaml
from redis.sentinel import Sentinel
import requests
import json
import pyotp
import logging

logging.basicConfig(filename="/var/log/freeradius/radius.log", level=logging.ERROR, format='%(asctime)s - otp.py - %(message)s')

with open('/etc/freeradius/3.0/config.otp.yaml') as f:
    config = yaml.load(f, Loader=yaml.FullLoader)

# get list of Redis Sentinels from config file
# convert to tuple
sentinels = list(config['sentinels'].items())
rpass = config['rpass']
spass = config['spass']

# connect to Redis
sentinel = Sentinel(sentinels, sentinel_kwargs={'password': spass})
master = sentinel.master_for('mymaster', password=rpass)

def pam_authen(u, p):
    url = "http://127.0.0.1:4567/authen"
    credential = { "username": u, "password": p}
    x = requests.post(url, json = credential)
    y = json.loads(x.text)
    return y["status"]

def ldapotp(username, p):
    # password followed by otp
    # password must be at least 7 characters
    if len(p) > 6:
        otp = p[-6:]
        password = p[0:-6]
    else:
        reply = ( ('Reply-Message', 'Password length too short'), )
        logging.error(username + ': Password length too short')
        return (radiusd.RLM_MODULE_REJECT, reply, ())

    r = pam_authen(username, password)
    if not r:
        reply = ( ('Reply-Message', 'Authentication Failed'), )
        logging.error(username + ': Authentication Failed')
        return (radiusd.RLM_MODULE_REJECT, reply, ())

    key = master.get(username)
    if not key:
        reply = ( ('Reply-Message', 'No OTP key found for this user'), )
        logging.error(username + ': No OTP key found for this user')
        return (radiusd.RLM_MODULE_REJECT, reply, ())

    totp = pyotp.TOTP(key.decode("utf-8"))
    if not totp.verify(otp, None, 1):
    # if totp.now() != otp:
        reply = ( ('Reply-Message', 'OTP mismatch'), )
        logging.error(username + ': OTP mismatch')
        return (radiusd.RLM_MODULE_REJECT, reply, ())

    reply = ( ('Reply-Message', 'Welcome!'), ) + extra_attributes(username)
    return (radiusd.RLM_MODULE_OK, reply, ())

def otp(d):
    # first check for State attribute
    # If there is a STATE attribute, this must be the Access-Reply to our Access-Challenge
    if 'State' in d:
        if d['State'] == '0x4f5450':
            # 0x4f5450 == OTP
            # The STATE attribute is set to 'OTP', exactly what we expect
            # check if Access-Challenge expires
            if not master.get(d['User-Name'] + "_otp"):
                reply = ( ('Reply-Message', 'Access-Challenge expires'), )
                logging.error(d['User-Name'] + ': Access-Challenge expires')
                return (radiusd.RLM_MODULE_REJECT, reply, ())
            key = master.get(d['User-Name'])
            if not key:
                reply = ( ('Reply-Message', 'No OTP key found for this user'), )
                logging.error(d['User-Name'] + ': No OTP key found for this user')
                return (radiusd.RLM_MODULE_REJECT, reply, ())
            totp = pyotp.TOTP(key.decode("utf-8"))
            # OTP is in User-Password
            if not totp.verify(d['User-Password'], None, 1):
            # if totp.now() != d['User-Password']:
                reply = ( ('Reply-Message', 'OTP mismatch'), )
                logging.error(d['User-Name'] + ': OTP mismatch')
                return (radiusd.RLM_MODULE_REJECT, reply, ())
            reply = ( ('Reply-Message', 'Welcome!'), ) + extra_attributes(d['User-Name'])
            return (radiusd.RLM_MODULE_OK, reply, ())

        # STATE is not OTP
        reply = ( ('Reply-Message', 'Access-Challenge Failed'), )
        logging.error(d['User-Name'] + ': Access-Challenge Failed')
        return (radiusd.RLM_MODULE_REJECT, reply, ())

    # No STATE attribute, so this must be the initial Access-Request
    # Authen the user
    r = pam_authen(d['User-Name'], d['User-Password'])
    if not r:
        reply = ( ('Reply-Message', 'Authentication Failed'), )
        logging.error(d['User-Name'] + ': Authentication Failed')
        return (radiusd.RLM_MODULE_REJECT, reply, ())

    # Authentication success, set STATE attribute and issue an Access-Challenge
    reply = ( ('Reply-Message', 'OTP: '), ('State', 'OTP'))
    config = ( ('Response-Packet-Type', "Access-Challenge"), )
    # set a key that expires in 1'
    master.set(d['User-Name'] + "_otp", "1")
    master.expire(d['User-Name'] + "_otp", 60)
    return (radiusd.RLM_MODULE_OK, reply, config)

def ldap(username, password):
    r = pam_authen(username, password)
    if not r:
        reply = ( ('Reply-Message', 'Authentication Failed'), )
        logging.error(username + ': Authentication Failed')
        return (radiusd.RLM_MODULE_REJECT, reply, ())

    reply = ( ('Reply-Message', 'Welcome!'), ) + extra_attributes(username)
    return (radiusd.RLM_MODULE_OK, reply, ())

def extra_attributes(username):
    # return extra attributes
    attr = master.get(username + "_attributes")
    # attributes are python tuple
    # example: (('User-Name', 'bob'), ('User-Password', 'hello'), ('NAS-IP-Address', '127.0.1.1'))
    # remember to use single quote
    if attr:
        reply = eval(attr.decode("utf-8"))
        return reply
    return ()

def authenticate(p):
    print("*** authenticate ***")
    print(p)
    # convert p to dict
    d = dict((x, y) for x, y in p)
    d['User-Name'] = d['User-Name'].lower()

    # some users, regardless of authen types, will never be able to use OTP
    # for example, PAM users
    if master.get(d['User-Name'] + "_nootp"):
        return ldap(d['User-Name'], d['User-Password'])

    # authen types
    if d['Custom-Request-For'] == 'ldapotp':
        return ldapotp(d['User-Name'], d['User-Password'])

    if d['Custom-Request-For'] == 'otp':
        return otp(d)

    if d['Custom-Request-For'] == 'ldap':
        return ldap(d['User-Name'], d['User-Password'])
