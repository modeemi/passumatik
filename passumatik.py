#!/usr/bin/python3
# -*- coding: utf-8 -*-

'''Modeemin passumatikki'''

import os
import sys
import getpass
import postgresql
import crypt
import codecs

class NoPasswordsException(Exception):
    pass

def method_from_crypt(method):
    def do_crypt(password):
        return crypt.crypt(password, crypt.mksalt(method))
    return do_crypt

def rot13(password):
    return codecs.getencoder("rot-13")(password)[0]

format_method = {
    "SHA512"      : method_from_crypt(crypt.METHOD_SHA512),
    "SHA256"      : method_from_crypt(crypt.METHOD_SHA256),
    "MD5"         : method_from_crypt(crypt.METHOD_MD5),
    "DES"         : method_from_crypt(crypt.METHOD_CRYPT),
    "rot13"       : rot13 # example; not used unless 'rot13' is listed in the format table
}

def password_complexity_requirements_check(password):
    return len(password) >= 8

def main():
    username = os.getenv("SUDO_USER")
    if not username:
        print("Ei sinua olemassa. Mene pois.")
        return
    db = postgresql.open('pq://modeemi/modeemiuserdb')
    old_hashes = [ hash[0] for hash in db.prepare("SELECT hash FROM shadowformat WHERE username=$1")(username) ]
    if not old_hashes:
        print("Tsorppa, ei sua löyty tietokannasta")
        return
    print("olet {}".format(username))
    print("syötä vanha salasana")
    old_password = getpass.getpass()
    found_hash = False
    for old_hash in old_hashes:
        if crypt.crypt(old_password, old_hash) == old_hash:
            found_hash = True
            break
    if not found_hash:
        print("Väärä salasana")
        return
    retries_left = 0
    while True:
        retries_left = retries_left - 1
        print("Syötä uusi salasana")
        new_password = getpass.getpass()
        if password_complexity_requirements_check(new_password):
            break;
        else:
            if retries_left == 0:
                print("Ei näin.")
                return
            print("Yritä nyt edes, ei toi ole salasana")
    print("Uudestaan!")
    new_password2 = getpass.getpass()
    if new_password != new_password2:
        print("Uh oh, ei tainnut nappulat osua kohdalleen. Uudestaan!")
        return
    try:
        with db.xact() as x:
            formats = [ format[0] for format in db.prepare("SELECT format FROM format")() ]

            # purge old frmat passwords
            db.prepare("DELETE from shadowformat WHERE username=$1")(username)
            
            current_formats = [ format[0] for format in db.prepare("SELECT format FROM shadowformat WHERE username=$1")(username) ]
            updated_count = 0
            for format in formats:
                if format in format_method:
                    hash = format_method[format](new_password)
                    # needless upsert, there are not going to be conflicts..
                    db.prepare('''
                        INSERT INTO shadowformat(username, format, hash, last_updated) VALUES ($1, $2, $3, DEFAULT)
                        ON CONFLICT(username, format) DO UPDATE SET hash=$3, last_updated=DEFAULT
                        ''')(username, format, hash)
                    updated_count = updated_count + 1
            if updated_count == 0:
                raise NoPasswordsException()
            db.prepare("UPDATE shadow SET lastchanged=ROUND(EXTRACT(EPOCH FROM NOW())/86400) WHERE username=$1")(username)
            print("Päivitetty {} salasana{}".format(updated_count, "a" if updated_count != 1 else ""))
    except NoPasswordsException:
        print("Ei yhteensopivia salasanoja kannassa; ei poistettu vanhoja")
        
if __name__ == "__main__":
    main ()
