#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""

__author__      = "Julien Benoit, Volkan Sutcu"
__copyright__   = "Copyright 2020, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "julien.benoit@heig-vd.ch, volkan.sutcu@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
from rc4 import RC4

#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'

# Nouveau fichier de sortie généré
arpGenerated = "arpGenerated.pcap"

# message à chiffrer
data="KEY" * 8

# lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]

# calcul du CRC32 (icv) et conversion de ce dernier en unsigned int little indian
#   Sources :   https://docs.python.org/2/library/binascii.html
#               https://docs.python.org/2/library/struct.html
icv = binascii.crc32(data.encode()) & 0xffffffff
icv_enclair = struct.pack('<L', icv)

# constuction de la trame pour RC4
msg = data.encode() + icv_enclair

# rc4 seed est composé de IV+clé
seed = arp.iv+key

# chiffrement rc4
cipher = RC4(seed, streaming=False)
cipherText = cipher.crypt(msg)

# on récupère le ICV et le passe en format Long big endian, puis on met à jour arp.icv
arp.icv = struct.unpack('!L', cipherText[-4:])[0]

# le message chiffré sans le ICV
arp.wepdata = cipherText[:-4]

print ('Message : ' + data)
print ('Encrypted Message : ' + cipherText[:-4].hex())
print ("icv : " + '{:x}'.format(icv)) 
print ("icv encrypted : " + cipherText[-4:].hex()) 

wrpcap(arpGenerated, arp)
