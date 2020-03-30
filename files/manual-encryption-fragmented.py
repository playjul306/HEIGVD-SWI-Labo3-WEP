#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key and Fragment the packet"""

__author__      = "Julien Benoit, Volkan Sutcu"
__copyright__   = "Copyright 2020, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "julien.benoit@heig-vd.ch, volkan.sutcu@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
import os
from rc4 import RC4

# Fonction permet d'encrypter la data
def encryption(key, data, arp):
    # Calcul du CRC32 (icv) et conversion de ce dernier en unsigned int little indian
    #   Sources :   https://docs.python.org/2/library/binascii.html
    #               https://docs.python.org/2/library/struct.html
    icv = binascii.crc32(data.encode()) & 0xffffffff
    icv_enclair = struct.pack('<L', icv)

    # Constuction de la trame pour RC4
    msg = data.encode() + icv_enclair

    # Rc4 seed est composé de IV+clé
    seed = arp.iv+key

    # Chiffrement rc4
    cipher = RC4(seed, streaming=False)
    cipherText = cipher.crypt(msg)

    return cipherText

# Fonction qui permet de créer un packet
def createPacket(data, key):
    # Lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
    arp = rdpcap('arp.cap')[0]
    packet = arp

    # On récupère le data encrypté
    cipherText = encryption(key, data, arp)

    # On récupère le ICV et le passe en format Long big endian, puis on met à jour arp.icv
    packet.icv = struct.unpack('!L', cipherText[-4:])[0]

    # Le message chiffré sans le ICV
    packet.wepdata = cipherText[:-4]

    return packet

# Fonction qui permet de créer un ou des paquets (donc de fragmenter si besoin), par rapport à la taille de la data
def fragmentation(data, fragSize = 36, arpFragmented = "arpFragmented.pcap", key= b'\xaa\xaa\xaa\xaa\xaa'):
    # On vérifie que la taille des fragments soit un multiple de 36
    if fragSize % 36:
        print ("error: fragSize must be a multiple of 36")
        return 0
    
    # Permet d'effacer l'anciennne capture si elle existe
    if os.path.isfile(arpFragmented):
        os.remove(arpFragmented)

    # Calcule le nombre de fragment
    nbFrag = int(math.ceil(len(data) / float(fragSize)))
    i = 0
    # Boucle permettant de traiter chaque fragment
    while (nbFrag > 0):
        # Récupère le début de la data
        msg = data[:fragSize]
        # Récupère le paquet créé avec le debut de la data
        packet = createPacket(msg, key)
        # Met le bit more fragments à 1 sauf pour le dernier fragment
        if (len(data) > fragSize):
            packet.FCfield |= 0x4
        # Numérote les fragments
        packet.SC = i
        i += 1
        # On enlève le début de la data de la variable data car elle a été traitée
        data = data[fragSize:]
        # On génère le fichier avec le paquet fragmenté (ou non) et on ajoute à la suite chaque fragment
        wrpcap(arpFragmented, packet, append=True)
        # On décrémente nbFrag car on passe au fragment suivant
        nbFrag -= 1  

    return 1

# Message à chiffrer
data="KEY" * 36

# Permet de savoir si la fragmentation s'est bien passée ou non
if fragmentation(data):
    print("la fragmentation s'est bien passée.")
else:
    print("fragmentation échouée.")
