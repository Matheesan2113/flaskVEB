from Crypto.PublicKey import RSA

# Code to create basic private and public keys for each application

key = RSA.generate(2048)
f = open('MMCLA','wb')
f.write(key.export_key('PEM'))
f.close()
f = open('MMCLA.pub','wb')
f.write(key.publickey().export_key())
f.close()
#
key = RSA.generate(2048)
f = open('MMCTF','wb')
f.write(key.export_key('PEM'))
f.close()
f = open('MMCTF.pub','wb')
f.write(key.publickey().export_key())
f.close()