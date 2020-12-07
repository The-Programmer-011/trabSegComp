from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hashlib
import pickle
import sys

def VerificaAssinatura(arquivo):  #Checa a assinatura no arquivo
  file = open(arquivo, 'rb')
  try:
    assinatura = pickle.load(file)
  except pickle.UnpicklingError as NoPickle:
    file.close()
    raise NoPickle('Arquivo sem assinatura!')
  file.close()
  return assinatura

def HashString(string): #funcao de hash para strings
  return hashlib.sha256(string.encode('utf-8')).hexdigest()

def CarregarChave(hashTable): #Carrega a chave para a autenticacao
  file = open(hashTable,'rb')
  token = pickle.load(file)
  return RSA.importKey(token[1])

def HashKey(key): #Gera o hash da chave
  exp_k = key.exportKey()
  return hashlib.sha3_256(exp_k).hexdigest()

def Decifrador(arquivo): #gera um novo arquivo texto com o conteudo do arquivo autenticado
  file = open(arquivo, 'rb')
  dec = arquivo.replace('enc', 'dec.txt')
  decFile = open(dec, 'w')
  pickle.load(file)
  for line in file:
    decFile.write(line.decode('utf-8'))
  file.close()
  decFile.close()

def DecifradorController(arquivo, token): #Decifra o hash a partir do formato(encrypted) a partir do caminho recebido como parametro
  assinatura = VerificaAssinatura(arquivo)
  chave = CarregarChave(token)
  decifrador = PKCS1_OAEP.new(chave)
  chavePrivada = decifrador.decrypt(assinatura).decode('utf-8')
  chavePublica = HashKey(chave.publickey())

  if(chavePrivada == chavePublica):
    print("Token autenticado!")
    Decifrador(arquivo)
    print("Arquivo decifrado!")
  else: 
    print("Token inválido!")

arquivo = input("Path do criptograma: ")
if '.enc' in arquivo:
	token = input("Token: ")
	DecifradorController(arquivo, token)
else:
    print("Arquivo Inválido!")