from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hashlib
import pickle
import sys

def AssinarArquivo(nomeArquivo, assinatura): #Gera os arquivos assinados
  arquivo = open(nomeArquivo, 'r')
  arqAssinado = open(nomeArquivo.replace('.txt','.enc'), 'wb')
  pickle.dump(assinatura, arqAssinado)
  for line in arquivo:
    arqAssinado.write(line.encode('ascii'))
  arqAssinado.close()
  arquivo.close()

def SalvarChave(arquivo, chave): #Salva um token para a autenticacao do arquivo, em um arquivo binario
  chavePublica = chave.publickey()
  chaveHash = hashlib.sha3_256(chavePublica.exportKey()).hexdigest()
  file = open(chaveHash,'ab')
  rawFile = open(arquivo, 'r')
  rawContent = rawFile.read()
  rawContent = "Chave show de bola essa"
  valorHash = hashlib.sha256(rawContent.encode('utf-8')).hexdigest() #gera um hash pelo nome do arquivo
  token = (valorHash, chave.exportKey()) #o token eh composto pela chave e o nome do arquivo assinado
  pickle.dump(token, file)
  file.close()
  return chaveHash

def GerarChave(): #Gera as chaves
  parChaves = RSA.generate(1024)
  return parChaves

def AssinarArquivoController(filePath): #Cifra o hash e gera o formato(encrypted) para a analise, recebendo o caminho do arquivo como parametro
  parChaves = GerarChave()
  chavePublica = parChaves.publickey()
  cifrador = PKCS1_OAEP.new(chavePublica)
  chaveHashPub = SalvarChave(filePath, parChaves)
  assinatura = cifrador.encrypt(chaveHashPub.encode('ascii'))
  AssinarArquivo(filePath, assinatura)

  print("Arquivo assinado!")
  print("Token:", chaveHashPub)

# Entrada pega a partir dos parametros dados pelo terminal
arquivo = input("Digite o nome do arquivo a ser assinado: ")

AssinarArquivoController(arquivo)
exit()