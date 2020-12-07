from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hashlib
import pickle
import sys

#necessaria a instalacao do pycryptocrome
#pip install pycryptocrome

def HashString(string): #funcao de hash para strings
  return hashlib.sha256(string.encode('utf-8')).hexdigest()

def HashKey(key): #Gera o hash da chave
  exp_k = key.exportKey()
  return hashlib.sha3_256(exp_k).hexdigest()

def SaveKey(filename, key): #Salva um token para a autenticação do arquivo, em um arquivo binario
  hashkeyvalue = HashKey(key.publickey())
  f = open(hashkeyvalue,'ab')
  valuehash = HashString(filename.replace('.txt', '.encrypted')) #gera um hash pelo nome do arquivo
  token = (valuehash, key.exportKey()) #o token é composto pela chave e o nome do arquivo assinado
  pickle.dump(token, f)
  f.close()
  return hashkeyvalue

def LoadKey(filename, hashvalue): #Carrega a chave para a autenticacao
  hashtoken = HashString(filename)
  f = open(hashvalue,'rb')
  try:
    f = open(hashvalue,'rb')
    while True:
      token = pickle.load(f)
      if token[0] == hashtoken: 
        break
    f.close()
  except (FileNotFoundError, EOFError):
    raise "Erro chave nao encontrada"
    pass
  return RSA.importKey(token[1])

def Assign(name_arq, signature): #Gera os arquivos assinados
  arq = open(name_arq, 'r')
  sigfile = open(name_arq.replace('.txt','.encrypted'), 'wb')
  pickle.dump(signature, sigfile)
  for line in arq:
    sigfile.write(line.encode('ascii'))
  sigfile.close()
  arq.close()

def CheckSign(name_arq):  #Checa a assinatura no arquivo
  sarq = open(name_arq, 'rb')
  try:
    signature = pickle.load(sarq)
  except pickle.UnpicklingError as NoPickle:
    sarq.close()
    raise NoPickle('Assinatura não encontrada!')
  sarq.close()
  return signature

def GenDecFile(name_arq): #gera um novo arquivo texto com o conteudo do arquivo autenticado
  arq = open(name_arq, 'rb')
  newarq = name_arq.replace('encrypted', 'decrypted.txt')
  narq = open(newarq, 'w')
  pickle.load(arq)
  for line in arq:
    narq.write(line.decode('utf-8'))
  arq.close()
  narq.close()

def GenKey(): #Gera as chaves
  key_pair = RSA.generate(3072)
  return key_pair

def Enc_Sign(arq_path): #Cifra o hash e gera o formato(encrypted) para a analise, recebendo o caminho do arquivo como parametro
  k_pair = GenKey()
  k_pub = k_pair.publickey()
  encryptor = PKCS1_OAEP.new(k_pub)
  HashKeyPub = SaveKey(arq_path, k_pair)
  signature = encryptor.encrypt(HashKeyPub.encode('ascii'))
  Assign(arq_path, signature)

  print("Hash Token Key:", HashKeyPub)
  print("Encrypted!")

def Dec_Sign(arq_path, hashkey): #Decifra o hash a partir do formato(encrypted) a partir do caminho recebido como parametro
  signature = CheckSign(arq_path)
  key = LoadKey(arq_path, hashkey)
  decryptor = PKCS1_OAEP.new(key)
  hashkey1 = decryptor.decrypt(signature).decode('utf-8')
  hashkey2 = HashKey(key.publickey())
  
  if(hashkey1 == hashkey2):
    print("Hash Key Authenticaded:", hashkey1)
    GenDecFile(arq_path)
    print("Decrypted!")
  else:
    print("Invalid Hash")

# Entrada pega a partir dos parametros dados pelo terminal
arquivo = sys.argv[1] #arquivo
instr = sys.argv[2] #instrucao

if instr == 'enc': #Se a instrucao for de cifracao, ele gerara um arquivo formatado assinado
  Enc_Sign(arquivo)
elif instr == 'dec': #Se a instrucao for de decifracao, ele checara um arquivo no formato(.encrypted) que por sua vez sera autenticado
  if '.encrypted' in arquivo:
    arq = input("Type Hash Token key:")
    Dec_Sign(arquivo, arq)
  else:
    print("Arquivo Inválido!")
else:
  print("Instrução Inválida ou não digitada!")