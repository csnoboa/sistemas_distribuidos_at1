from __future__ import print_function
import threading
import Pyro5.api

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Signature import pss

from enquete import Enquete
from data import Data

@Pyro5.api.expose
class Cliente(object):
    def __init__(self, name, server):
        daemon = Pyro5.api.Daemon()
        self.uri = daemon.register(self)  # registra a classe para que o server possa chamar
        threading.Thread(target=daemon.requestLoop).start() # começa a thread para receber chamadas assincronamente
        self.name = name
        self.chave = self.gerar_chave()
        self.server = server

    # Cadastro do Cliente
    def cadastrar(self):
        print("Aqui é {0}.".format(self.name))
        public_key = self.chave.publickey()
        publickey = public_key.export_key("PEM")
        self.server.cadastra_cliente(
            self.name,
            publickey,
            self.uri)
        print("Fui cadastrado!")

    # Geração do par de chaves
    def gerar_chave(self):
        random_seed = Random.new().read
        keyPair = RSA.generate(1024, random_seed)
        return keyPair

    # Assina a mensagem
    def assinatura(self):
        mensagem = self.name
        mensagem = mensagem.encode("utf-8")
        hash = SHA256.new(mensagem)
        assinatura_digital = pss.new(self.chave).sign(hash)

        return assinatura_digital, mensagem

    # Cria enquete no servidor
    def cria_enquete(self, titulo, local, datas_json, data_limite):
        print("Criando enquete: " + titulo)

        datas = []
        for d in datas_json:
            datas.append(Data.criar_data_json(d))

        enquete = Enquete(titulo, self.name, local, datas, data_limite)
        self.server.cria_enquete(enquete.to_json())
        print("Enquete criada, serei notificado quando acabar")

    # Vota em enquete ( o servidor que chama esse metodo )
    def votar(self, enquete_json):
        datas = []

        enquete = Enquete.criar_enquete_json(enquete_json)
        resp = input("A enquete {0} foi criada, deseja votar nos horários? \n1 - Sim\n2 - Não\n".format(enquete.titulo))
        if resp == '1':
            for data in enquete.datas:
                r = input("\nDia: {0}\nHorário: {1}\nPode comparecer?\n1 - Sim\n2 - Não\n".format(data.dia, data.horario))
                if r == '1':
                    datas.append(data.to_json())
        return datas

    # Servidor chama quando alguma enquete tiver acabado
    def notificar_acabou(self, enquete_json):
        enquete = Enquete.criar_enquete_json(enquete_json)
        print("A enquete {0} terminou".format(enquete.titulo))
        print("A data decidida foi: \nDia: {0}\nHorário: {1}\nQuantidade de votos:{2}\n".format(
            enquete.data_escolhida.dia,
            enquete.data_escolhida.horario,
            enquete.data_escolhida.votos
            ))

    # Visualiza uma unica enquete, e com assinatura digital
    def ver_enquete(self, titulo):
        assinatura_digital, mensagem = self.assinatura()
        enquete_json = self.server.ver_enquete(self.name, titulo, assinatura_digital, mensagem)
        if isinstance(enquete_json, str):
            print(enquete_json)
            return
        enquete = Enquete.criar_enquete_json(enquete_json)
        print("Título: {0}\nStatus: {1}\nLocal: {2}\nData decidida: \n  Dia: {3}\n  Horário: {4}\n  Quantidade de votos:{5}\n".format(
            enquete.titulo,
            enquete.status,
            enquete.local,
            enquete.data_escolhida.dia,
            enquete.data_escolhida.horario,
            enquete.data_escolhida.votos
        ))
