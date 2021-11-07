import sys
import Pyro5.api
from cliente import Cliente
import time



server = Pyro5.api.Proxy("PYRONAME:server.enquete")

nome = input("Digite o nome do usuario: ")
cliente = Cliente(nome, server)
cliente.cadastrar()

while True:
    resp = input("Ver menu? \n1 - Sim \n2 - Não\n")
    if resp == "1":
        resp = input("""
O que deseja fazer?
    0 - Atualizar ( Receber enquetes )
    1 - Criar enquete
    2 - Consultar enquete
""")

        if resp == "1":
            resp = input("Qual enquete pronta deseja criar? de 1 a 3\n")

            if resp == "1":
                cliente.cria_enquete("mais saches", "casa", [
                    {
                        "dia": "sabado",
                        "horario": "13:00",
                        "votos": 0
                    },
                    {
                        "dia": "sabado",
                        "horario": "18:00",
                        "votos": 0
                    },
                    {
                        "dia": "domingo",
                        "horario": "13:00",
                        "votos": 0
                    },
                    ], 100)
            if resp == "2":
                cliente.cria_enquete("mais ração", "casa", [
                    {
                        "dia": "sexta",
                        "horario": "13:00",
                        "votos": 0
                    },
                    {
                        "dia": "sabado",
                        "horario": "18:00",
                        "votos": 0
                    },
                    ], 15)
            if resp == "3":
                cliente.cria_enquete("mais brinquedos", "casa", [
                    {
                        "dia": "segunda",
                        "horario": "10:00",
                        "votos": 0
                    },
                    {
                        "dia": "terça",
                        "horario": "18:00",
                        "votos": 0
                    },
                    ], 60)


        elif resp == "2":
            titulo = input("Qual o nome da enquete que quer consultar?\n")
            cliente.ver_enquete(titulo)

        else:
            time.sleep(15)

    else:
        time.sleep(120)
