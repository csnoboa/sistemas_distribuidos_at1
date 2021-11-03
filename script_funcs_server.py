import Pyro5.api
server = Pyro5.api.Proxy("PYRONAME:server.enquete")
server.lista_usuarios()
server.notifica_usuarios()