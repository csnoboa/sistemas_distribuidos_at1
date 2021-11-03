# Classe utilizada pelo Servidor
class User:
    def __init__(self, name, chave_publica, uri):
        self.name = name
        self.chave_publica = chave_publica
        self.uri = uri
