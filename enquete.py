from data import Data

class Enquete(object):
    def __init__(self, titulo, usuario_criador, local, datas, data_limite, data_escolhida=None, status="Em votação"):
        self.titulo = titulo
        self.usuario_criador = usuario_criador
        self.local = local
        self.datas = datas
        self.data_limite = data_limite
        self.usuarios_votantes = []
        self.data_escolhida = data_escolhida
        self.status = status
        self.segundos = 0


    # Metodo que converte o json recebido pela rede, em um objeto Enquete
    def criar_enquete_json(enquete):
        datas = []
        if enquete['datas']:
            for data in enquete['datas']:
                datas.append(Data.criar_data_json(data))
        titulo = enquete['titulo']
        usuario_criador = enquete['usuario_criador']
        local = enquete['local']
        data_limite = enquete['data_limite']
        data_escolhida = enquete['data_escolhida'] if enquete['data_escolhida'] == None else Data.criar_data_json(enquete['data_escolhida'])
        status = enquete['status']

        return Enquete(titulo, usuario_criador, local, datas, data_limite, data_escolhida, status)

    # Metodo que converte uma enquete em um json, para ser passado pela rede
    def to_json(self):
        datas = []
        for data in self.datas:
            datas.append(data.to_json())
        return {
            "titulo": self.titulo,
            "usuario_criador" : self.usuario_criador,
            "local": self.local,
            "datas": datas,
            "data_limite": self.data_limite,
            "data_escolhida": self.data_escolhida if self.data_escolhida == None else self.data_escolhida.to_json(),
            "status": self.status
        }
