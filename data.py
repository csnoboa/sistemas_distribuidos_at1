class Data(object):
    def __init__(self, dia, horario, votos = 0):
        self.dia = dia
        self.horario = horario
        self.votos = votos

    def votar(self):
        self.votos += 1

    def get_votos(self):
        return self.votos

    # Metodo que converte o json recebido pela rede, em um objeto Enquete
    def criar_data_json(data):
        dia = data['dia']
        horario = data['horario']
        votos = data['votos']

        return Data(dia, horario, votos)

    # Metodo que converte uma enquete em um json, para ser passado pela rede
    def to_json(self):
        return {
            "dia": self.dia,
            "horario" : self.horario,
            "votos": self.votos
        }
