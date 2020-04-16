class APDUCommand(object):
    CLA_OFFSET = 0
    INS_OFFSET = 1
    P1_OFFSET = 2
    P2_OFFSET = 3
    Lc_OFFSET = 4
    DATA_OFFSET = 5

    def __init__(self, cla, ins, p1, p2, data=[]):
        self.buffer = [cla, ins, p1, p2, len(data)] + data

    def getCLA(self):
        return self.buffer[self.CLA_OFFSET]

    def getINS(self):
        return self.buffer[self.INS_OFFSET]

    def getP1(self):
        return self.buffer[self.P1_OFFSET]

    def getP2(self):
        return self.buffer[self.P2_OFFSET]

    def getLc(self):
        return self.buffer[self.Lc_OFFSET]

    def getData(self):
        return self.buffer[self.DATA_OFFSET:]