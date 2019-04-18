from string import punctuation
from bitstring import pack

PunctuationToSpace = str.maketrans(punctuation, ' ' * len(punctuation))


class instruction:
    def __init__(self, mnemonic, op_args, encoding, esil="TODO"):
        self._mnemonic = mnemonic
        self._op_args_raw = op_args
        self._op_args = op_args.translate(PunctuationToSpace).split()
        self._encoding = pack('hex:4', encoding.split()[0]).bin + ''.join(encoding.split()[1:])
        self._esil = esil

    def __call__(self, cls):
        cls.MNEMONIC = self._mnemonic
        cls.ARGS_RAW = self._op_args_raw
        cls.ARGS = self._op_args
        cls.ENCODING = self._encoding
        cls.ESIL = self._esil

        return cls
