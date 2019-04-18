import r2lang

from asm import ba2asm
from anal import ba2anal
from bin import jn5168bin


r2lang.plugin("asm", ba2asm)
r2lang.plugin("anal", ba2anal)
r2lang.plugin("bin", jn5168bin)
