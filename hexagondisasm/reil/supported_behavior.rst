***********************************************************
List of supported Hexagon behavior pseudo-code instructions
***********************************************************


Operands
========

Register: e.g., Rt, Rs. Regex. used in the parser: ``r'[RPNMC]\w{1,2}(\.new)?'``

Immediate: e.g., #s. Regex. used in the parser: ``r'(0x)?[a-fA-F0-9]+'``


Binary operations: arithmetic and logical
-----------------------------------------

Rd=Rs+#s;
Rd=Rs+Rt;

Rd=#s-Rs;
Rd=Rt-Rs;

Rd=Rs&Rt;
Rd=Rs|Rt;
Rd=Rs^Rt;


Transfer immediate
------------------

Rd=#s;


Transfer register
-----------------

Rd=Rs;

