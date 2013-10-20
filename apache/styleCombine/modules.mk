mod_styleCombine.la: mod_styleCombine.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_styleCombine.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_styleCombine.la
