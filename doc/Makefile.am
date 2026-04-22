.NOTPARALLEL:

SUBDIRS = . test

MAN3_FILES_PRIMARY = \
	man3/flux_security_create.3 \
	man3/flux_security_last_error.3 \
	man3/flux_security_aux_set.3 \
	man3/flux_sign_unwrap.3 \
	man3/flux_sign_wrap.3
MAN3_FILES_SECONDARY = \
	man3/flux_security_destroy.3 \
	man3/flux_security_last_errnum.3 \
	man3/flux_security_aux_get.3 \
	man3/flux_sign_unwrap_anymech.3 \
	man3/flux_sign_wrap_as.3
MAN3_FILES = $(MAN3_FILES_PRIMARY) $(MAN3_FILES_SECONDARY)


MAN5_FILES = \
	man5/flux-config-security.5 \
	man5/flux-config-security-imp.5 \
	man5/flux-config-security-sign.5

MAN8_FILES = \
	man8/flux-imp.8

RST_FILES = \
	$(MAN3_FILES_PRIMARY:.3=.rst) \
	$(MAN5_FILES:.5=.rst) \
	$(MAN8_FILES:.8=.rst)

MAN_FILES = \
	$(MAN3_FILES) \
	$(MAN5_FILES) \
	$(MAN8_FILES)

if ENABLE_DOCS
man_MANS = \
	$(MAN3_FILES) \
	$(MAN5_FILES) \
	$(MAN8_FILES)
endif

.SUFFIXES = .rst .3 .5 .8

sphinx_man = $(sphinx_man_$(V))
sphinx_man_ = $(sphinx_man_$(AM_DEFAULT_VERBOSITY))
sphinx_man_0 = @echo "  BUILD     manpages";

sphinx_html = $(sphinx_html_$(V))
sphinx_html_ = $(sphinx_html_$(AM_DEFAULT_VERBOSITY))
sphinx_html_0 = @echo "  BUILD     html";

sphinx_verbose_flags = $(sphinx_verbose_flags_$(V))
sphinx_verbose_flags_ = $(sphinx_verbose_flags_$(AM_DEFAULT_VERBOSITY))
sphinx_verbose_flags_0 =
sphinx_verbose_flags_1 = -v
sphinx_verbose_flags_2 = -vv

STDERR_DEVNULL = $(stderr_devnull_$(V))
stderr_devnull_ =  $(stderr_devnull_$(AM_DEFAULT_VERBOSITY))
stderr_devnull_0 = >/dev/null 2>&1

$(MAN_FILES): conf.py $(RST_FILES)
	$(sphinx_man) \
	PYTHONPATH=$(PYTHONPATH):$(abs_srcdir) \
	SPHINX_BUILDDIR=$(abs_builddir) $(PYTHON) \
	        -m sphinx $(sphinx_verbose_flags) -b man $(srcdir) ./man \
	        $(STDERR_DEVNULL)
	@echo "  MV        manpages"; \
	for sec in 1 3 5 7 8; do \
	  set -- $(abs_builddir)/man/*.$$sec; \
	  if test -f $$1; then \
	    $(MKDIR_P) man$$sec && \
	    mv -f "$$@" man$$sec/; \
	  fi; \
	done

.PHONY: html
html: conf.py $(RST_FILES)
	$(sphinx_html) \
	PYTHONPATH=$(PYTHONPATH):$(abs_srcdir) \
	SPHINX_BUILDDIR=$(abs_builddir) $(PYTHON) \
	        -m sphinx $(sphinx_verbose_flags) -b html $(srcdir) ./html \
	        $(STDERR_DEVNULL)

EXTRA_DIST = \
	conf.py \
	manpages.py \
	domainrefs.py \
	index.rst \
	index_man.rst \
	guide/internals.rst \
	requirements.txt \
	man3/index.rst \
	man5/index.rst \
	man8/index.rst \
	$(RST_FILES)

CLEANFILES = \
	$(MAN_FILES)

clean-local:
	-rm -rf man python

distclean-local:
	-rm -rf doctrees


