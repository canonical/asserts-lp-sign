TMP=$(CURDIR)/tmp
GOBIN=${TMP}/bin

# Binaries: prefer whatever go/gofmt is on PATH (GitHub-hosted runners,
# contributor laptops); fall back to the Go snap used by the team's
# internal workflow.
GO ?= $(shell command -v go 2>/dev/null || echo /snap/bin/go)
GOFMT ?= $(shell command -v gofmt 2>/dev/null || echo /snap/bin/gofmt)
STATICCHECK=$(GOBIN)/staticcheck

PACKAGES=./...

default: test

# Install required dev tools.
$(GOBIN):
	GOBIN=$(GOBIN) $(GO) install honnef.co/go/tools/cmd/staticcheck@v0.7.0
	touch $@

.PHONY: test
test: ${GOBIN} lint
	@${MAKE} _test

.PHONY: _test
# COVERAGE_HTML=1 generates HTML coverage data under ./coverage.
_test: COVERAGE_HTML=
_test: V=
_test: |${TMP}
	@ \
	export COVERPROFILE=`mktemp ${TMP}/coverage.XXX`; \
	trap "rm -f $$COVERPROFILE" EXIT INT; \
	# Disable RSA 1024-bit minimum key size enforcement for tests: \
	# github.com/snapcore/snapd/asserts/assertstest generates <1024-bit keys \
	# for package-level variables and backend_test.go relies on that package. \
	export GODEBUG="rsa1024min=0"; \
	TESTCMD="${GO} test -count=1 -coverprofile=$$COVERPROFILE ${PACKAGES} ${ARGS}"; \
	if [ "${V}" ]; then $$TESTCMD -v -check.v; else $$TESTCMD; fi || exit $$? ; \
	if [ "${COVERAGE_HTML}" ]; then \
		mkdir -p ./coverage; \
		${GO} tool cover -html=$$COVERPROFILE -o ./coverage/coverage.html; \
		${GO} tool cover -func=$$COVERPROFILE; \
	fi

.PHONY: vet
vet:
	${GO} vet $(PACKAGES)

.PHONY: fmt fmt-check
fmt-check:
	@test -z "`${GOFMT} -l -s $$(git ls-files '*.go')`" || { ${GOFMT} -d -s $$(git ls-files '*.go'); echo "ERROR: gofmt found the above formatting errors, please correct"; exit 1; }

fmt:
	@echo "Formatting and simplifying files..."
	@${GOFMT} -l -s -w $$(git ls-files '*.go')

.PHONY: lint
lint:: ${GOBIN} fmt-check vet
	${STATICCHECK} $(PACKAGES)

${TMP}:
	@mkdir -p $@

.PHONY: clean
clean::
	rm -rf ${TMP}
	rm -rf ./coverage

