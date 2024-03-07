#!/bin/bash
# shellcheck disable=SC2086
# NOTE: Ignore violations as 'echo "name=foo::bar" >> $GITHUB_OUTPUT'.
set -Eeuo pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"

export REVIEWDOG_GITHUB_API_TOKEN="${INPUT_GITHUB_TOKEN:?}"

# Set SSH tunnel
if [ -n "${BASTION_HOST}" ]; then
	for env_var in "BASTION_USER" "BASTION_PEM" "SSH_TUNNEL_PORT" "DB_HOST" "DB_PORT" "DB_USER" "DB_PASSWORD" "DB_NAME"; do
		[[ -z "${!env_var}" ]] && echo "Please set $env_var" && exit 1
	done

	echo '::group::🔑 Set SSH PEM'
	# Save PEM
	mkdir ~/.ssh
	touch ~/.ssh/known_hosts
	touch ~/.ssh/ssh_key.pem
	ssh-keyscan -H "$BASTION_HOST" >>~/.ssh/known_hosts
	eval $(ssh-agent -s)
	ssh-add - <<<"$BASTION_PEM"
	echo "$BASTION_PEM" >>~/.ssh/ssh_key.pem
	chmod 400 ~/.ssh/ssh_key.pem

	# Test SSH connection
	echo '::group::⚙️  Test SSH Connection'
	ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=30 "$BASTION_USER@$BASTION_HOST" -i ~/.ssh/ssh_key.pem 'exit 0'

	echo '::group::🔌 Set ssh tunnel'
	# Set SSH tunnel
	ssh -o ExitOnForwardFailure=yes -f -N -L "localhost:$SSH_TUNNEL_PORT:$DB_HOST:$DB_PORT" "$BASTION_USER@$BASTION_HOST" -i ~/.ssh/ssh_key.pem
else
	echo '::group::🔌 Set ssh tunnel - Bastion Host not specified, skipping.'
fi

# Avoid 'fatal: detected dubious ownership in repository'
git config --global --add safe.directory /github/workspace

# Get changed files
echo '::group::🐶 Get changed files'
# The command is necessary to get changed files.
# TODO Fetch only the target branch
git fetch --prune --no-tags

SQL_FILE_PATTERN="${FILE_PATTERN:?}"
SOURCE_REFERENCE="origin/${GITHUB_PULL_REQUEST_BASE_REF:?}"
changed_files=$(git diff --name-only --no-color "$SOURCE_REFERENCE" "HEAD" -- "${SQLFLUFF_PATHS:?}" |
	grep -e "${SQL_FILE_PATTERN:?}" |
	xargs -I% bash -c 'if [[ -f "%" ]] ; then echo "%"; fi' || :)
echo "Changed files:"
echo "$changed_files"
# Halt the job
if [[ "${changed_files}" == "" ]]; then
	echo "There is no changed files. The action doesn't scan files."
	echo "name=sqlfluff-exit-code::0" >>$GITHUB_OUTPUT
	echo "name=reviewdog-return-code::0" >>$GITHUB_OUTPUT
	exit 0
fi
echo '::endgroup::'

# Install sqlfluff
echo '::group::🐶 Installing sqlfluff ... https://github.com/sqlfluff/sqlfluff'
pip install --no-cache-dir -r "${SCRIPT_DIR}/requirements/requirements.txt" --use-deprecated=legacy-resolver
# Make sure the version of sqlfluff
sqlfluff --version
echo '::endgroup::'

# Install extra python modules
echo '::group:: Installing extra python modules'
if [[ "x${EXTRA_REQUIREMENTS_TXT}" != "x" ]]; then
	pip install --no-cache-dir -r "${EXTRA_REQUIREMENTS_TXT}" --use-deprecated=legacy-resolver
	# Make sure the installed modules
	pip list
fi
echo '::endgroup::'

# Install dbt packages
echo '::group:: Installing dbt packages'
if [[ -f "${INPUT_WORKING_DIRECTORY}/dependencies.yml" ]]; then
	default_dir="$(pwd)"
	cd "$INPUT_WORKING_DIRECTORY"
	dbt deps --profiles-dir "${SCRIPT_DIR}/resources/dummy_profiles"
	cd "$default_dir"
fi
echo '::endgroup::'

if [[ ! "${SQLFLUFF_COMMAND:?}" == @(lint|fix|both) ]]; then
	echo 'ERROR: SQLFLUFF_COMMAND must be one of lint and fix'
	exit 1
fi

# Lint changed files if the mode is lint
if [[ "${SQLFLUFF_COMMAND:?}" == @(lint|both) ]]; then
	echo '::group:: Running sqlfluff 🐶 ...'
	# Allow failures now, as reviewdog handles them
	set +Eeuo pipefail
	lint_results="sqlfluff-lint.json"
	# shellcheck disable=SC2086,SC2046
	sqlfluff lint \
		--format json \
		$(if [[ "x${SQLFLUFF_CONFIG}" != "x" ]]; then echo "--config ${SQLFLUFF_CONFIG}"; fi) \
		$(if [[ "x${SQLFLUFF_DIALECT}" != "x" ]]; then echo "--dialect ${SQLFLUFF_DIALECT}"; fi) \
		$(if [[ "x${SQLFLUFF_PROCESSES}" != "x" ]]; then echo "--processes ${SQLFLUFF_PROCESSES}"; fi) \
		$(if [[ "x${SQLFLUFF_RULES}" != "x" ]]; then echo "--rules ${SQLFLUFF_RULES}"; fi) \
		$(if [[ "x${SQLFLUFF_EXCLUDE_RULES}" != "x" ]]; then echo "--exclude-rules ${SQLFLUFF_EXCLUDE_RULES}"; fi) \
		$(if [[ "x${SQLFLUFF_TEMPLATER}" != "x" ]]; then echo "--templater ${SQLFLUFF_TEMPLATER}"; fi) \
		$(if [[ "x${SQLFLUFF_DISABLE_NOQA}" != "x" ]]; then echo "--disable-noqa ${SQLFLUFF_DISABLE_NOQA}"; fi) \
		$(if [[ "x${SQLFLUFF_DIALECT}" != "x" ]]; then echo "--dialect ${SQLFLUFF_DIALECT}"; fi) \
		$changed_files |
		tee "$lint_results"
	sqlfluff_exit_code=$?

	echo "name=sqlfluff-results::$(cat <"$lint_results" | jq -r -c '.')" >>$GITHUB_OUTPUT # Convert to a single line
	echo "name=sqlfluff-exit-code::${sqlfluff_exit_code}" >>$GITHUB_OUTPUT

	set -Eeuo pipefail
	echo '::endgroup::'

	echo '::group:: Running reviewdog 🐶 ...'
	# Allow failures now, as reviewdog handles them
	set +Eeuo pipefail

	lint_results_rdjson="sqlfluff-lint.rdjson"
	cat <"$lint_results" |
		jq -r -f "${SCRIPT_DIR}/to-rdjson.jq" |
		tee >"$lint_results_rdjson"

	cat <"$lint_results_rdjson" |
		reviewdog -f=rdjson \
			-name="sqlfluff-lint" \
			-reporter="${REVIEWDOG_REPORTER}" \
			-filter-mode="${REVIEWDOG_FILTER_MODE}" \
			-fail-on-error="${REVIEWDOG_FAIL_ON_ERROR}" \
			-level="${REVIEWDOG_LEVEL}"
	reviewdog_return_code="${PIPESTATUS[1]}"

	echo "name=sqlfluff-results-rdjson::$(cat <"$lint_results_rdjson" | jq -r -c '.')" >>$GITHUB_OUTPUT # Convert to a single line
	echo "name=reviewdog-return-code::${reviewdog_return_code}" >>$GITHUB_OUTPUT

	set -Eeuo pipefail
	echo '::endgroup::'

	exit $sqlfluff_exit_code
fi
# END OF lint

# Format changed files if the mode is fix
if [[ "${SQLFLUFF_COMMAND}" == @(fix|both) ]]; then
	echo '::group:: Running sqlfluff 🐶 ...'
	# Allow failures now, as reviewdog handles them
	set +Eeuo pipefail
	# shellcheck disable=SC2086,SC2046
	sqlfluff fix --force \
		$(if [[ "x${SQLFLUFF_CONFIG}" != "x" ]]; then echo "--config ${SQLFLUFF_CONFIG}"; fi) \
		$(if [[ "x${SQLFLUFF_DIALECT}" != "x" ]]; then echo "--dialect ${SQLFLUFF_DIALECT}"; fi) \
		$(if [[ "x${SQLFLUFF_PROCESSES}" != "x" ]]; then echo "--processes ${SQLFLUFF_PROCESSES}"; fi) \
		$(if [[ "x${SQLFLUFF_RULES}" != "x" ]]; then echo "--rules ${SQLFLUFF_RULES}"; fi) \
		$(if [[ "x${SQLFLUFF_EXCLUDE_RULES}" != "x" ]]; then echo "--exclude-rules ${SQLFLUFF_EXCLUDE_RULES}"; fi) \
		$(if [[ "x${SQLFLUFF_TEMPLATER}" != "x" ]]; then echo "--templater ${SQLFLUFF_TEMPLATER}"; fi) \
		$(if [[ "x${SQLFLUFF_DISABLE_NOQA}" != "x" ]]; then echo "--disable-noqa ${SQLFLUFF_DISABLE_NOQA}"; fi) \
		$(if [[ "x${SQLFLUFF_DIALECT}" != "x" ]]; then echo "--dialect ${SQLFLUFF_DIALECT}"; fi) \
		$changed_files
	sqlfluff_exit_code=$?
	echo "name=sqlfluff-exit-code::${sqlfluff_exit_code}" >>$GITHUB_OUTPUT

	set -Eeuo pipefail
	echo '::endgroup::'

	# SEE https://github.com/reviewdog/action-suggester/blob/master/script.sh
	echo '::group:: Running reviewdog 🐶 ...'
	# Allow failures now, as reviewdog handles them
	set +Eeuo pipefail

	# Suggest the differences
	temp_file=$(mktemp)
	git diff | tee "${temp_file}"
	git stash -u

	# shellcheck disable=SC2034
	reviewdog \
		-name="sqlfluff-fix" \
		-f=diff \
		-f.diff.strip=1 \
		-reporter="${REVIEWDOG_REPORTER}" \
		-filter-mode="${REVIEWDOG_FILTER_MODE}" \
		-fail-on-error="${REVIEWDOG_FAIL_ON_ERROR}" \
		-level="${REVIEWDOG_LEVEL}" <"${temp_file}" || exit_code=$?

	# Clean up
	git stash drop || true
	set -Eeuo pipefail
	echo '::endgroup::'

	exit $sqlfluff_exit_code
fi
# END OF fix
