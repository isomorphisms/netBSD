# $NetBSD$

atf_test_case contract
contract_head()
{
	atf_set "descr" "single-principal compatibility-mode contract"
	atf_set "require.user" "root"
}
contract_body()
{
	if ! sysctl -n security.models.singleprincipal.enabled >/dev/null 2>&1; then
		atf_skip "SINGLE_PRINCIPAL is not enabled on this kernel"
	fi
	[ "$(sysctl -n security.models.singleprincipal.enabled)" = 1 ] ||
		atf_skip "single-principal mode detector is not enabled"

	atf_check -s exit:0 -o match:'SUMMARY[[:space:]]+PASS' \
	    -e empty "$(atf_get_srcdir)/h_singleprincipal"
}

atf_init_test_cases()
{
	atf_add_test_case contract
}
