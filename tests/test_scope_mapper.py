"""Tests for the scope-to-KYA tier mapper."""

from mcp_trust_gateway.trust.scope_mapper import (
    KYALevel,
    MCPScope,
    kya_for_scope,
    max_kya_for_scopes,
    filter_scopes_by_kya,
    default_requirements_for_scope,
    requirements_from_annotations,
    scope_taxonomy,
)


class TestKyaForScope:
    def test_read_is_sandbox(self):
        assert kya_for_scope(MCPScope.READ) == KYALevel.SANDBOX

    def test_invoke_is_sandbox(self):
        assert kya_for_scope(MCPScope.TOOL_INVOKE) == KYALevel.SANDBOX

    def test_write_is_organizational(self):
        assert kya_for_scope(MCPScope.TOOL_WRITE) == KYALevel.ORGANIZATIONAL

    def test_financial_is_auditable(self):
        assert kya_for_scope(MCPScope.TOOL_FINANCIAL) == KYALevel.AUDITABLE

    def test_delegate_is_auditable(self):
        assert kya_for_scope(MCPScope.DELEGATE) == KYALevel.AUDITABLE

    def test_unknown_scope_defaults_to_sandbox(self):
        assert kya_for_scope("custom:scope") == KYALevel.SANDBOX


class TestMaxKyaForScopes:
    def test_empty_returns_sandbox(self):
        assert max_kya_for_scopes(set()) == KYALevel.SANDBOX

    def test_read_only(self):
        assert max_kya_for_scopes({MCPScope.READ}) == KYALevel.SANDBOX

    def test_mixed_returns_highest(self):
        scopes = {MCPScope.READ, MCPScope.TOOL_WRITE, MCPScope.TOOL_FINANCIAL}
        assert max_kya_for_scopes(scopes) == KYALevel.AUDITABLE


class TestFilterScopesByKya:
    def test_sandbox_filters_write(self):
        scopes = {MCPScope.READ, MCPScope.TOOL_INVOKE, MCPScope.TOOL_WRITE}
        filtered = filter_scopes_by_kya(scopes, KYALevel.SANDBOX)
        assert MCPScope.TOOL_WRITE not in filtered
        assert MCPScope.READ in filtered
        assert MCPScope.TOOL_INVOKE in filtered

    def test_organizational_keeps_write(self):
        scopes = {MCPScope.READ, MCPScope.TOOL_WRITE}
        filtered = filter_scopes_by_kya(scopes, KYALevel.ORGANIZATIONAL)
        assert MCPScope.TOOL_WRITE in filtered

    def test_auditable_keeps_all(self):
        all_scopes = {s.value for s in MCPScope}
        filtered = filter_scopes_by_kya(all_scopes, KYALevel.AUDITABLE)
        assert filtered == all_scopes


class TestDefaultRequirements:
    def test_financial_has_economic_impact(self):
        reqs = default_requirements_for_scope(MCPScope.TOOL_FINANCIAL)
        assert reqs.economic_impact is True
        assert reqs.required_kya_level == KYALevel.AUDITABLE

    def test_read_no_economic_impact(self):
        reqs = default_requirements_for_scope(MCPScope.READ)
        assert reqs.economic_impact is False
        assert reqs.required_kya_level == KYALevel.SANDBOX


class TestAnnotations:
    def test_parses_trust_annotations(self):
        ann = {
            "trust": {
                "required_kya_level": 2,
                "required_reputation": 0.8,
                "required_scope": "mcp:tool:financial",
                "economic_impact": True,
            }
        }
        reqs = requirements_from_annotations(ann)
        assert reqs is not None
        assert reqs.required_kya_level == 2
        assert reqs.required_reputation == 0.8
        assert reqs.economic_impact is True

    def test_returns_none_for_missing(self):
        assert requirements_from_annotations(None) is None
        assert requirements_from_annotations({}) is None
        assert requirements_from_annotations({"other": 1}) is None


class TestScopeTaxonomy:
    def test_returns_all_scopes(self):
        taxonomy = scope_taxonomy()
        scope_names = {entry["scope"] for entry in taxonomy}
        for s in MCPScope:
            assert s.value in scope_names
