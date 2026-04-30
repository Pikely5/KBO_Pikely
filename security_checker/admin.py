from django.contrib import admin
from .models import (
    CloudProvider, SecurityProtocol, CloudComplianceData,
    TestProtocol, SecurityFinding
)


@admin.register(CloudProvider)
class CloudProviderAdmin(admin.ModelAdmin):
    list_display = ['name', 'region', 'is_active', 'created_at']
    list_filter = ['region', 'is_active']
    search_fields = ['name']


@admin.register(SecurityProtocol)
class SecurityProtocolAdmin(admin.ModelAdmin):
    list_display = ['protocol_id', 'name', 'category', 'severity_on_fail', 'responsibility', 'is_active']
    list_filter = ['category', 'severity_on_fail', 'responsibility', 'is_active']
    search_fields = ['protocol_id', 'name']


@admin.register(CloudComplianceData)
class CloudComplianceDataAdmin(admin.ModelAdmin):
    list_display = ['cloud', 'protocol', 'is_compliant', 'compliance_level', 'last_checked']
    list_filter = ['is_compliant', 'cloud', 'protocol__category']
    search_fields = ['cloud__name', 'protocol__name']


@admin.register(TestProtocol)
class TestProtocolAdmin(admin.ModelAdmin):
    list_display = ['protocol_number', 'test_date', 'tester_name', 'cloud', 'status', 'risk_score']
    list_filter = ['status', 'test_date', 'cloud']
    search_fields = ['protocol_number', 'tester_name']


@admin.register(SecurityFinding)
class SecurityFindingAdmin(admin.ModelAdmin):
    list_display = ['resource_name', 'severity', 'responsibility', 'detection_time', 'resolved']
    list_filter = ['severity', 'responsibility', 'resolved']
    search_fields = ['resource_name', 'finding_message']