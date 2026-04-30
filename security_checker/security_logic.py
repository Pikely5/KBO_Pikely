"""
Модуль проверки безопасности облачной инфраструктуры
Вариант 32 - Контейнер безопасности облака
Автор: Петров Виктор
"""

import os
import re
import json
from datetime import datetime

from django.conf import settings
from django.utils import timezone

from .models import (
    CloudProvider,
    SecurityProtocol,
    CloudComplianceData,
    TestProtocol,
    SecurityFinding
)


class SecurityChecker:
    """Класс для проверки безопасности облачной инфраструктуры."""

    def __init__(self, cloud_id=None, protocol_ids=None):
        self.cloud_id = cloud_id
        self.protocol_ids = protocol_ids
        self.findings = []
        self.start_time = timezone.now()

    def run_check(self):
        self.findings = []

        if self.cloud_id:
            compliance_data = CloudComplianceData.objects.filter(
                cloud_id=self.cloud_id,
                is_compliant=False
            )
            if self.protocol_ids:
                compliance_data = compliance_data.filter(
                    protocol_id__in=self.protocol_ids
                )

            for data in compliance_data.select_related('protocol', 'cloud'):
                bucket_match = re.search(r'\[Бакет: ([^\]]+)\]', data.notes)
                bucket_name = bucket_match.group(1) if bucket_match else data.cloud.name
                clean_notes = re.sub(r'\[Бакет: [^\]]+\]\s*', '', data.notes)

                finding = {
                    'resource': bucket_name,
                    'type': data.protocol.get_category_display(),
                    'severity': data.protocol.severity_on_fail,
                    'message': f"Нарушение протокола «{data.protocol.name}»: {clean_notes}",
                    'remediation': data.protocol.remediation_template,
                    'responsible': data.protocol.responsibility,
                    'protocol_id': data.protocol.protocol_id,
                    'compliance_level': data.compliance_level
                }
                self.findings.append(finding)
        else:
            self._run_default_check()

        return self.findings

    def _run_default_check(self):
        buckets = [
            {"name": "customer-data", "public": True, "has_pii": True},
            {"name": "public-logs", "public": True, "has_pii": False},
            {"name": "private-backup", "public": False, "has_pii": True},
            {"name": "analytics-data", "public": True, "has_pii": True},
        ]
        users = [
            {"name": "admin", "rights": "full_access", "mfa_enabled": False},
            {"name": "developer", "rights": "read_only", "mfa_enabled": True},
            {"name": "service-account", "rights": "full_access", "mfa_enabled": False},
        ]
        services = [
            {"name": "Compute Engine", "status": "problem"},
            {"name": "Cloud Storage", "status": "ok"},
            {"name": "BigQuery", "status": "problem"},
        ]
        resources = [
            {"name": "backup-storage", "encrypted": False},
            {"name": "logs", "encrypted": False},
            {"name": "database", "encrypted": True},
            {"name": "user-data", "encrypted": False},
        ]

        for bucket in buckets:
            if bucket["public"] and bucket["has_pii"]:
                self.findings.append({
                    'resource': bucket['name'], 'type': 'storage', 'severity': 'CRITICAL',
                    'message': f"Хранилище {bucket['name']} публично и содержит ПД",
                    'remediation': 'Сделать хранилище приватным', 'responsible': 'consumer'
                })
            elif bucket["public"]:
                self.findings.append({
                    'resource': bucket['name'], 'type': 'storage', 'severity': 'WARNING',
                    'message': f"Хранилище {bucket['name']} публично доступно",
                    'remediation': 'Проверить необходимость публичного доступа', 'responsible': 'consumer'
                })

        for user in users:
            if user["rights"] == "full_access":
                self.findings.append({
                    'resource': user['name'], 'type': 'iam', 'severity': 'CRITICAL',
                    'message': f"Пользователь {user['name']} имеет полные права",
                    'remediation': 'Применить минимальные привилегии', 'responsible': 'consumer'
                })
            if not user.get("mfa_enabled", True):
                self.findings.append({
                    'resource': user['name'], 'type': 'iam', 'severity': 'CRITICAL',
                    'message': f"У пользователя {user['name']} отключена MFA",
                    'remediation': 'Включить MFA', 'responsible': 'consumer'
                })

        for service in services:
            if service["status"] != "ok":
                self.findings.append({
                    'resource': service['name'], 'type': 'service', 'severity': 'WARNING',
                    'message': f"Сервис {service['name']} работает с нарушениями SLA",
                    'remediation': 'Связаться с провайдером', 'responsible': 'provider'
                })

        for resource in resources:
            if not resource["encrypted"]:
                self.findings.append({
                    'resource': resource['name'], 'type': 'storage', 'severity': 'CRITICAL',
                    'message': f"Ресурс {resource['name']} не зашифрован",
                    'remediation': 'Включить шифрование', 'responsible': 'consumer'
                })

    def run_full_check(self):
        return self.run_check()

    def save_protocol(self, metrics):
        protocol = TestProtocol.objects.create(
            tester_name="Петров Виктор",
            cloud_id=self.cloud_id,
            status=self._determine_status(metrics),
            total_checks=metrics['total_findings'],
            passed_checks=self._count_passed(metrics),
            failed_checks=metrics['critical_findings'] + metrics['warning_findings'],
            risk_score=metrics['risk_score'],
            compliance_percent=metrics['compliance_percent'],
            detailed_results={'metrics': metrics},
            recommendations=self._generate_recommendations(),
            test_duration=(timezone.now() - self.start_time).total_seconds()
        )
        if self.protocol_ids:
            protocol.selected_protocols.set(self.protocol_ids)
        for finding in self.findings:
            SecurityFinding.objects.create(
                protocol=protocol,
                resource_name=finding.get('resource', 'Unknown'),
                resource_type=finding.get('type', 'Unknown'),
                severity=finding.get('severity', 'WARNING'),
                finding_message=finding.get('message', ''),
                remediation=finding.get('remediation', ''),
                responsibility=finding.get('responsible', 'consumer')
            )
        return protocol

    def _determine_status(self, metrics):
        if metrics['critical_findings'] == 0 and metrics['warning_findings'] == 0:
            return 'SUCCESS'
        elif metrics['critical_findings'] == 0:
            return 'WARNING'
        else:
            return 'FAILED'

    def _count_passed(self, metrics):
        total = metrics.get('total_findings', 0)
        failed = metrics.get('critical_findings', 0) + metrics.get('warning_findings', 0)
        return total - failed

    def _generate_recommendations(self):
        recommendations = []
        for finding in self.findings[:5]:
            recommendations.append(
                f"[{finding.get('severity', 'UNKNOWN')}] "
                f"{finding.get('resource', 'Unknown')}: "
                f"{finding.get('remediation', '')}"
            )
        return "\n".join(recommendations)


def calculate_metrics(findings):
    critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
    warning = sum(1 for f in findings if f.get('severity') == 'WARNING')
    provider = sum(1 for f in findings if f.get('responsible') == 'provider')
    consumer = sum(1 for f in findings if f.get('responsible') == 'consumer')
    total = len(findings)

    risk_score = 0 if total == 0 else min(100, (critical * 30 + warning * 10) / max(total, 1) * 20)
    compliance = max(0, 100 - (critical * 15 + warning * 5))

    return {
        "risk_score": round(risk_score, 2),
        "compliance_percent": round(compliance, 2),
        "critical_findings": critical,
        "warning_findings": warning,
        "provider_issues": provider,
        "consumer_issues": consumer,
        "total_findings": total,
        "timestamp": datetime.now().isoformat(),
        "findings": findings
    }


def create_visualization(metrics):
    """Заглушка — графики строятся на стороне клиента через Chart.js"""
    pass