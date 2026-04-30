import unittest
import os
import sys
import django

# Настройка окружения Django
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
django.setup()

from security_checker.security_logic import calculate_metrics


class TestCalculateMetrics(unittest.TestCase):
    """Тесты для функции calculate_metrics"""

    def test_critical_and_warning(self):
        """Проверка расчета при наличии CRITICAL и WARNING находок"""
        findings = [
            {'severity': 'CRITICAL', 'responsible': 'consumer'},
            {'severity': 'WARNING', 'responsible': 'provider'}
        ]
        metrics = calculate_metrics(findings)

        self.assertEqual(metrics['total_findings'], 2)
        self.assertEqual(metrics['critical_findings'], 1)
        self.assertEqual(metrics['warning_findings'], 1)
        # Формула: (1*30 + 1*10) / 2 * 20 = 400/2 = 200 → min(100, 200) = 100
        self.assertEqual(metrics['risk_score'], 100.0)
        # Формула: max(0, 100 - (1*15 + 1*5)) = max(0, 80) = 80
        self.assertEqual(metrics['compliance_percent'], 80.0)

    def test_empty_findings(self):
        """Проверка расчета при отсутствии находок"""
        findings = []
        metrics = calculate_metrics(findings)

        self.assertEqual(metrics['total_findings'], 0)
        self.assertEqual(metrics['risk_score'], 0.0)
        self.assertEqual(metrics['compliance_percent'], 100.0)

    def test_only_critical(self):
        """Проверка расчета только с критическими находками"""
        findings = [
            {'severity': 'CRITICAL', 'responsible': 'consumer'},
            {'severity': 'CRITICAL', 'responsible': 'consumer'},
            {'severity': 'CRITICAL', 'responsible': 'consumer'}
        ]
        metrics = calculate_metrics(findings)

        self.assertEqual(metrics['critical_findings'], 3)
        # Формула: (3*30 + 0*10) / 3 * 20 = 90/3 * 20 = 600/3 = 200 → min(100, 200) = 100
        self.assertEqual(metrics['risk_score'], 100.0)
        # Формула: max(0, 100 - (3*15 + 0*5)) = max(0, 55) = 55
        self.assertEqual(metrics['compliance_percent'], 55.0)

    def test_provider_and_consumer(self):
        """Проверка разделения по зонам ответственности"""
        findings = [
            {'severity': 'CRITICAL', 'responsible': 'provider'},
            {'severity': 'WARNING', 'responsible': 'consumer'},
            {'severity': 'WARNING', 'responsible': 'consumer'}
        ]
        metrics = calculate_metrics(findings)

        self.assertEqual(metrics['provider_issues'], 1)
        self.assertEqual(metrics['consumer_issues'], 2)

    def test_mixed_scenario(self):
        """Проверка смешанного сценария с 7 находками (как в базовом тесте)"""
        findings = [
            {'severity': 'CRITICAL', 'responsible': 'consumer'},
            {'severity': 'CRITICAL', 'responsible': 'consumer'},
            {'severity': 'CRITICAL', 'responsible': 'consumer'},
            {'severity': 'CRITICAL', 'responsible': 'consumer'},
            {'severity': 'WARNING', 'responsible': 'provider'},
            {'severity': 'WARNING', 'responsible': 'consumer'},
            {'severity': 'WARNING', 'responsible': 'consumer'}
        ]
        metrics = calculate_metrics(findings)

        self.assertEqual(metrics['total_findings'], 7)
        self.assertEqual(metrics['critical_findings'], 4)
        self.assertEqual(metrics['warning_findings'], 3)
        self.assertEqual(metrics['provider_issues'], 1)
        self.assertEqual(metrics['consumer_issues'], 6)
        # Формула: (4*30 + 3*10) / 7 * 20 = 150/7 * 20 = 428.57 → min(100, 428.57) = 100
        self.assertEqual(metrics['risk_score'], 100.0)
        # Формула: max(0, 100 - (4*15 + 3*5)) = max(0, 100 - 75) = 25
        self.assertEqual(metrics['compliance_percent'], 25.0)


if __name__ == '__main__':
    unittest.main()