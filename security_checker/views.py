from django.shortcuts import render
from .security_logic import SecurityChecker, calculate_metrics, create_visualization
from .models import CloudProvider, SecurityProtocol

def index(request):
    clouds = CloudProvider.objects.filter(is_active=True).exclude(name="Yandex Cloud")
    protocols = SecurityProtocol.objects.filter(is_active=True)

    context = {
        'title': 'Контейнер безопасности облака - Вариант 32',
        'author': 'Петров Виктор',
        'clouds': clouds,
        'protocols': protocols,
    }

    if request.method == 'POST':
        cloud_id = request.POST.get('cloud')
        protocol_ids = request.POST.getlist('protocols')

        checker = SecurityChecker(cloud_id=cloud_id, protocol_ids=protocol_ids)
        findings = checker.run_full_check()
        metrics = calculate_metrics(findings)
        create_visualization(metrics)

        if cloud_id or protocol_ids:
            checker.save_protocol(metrics)

        findings_html = ""
        for finding in metrics.get("findings", []):
            severity_class = "critical" if finding.get("severity") == "CRITICAL" else "warning"
            responsible_text = "Потребитель" if finding.get("responsible") == "consumer" else "Поставщик"
            findings_html += f"""
            <li class='{severity_class}'>
                <strong>[{finding.get('severity')}]</strong> {finding.get('resource')}: {finding.get('message')}<br>
                <small>Рекомендация: {finding.get('remediation')} | Ответственный: {responsible_text}</small>
            </li>
            """

        context.update({
            'metrics': metrics,
            'findings_html': findings_html,
            'has_results': True,
            'selected_cloud': int(cloud_id) if cloud_id else None,
            'selected_protocols': [int(p) for p in protocol_ids],
        })
    else:
        context['has_results'] = False

    return render(request, 'security_checker/index.html', context)