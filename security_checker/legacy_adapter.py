# Модуль-прокладка для обеспечения обратной совместимости со старым форматом запросов

from django.shortcuts import render
from django.http import HttpResponse
from .security_logic import SecurityChecker, calculate_metrics

def legacy_check(request):
    """
    Обработчик устаревшего формата запросов.
    Принимает параметры:
        project_id - идентификатор облака (как раньше назывался)
        check_type - список протоколов через запятую (опционально)
    Возвращает HTML-отчёт в упрощённом виде.
    """
    cloud_id = request.GET.get('project_id')
    protocol_ids_str = request.GET.get('check_type', '')
    protocol_ids = protocol_ids_str.split(',') if protocol_ids_str else []

    # Преобразование к стандартным типам (ожидаем, что придут ID как строки)
    checker = SecurityChecker(cloud_id=cloud_id, protocol_ids=protocol_ids)
    findings = checker.run_full_check()
    metrics = calculate_metrics(findings)

    # Формируем HTML с результатами (можно использовать упрощённый шаблон)
    context = {
        'metrics': metrics,
        'findings': metrics.get('findings', []),
        'cloud_id': cloud_id,
    }
    # Используем шаблон для устаревшего отчёта (можно создать отдельный)
    return render(request, 'security_checker/legacy_report.html', context)