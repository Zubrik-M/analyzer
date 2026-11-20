# Демонстрационный AST-анализатор

Нужны Python 3 и PyYAML (`python3 -m pip install PyYAML`). Из корня проекта:

```bash
python3 prototype/analyzer.py prototype/examples --output prototype/example_report.json
```

Результат сохранится в `prototype/example_report.json`. Ожидаются 2 проверенных файла, 3 предупреждения и 0 ошибок. Исходный код примеров анализируется через AST и не выполняется.

Прототип распознаёт только точные имена `subprocess.run`, `pickle.loads` и переменной `password`. Он не отслеживает значения переменных, псевдонимы импортов, происхождение данных и достижимость кода. Предупреждения требуют ручной проверки.

