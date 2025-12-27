# Transformations

The primary purpose of a logsource pipeline is to transform publicly agreed upon rules into however it is that you decided (or some vendor decided) to format the logs in your environment. 

```
transformations:
    - id: index_condition
      type: add_condition
      conditions:
        index: winevent
      rule_conditions:
      - type: logsource
        product: windows
```

- `transformations`: This tells your PySigma interpreter that you are starting the section of the pipeline that will contain the transformations. 
- `- id: index_condition`: 