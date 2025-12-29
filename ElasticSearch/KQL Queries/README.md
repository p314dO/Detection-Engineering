# KQL Queries


Exclude computer accounts
```
NOT user.name: *$ AND winlog.channel.keyword: Security
```