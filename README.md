#Netronome Flow Processor prometheus exporter
该项目包括网卡数据相关的监控及流表dump工具
#监控
作为prometheus exporter,将网卡如下工具推送到到prometheus监控系统。
- 网卡温度
- POD对应流表数量
- 网卡总流表数量
- 接口30s统计数据
#流表dump工具
dump网卡指定POD的流表信息，支持根据五元组进行过滤。

#使用限制
