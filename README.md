## 图床

![](https://raw.githubusercontent.com/lwtdzh/imghost/master/favicon.png)

## 使用方法

需要先查看工程项目的 token，然后部署到 PicGo 中

## PicGo 帮助
[https://picgo.github.io/PicGo-Doc/zh/guide/#picgo-is-here](https://picgo.github.io/PicGo-Doc/zh/guide/#picgo-is-here)

## 流量限制与钉钉报告脚本

[UFW 流量限制脚本](support_parameter_adjust_ufw_by_traffic_limit.sh) 和 [钉钉流量报告脚本](support_parameter_report_traffic_to_dingtalk.sh) 需要一起更新。安装命令、依赖和注意事项写在各自文件开头；钉钉配置见 [.env.example](support_parameter_report_traffic_to_dingtalk.env.example)，真实 token 和 secret 只保存在服务器上。

流量超限后，IPv4/IPv6 的 TCP 22 放行规则排在入站拒绝规则之前。出站仍允许访问已配置的 DNS 服务器，以及 traffic-dingtalk 专用用户发起的 HTTPS 请求。这个用户可以访问任意 TCP 443 目的地址，应只供报告脚本使用。SSH、DNS、报告和已有连接产生的流量仍会计入 vnStat。

DNS/HTTPS 规则写在 UFW 的 before.rules 和 before6.rules 中，检查时使用 iptables/ip6tables 的 before-output 链；ufw status 不显示这些规则。启用防火墙后，应确认能建立新的 SSH 连接，并检查报告日志里的 “DingTalk report accepted (errcode=0)”。

需要临时放开本月剩余时间的网络访问时，运行一次：

```bash
sudo /usr/local/sbin/traffic-limit-ufw.sh --unlock-current-month
```

月份按服务器本地时区计算。例如 11 月 23 日执行后，11 月剩余时间都会放行；进入 12 月后，监控服务下一次检查时（通常不超过五分钟）恢复原先的 UFW 启用状态，并按 vnStat 的 12 月流量判断是否超限。12 月再次超限时仍会自动阻断。重复执行不会把恢复时间延长到下个月，也不会覆盖最初记录的防火墙状态；下个月如需再次放行，需要重新执行。

放行期间 UFW 整体关闭，因此其他 UFW 规则也暂停生效。脚本不清零 vnStat、不停止监控或报告服务；流量继续累计，vnStat 暂时读取失败也不会取消本月放行。保留服务器上的 /var/lib/traffic-limit-ufw/month-unlock 文件，脚本会在到期或主动恢复时清理它。系统时钟和时区应保持正确。

提前恢复监控时，带上平时使用的网卡和限额，立即按当前流量判断：

```bash
sudo /usr/local/sbin/traffic-limit-ufw.sh --interface eth0 --upload-limit 180g --resume-monitoring
```

如果本月已经超限，主动恢复会立即重新阻断。这个命令不会修改监控服务的配置；未指定限额时沿用脚本默认的总流量 180 GiB。两个命令都支持追加 --dry-run 预览，且不能同时使用 --unlock-current-month 和 --resume-monitoring。

回归测试在 tests 目录中。UFW 测试需要 Linux、root 权限和 IPv4/IPv6 restore 工具；报告测试需要 Bash、Python 3 和 OpenSSL。测试使用临时规则、模拟账号和 curl，不修改实际防火墙或账号，也不发送钉钉消息：

```bash
sudo python3 tests/test_traffic_limit_ufw.py support_parameter_adjust_ufw_by_traffic_limit.sh
python3 tests/test_dingtalk_reporter.py support_parameter_report_traffic_to_dingtalk.sh
```
