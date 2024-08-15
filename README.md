# Remote Desktop Licensing 服务排查 
参考https://github.com/fortra/impacket/blob/master/examples/rpcdump.py

通过MSRPC枚举开放服务，根据UUID: 3d267954-eeb7-11d1-b94e-00c04fa3080d判断是否包含Terminal Server Licensing 

## 使用

- 依赖安装

```shell
pip install -r requirements.txt
```

- 批量探测

```
python rdl-detect.py -f ip.txt
```

## 探测结果

- `RPC Check Error`：135端口未开放，不受此影响；
- `Found Terminal Server Licensing`：目标主机安装并运行了RDL服务；
- `Not Found Terminal Server Licensing`：目标主机未安装RDL服务，不受此影响。