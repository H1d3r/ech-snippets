# ech-snippets

这个只是简单的把股神的ech-workers改成支持snippets，这样就没有每日10w次请求的限制了，客户端方便还是用股神编译好的各个平台的ech-workers客户端，也可以自己用ech-workers.go源码自己编译。

## 客户端帮助

客户端 -h 以后的帮助文件：

Usage of ./ech-workers:

-dns string

ECH 查询 DNS 服务器 (default "119.29.29.29:53")

-ech string

ECH 查询域名 (default "cloudflare-ech.com")

-f string

服务端地址 (格式: x.x.workers.dev:443)

-ip string

指定服务端 IP（绕过 DNS 解析）

-l string

代理监听地址 (支持 SOCKS5 和 HTTP) (default "127.0.0.1:30000")

-token string

身份验证令牌


## 使用说明

1. **（非必需）先修改snippets.js里面的代码**  
   - 第五行：默认的PROXYIP （默认是我的PROXYIP域名，你可以替换成你自己喜欢的PROXYIP或者域名）  
   - 第十三行：设置一个token （建议设置，免得被别人白嫖）

2. **创建一个新的snippets片段**  
   把snippets.js的内容复制进去，左上角取一个你喜欢的名字比如ech，右上角Snippet rule设置Hostname equals 你的自定义域名，保存。在弹出的对话框中选择创建一个对应的开启了小黄云的A记录，内容为192.0.2.1

3. **复制你刚刚的自定义域名，用客户端启动**  
   默认混合代理端口运行在本机的30000端口上，比如在win11下为ech-workers-windows-amd64.exe -f 你的自定义域名:443 -l 127.0.0.1:30000 -token 你的token -ip 你的优选ip  
   或者你也可以使用股神的GUI，但是我习惯使用nekobox的自定义核心来调用。

## nekobox的调用

1. 设置-其它核心-添加，起个名字，比如ech确定，选择你的ech-workers-windows-amd64.exe所在路径，确定。  
2. 在主界面空白处右键，手动输入配置-类型-自定义（其它核心），在弹出的窗口中，名称（随便起一个），地址和端口（默认即可，这个不生效），核心（选择你刚才添加的核心名字，比如ech），命令（-f 你的自定义域名:443 -l 127.0.0.1:30000 -token 你的token -ip 你的优选ip），确定即可。
