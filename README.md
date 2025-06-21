config：

- path：请求路径。（字符串）
- http_method：http 方法。（字符串）
- header：http 请求头。（字典）
- param：http 请求体参数。（字典）
- injector_param：注入位置。（字符串）
- payload：自定义的注入 payload。
- 配置多项：
  - 布尔注入：期待的字符串。
  - 时间注入：期待的等待时间。
- 代理

worker 爆破遍历：

- 爆破

finder 二分遍历：

- 猜数字

attacker 攻击判断：

- 发送请求。
- 若符合预期就返回 true，否则就返回 false：
  - 布尔注入：期待的字符串。
  - 时间注入：期待的等待时间。

