# https://chat.deepseek.com/share/kkay9u1xe4dt0863ue

import hashlib

def f(*args):
      
    ## 支持任意数量参数的加密函数

    def h(t): # 计算SHA256哈希
        return hashlib.sha256(t.encode()).hexdigest()

    def fct(t: str) -> str:
        """字符转换函数（防冲突）：
        □ → △
        △ → △u
        ■ → △v
        ◧ → △l
        ◨ → △r
        其他字符不变
        """
        mapping = {"□": "△", "△": "△u", "■": "△v", "◧": "△l", "◨": "△r"}
        return ''.join(mapping.get(c, c) for c in str(t))
    
    def merge(*args):
        """合并函数：
        1. 无参数 → "■"
        2. 单参数 → "◧" + fct(参数) + "◨"
        3. 多参数 → "◧" + fct(参数1) + "□" + fct(参数2) + ... + "◨"
        """
        # 如果没有参数，返回"■"符号
        if not args:
            return "■"
        
        # 如果只有一个参数
        if len(args) == 1:
            return "◧" + fct(args[0]) + "◨"
        
        # 多个参数：用"□"连接所有转换后的参数
        transformed_args = [fct(arg) for arg in args]
        concatenated = "□".join(transformed_args)
        return f"◧{concatenated}◨"
    
    # 不可变盐（6个）
    # 这些盐都是SHA256哈希值
    immutable_salt1 = "26385bc30aed20b09ce90684e8e7a5c19c0c55563be97b19830b4a7bdf42795b" # 1/1
    immutable_salt2 = "04baa4f6f798a0f5187f87edb0fbfa544865c75998b96499ebd6857a42750445" # 2/6
    immutable_salt3 = "ee5d961da544e23830b5bff3da08dafb5d7002b08f4b407ca8671652aaa91041" # 3/6
    immutable_salt4 = "565db5bd2691988e7ab503d4591f18fcacb9c76df661521e071ecbd249f32196" # 4/6
    immutable_salt5 = "4c14acb72700231f1b6d25b3c714a49c7eb9e4e1e9057efd5c8187f84c3421f0" # 5/6
    immutable_salt6 = "8f1be6b230d9354d191b7aae016bf668ea418f11c3a68a8f13e49181dd1623d8" # 6/6
    immutable_salts = f"{immutable_salt1}▮{immutable_salt2}▮{immutable_salt3}▮{immutable_salt4}▮{immutable_salt5}▮{immutable_salt6}"

    # 可变盐（19个）
    salt1 = h(merge(*args))
    salt2 = h(merge(*args) + "脱口秀")
    salt3 = h(salt1 + merge(*args) + salt2)
    salt4 = h(salt2 + merge(*args) + salt3)
    salt5 = h(salt3 + merge(*args) + salt4)
    salt6 = h(salt4 + merge(*args) + salt5)
    salt7 = h(salt5 + merge(*args) + salt6)
    salt8 = h(salt6 + merge(*args) + salt7)
    salt9 = h(salt7 + merge(*args) + salt8)
    salt10 = h(salt8 + merge(*args) + salt9)
    salt11 = h(salt9 + merge(*args) + salt10)
    salt12 = h(salt10 + merge(*args) + salt11)
    salt13 = h(salt11 + merge(*args) + salt12)
    salt14 = h(salt12 + merge(*args) + salt13)
    salt15 = h(f"{salt1}{merge(*args)}{salt2}△{salt3}△{salt4}△{salt5}△{salt6}△{salt7}△{salt8}△{salt9}△{salt10}△{salt11}△{salt12}△{salt13}△{salt14}")
    salt16 = h(f"{salt1}△{salt2}△{salt3}△{salt4}△{salt5}△{salt6}△{salt7}△{salt8}△{salt9}△{salt10}△{salt11}△{salt12}△{salt13}{merge(*args)}{salt14}△{salt15}")
    salt17 = h(f"{salt14}□{salt15}{merge(*args)}{salt16}")
    salt18 = h(f"{merge(*args)}{salt17}□{salt16}△{salt15}□{salt14}△{salt13}□{salt12}△{salt11}□{salt10}△{salt9}□{salt8}△{salt7}□{salt6}△{salt5}□{salt4}△{salt3}□{salt2}△{salt1}")
    salt19 = h(f"{salt1}{merge(*args)}{salt2}-{salt3}-{salt4}_{salt5}-{salt6}_{salt7}_{salt8}-{salt9}_{salt10}_{salt11}_{salt12}-{salt13}_{salt14}_{salt15}_{salt16}-{salt17}¬{salt18}")
    salts = f"{salt1}▮{salt2}▮{salt3}▮{salt4}▮{salt5}▮{salt6}▮{salt7}▮{salt8}▮{salt9}▮{salt10}▮{salt11}▮{salt12}▮{salt13}▮{salt14}▮{salt15}▮{salt16}▮{salt17}▮{salt18}▮{salt19}"
    sa2ts = f"{salt1},{salt2}[{salt3}]{salt4}[{salt5},{salt6}]{salt7}[{salt8}[{salt9}]{salt10}]{salt11}[{salt12}\{salt13}]{salt14}[{salt15}[{salt16}¬{salt17}]{salt18}]{salt19}"

    return h(f"{immutable_salts}{merge(*args)}{salts}") # 将salts替换为sa2ts可得到不同的结果

print(f("曼德博罗集", "茱莉亚集", "爆笑虫子集"))  # 示例调用
