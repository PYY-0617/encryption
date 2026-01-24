# https://chat.deepseek.com/share/thurkx2u86lwtrk5lv

import hashlib

def f(*args):
    """
    支持任意数量参数的哈希函数
    
    规则:
    1. 对每个参数进行字符转换：□→△，△→△u，■→△v，其他字符不变
    2. 如果没有参数，使用"■"符号
    3. 用"□"连接所有转换后的参数
    4. 计算SHA256哈希
    
    示例:
    f(t) = h(fct(t))
    f(t,u) = h(f"{fct(t)}□{fct(u)}")
    f(t,u,v) = h(f"{fct(t)}□{fct(u)}□{fct(v)}")
    f(t,u,v,w) = h(f"{fct(t)}□{fct(u)}□{fct(v)}□{fct(w)}")
    """
    
    def fct(t: str) -> str:
        # 字符转换：□→△，△→△u，■→△v，其他字符不变
        mapping = {"□": "△", "△": "△u", "■": "△v"}
        return ''.join(mapping.get(c, c) for c in str(t))
    
    def h(t): # 计算SHA256哈希
        return hashlib.sha256(t.encode()).hexdigest()
    
    # 如果没有参数，变成"■"符号
    if not args:
        return h("■")
    
    # 如果只有一个参数
    if len(args) == 1:
        return h(fct(args[0]))
    
    # 多个参数：用"□"连接所有转换后的参数
    transformed_args = [fct(arg) for arg in args]
    concatenated = "□".join(transformed_args)
    return h(concatenated)

print(f("a△□", "b△u", "c□□□△"))  # 示例调用
# f("a△□", "b△u", "c□□□△") = SHA256("a△u△□b△uu□c△△△△u") = b6b8c01295021bad65b7a671ec20927718aacfa55023ded86f68fff4678f6951
