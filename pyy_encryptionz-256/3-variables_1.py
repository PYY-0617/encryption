class __sha256__:
    def __init__(self):
        # 初始化常量（K值）和初始哈希值（H值）
        self.K = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]
        
        self.H = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]

    @staticmethod
    def rightrotate(x, n, size=32):
        """循环右移"""
        return (x >> n) | (x << (size - n)) & ((1 << size) - 1)

    @staticmethod
    def pad_message(message):
        """对消息进行填充"""
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        # 原始消息长度（位）
        original_bit_len = len(message) * 8
        
        # 添加1和0的填充
        padded = bytearray(message)
        padded.append(0x80)  # 添加1比特
        
        # 填充0直到长度 ≡ 448 mod 512
        while (len(padded) * 8) % 512 != 448:
            padded.append(0x00)
        
        # 添加原始长度（64位大端序）
        padded.extend(original_bit_len.to_bytes(8, 'big'))
        
        return padded

    def hash(self, message):
        """计算SHA-256哈希值"""
        # 1. 填充消息
        padded = self.pad_message(message)
        
        # 2. 初始化哈希值
        h0, h1, h2, h3, h4, h5, h6, h7 = self.H
        
        # 3. 处理每个512位数据块
        for chunk_start in range(0, len(padded), 64):
            chunk = padded[chunk_start:chunk_start + 64]
            
            # 3.1 将块分解为16个32位字
            w = [0] * 64
            for i in range(16):
                w[i] = int.from_bytes(chunk[i*4:(i+1)*4], 'big')
            
            # 3.2 扩展消息
            for i in range(16, 64):
                s0 = self.rightrotate(w[i-15], 7) ^ self.rightrotate(w[i-15], 18) ^ (w[i-15] >> 3)
                s1 = self.rightrotate(w[i-2], 17) ^ self.rightrotate(w[i-2], 19) ^ (w[i-2] >> 10)
                w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF
            
            # 3.3 初始化工作变量
            a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
            
            # 3.4 主循环
            for i in range(64):
                S1 = self.rightrotate(e, 6) ^ self.rightrotate(e, 11) ^ self.rightrotate(e, 25)
                ch = (e & f) ^ ((~e) & g)
                temp1 = (h + S1 + ch + self.K[i] + w[i]) & 0xFFFFFFFF
                
                S0 = self.rightrotate(a, 2) ^ self.rightrotate(a, 13) ^ self.rightrotate(a, 22)
                maj = (a & b) ^ (a & c) ^ (b & c)
                temp2 = (S0 + maj) & 0xFFFFFFFF
                
                h = g
                g = f
                f = e
                e = (d + temp1) & 0xFFFFFFFF
                d = c
                c = b
                b = a
                a = (temp1 + temp2) & 0xFFFFFFFF
            
            # 3.5 添加到当前哈希值
            h0 = (h0 + a) & 0xFFFFFFFF
            h1 = (h1 + b) & 0xFFFFFFFF
            h2 = (h2 + c) & 0xFFFFFFFF
            h3 = (h3 + d) & 0xFFFFFFFF
            h4 = (h4 + e) & 0xFFFFFFFF
            h5 = (h5 + f) & 0xFFFFFFFF
            h6 = (h6 + g) & 0xFFFFFFFF
            h7 = (h7 + h) & 0xFFFFFFFF
        
        # 4. 生成最终哈希值
        result = (h0.to_bytes(4, 'big') + h1.to_bytes(4, 'big') + 
                  h2.to_bytes(4, 'big') + h3.to_bytes(4, 'big') +
                  h4.to_bytes(4, 'big') + h5.to_bytes(4, 'big') +
                  h6.to_bytes(4, 'big') + h7.to_bytes(4, 'big'))
        
        return result.hex()
    
def hash0(t):
    h = __sha256__()
    return h.hash(t)
    
def hash1(t): # 将 hash0 的 self.H 的第一个参数改为 0x6a09e677
    h = __sha256__()
    h.H[0] = 0x6a09e677
    return h.hash(t)
    
def hash2(t): # 将 hash0 的 self.H 的第一个参数改为 0x6a09e657
    h = __sha256__()
    h.H[0] = 0x6a09e657
    return h.hash(t)

def hash3(t): # 将 hash0 的 self.H 的第一个参数改为 0x6a09e647
    h = __sha256__()
    h.H[0] = 0x6a09e647
    return h.hash(t)

def F(a, b, c):
    def fct(t: str) -> str: # 防冲突
        mapping = {'▚': '▚s', '▞': '▚,', '▟': '▚l', '▙': '▚r'}
        return ''.join(mapping.get(c, c) for c in str(t))
    A = fct(a)
    B = fct(b)
    C = fct(c)
    def m(a,b,c):
        return f"▟{a}▞{b}▙{c}"
    M = m(A, B, C)
    # 盐值
    s1 = hash0(hash0(a) + M + hash1(b) + ',' + hash2(c))
    s2 = hash1(hash1(a) + M + hash2(b) + ',' + hash3(c))
    s3 = hash2(hash2(a) + M + hash3(b) + ',' + hash0(c))
    s4 = hash3(hash3(a) + M + hash0(b) + ',' + hash1(c))
    s5 = hash0(f"{s1},{s2}{M}{s3},{s4}")
    s6 = hash1(f"{s2},{s3}{M}{s4},{s5}")
    s7 = hash2(f"{s3},{s4}{M}{s5},{s6}")
    s8 = hash3(f"{s4},{s5}{M}{s6},{s7}")
    s9 = hash0(f"{s5},{s6}{M}{s7},{s8}")
    s10 = hash1(f"{s1}脱{s2}口{s3}秀{s4}{M}{s5}黑{s6}客{s7},{s8},{s9}")
    s11 = hash2(f"1efab8ad12e92096487b894fd9500048{M}{s10}")
    s12 = hash3(f"686b7762985bb9bbc28d8102d0decd3e{M}{s10},{s11}")
    s13 = hash0(f"0c97a2b6fae0b071b43761cb532f29d6,ba2a5fedef2a3002b11d8956c03cf7e9{M}{s10},{s12}")
    s14 = hash1(f"7eadf63798d64ea5cd39e21b687eef49,3832593989ef3c25a7e589a8429650c0{M}{s10},{s11},{s12},{s13}")
    s15 = hash2(f"9222c7046082d3c8e8a1f572f888d3d6,1f2a18d1f8fc2ac64c12bbf0eedf6628{M}{s10},{s11},{s12},{s13},{s14}")
    __s15dot5__ = f"{s15},1f2a18d1f8fc2ac64c12bbf0eedf6628{M}{s10},{s11},{s12},{s13},{s14},{s15[0:32]}"
    s15dot5 = hash2(__s15dot5__)[0:32] + hash3(__s15dot5__)[32:64]
    s16 = hash3(f"{s1},{s5}{M}{s10},{s11},{s12},{s13},{s14},{s15}[下一个盐是s15.5]{s15dot5}")
    s17 = hash0(f"{s2},{s6}{M}{s10},{s11},{s12},{s13},{s14},{s15},{s16}")
    s18 = hash1(f"{s3},{s7}{M}{s10},{s11},{s12},{s13},{s14},{s15},{s16},{s17}")
    s19 = hash2(f"{s4},{s8}{M}{s10},{s11},{s12},{s13},{s14},{s15},{s16},{s17},{s18}")
    s20 = hash3(f"{s1},{s2},{s3},{s4},{s9}{M}{s10},{s11},{s12},{s13},{s14},{s15},{s16},{s17},{s18},{s19}")
    s21 = hash0(f"{M}{s1}¦{s2}¥{s3}¤{s4}£{s5}¢{s6}¡{s7}¨{s8}©{s9}¬{s10}¿{s11}[¿¦]{s12}[¿¥]{s13}[¿¤]{s14}[¿¤]{s15}[¿£]{s16}[¿¢]{s17}[¿¡]{s18}[¿¨]{s19}[¿©]{s20}")
    s22 = hash1(f"{hash0(a)},{hash1(b)},{hash2(c)}{M}{s1}◊{s2}◊{s3}◊{s4}◊{s5}◊{s6}◊{s7}◊{s8}◊{s9}◊{s10}◊{s11}◊{s12}◊{s13}◊{s14}◊{s15}◊{s16}◊{s17}◊{s18}◊{s19}◊{s20}◊{s21}")
    return hash0(f"{hash0(a)},{hash0(b)},{hash0(c)}◈{hash1(a)},{hash1(b)},{hash1(c)}◈{hash2(a)},{hash2(b)},{hash2(c)}◈{hash3(a)},{hash3(b)},{hash3(c)}{M}{s1},{s2},{s3},{s4},{s5},{s6},{s7},{s8},{s9},{s10},{s11},{s12},{s13},{s14},{s15},{s16},{s17},{s18},{s19},{s20},{s21},{s22}")
