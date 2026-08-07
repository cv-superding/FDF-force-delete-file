"""生成 FDF 应用图标 assets/fdf.ico（32x32，红色圆角底 + 白色垃圾桶）。"""
import struct
import os

S = 32
BG = (210, 59, 59, 255)      # 红色背景 RGBA
WHITE = (255, 255, 255, 255)
EMPTY = (0, 0, 0, 0)


def rounded_rect_alpha(x, y, w, h, r):
    """返回是否在该圆角矩形内部（含圆角）。"""
    if x < 0 or y < 0 or x >= w or y >= h:
        return False
    if r <= 0:
        return True
    # 四个圆角中心
    corners = [(r, r), (w - 1 - r, r), (r, h - 1 - r), (w - 1 - r, h - 1 - r)]
    if x >= r and x < w - r:
        return True
    if y >= r and y < h - r:
        return True
    for (cx, cy) in corners:
        if (x - cx) ** 2 + (y - cy) ** 2 <= r * r:
            return True
    return False


def draw(cx, cy, rx, ry, color, grid):
    for y in range(S):
        for x in range(S):
            if (x - cx) ** 2 / (rx * rx) + (y - cy) ** 2 / (ry * ry) <= 1:
                grid[y][x] = color


def build():
    grid = [[EMPTY for _ in range(S)] for _ in range(S)]
    # 背景圆角矩形
    for y in range(S):
        for x in range(S):
            if rounded_rect_alpha(x, y, S, S, 7):
                grid[y][x] = BG
    # 垃圾桶（白色）
    # 把手
    for y in range(5, 9):
        for x in range(13, 19):
            grid[y][x] = WHITE
    # 盖
    for y in range(9, 12):
        for x in range(7, 25):
            grid[y][x] = WHITE
    # 桶身
    for y in range(12, 27):
        for x in range(9, 23):
            grid[y][x] = WHITE
    # 竖向纹路（用背景色挖出）
    for y in range(13, 26):
        for x in (12, 15, 18):
            grid[y][x] = BG
    # 底部加厚
    for y in range(25, 27):
        for x in range(8, 24):
            grid[y][x] = WHITE
    return grid


def to_ico(grid, path):
    # 行从下到上（bottom-up），BGRA
    xor = bytearray()
    for y in range(S - 1, -1, -1):
        for x in range(S):
            r, g, b, a = grid[y][x]
            xor += bytes((b, g, r, a))
    # AND mask：全 0（全部绘制，由 alpha 决定透明）
    and_row = b"\x00" * 4  # 32px -> 1 DWORD
    and_mask = and_row * S
    bmp_header = struct.pack("<IiiHHIIiiII",
                             40,        # biSize
                             S,         # biWidth
                             S * 2,     # biHeight（含 AND mask 高度翻倍）
                             1,         # biPlanes
                             32,        # biBitCount
                             0,         # biCompression
                             len(xor) + len(and_mask), 0, 0, 0, 0)
    image = bmp_header + bytes(xor) + and_mask
    icon_dir = struct.pack("<HHH", 0, 1, 1)  # reserved, type=icon, count=1
    entry = struct.pack("<BBBBHHII",
                        S, S, 0, 0, 1, 32,
                        len(image), 6 + 16)
    with open(path, "wb") as f:
        f.write(icon_dir + entry + image)


if __name__ == "__main__":
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fdf.ico")
    build_ = build()
    to_ico(build_, out)
    # 校验
    with open(out, "rb") as f:
        data = f.read()
    reserved, typ, count = struct.unpack("<HHH", data[:6])
    w_, h_, _, _, planes, bpp, sz, off = struct.unpack("<BBBBHHII", data[6:22])
    print(f"ico size={len(data)} bytes, count={count}, dim={w_}x{h_}, bpp={bpp}, imgBytes={sz}, off={off}")
    assert len(data) == off + sz, "size mismatch"
    print("OK ->", out)
