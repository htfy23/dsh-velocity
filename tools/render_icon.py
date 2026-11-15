"""把 icon.svg 的图案用 Pillow 重绘成 180x180 PNG。

为什么不直接转 SVG：环境里没有 cairo（cairosvg 报 libcairo-2 缺失），
也没有 inkscape/rsvg/ImageMagick。而这张图只有圆、椭圆、直线三种元素，
按 SVG 里的坐标等比放大重绘比装依赖更可靠。

坐标全部来自 icon.svg 的 viewBox 0 0 32 32，按目标尺寸缩放。
用 4x 超采样再缩小做抗锯齿。
"""
import sys
from PIL import Image, ImageDraw

SIZE = 180
SS = 4                      # 超采样倍数
S = SIZE * SS
K = S / 32.0                # viewBox 32 -> 像素


def px(v):
    return v * K


def main(out_path):
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # 1. 主体圆盘：径向渐变用多层同心圆近似（外圈偏紫，中心近黑）
    cx = cy = px(16)
    r = px(15)
    stops = [
        (0.00, (10, 10, 18)),
        (0.55, (22, 18, 42)),
        (0.82, (58, 43, 116)),
        (1.00, (106, 79, 208)),
    ]
    # SVG 的 offset 0% 在圆心（近黑），100% 在外缘（紫）——
    # 所以从外向内画：t=1 画最外圈，t=0 画圆心，半径随 t 减小。
    steps = 220
    for i in range(steps):
        t = 1.0 - i / (steps - 1)
        lo = max(s for s in stops if s[0] <= t)
        hi = min((s for s in stops if s[0] >= t), default=lo)
        if hi[0] == lo[0]:
            col = lo[1]
        else:
            f = (t - lo[0]) / (hi[0] - lo[0])
            col = tuple(round(lo[1][j] + (hi[1][j] - lo[1][j]) * f) for j in range(3))
        rr = r * t
        d.ellipse([cx - rr, cy - rr, cx + rr, cy + rr], fill=col + (255,))

    # 2. 外圈描边（#8f74ff 45%）
    sw = max(1, round(px(1)))
    d.ellipse([cx - r, cy - r, cx + r, cy + r], outline=(143, 116, 255, 115), width=sw)

    # 3. 两条倾斜椭圆环（吸积盘），绕中心 -26 度
    #    Pillow 画不了旋转椭圆，先在独立图层画正椭圆再旋转合成
    for rx, ry, col, opac, wid in (
        (14.2, 4.1, (165, 140, 255), 140, 0.9),
        (12.4, 3.1, (205, 188, 255), 71, 0.7),
    ):
        layer = Image.new("RGBA", (S, S), (0, 0, 0, 0))
        ld = ImageDraw.Draw(layer)
        ex, ey = px(rx), px(ry)
        lw = max(1, round(px(wid)))
        ld.ellipse([cx - ex, cy - ey, cx + ex, cy + ey],
                   outline=col + (opac,), width=lw)
        layer = layer.rotate(-26, center=(cx, cy), resample=Image.BICUBIC)
        img = Image.alpha_composite(img, layer)
    d = ImageDraw.Draw(img)

    # 4. 内圈黑核（#05050b）
    hr = px(6.4)
    d.ellipse([cx - hr, cy - hr, cx + hr, cy + hr], fill=(5, 5, 11, 255))

    # 5. 黑核外的亮环（#bdaaff 85%）
    er = px(7.2)
    d.ellipse([cx - er, cy - er, cx + er, cy + er],
              outline=(189, 170, 255, 217), width=max(1, round(px(0.9))))

    # 6. 表针（时钟感）：指向 12 点与 ~4:30
    lw1 = max(2, round(px(1.5)))
    d.line([cx, cy, cx, cy - px(4.3)], fill=(232, 220, 255, 255), width=lw1)
    d.line([cx, cy, cx + px(3.2), cy + px(2.05)], fill=(232, 220, 255, 255),
           width=max(2, round(px(1.25))))

    # 7. 中心点
    pr = px(0.95)
    d.ellipse([cx - pr, cy - pr, cx + pr, cy + pr], fill=(241, 233, 255, 255))

    # 缩小做抗锯齿
    out = img.resize((SIZE, SIZE), Image.LANCZOS)
    out.save(out_path, "PNG", optimize=True)
    print("wrote %s (%dx%d)" % (out_path, SIZE, SIZE))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "assets/icon-180.png")
