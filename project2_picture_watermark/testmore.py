#main.py
import os
import cv2
from blind_watermark import WaterMark
import att
import numpy as np

# ========== 配置 ==========
# 原始图像路径（用于嵌入水印）
img_path = 'test.jpg'

# 水印内容，可以是字符串，也可以是图片路径
watermark = '这是一段测试水印'  # 或 'logo.png'
#watermark = 'watermark.png'  # 或 'logo.png'
# 输出路径
output_embed_path = 'test_embed.jpg'
output_extracted_path = 'test_extracted.png'

# 密码
password_wm = 1
password_img = 1

#判断水印类型
if isinstance(watermark, str) and os.path.isfile(watermark):
    wm_mode = 'img'
elif isinstance(watermark, str):
    wm_mode = 'str'
else:
    raise ValueError('无法识别的水印类型')

#嵌入
bwm = WaterMark(password_wm=password_wm, password_img=password_img)
bwm.read_img(img_path)

if wm_mode == 'str':
    bwm.read_wm(watermark, mode='str')
    wm_shape = (1, len(bwm.wm_bit))  #一维字符串的比特长度
elif wm_mode == 'img':
    wm_img = cv2.imread(watermark, cv2.IMREAD_GRAYSCALE)
    assert wm_img is not None, f"无法读取水印图像: {watermark}"
    bwm.read_wm(watermark, mode='img')
    wm_shape = wm_img.shape  # 获取图像尺寸

bwm.embed(output_embed_path)
print(f"成功嵌入水印，保存为：{output_embed_path}")

#提取
bwm_extract = WaterMark(password_wm=password_wm, password_img=password_img)
wm_result = bwm_extract.extract(
    filename=output_embed_path,
    wm_shape=wm_shape,
    out_wm_name=output_extracted_path if wm_mode == 'img' else None,
    mode=wm_mode
)

if wm_mode == 'str':
    print(f"成功提取字符串水印: {wm_result}")
elif wm_mode == 'img':
    print(f"成功提取图片水印，保存为：{output_extracted_path}")

# 创建一个攻击输出目录
os.makedirs('attacked', exist_ok=True)

# 攻击测试列表（函数名、参数、输出名）
attack_list = [
    ('flip', lambda: cv2.flip(cv2.imread(output_embed_path), 1), 'attacked/flip.jpg'),
    ('shift', lambda: np.roll(cv2.imread(output_embed_path), 10, axis=1), 'attacked/shift.jpg'),
    ('crop', lambda: att.cut_att3(input_filename=output_embed_path, loc_r=((0.2, 0.2), (0.8, 0.8))), 'attacked/crop.jpg'),
    ('contrast', lambda: att.bright_att(input_filename=output_embed_path, ratio=1.5), 'attacked/contrast.jpg'),
    ('blur', lambda: cv2.GaussianBlur(cv2.imread(output_embed_path), (5, 5), 0), 'attacked/blur.jpg'),
    ('jpeg', lambda: cv2.imdecode(cv2.imencode('.jpg', cv2.imread(output_embed_path), [int(cv2.IMWRITE_JPEG_QUALITY), 25])[1], 1), 'attacked/jpeg.jpg'),
    ('resize', lambda: att.resize_att(input_filename=output_embed_path, out_shape=(300, 300)), 'attacked/resize.jpg'),
    ('shelter', lambda: att.shelter_att(input_filename=output_embed_path, ratio=0.2, n=2), 'attacked/shelter.jpg'),
    ('salt_pepper', lambda: att.salt_pepper_att(input_filename=output_embed_path, ratio=0.01), 'attacked/salt.jpg'),
    ('rotate', lambda: att.rot_att(input_filename=output_embed_path, angle=30), 'attacked/rotate.jpg'),
]

print("开始鲁棒性攻击测试：")
for name, attack_func, attacked_path in attack_list:
    try:
        attacked_img = attack_func()
        cv2.imwrite(attacked_path, attacked_img)

        # 提取攻击后的水印
        bwm_attacked = WaterMark(password_wm=password_wm, password_img=password_img)
        wm_att = bwm_attacked.extract(
            filename=attacked_path,
            wm_shape=wm_shape,
            out_wm_name=None if wm_mode == 'str' else f'attacked/{name}_wm.png',
            mode=wm_mode
        )

        if wm_mode == 'str':
            print(f"{name}：提取字符串水印成功：{wm_att}")
        else:
            print(f"{name}：提取图像水印成功，保存为 attacked/{name}_wm.png")

    except Exception as e:
        print(f"{name}：提取失败，错误信息：{e}")
