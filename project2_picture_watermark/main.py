import os
import cv2
from blind_watermark import WaterMark

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
