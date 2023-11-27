import numpy as np
import matplotlib.pyplot as plt

# 生成 x 值的范围
x = np.linspace(0, 1, 100)

# 计算对应的 y 值
y = (61.8404 - 11.88*x) / 72

# 绘制曲线
plt.plot(x, y)

# 设置坐标轴标签
plt.xlabel('x')
plt.ylabel('y')

# 设置图标题
plt.title('Graph of 11.88*x + 72*y = 61.8404')

# 显示图形
plt.show()
