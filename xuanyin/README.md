# 玄印（Xuanyin）

面向无安全设计程序的可嵌入跨语言加密信封。本仓库用于赛事评审与复现验证。

- 在线试用：`index.html`（加密器入口 `app.html`）
- 源码索引：`source.html`
- 校验清单：`SHA256SUMS.txt`（逐文件 SHA256，与提交文档 4.2 一致）

## 结构

```
app.html            加密器主程序（与 source/玄印_v1.1.0.html 逐字节相同）
example.html        嵌入宿主程序的接入示例
source/             全部源码与规范，路径同交付目录
SHA256SUMS.txt      校验清单
```

## 复现

按 `source/跨语言/README.md` 的顺序运行各语言 demo，可复现同一封信封在不同实现间解密一致；
三级中间值见 `source/跨语言/test_vectors.json`。

## 许可

仅授权赛事评审、学习与复现验证使用，未授权商业使用与再分发。见 `LICENSE`。
