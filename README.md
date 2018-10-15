## SDL China

所有文档都来自中国互联网一线安全工程师编写整理

## 官网

```
https://www.sdlchina.org.cn
```
 
## 下载文档方法

clone 项目到本地

所有文档都在**_post**目录下，以markdown文件进行存储，可以直接保存

## 本地搭建方法

需要安装ruby和bundler以及jekyll
```
git clone https://github.com/sdlchina/sdlchina-web.git
```

在项目根目录执行

```
bundler install
```
安装完成后执行
```
jekyll server
```
打开浏览器
```
http://127.0.0.1:4000
```

## 提交文章和改进

请参考git工作流方法

fork项目到自己账户，修改后提交给主分支，审核后即可展示。
提交可以多种方式，如web、命令、客户端，这里演示web提交方式
提交SDL落地方案-产品设计
1. 选择相应的文件,所有文档都在**_post**目录下
```
sdlchina-web/_posts/3.SDL落地方案/2018-08-17-SDL-3-产品设计.md
```

选择edit或者create new file，文件名必须要符合: YEAR-MONTH-DAY-title.md

![图片1](1.png)

1. 编辑文档
所有博客文章顶部必须有一段YAML头信息(YAML front- matter),文章可以使用markdown格式编写
```
---
date: 2018-08-17
title: 03.产品设计
categories:
  - 3.SDL落地方案
description: 和研发同学进行产品设计定框架部分应该怎么去执行
type: Document
---
```

编辑完成之后点击commit changes(同命令git add . && git commit -m "添加产品设计" && git pusht origin master)

![图片2](2.png)

1. 提交pull请求
点击New pull request

![图片3](3.png)

检查没有问题，点击Create pull request

![图片4](4.png)

提交成功，等待管理员Merge之后就成功了

![图片5](5.png)

## 署名

原则上对文章修改后即可进行署名在协作者添加上自己的ID。

## About页面变更

需要对网站文档进行提交建议以及文档改进或者文档编写方可在About页面添加自己ID

排序需要按照字母顺序排序。
