styleCombine3
=============

功能简介
---------------------

styleCombine 有以下几个核心功能：

1、将 HTML 页面上的多个 js/css 请求自动地合并成一个请求，发送给 combo 服务器。

2、对于入口的 AMD/CMD 模块，能够自动解析出模块的深层依赖关系，并将所依赖文件及页面上的其它 js 文件合并为一个请求发送。

3、对 HTML 页面中每个 js/css 链接都会根据文件内容自动地添加版本号后缀，js/css 内容更新将触发版本号的实时更新，使得浏览器端缓存或 CDN 缓存能够强制失效。

4、解决平滑发布问题：当js/css服务器与后台应用服务器分集群部署时，在发布过程中会遇到样式与后台代码上线不同步的问题，造成短时间的线上服务异常，StyleCombine可以自动化地解决这个问题。


styleCombine 系统主要由三大部分组成，分别是：

1、安装在应用服务器上的 apache/nginx 模块。

2、运行在静态资源服务器上的 NodeJS [依赖解析服务](https://github.com/fangdeng/VersionCenter)。

3、接收 combo URL 请求的 [Tengine 服务器](http://tengine.taobao.org/index_cn.html)。

该项目是对 apache/nginx 模块的代码实现。


安装配置
---------------------

apache 版本：

(1)获取[最新版本](bin/apache/20140402.zip)的 mod_styleCombine.so 及 StyleVersionUpdator 文件。

(2)将 mod_styleCombine.so 放置在应用的 ${xxx_deployhome}/conf/modules文件夹中，StyleVersionUpdator 放在应用的 ${xxx_deployhome}/bin/ 文件夹中

(3)配置 Apache 服务器的 httd.conf 文件，增加如下代码：

	    #set($appName = "应用的名称")
		LoadModule styleCombine_module   ${xxx_deployhome}/conf/modules/mod_styleCombine.so
		<IfModule mod_styleCombine.c>
			SC_Enabled       On
			SC_AppName       $!appName
			SC_OldDomains    http://style.c.aliimg.com;
			SC_NewDomains    http://astyle.alicdn.com;
			SC_FilterCntType text/html;text/htm;
			SC_MaxUrlLen     1024
			LogFormat        nolog
			CustomLog "| ${xxx_deployhome}/bin/StyleVersionUpdator http://style-center.alibaba-inc.com:8080/output/styleVersion.tar.gz?appName=$!appName ${xxx_output}/ 120" nolog
		</IfModule>

	注意：
	
	a、$appName、${xxx_deployhome}、${xxx_output} 这三个变量需要替代为应用自定义的值。
	
	b、SC_OldDomains可以配置为多域名，域名之间用封号分隔，并需要在SC_NewDomains中对应重写后的域名。
	
	c、SC_AsyncVariableNames 可以配置将 js 异步加载时生成的全局变量的名字。
	
	d、SC_BlackList 及 SC_WhiteList配置可以为符合某些规则的 URL 不进行或进行 Combine 处理。
	
	e、CustomLog 中 StyleVersionUpdator 传入的第一个参数就是 NodeJS 依赖解析服务(https://github.com/fangdeng/VersionCenter)的服务接口 URL 地址。 

	
	
nginx 版本：

(1)获取最新版本的源码，并编译安装为 nginx 插件。 

(2)配置 nginx 服务器 nginx.conf 文件，增加如下代码：

	SC_Enabled on;
	SC_AppName searchweb2;
	SC_OldDomains http://style.c.aliimg.com;
	SC_OldDomains http://static.c.aliimg.com;
	SC_NewDomains http://astyle.alicdn.com;
	SC_NewDomains http://astatic.alicdn.com;
	SC_FilterCntType  text/html;
	SC_AsyncVariableNames asyncResource;
	#SC_BlackList  /nginx_combine_test/7/[0-9]*.[0-9]*.html;
	#SC_WhiteList  /nginx_combine_test/7/[0-9]*.[0-9]*.html;
	SC_MaxUrlLen    1024;
	process styleupdator {
	 style_updator_url http://style-center.alibaba-inc.com:8080/output/styleVersion.tar.gz?appName=offerweb;
	 style_updator_path /home/admin/output/run/stylecombine/;
	 style_updator_internal 120;
	 style_updator_amd on;
	 style_updator_debug off;
	}

	
目录结构
-------------------------

src/目录

	  apache目录
		styleCombine提供apache的模块支持；进入apache目录运行make && make install 进行编译。
	  client目录
		styleCombine必须有一个client运行在应用端，用于定时更新style文件的版本号作用，进入client目录运行 make && make install 编译
	  nginx目录
		styleCombine提供nginx的模块支持；编译Nginx时在configure命令后面加上--add-module=/path/to/styleCombine3/src/nginx/即可完成编译。
	  lib目录
		模块的核心库

tests/目录

    src/lib 库的测试代码

conf/目录

    apache目录
        在apache中如何配置模块
    nginx目录
        在nginx中如何配置模块

开发历史
--------------------
1.styleCombine最初的版本由@zhiwen(doudouhamao@gmail.com)独立开发，最初版只支持Apache。

2.styleCombine2 是在最初版本的基础之上进行了以下功能增强：

  增加了平滑发布功能 @wtxidian(wtxidian@163.com)。
	
  增加了对js依赖关系解析功能的支持，使之成为一个服务端的 AMD 加载器。能够促进前端更彻底的模块化开发 @xiaoji121(dong.fly.ming@gmail.com)
	
  对内存的使用进行了优化，解决大页面渲染的内存使用bug @zhiwen

3.styleCombine3 是由 @zhiwen 对整个代码结构进行了分离，把 stylecombine 合并 js/css 链接的逻辑独立出来，为 styleCombine 支持多种WEB容器做准备;

@brytonlee(brytonlee01@gmail.com)在 @zhiwen 的工作之上继续开发，使之能够适配 Nginx; 到目前为止(2014-02-21) styleCombine2 的新增功能也已合并到 styleCombine3 中。

