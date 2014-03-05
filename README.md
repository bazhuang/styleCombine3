styleCombine3
=============

styleCombine3功能简介
---------------------

styleCombine 有以下几个核心功能：

1、将页面上的多个js/css请求自动地合并成一次请求，发送给style combo服务器，提升页面的性能。

2、js/css版本管理：每个js/css都会被自动地加上版本号后缀，一旦js/css内容有修改，版本号会重新生成，并更新页面上的js/css版本号后缀，使得浏览器端缓存(CDN缓存)自动失效，浏览器可获取到服务端最新的js/css。js/css版本升级过程实现自动化。

3、解决平滑发布问题：当js/css服务器与后台应用服务器分集群部署时，在发布过程中会遇到样式与后台代码上线不同步的问题，造成短时间的线上服务异常，StyleCombine可以自动化地解决这个问题。

4、AMD开发模式的支持：可以动态自动解析入口的main.js所依赖的所有子模块js，并合并成一个combo请求发送给Tengine服务器。这样开发模式下多个js会被异步加载，而线上模式多个js则被合并为一个请求。整个过程无需手工配置，全自动完成。


为了实现以上目标可以通过多种方式实现,比如:

    1.通过前端研发工程师手动合并页面引用到的js/css文件到一个大的js/css文件里面，然后把页面引用到js/css的链接全部去掉，页面中只留下合并之后的js/css文件链接，
    这种方式的对于前端研发工程师的工作量较大，并且当有很多页面需要开发或者持续开发的时候，又或者是页面由动态内容产生时，这种方法显得不太现实。
    
    2.另外一种可能就是在动态内容容器(Jetty/Tomcat/Jboss)里面对js/css引用的链接进行合并，页面最终只引用合并之后的js/css链接，
    然后输出到前端的WEB容器(Apache/Nginx),最后发送到浏览器。
    这种实现最大的问题在于动态内容容器通常使用的脚本语言，而脚本语言的执行效率通常被认为低于编译型语言; 
    
styleCombine采用的方式不同于前面的两种，而是通过在WEB容器(Apache/Nginx)安装模块的方法来实现这一目标。由于在WEB容器中完成合并引用js/css资源的链接，对于前端研发工程师的介入较少，同时又能得益于编译型语言的执行效率。

styleCombine不能独立工作，还需要一个存放js/css的集群，这个集群能对合并之后js/css链接进行解析并把合并之后内容发送给浏览器。前端研发工程师把每一个开发好的js/css页面存放到集群，然后在开发其他页面或者动态内容当中对于需要引用合并资源的链接进行简单的标注，当浏览器请求一张页面时，页面经过WEB容器的styleCombine模块，styleCombine模块对页面引用的js/css链接进行合并，并把合并之后的域名替换成存有js/css资源的集群域名。最终页面到浏览器端的时候对于页面js/css资源的加载只需一次。


styleCombine3的目录结构
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

styleCombine开发历史
--------------------
1.styleCombine最初的版本由@zhiwen(doudouhamao@gmail.com)独立开发，最初版只支持Apache。

2.styleCombine2 是在最初版本的基础之上进行了以下功能增强：

	1、增加了平滑发布功能 @wtxidian(wtxidian@163.com)。
	
	2、增加了对js依赖关系解析功能的支持，使之成为一个服务端的 AMD 加载器。能够促进前端更彻底的模块化开发 @xiaoji121(dong.fly.ming@gmail.com)
	
	3、对内存的使用进行了优化，解决大页面渲染的内存使用bug @zhiwen

3.styleCombine3是由@zhiwen对整个代码结构进行了分离，把stylecombine合并js/css链接的逻辑独立出来，为styleCombine支持多种WEB容器做准备;

@brytonlee(brytonlee01@gmail.com)在@zhiwen的工作之上继续开发，使之能够适配 Nginx; 到目前为止(2014-02-21) styleCombine2的新增功能也已合并到styleCombine3中。

