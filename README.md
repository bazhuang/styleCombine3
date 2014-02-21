styleCombine3
=============

styleCombine3功能简介
---------------------
styleCombine3主要用于合并HTML页面里的js和css链接，并把合成之后链接地址的域名替换成指定的域名。

通常前端研发工程师在开发当中，会在一张页面中引用很多js和css文件，浏览器要渲染一张完整的页面需要对每一个js/css文件引用做加载，当页面引用js/css资源较多时页面渲染的速度较慢，对用户的体验不佳。如果能把页面用到的js/css资源合并到一个大的js/css文件里面，页面在浏览器端进行渲染的时候只要加载一次就能把页面渲染出来，加快了渲染的速度和提升了用户的体验。

styleCombine就是为了这个目标而创建的。为了实现这个目标可以通过很多方式实现,比如:

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

2.styleCombine2在最初版本的基础之上做了改进和功能的增加。

3.styleCombine3由@zhiwen对整个代码结构进行了分离，把stylecombine合并js/css链接的逻辑独立出来，为styleCombine支持多种WEB容器做准备;@brytonlee(brytonlee01@gmail.com)在@zhiwen的工作之上继续开发，使之能支持Nginx;与此同时在@zhiwen开发styleCombine2之后，@xiaoji121(dong.fly.ming@gmail.com)在styleCombine2的基础之上增加了js/css依赖关系解析功能。到目前为止(2014-02-21) @xiaoji121开发的功能也合并到styleCombine3当中。

