styleCombine3
=============

styleCombine3

src/apache 目录
	styleCombine提供apache的模块支持；进入apache目录运行make && make install 进行编译

	client 目录
	styleCombine必须有一个client运行在应用端，用于定时更新style文件的版本号作用，进入client目录运行 make && make install 编译

	nginx 目录
	styleCombine提供nginx的模块支持；目录还未开发好nginx版本。

	lib 目录
	模块的核心庘

tests 目录
	lib 庘的测试代码

conf/apache 目录
	在apache中如何配置模块

	nginx 目录
	在nginx中如何配置模块