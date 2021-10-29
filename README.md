# turned

A coredns plugin to turn DNS query.

forward的改造，dns按分组选择查询上游。没计划实现dns优选(建议使用Edns-Client-Subnet)。 


## Usage

```
.:1053 {
    bind 127.0.0.1
    errors

    log . {
        class all
    }

    returned push {
        from *.push.apple.com *.ntp.org
        to 223.5.5.5:53 
        prefer_udp
        policy sequential
    }

    turned inside {
        rules domains.txt
        to 223.5.5.5:53
        except b.example.com
    }

    turned finally {
        from .
        to 1.1.1.1:53 1.0.0.1:53
    }
    
    # 基本组成单位
    turned 组名 {
        # 来自配置的单个或多个域名，多个时会自动转换类型(from与rules 不能共存)
        from .
        
        # 来自文件的域名规则
        rules domains-1.txt
        rules domains-2.txt
        rules https://domains.txt

        rules cache+domains.dat
        rules cache+https://domains.dat
        
        # 转发至指定dns
        to 1.1.1.1:53
    }
}
```

+ 默认支持泛域名检测，即
  - `*.cn` 会匹配所有`cn`域名

  * `*.example.com` 会匹配所有`example.com`的子域名
    - 要匹配`example.com`则需要创建一条`example.com`的规则

TODO:

- 使用`C99.NL`收集域名
- 
