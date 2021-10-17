# turned

A coredns plugin to turn DNS query.

forward 的变形, dns 按分组选择查询上游。没计划实现dns优选(建议使用 Edns-Client-Subnet)。 收集常用的app的一，二级域名

## Usage

```
.:1053 {
    bind 127.0.0.1
    errors

    log . {
        class all
    }

    turned inside {
        rules domains.txt
        to 223.5.5.5:53
#        size_rate 10000 0.01
        except b.example.com
    }

    turned finally {
        from .
        to 10.2.0.22:53
    }
    
    # 基本组成单位
    turned 组名 {
        # 来自配置的单个或多个域名，多个时会自动转换类型
        from .
        
        # 来自文件的域名规则
        rules domains.txt
        
        # 转发至指定dns
        to 10.2.0.22:53
    }
}
```

+ 默认支持泛域名检测，即
    - `*.cn` 会匹配所有`cn`域名

    * `*.example.com` 会匹配所有`example.com`的子域名
        - 要匹配`example.com`则需要创建一条`example.com`的规则