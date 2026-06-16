# CFL 接入说明

## 当前实现

后端已实现两种 CFL 模式：

- `mock`：默认模式，使用 HMAC 模拟签名验签，适合无 UKey 环境演示。
- `real`：使用 `ctypes` 调用 `CFLClientLib.dll`，接口来自 CFL 教学版开放接口头文件和密码应用接口规范。

真实接入文件：

- `backend/app/services/cfl_real_service.py`
- `backend/app/services/cfl_service.py`
- `backend/CFLClientLib.dll`
- `backend/cfl_helper/CflHelper.exe`

## 已封装接口

- `CFL_Connect`
- `CFL_Close`
- `CFL_GenRandom`
- `CFL_ExportPublicKey`
- `CFL_DigestInit`
- `CFL_Digest`
- `CFL_Sign`
- `CFL_Verify`
- `HexToBytes`

## 配置

`.env`：

```env
CLAWGUARD_CFL_MODE=real
CLAWGUARD_CFL_DLL_PATH=./CFLClientLib.dll
```

保持 mock：

```env
CLAWGUARD_CFL_MODE=mock
```

## 自检接口

```text
GET /api/auth/cfl/status
```

返回示例：

```json
{
  "mode": "mock",
  "using_real": false,
  "dll_path": "CFLClientLib.dll",
  "real": {
    "dll_path": "D:\\clawguard\\backend\\CFLClientLib.dll",
    "dll_exists": true,
    "dll_arch": "x86",
    "connected": false,
    "loadable": false,
    "error": "load_dll failed: [WinError 193] %1 不是有效的 Win32 应用程序。"
  }
}
```

管理员可调用更深的导出诊断：

```text
GET /api/auth/cfl/diagnostics
```

该接口会模拟厂商 `FunTest.exe` 的 “导出公钥” 路径，并返回连接和导出接口的原始返回码。

## 位数要求

当前教学包 `CFLClientLib.dll` 是 x86 DLL。64 位 Python 无法直接加载 x86 DLL，会报 `WinError 193`。

项目已内置 x86 `.NET Framework` 本地助手：

```text
backend/cfl_helper/CflHelper.exe
```

当后端检测到 `dll_arch=x86` 且 `python_bits=64` 时，会自动通过该 helper 调用真实 `CFLClientLib.dll`，不再需要把整个后端换成 32 位 Python。

helper 同目录需要包含：

- `CFLClientLib.dll`
- `pkb_mimaji.txt`
- `MSVCR120.dll`

`MSVCR120.dll` 是 Visual C++ 2013 x86 运行库。缺少时 `LoadLibrary` 会返回 126，表现为 “找不到指定的模块”。

当前本机验证结果：

- DLL 可加载：`dll_loadable=true`
- helper 桥接可用：`using_helper=true`
- 真实设备调用到达 `CFL_Connect`
- Windows PC/SC 可见读卡器：`JNZG CCID KEY 0`、`JNZG CCID KEY 1`
- Windows 可见卡：`Identity Device (NIST SP 800-73 [PIV])`
- 当前 `CFL_Connect` 返回 `167772197 (0x0A000025)`，`CFL_Connect2` 返回 `167772196 (0x0A000024)`。
- 模拟 `FunTest.exe` 的导出公钥路径时，`CFL_ExportPublicKey` 返回 `167772165 (0x0A000005)`，输出公钥缓冲区保持全零。

这说明调用已经进入真实 `CFLClientLib.dll`，但 CFL DLL 没有打开它期望的 CFL 应用/容器。常见原因：

- UKey 不是该教学包 DLL 配套初始化过的 CFL UKey。
- 设备驱动只暴露为通用 PIV/CCID，未暴露 CFL DLL 期望的应用。
- UKey 内未创建或未初始化 DLL 内置期望的 `CFLL_APP` / `CFL_CON` 应用容器。
- PIN/初始化参数与教学版测试程序不一致。

下一步建议先手动运行厂商 `测试实例/FunTest.exe`。如果厂商测试程序也无法完成 “CFL 安盾连接/随机数/导出公钥”，则需要先用厂商工具初始化 UKey 或安装匹配驱动；如果厂商测试程序能成功，再按其初始化参数同步到 `CflHelper.cs`。

可选方案：

1. 使用当前内置 x86 helper。
2. 使用厂商提供的 x64 版本 `CFLClientLib.dll`，后端可直接 `ctypes` 加载。
3. 改用 32 位 Python 运行后端。

## 登录验签流程

1. `POST /api/auth/challenge` 生成 nonce 和 canonical message。
2. 客户端或签名助手用 CFL UKey 对 message 签名。
3. `POST /api/auth/cfl-login` 提交 uid、nonce、timestamp、signature。
4. 后端使用用户数据库中的 CFL 公钥验签；若未登记公钥，在教学 real 模式下可导出当前 UKey 公钥用于本机演示。
