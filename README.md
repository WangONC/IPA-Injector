# IPA-Injector

IPA-Injector是一个macOS下的全自动的IPA动态库注入shell脚本，支持注入 `.dylib` 和 `.framework` ，并自动完成重签名和安装。从开始注入到启动应用，一键完成，非常丝滑。

因为是shell脚本，所以只有现有工具集中调用，没有造任何轮子。

## 依赖

在运行脚本之前，请确保已安装以下依赖：

### 必需依赖

- `unzip`：用于解压 IPA 文件，一般macOS自带，无需手动安装。
- `zip`：用于重新打包 IPA 文件，一般macOS自带，无需手动安装。
- `codesign`：用于代码签名，通常包含在 Xcode 命令行工具中。
- `security`：用于处理证书和描述文件，一般macOS自带，无需手动安装。
- `plutil`：用于处理 `.plist` 文件，一般macOS自带，无需手动安装。
- `pymobiledevice3`：用于与 iOS 设备交互，安装 IPA 文件，启动debugserver等。
- `insert_dylib`：用于将动态库注入到二进制文件中。
- `applesign`：node工具，用于重签名 IPA 文件（所以还需要node）。

### 可选依赖

- `openssl`：用于生成随机字符串作为动态库名称。如果未安装，脚本将使用其他的随机字符串作为备选方案。

### 安装依赖

```bash
# 安装 Xcode 命令行工具
xcode-select --install

# 安装 unzip 和 zip，一般来说系统会有
brew install unzip zip

# 安装 pymobiledevice3
python3 -m pip install -U pymobiledevice3

# 安装 insert_dylib
git clone https://github.com/Tyilo/insert_dylib
cd insert_dylib
xcodebuild
cp build/Release/insert_dylib /usr/local/bin/insert_dylib

# 安装 applesign
brew install node
npm install -g applesign

# 安装 openssl（可选）
brew install openssl
```

## 使用说明

### 基本用法

首先单独创建一个文件夹，将当前脚本，需要注入的ipa，以及所有dylib、framework，描述文件放入其中。

描述文件建议命名为`embedded.mobileprovision`

对于动态库，如果是frida的gadget，建议命名为`FridaGadget.dylib`。

```bash
./ipa_injector.sh <ipa文件> [描述文件]
```

- `<ipa文件>`：需要注入的 IPA 文件路径。
- `[描述文件]`：可选（但必须要有），用于重签名的描述文件，默认为 `embedded.mobileprovision`。

### 示例

```bash
# 使用默认描述文件
./ipa_injector.sh WeChat.ipa

# 使用自定义描述文件
./ipa_injector.sh WeChat.ipa profile.mobileprovision
```

### frida
如果动态库名称是`FridaGadget.dylib`，脚本会生成一个config文件（所以最好不要将其他的动态库改成这个名字），其默认内容如下

```json
{
  "interaction": {
    "type": "listen",
    "address": "0.0.0.0",
    "port": 27042,
    "on_port_conflict": "fail",
    "on_load": "wait"
  }
}
```

需要需要修改，可以修改脚本中的`generate_gadget_config`部分（当前还不支持附加内嵌脚本的相关逻辑）。

### 动态库命名

脚本的默认行为是将注入的dylib进行随机命名后注入，本意是缓解一些反调试情况。但是对于framework不会这么做。

## 输出

脚本执行成功后，会生成一个注入后的 IPA 文件，文件名为 `<原IPA文件名>_patch.ipa`。同时，脚本会自动安装到连接的 iOS 设备上。


## 注意事项

1. 确保设备已连接并信任当前电脑。
2. 脚本会首先要求选择签名证书，所以确保在钥匙串中已经导入了需要的证书（应当使用dev证书）。
3. 通过lldb来启动应用时，需要根据最后的提示手动执行两条命令，尝试通过脚本执行会阻塞，原因未知。
