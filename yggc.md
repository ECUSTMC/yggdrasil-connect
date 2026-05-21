Yggdrasil Connect 是基于 OpenID Connect 协议的全新用户身份认证协议，为 authlib-injector 外置登录提供了一种基于 OAuth 2.0 的用户身份认证解决方案，目的是取代 Yggdrasil API 中的 Auth Server 部分。

以下是 Yggdrasil Connect 协议的规范文档的草案，供公开审阅：

[下载 PDF 版本](https://github.com/user-attachments/files/18490081/Yggdrasil-Connect.pdf)

------

# 概述

Yggdrasil Connect 是基于 OpenID Connect 协议的全新用户身份认证协议，其目的是取代 Yggdrasil API 中的 Auth Server 部分。

在 Yggdrasil API 的 Auth Server 部分中，用户需要将自己的用户名和密码直接暴露给第三方应用，才能通过第三方应用访问 Yggdrasil API，这增加了用户账户关键信息泄露的风险；且该部分的 API 在设计上几乎没有考虑到二步验证，无法良好地保障用户账户的安全。并且，由于各个第三方应用在该部分的实现的差异，用户在不同应用之间的登录体验存在较大割裂，时常出现应用实现不完整导致用户无法正常登录的问题。

Yggdrasil Connect 的目的即是解决这些问题。通过 OpenID Connect 协议，Yggdrasil Connect 可以实现用户在不同应用间的登录体验的统一，同时方便各验证服务器自行设计用户身份认证方式，以保障用户账户的安全。

## OAuth 2.0、OpenID Connect 及 Yggdrasil Connect 的关系

Yggdrasil Connect 协议基于 OpenID Connect 协议及其扩展 MS-OIDCE，而 OpenID Connect 基于 OAuth 2.0 协议。

本质上，Yggdrasil Connect 仅是针对 Minecraft 多人联机玩家身份认证场景，对 OpenID Connect 协议进行了部分简化及少量扩展。通过利用 OpenID Connect 协议中的 ID 令牌、服务发现等特性，并在此之上定义统一的权限范围及用户信息声明，第三方应用（如启动器）可以从不同的 Yggdrasil 验证服务器处向用户请求 OAuth 2.0 授权并获取访问令牌，以实现 authlib-injector 外置登录，而无需针对不同的验证服务器编写针对性的代码。

由于 OpenID Connect 协议基于 OAuth 2.0 协议，因此所有的 OpenID 提供者（OpenID Provider，OP，即所谓的“OpenID Connect 认证服务器”）同时也应为 OAuth 2.0 授权服务器（Authorization Server，AS）；但反之不成立，即不是所有的 OAuth 2.0 授权服务器都是 OpenID 提供者。

由于 Yggdrasil Connect 协议对 OpenID Connect 协议进行了部分简化，因此不是所有的 Yggdrasil Connect 验证服务器都是 OpenID 提供者；反之亦然，由于 Yggdrasil Connect 协议对 OpenID Connect 协议进行了扩展，因此不是所有的 OpenID 提供者都是 Yggdrasil Connect 服务器。但 Yggdrasil Connect 协议对 OAuth 2.0 授权服务器的实现相对完整，因此可以说所有 Yggdrasil Connect 验证服务器都是 OAuth 2.0 授权服务器，但反之不成立，即不是所有的 OAuth 2.0 授权服务器都是 Yggdrasil Connect 验证服务器。

![Image](https://github.com/user-attachments/assets/5b94b47b-f60a-4353-9737-8fc912abe427)

综上所述，在 Yggdrasil Connect 应用开发中，开发者或许无法直接使用现成的 OpenID Connect 客户端库（可以尝试使用，但不保证一定可用），但可使用现成的 OAuth 2.0 客户端库，并在其基础上进行扩展以实现 Yggdrasil Connect 客户端。考虑到 OAuth 2.0 及 OpenID Connect 客户端的最小实现也较为简单，从零开始实现 Yggdrasil Connect 客户端也并不复杂。同理，在 Yggdrasil Connect 验证服务器开发中，开发者可尝试直接使用现成的 OAuth 2.0 或 OpenID Connect 服务端库，并在其基础上进行扩展以实现 Yggdrasil Connect 验证服务器。

由于 Yggdrasil Connect 协议本身基于 OpenID Connect 协议，因此 Yggdrasil Connect 不止可以为 authlib-injector 外置登录的验证服务器所用。通过构建合理的 OAuth 2.0 授权服务器和鉴权体系，Yggdrasil Connect 验证服务器的适用范围和应用场景可以扩展至 authlib-injector 外置登录之外。

## 参考文档

- [[RFC 6749]](https://datatracker.ietf.org/doc/html/rfc6749) The OAuth 2.0 Authorization Framework
- [[RFC 6750]](https://datatracker.ietf.org/doc/html/rfc6750) The OAuth 2.0 Authorization Framework: Bearer Token Usage
- [[RFC 7519]](https://datatracker.ietf.org/doc/html/rfc7519) JSON Web Token (JWT)
- [[RFC 8628]](https://datatracker.ietf.org/doc/html/rfc8628) OAuth 2.0 Device Authorization Grant
- [[OpenID.Core]](https://openid.net/specs/openid-connect-core-1_0.html) OpenID Connect Core 1.0
- [[OpenID.Discovery]](https://openid.net/specs/openid-connect-discovery-1_0.html) OpenID Connect Discovery 1.0
- [[OpenID.Registration]](https://openid.net/specs/openid-connect-registration-1_0.html) OpenID Connect Dynamic Client Registeration 1.0
- [[MS-OIDCE]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-oidce/718379cf-8bc1-487e-962d-208aeb8e70ee) OpenID Connect 1.0 Protocol Extensions

# 基本约定

## 模型

### 验证服务器

验证服务器是 Yggdrasil Connect 的核心部分，它负责处理用户身份认证请求，并返回用户身份认证结果。

验证服务器分为两个逻辑服务器：

- **认证服务器（Auth Server）**：主要负责用户身份认证，大部分情况下不与 Minecraft 游戏本体产生交互。
- **会话服务器（Session Server）**：主要负责用户进服验证、角色属性查询等 Minecraft 多人联机游戏中的操作。

两个逻辑服务器可以是同一个单体服务，也可以是使用不同域名的、分离的服务。

**验证服务器必须以 HTTPS 协议提供服务**，所有 URL 均必须以 `https://` 开头。客户端应拒绝使用不支持 HTTPS 协议的验证服务器，也不得在任何情况下降级为 HTTP 协议。

本文档主要描述认证服务器的实现规范。考虑到用户身份认证主要由启动器在 Minecraft 游戏外处理，所以在认证服务器部分使用与 Mojang 官方不同的实现并无不妥；但会话服务器需要与 Minecraft 游戏本体进行交互，其行为应能被 Minecraft 游戏本体正确处理，而具体规范已于 [Yggdrasil 服务端技术规范](https://github.com/yushijinhun/authlib-injector/wiki/Yggdrasil-%E6%9C%8D%E5%8A%A1%E7%AB%AF%E6%8A%80%E6%9C%AF%E8%A7%84%E8%8C%83) 中记载（会话部分、角色部分），本文档不再重复说明。

认证服务器至少具有以下属性：

- **OpenID 提供者标识符**
    - **必须**：一个指向认证服务器自身的 URL，大小写敏感，可包含端口号及路径，但**不得**包含查询或片段参数。
- **签名密钥对**
    - **必须**：用于给 ID 令牌签名的非对称加密密钥对，可选 RSA、ECDSA 或 EdDSA 算法。
    - 私钥**必须**严格保密，而公钥应以 JWKS 格式对外公开。
    - 验证服务器可以拥有多个签名密钥对，但：
        - **必须**至少拥有一个 RSA 算法的签名密钥对。
        - 每个签名密钥对都**必须具有**其对应的密钥 ID（可为任意字符串），且**必须**在 ID 令牌的 JWT 头部和 JWKS 中予以标明（`kid` 字段）。
    - 出于信息安全因素考虑，签名密钥对应定期轮换。

认证服务器需要实现以下 API 端点：

- **授权端点（Authorization Endpoint）**
    - **可选**：OAuth 2.0 协议中用于发起授权请求的 API 端点，详见 RFC 6749。
- **设备授权端点（Device Authorization Endpoint）**
    - **可选**：OAuth 2.0 协议的扩展中用于通过设备代码流授予应用访问权限的 API 端点，详见 RFC 8628。
- **令牌端点（Token Endpoint）**
    - **必须**：OAuth 2.0 协议中用于颁发访问令牌的 API 端点，详见 RFC 6749。
- **用户信息端点（UserInfo Enpoint）**
    - **必须**：OpenID Connect Core 1.0 规范的 5.3 节中描述的受 OAuth 2.0 保护的、返回用户信息声明的 API 端点。详见 [用户信息的获取](#用户信息的获取)。

上述 API 端点的 URL 可由验证服务器自定义，但**必须**标注于认证服务器的 OpenID 提供者元数据中。详见 [OpenID 提供者元数据](#OpenID-提供者元数据)。


### 用户

一个验证服务器中可以存在多个用户。

用户必须具有的属性只有一个：

- **用户标识符**
    - **必须具有**：可以是任意内容的字符串，但**必须**保证在同一应用范围内唯一，且不可变更。
    - 针对不同的应用，同一个用户可以返回不同的用户标识符。

除此之外，Yggdrasil Connect 还建议用户包含以下属性：

- **昵称**
    - **可选具有**： 由用户自行设定的昵称。可为任意字符串。

用户注册和登录的方式，以及所需的凭证（如密码）等信息，应由验证服务器自行设计。

### 角色

角色（或称为档案，Profile）对应着 Minecraft 游戏中的玩家实体。

角色与用户为多对一关系，即一个用户可以拥有多个角色。

角色具有以下属性：

- **UUID**
    - **必须具有**：一个 32 位无符号 UUID，**必须**保证全局唯一，且不可变更。
- **角色名称**
    - **必须具有**：任意长度的字符串，可变更，但**必须**保证全局唯一。
- **角色属性**
    - **可选具有**：材质
        - 皮肤
        - 披风
    - …（其它可选属性）

#### 角色信息的序列化

参见 [Yggdrasil 服务端技术规范 § 角色信息的序列化](https://github.com/yushijinhun/authlib-injector/wiki/Yggdrasil-%E6%9C%8D%E5%8A%A1%E7%AB%AF%E6%8A%80%E6%9C%AF%E8%A7%84%E8%8C%83#%E8%A7%92%E8%89%B2%E4%BF%A1%E6%81%AF%E7%9A%84%E5%BA%8F%E5%88%97%E5%8C%96)。

#### 多角色场景下的角色选择

部分验证服务器可能支持单个用户持有多个角色。在该场景下，出于用户隐私和应用适配难度考虑，认证服务器应支持在授权时选择角色。

如应用在请求授权时申请了 `Yggdrasil.PlayerProfiles.Select` 权限范围，则认证服务器应在询问用户授权时要求用户选择角色，详见 [权限范围](#权限范围)；用户完成角色选择并授权后，如认证服务器最终向应用颁发访问令牌，则该访问令牌**必须**绑定至角色，详见 [访问令牌](#访问令牌)。

### 应用

应用是需要访问 Yggdrasil API 的主体，在 OpenID Connect 协议中被称为依赖方（Relying Party, RP）。

应用具有以下属性：

- **应用标识符**
    - **必须具有**：用于唯一识别应用的 ASCII 字符串。内容可以是任意的，但**必须**保证全局唯一，且创建后不可变更。
- **应用机密**
    - **可选具有**：任意内容的 ASCII 字符串，用于机密客户端在请求颁发访问令牌时的应用身份认证。
    - 除非应用仅允许公共客户端访问，否则**必须具有**。详见 [机密客户端和公共客户端](#机密客户端和公共客户端)
    - 同一个应用可创建多个应用机密，但已创建的应用机密**必须**不可变更。
- **回调 URL**
    - **可选具有**：应用的 OAuth 2.0 回调 URL，大小写敏感，可包含端口号及路径，但**不得**包含查询或片段参数。
    - 除非应用仅允许通过设备授权授予方式授予权限，否则**必须具有**。
    - 一个应用可以注册多个回调 URL。

除此之外，Yggdrasil Connect 还建议应用包含以下可选属性：

- **应用名称**
    - **可选具有**：应用的名称，可由应用所有者自定义。可以是任意内容的字符串。
- **应用创建者**
    - **可选具有**：应用创建者的用户标识符。
- **ID 令牌签名算法**
    - **可选具有**：应用所支持的 ID 令牌签名算法。详见 [ID 令牌的签名](#ID-令牌的签名)。


#### 应用、客户端和 Minecraft 本体的关系

应用是一个逻辑概念，是客户端在认证服务器上的抽象表示，而客户端是应用的具体实现，是用户直接与之交互的实体。

应用与客户端是一对多的关系，多个客户端可以使用同一应用标识符来请求访问权限。认证服务器不需要了解应用拥有多少个客户端，只需要按照规范规定对客户端进行鉴权即可。如需撤销访问权限或对应用实施限制措施，则相关操作应直接作用于整个应用。

> [!NOTE]
> 以 HMCL 为例：
>
> - HMCL 是一个应用，它在认证服务器上有一个抽象的表示。
>
> - HMCL 3.5 和 HMCL 3.6 是 HMCL 应用的两个不同的客户端，这两个客户端使用相同的应用标识符来请求访问权限。
>
> 如果用户撤销了对 HMCL 的授权，实际上是撤销了对整个 HMCL 应用的授权。因此，无论是哪个版本的 HMCL 启动器，都将失去访问受保护资源的权限，直到用户重新授权。

通常情况下，Minecraft 本体并不直接与认证服务器交互，因此其既不是应用，也不是客户端。然而，在与会话服务器交互时，Minecraft 本体会使用启动器在启动游戏时传入的访问令牌进行鉴权（换句话说，其以应用的身份与会话服务器交互），因此其应被视为持有该访问令牌的应用的一个客户端。

#### 机密客户端和公共客户端

客户端根据其安全特性和能力，可以分为两类：

- **机密客户端（Confidential Client）**
    - 可以安全地保存应用机密，保证其不对外泄露，并在请求颁发访问令牌时通过应用机密进行应用身份认证的客户端。
    - 使用授权代码流请求授权，但不包含使用 PKCE 的情况。
- **公共客户端（Public Client）**
    - 由于各种原因，无法安全保存用户机密，因而无法在请求颁发访问令牌进行应用身份认证的客户端：
        - 由于缺少有效的应用身份认证手段，公共客户端存在应用身份伪造问题（即，客户端在请求颁发访问令牌时可声称其为任意应用，而认证服务器无法对应用身份加以验证）。
    - 通常使用除授权代码流以外的授权流来请求授权。

> [!NOTE]
> 认证服务器可通过应用请求授权时使用的授权流来区分客户端类型：
>
> - 只有使用授权代码流请求授权的客户端是机密客户端（不包含使用 PKCE 的情况）：
>     - 因为只有授权代码流需要使用应用机密认证应用身份。
> - 使用其它授权流请求授权的客户端均为公共客户端。

为降低公共客户端的安全问题带来的影响，认证服务器应对公共客户端加以限制，例如：

- 公共客户端每次请求授权时都询问用户意见（强制 `prompt=consent`）。
- 缩短向公共客户端颁发的令牌的有效期。
- 禁止公共客户端申请部分敏感的权限范围。

具体限制措施应由认证服务器自行设计和实施。

### 令牌

Yggdrasil Connect 中存在三种令牌：

- 访问令牌（Access Token）
- 刷新令牌（Refresh Token）
- ID 令牌（ID Token）

#### 访问令牌

访问令牌是应用代表用户访问受保护的资源及执行操作（如获取用户信息及加入多人游戏服务器）时使用的凭证。访问令牌由认证服务器在用户授予应用访问权限后向应用颁发，其值可为任意 ASCII 字符串。

访问令牌具有时效性，在有效期内可多次使用；访问令牌过期后，应用如需继续访问受保护的资源或执行操作，则需要获取一个新的访问令牌。访问令牌与刷新令牌为一对一关系，访问令牌被吊销后，其对应的刷新令牌也应被吊销。

对应用来说，访问令牌是不透明的。这意味着访问令牌没有明确的模型定义，只需要验证服务器可以通过访问令牌来确定用户和应用的身份及其权限范围即可。

单个应用可以持有同一用户的多个访问令牌，但验证服务器应对同一应用持有的属于单一用户的有效的访问令牌的数量进行限制。当访问令牌数量超出限制时，应先吊销颁发时间最早的有效的访问令牌，然后再颁发新的访问令牌。

在 Yggdrasil Connect 中，访问令牌不再必须绑定至角色，但若访问令牌已绑定至角色，则仅应允许对已绑定的角色执行操作。

##### 访问令牌的使用

除会话服务器外，Yggdrasil Connect 中访问令牌的使用方法与 OAuth 2.0 协议一致，即，将访问令牌作为 Bearer Token，在请求受保护的 API 时放置于 HTTP 请求的 `Authorization` 头部中：

```http
GET /oidc/userinfo HTTP/1.1
Host: example.com
Authorization: Bearer ACCESS_TOKEN
```

如访问令牌有效，且请求无误，API 将返回正常响应；如访问令牌无效或请求参数有误，API 将根据错误类型返回对应的 HTTP 状态码，并在 HTTP 响应的 `WWW-Authenticate` 头部中返提供详细错误信息。

关于错误响应的更多信息，详见 [错误响应](#错误响应)。

> [!NOTE]
> 关于在会话服务器中使用访问令牌以实现 authlib-injector 外置登录的方法，请参阅 [Yggdrasil 服务端技术规范 - 会话部分](https://github.com/yushijinhun/authlib-injector/wiki/Yggdrasil-%E6%9C%8D%E5%8A%A1%E7%AB%AF%E6%8A%80%E6%9C%AF%E8%A7%84%E8%8C%83#%E4%BC%9A%E8%AF%9D%E9%83%A8%E5%88%86)。

##### 访问令牌有效性的验证

如应用需要验证访问令牌的有效性，可使用访问令牌请求用户信息端点：

- 如验证服务器正常返回用户信息，则说明访问令牌有效；
- 如验证服务器返回 `invalid_token` 错误，则说明访问令牌无效。

详见 [用户信息端点](#用户信息端点) 和 [错误响应](#错误响应)。

#### 刷新令牌

刷新令牌是一种特殊的令牌，用于在访问令牌有效期内及过期后一段时间内刷新访问令牌（即，吊销刷新令牌对应的访问令牌，并颁发一个新的访问令牌及对应的刷新令牌）。详见 [令牌的刷新](#令牌的刷新)。

刷新令牌也具有时效性，其有效期可以比其对应的访问令牌稍长，但刷新令牌仅能使用一次。刷新令牌与访问令牌为一对一关系，访问令牌被吊销后，其对应的刷新令牌也应被吊销。

与访问令牌相同，刷新令牌对应用来说也是不透明的，因此刷新令牌也没有明确的模型定义，只需要验证服务器可以通过刷新令牌来确定对应的访问令牌即可。

刷新令牌随着访问令牌一同颁发，但应仅在授权时申请了 `offline_access` 权限范围时颁发。详见 [权限范围](#权限范围)。

#### ID 令牌

ID 令牌是 OpenID Connect 对 OAuth 2.0 进行的最主要的扩展，它是一个由认证服务器签名的、包含了用户身份信息声明的 JWT。不同于访问令牌和刷新令牌，ID 令牌并非用于鉴权，而是提供给应用做用户身份进行验证及用户信息获取之用。

ID 令牌也具有时效性，其有效期一般与访问令牌一致。已过期的 ID 令牌是不可信的，不得被再次使用。

ID 令牌随着访问令牌一同颁发，但应仅在授权时申请了 `openid` 权限范围时颁发。详见 [权限范围](#权限范围)。

ID 令牌具有以下声明和属性：

- `iss`
    - **必须具有**：OpenID 提供者标识符。
- `sub`
    - **必须具有**：用户标识符。
- `aud`
    - **必须具有**：应用标识符。
- `iat`
    - **必须具有**：ID 令牌的颁发时间，10 位 UNIX 时间戳。
- `exp`
    - **必须具有**：ID 令牌的过期时间，10 位 UNIX 时间戳。
- `selectedProfile`
    - **条件必须**：如应用在请求授权时申请了 `Yggdrasil.PlayerProfiles.Select` 权限范围，则**必须具有**。包含用户选择的访问令牌绑定的角色的信息的 JSON 对象（不包含角色属性）。参见 [角色信息的序列化](#角色信息的序列化)。
- `availableProfiles`
    - **条件必须**：如应用在请求授权时申请了 `Yggdrasil.PlayerProfiles.Read` 权限范围，则**必须具有**。包含用户名下所有可用角色的角色信息的 JSON 对象的JSON 数组（不包含角色属性）。参见 [角色信息的序列化](#角色信息的序列化)。

除上述声明外，根据应用所申请的权限范围，ID 令牌中还可包含更多可选字段，以及其它由认证服务器自定义的声明。应用**必须**忽略 ID 令牌中的无法识别的声明。

OpenID Connect 还规定了更多可选声明，篇幅所限，在此不再赘述。如需了解，请参阅 OpenID Connect Core 1.0 规范的第 5.1 节。

以下是一个使用 RS256 算法签名的 ID 令牌的示例：

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleV9pZCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwiaWF0IjoxNzM0OTc0MzM4LCJzdWIiOiJ1c2VyX2lkIiwiYXVkIjoiY2xpZW50X2lkIiwiZXhwIjoxNzM1MjMzNTMxLCJzZWxlY3RlZFByb2ZpbGUiOnsiaWQiOiJmNzAyYzVkMzlkNWM0NTdmODBjNjkxYzY2NDc1NzA5MiIsIm5hbWUiOiJTU1NTU3RldmVuIn19.NHTbt2n8nz6rkR0ysG_pJmXZlywiGGVrDg8mDE5du3Hv_OBS7i__vRmvuAI-3Rcyodb9ZSy5mwy47HI4zUEIfsRhvfQ3yzhRBi6Vki2dKukkTsZ1y5djze0Oc_q1pNoKJTMt4Ieu8NUyQ_7Yl0oWDlahV2QPtlDnWBK3g-IZXUYXtCH-dZz6N1_ZisHdaA2NfFCrjOSyhXI-_2r8iGfsWNRGflgGH-XKb0XObE1vGz61z-oPuKHZ8dTfnovEi1JS8BBloFDW_Z64-r8nWwzgRaLLqPbf93lqYoY6hlz9xf2oUNOx3m4MX7w2dkYaYr76sPZEA97luqsaWZOUrwhjfg
```

对该 ID 令牌进行解析，得到其 JWT 头部和负载分别为：

```json
{
    "alg": "RS256",
    "typ": "JWT",
    "kid": "key_id"
}
```

```json
{
    "iss": "https://example.com",
    "iat": 1734974338,
    "sub": "user_id",
    "aud": "client_id",
    "exp": 1735233531,
    "selectedProfile": {
        "id": "f702c5d39d5c457f80c691c664757092",
        "name": "SSSSSteven"
    }
}
```

##### ID 令牌的签名

ID 令牌**必须**由认证服务器使用其拥有的签名密钥对签名，且所使用的签名算法及密钥 ID **必须**分别标注于 ID 令牌的 JWT 头部的 `alg` 字段和 `kid` 字段中。

允许使用的签名算法如下：

- `RS256`、`RS384`、`RS512`
- `ES256`、`ES384`、`ES512`、`ES256K`
- `EdDSA`

除非应用在注册时明确声明其支持其它签名算法，否则认证服务器应默认使用 RS256 算法对 ID 令牌进行签名。

##### ID 令牌有效性的验证

应用在使用 ID 令牌前，应按照以下规则对 ID 令牌进行验证：

- ID 令牌的 `iss` 声明的值与 OpenID 提供者标识符一致。
- ID 令牌的 `aud` 声明的值与应用标识符一致。
- ID 令牌的颁发时间不应晚于当前时间，过期时间不应早于当前时间。
- ID 令牌的签名有效。

如 ID 令牌不满足上述条件中的任意一条，其应被视为无效令牌。应用**必须**拒绝使用无效的 ID 令牌。

应用可通过认证服务器的 OpenID 提供者元数据中 `jwks_uri` 字段的值来获得用于验证 ID 令牌的签名的密钥的集合（JWKS 格式）。详见 [OpenID 提供者元数据](#OpenID-提供者元数据)。

## 权限范围

在 OAuth 2.0 中，权限范围（scope）用于限定持有访问令牌的应用允许访问的资源的范围。

Yggdrasil Connect 规定了如下权限范围：

- `openid`
    - **必须支持**：向应用颁发 ID 令牌，并允许应用通过用户信息端点获取用户基础信息。详见 [用户信息的获取](#用户信息的获取)。
    - 应用在请求授权时**必须申请**该权限范围。如未申请，则认证服务器不应将该次授权视为 OpenID Connect 或 Yggdrasil Connect 授权，但其仍可被视为普通的 OAuth 2.0 授权。
- `profile`
    - **可选支持**：允许应用通过用户信息端点获取用户详细信息，并将用户详细信息添加至 ID 令牌中。详见 [用户信息的获取](#用户信息的获取)。
- `offline_access`
    - **可选支持**：向应用颁发刷新令牌。详见 [刷新令牌](#刷新令牌)。
    - 如应用在请求授权时未包含该权限范围，则不应该向应用颁发刷新令牌。
- `Yggdrasil.PlayerProfiles.Select`
    - **必须支持**：允许应用获取用户选择的角色的信息（不包含角色属性）。
    - 如应用在请求授权时申请了该权限范围，则认证服务器应在询问用户授权时要求用户选择角色，且访问令牌**必须**绑定至用户选择的角色，并将该角色的信息（不包含角色属性）加入 ID 令牌的 `selectedProfile` 声明中。
- `Yggdrasil.PlayerProfiles.Read`
    - **可选支持**：允许应用获取用户名下所有可用角色的信息的列表（不包含角色属性）。
    - 如应用在请求授权时申请了该权限范围，则认证服务器应将用户名下所有可用角色的信息（不包含角色属性）加入 ID 令牌的 `availableProfiles` 声明中。
- `Yggdrasil.Server.Join`
    - **必须支持**：允许应用加入 Minecraft 多人游戏服务器。
    - 如应用在请求授权时申请了该权限范围，则**必须**同时申请 `Yggdrasil.PlayerProfiles.Select` 权限范围（换句话说，访问令牌必须绑定至角色）；如未申请该权限范围，则会话服务器**必须**拒绝使用该访问令牌的客户端进入；如未申请该权限范围，则会话服务器**必须**拒绝使用该访问令牌的客户端进入 Minecraft 多人游戏服务器。

> [!WARNING]
> 如应用在请求授权时申请了上述任一权限范围，但未同时申请 `openid` 权限范围，认证服务器应拒绝授权，并返回 `invalid_scope` 错误。

> [!IMPORTANT]
> 为防止用户被误导，认证服务器不应允许应用同时申请 `Yggdrasil.PlayerProfiles.Select` 和 `Yggdrasil.PlayerProfiles.Read` 权限范围。

OpenID Connect 还规定了更多可选的权限范围，篇幅所限，在此不再赘述。如需了解，请参阅 OpenID Connect Core 1.0 规范。

## 错误响应

除会话服务器外，Yggdrasil Connect 中的错误响应与 OAuth 2.0 协议即 OpenID Connect 协议一致。

认证服务器可能通过多种方式返回错误（如，在应用回调 URL 的查询参数中返回错误、在 HTTP 响应体中返回错误等），但所有错误响应都包含下列参数：

- `error`
    - **必须提供**：返回的错误的类型，详见 [错误类型](#错误类型)。
- `error_description`
    - **可选提供**：人类可读的错误描述信息。
- `error_uri`
    - **可选提供**：指向人类可读的错误描述文档的 URL。

### 错误响应的形式

认证服务器可以以下形式返回错误：

- 在应用回调 URL 的查询参数中返回错误
- 在 HTTP 响应头中返回错误
- 在 HTTP 响应体中返回错误

#### 在应用回调 URL 的查询参数中返回错误

在应用的回调 URL 的查询参数中添加错误响应参数的错误响应形式。

仅于 OAuth 2.0 授权代码流或隐式流的授权响应中返回，因为授权代码流和隐式流的授权响应即是 URL 回调。

```
https://demo.com/oauth/callback?error=access_denied&error_description=The%20authorization%20request%20was%20denied.&error_uri=https%3A%2F%2Fexample.com%2Fdocs%2Ferror%2Faccess_denied&state=114514
```

详见 RFC 6749 的 4.1.2.1 节和 4.2.2.1 节。

#### 在 HTTP 响应体中返回错误

在 HTTP 响应体中返回一个包含错误响应参数的 JSON 文档的错误响应形式。

于 OAuth 2.0 令牌响应及设备代码流的授权响应中返回。

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
	"error": "invalid_request",
	"error_description": "The request is malformed.",
	"error_uri": "https://example.com/error/invalid_response"
}
```

详见 RFC 6749 的 5.2 节。

#### 在 HTTP 响应头中返回错误

在 HTTP 响应的 `WWW-Authenticate` 头部中添加错误响应参数的错误响应形式。

于应用使用访问令牌获取受 OAuth 2.0 保护的资源或执行操作时返回。

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="openid" error="invalid_token" error_description="The access token has expired." error_uri="https://example.com/error/invalid_token"
```

其中 `realm` 为一个可选的参数，其值为访问该 API 端点所需的权限范围。

详见 RFC 6750 的第三章。

### 错误类型

下列是部分 OAuth 2.0 和 OpenID Connect 协议中常见的错误类型：

- `access_denied`
    - 用户或认证服务器拒绝了应用的授权请求。
    - 于应用申请授权或请求颁发访问令牌时返回。
    - 如以 HTTP 响应的形式返回错误，则 HTTP 响应状态码应为 `401 Unauthorized`。
- `authorization_pending`
    - 正在等待用户完成授权，应用可继续轮询以请求颁发访问令牌。
    - 于应用通过 OAuth 2.0 设备授权授予请求颁发访问令牌时返回。
    - HTTP 响应状态码应为 `400 Bad Request`。
- `expired_token`
    - 设备代码已过期或不存在。
    - 于应用通过 OAuth 2.0 设备授权授予请求颁发访问令牌时返回。
    - HTTP 响应状态码应为 `400 Bad Request`。
- `insufficient_scope`
    - 访问令牌拥有的权限范围不足。
    - 于应用持访问令牌请求受保护的资源时返回。
    - 如通过 HTTP 响应的形式返回错误，则 HTTP 响应状态码应为 `403 Forbidden`。
- `invalid_client`
    - 客户端未能通过应用身份认证。
    - 于应用申请授权或请求颁发访问令牌时返回。
    - 如以 HTTP 响应的形式返回错误，则 HTTP 响应状态码应为 `401 Unauthorized`。
- `invalid_request`
    - 请求参数有误。
    - 可在任意情况下返回。
    - 如通过 HTTP 响应的形式返回错误，则 HTTP 响应状态码应为 `400 Bad Request`。
- `invalid_scope`
    - 应用申请的权限范围有误。
    - 于应用申请授权时返回。
    - 如通过 HTTP 响应的形式返回错误，则 HTTP 响应状态码应为 `400 Bad Request`。
- `invalid_token`
    - 访问令牌无效。
    - 于应用使用访问令牌请求受 OAuth 2.0 保护的资源时返回。
    - HTTP 响应状态码应为 `401 Unauthorized`。
- `server_error`
    - 服务器内部错误。
    - 可在任意情况下返回。
    - 如通过 HTTP 响应的形式返回错误，则 HTTP 响应状态码应为 `500 Internal Server Error`。
- `slow_down`
    - `authorization_pending` 错误的变种，正在等待用户完成授权，但应用轮询过快。
    - 于应用通过 OAuth 2.0 设备授权授予请求颁发访问令牌时返回。
    - HTTP 响应状态码应为 `400 Bad Request`。
- `temporarily_unavailable`
    - 服务器由于超载或维护等原因，暂时无法处理该请求，可稍后再试。
    - 可在任意情况下返回。
    - 如通过 HTTP 响应的形式返回错误，则 HTTP 响应状态码应为 `503 Service Unavailable`。

OAuth 2.0 及 OpenID Connect 还规定了更多错误类型，详见 RFC 6749、RFC 8628 及 OpenID Connect Core 1.0 规范。

# 服务发现

Yggdrasil Connect 的服务发现依赖于 [authlib-injector API 元数据获取](https://github.com/yushijinhun/authlib-injector/wiki/Yggdrasil-%E6%9C%8D%E5%8A%A1%E7%AB%AF%E6%8A%80%E6%9C%AF%E8%A7%84%E8%8C%83#api-%E5%85%83%E6%95%B0%E6%8D%AE%E8%8E%B7%E5%8F%96) 。

支持 Yggdrasil Connect 的验证服务器的 authlib-injector API 元数据中应包含一个 `feature.openid_configuration_url` 字段，其值为该验证服务器的 OpenID 提供者的元数据的 URL。若验证服务器的 authlib-injector API 元数据中不包含该字段，则应认为该验证服务器不支持 Yggdrasil Connect。

> [!NOTE]
> OpenID 提供者可以使用与 Yggdrasil API 不同的域名，只需要保证会话服务器能够识别并验证 OpenID 提供者颁发的访问令牌即可。

## OpenID 提供者元数据

OpenID 提供者元数据是一个 JSON 文档，其中标明了 OpenID 提供者支持的各项参数，是 Yggdrasil Connect 服务发现的重要组成部分。

OpenID 提供者元数据应位于 OpenID 提供者标识符 URL 下的 `/.well-known/openid-configuration` 中，可由客户端在无需鉴权的情况下通过发起 GET 请求获取：

```http
GET /.well-known/openid-configuration HTTP/1.1
Host: example.com
Accept: application/json
```

Yggdrasil Connect 规定 OpenID 提供者元数据中应包含下列字段：

- `issuer`
    - **必须提供**：OpenID 提供者标识符。
- `authorization_endpoint`
    - **可选提供**：OpenID 提供者的 OAuth 2.0 授权端点（Authorization Endpoint）的 URL。
- `device_authorization_endpoint`
    - **可选支持**：OpenID 提供者的 OAuth 2.0 设备授权授予端点（Device Authorization Endpoint）的 URL。
- `token_endpoint`
    - **必须提供**：OpenID 提供者的 OAuth 2.0 令牌端点（Token Endpoint）的 URL。
- `userinfo_endpoint`
    - **必须提供**：OpenID 提供者的用户信息端点（UserInfo Enpoint）的 URL。
- `registration_endpoint`
    - **可选提供**：OpenID 提供者的动态客户端注册端点（Client Registration Endpoint）。详见 [动态注册](#动态注册)。
- `jwks_uri`
    - **必须提供**：用于验证 ID 令牌及其它可被第三方验证的 JWT 的密钥的集合（JWKS）的 URL。
- `scopes_supported`
    - **必须提供**：包含 OpenID 提供者支持的权限范围的 JSON 数组。
    - 认证服务器可出于某些因素不列出部分权限范围，但**必须**至少包含 `openid`、`Yggdrasil.PlayerProfiles.Select` 和 `Yggdrasil.Server.Join` 三项权限范围，如不包含其中任意一项，则应视为该 OpenID 提供者不支持 Yggdrasil Connect。
- `subject_types_supported`
    - **必须提供**：包含 OpenID 提供者支持的用户标识符类型的 JSON 数组。
    - 有效的值包括：
        - `public`：针对单一用户，向所有应用返回相同的用户标识符。
        - `pairwise`：针对同一用户，向不同的应用返回不同的用户标识符。
- `id_token_signing_alg_values_supported`
    - **必须提供**：包含认证服务器支持的 ID 令牌签名算法的 JSON 数组。
    - 所有有效取值详见 [ID 令牌的签名](#ID-令牌的签名)。
    - **必须包含** `RS256`。
- `shared_client_id`
    - **可选提供**：由认证服务器预注册的公用应用的应用标识符。详见 [公用应用](#公用应用)。

上述字段中，`authorization_endpoint` 和 `device_authorization_endpoint` **必须提供**其中至少一个。

OpenID Connect 还规定了更多可选字段，篇幅所限，在此不再赘述。如需了解，请参阅 OpenID Connect Discovery 1.0 规范的第三章。

以下是一个 OpenID 提供者元数据的示例：

```json
{
    "issuer": "https://example.com",
    "jwks_uri": "https://example.com/.well-known/jwks",
    "subject_types_supported": [
        "pairwise"
    ],
    "id_token_signing_alg_values_supported": [
        "RS256",
        "ES256",
        "EdDSA"
    ],
    "scopes_supported": [
        "openid",
        "offline_access",
        "Yggdrasil.PlayerProfiles.Select",
        "Yggdrasil.PlayerProfiles.Read",
        "Yggdrasil.Server.Join"
    ],
    "authorization_endpoint": "https://example.com/oauth/authorize",
    "device_authorization_endpoint": "https://example.com/oauth/device_code",
    "token_endpoint": "https://example.com/oauth/token",
    "userinfo_endpoint": "https://example.com/userinfo",
    "shared_client_id": "example_shared_client_id"
}
```

## 应用注册

应用必须事先在认证服务器上注册，并获取应用标识符，然后才能请求用户授权。

Yggdrasil Connect 支持的应用注册方式有三种：

- 主动注册
- 动态注册
- 公用应用

认证服务器应至少支持上述三种应用注册方式中的一种。

### 主动注册

最主流的应用注册方式，由应用开发者通过认证服务器提供的用户界面手动注册应用。

具体实现方式可由认证服务器自行设计。

### 动态注册

由客户端以编程方式通过 OpenID Connect 动态客户端注册（Dynamic Client Registeration）自动注册应用。

由于其规范较为复杂，在此暂不详细描述，具体请参见 OpenID Connect Dynamic Client Registeration 1.0 规范。

### 公用应用

由认证服务器预先注册一个应用，将其应用标识符标注于 OpenID 提供者元数据的 `shared_client_id` 中，客户端直接以该应用的身份请求授权。

> [!NOTE]
> 公用应用的应用机密不应该对外公开。因此，所有以公用应用身份请求授权的客户端均应被视为公共客户端。详见 [机密客户端和公共客户端](#机密客户端和公共客户端)。

由于公用应用不支持配置回调 URL，因此其回调 URL 可以为本地环回地址或任意以 `https://` 开头的 URL。

认证服务器应对公用应用实施一定的限制措施，例如：

- 每次请求授权时都应询问用户意见（强制 `prompt=consent`）。
- 在授权页面标注正在请求授权的应用为公用应用。
- 缩短向公用应用颁发的令牌的有效期。
- 禁止公用应用申请部分敏感的权限范围。

具体限制措施应由认证服务器自行设计。

# 授权流程

本章以 Minecraft 启动器中最常见的两种 OAuth 2.0 授权流（授权代码流、设备代码流）为例，描述应用请求授权的流程。

## 授权代码流

RFC 6749 的 4.1 节中描述的 OAuth 2.0 授权方式。

![Image](https://github.com/user-attachments/assets/51732394-fa69-4ecf-b452-94d16f71d5e0)

<!-- https://www.plantuml.com/plantuml/svg/LP4_JiCm6CLtdyBgpWKwe5PHHwQg1p292HQj4s97OgIK8KLjque8XFWZWJemfJ2WI52fby6kE_KAVAeRYImUtk-zxpt93I599EDU5vqoZ-AJ8937mGKIPuo7928zBEXvJBbBZwWGnAVDBlCvzbX4NSa2Zi0acSj2mYMkhRDtdHGrJ0HkTQf8VMT0TyYf4fFFpQAldyRgvbKzM4kpZVmeY4Di5eN-lB9tzIJHpmFau8D3CDInIcVcQwzQ7sgs0K9t7O9lc_lyVr1VfsewGwrEcRTGJKT0h6MVTo2-ojJZYrNLxHZMRvS9AEPZi5qE4ULUEN1IgFJEv2je-_sPhuUZoi3DPT-gvS1gWMMsO7Uq0GzynXy0 -->

### 请求用户授权

#### 请求

首先，应用需要在认证服务器的授权端点 URL 之上拼接以下查询参数，形成授权 URL：

- `client_id`
    - **必须提供**：应用标识符。
- `redirect_uri`
    - **必须提供**：应用的回调 URL 之一。
- `response_type`
    - **必须提供**：应用使用的授权响应类型，用于确定授权流类型。
    - 对于授权代码流，该值为 `code`。关于其它授权流的取值，请参阅 RFC 6749。
- `scope`
    - **必须提供**：应用所申请的权限范围列表，多个权限范围以空格分隔。
- `state`
    - **可选提供**：用于维护授权请求与回调之间状态的任意不透明字符串。

OAuth 2.0 及 OpenID Connect 还规定了更多参数，详见 RFC 6749 及 OpenID Connect Core 1.0 规范。

以下是一个拼接好参数的授权 URL 的示例：

```
https://example.com/oauth/authorize?client_id=DEMO_CLIENT&redirect_uri=https%3A%2F%2Fdemo.com%2Foauth%2Fcallback&response_type=code&scope=openid%20offline_access%20Yggdrasil.PlayerProfiles.Select&state=abcd1234
```

然后，应用需要将用户重定向至授权 URL。认证服务器此时需要提供一个用户界面，向用户展示应用信息及其申请的权限，并让用户决定是否授权。

#### 响应

用户完成授权后，认证服务器需要将用户重定向至应用提供的回调 URL，并在查询参数中添加授权响应：

- `code`
    - **必须提供**：认证服务器向应用提供的授权代码，可为任意的不透明字符串，用于请求颁发访问令牌。
    - 授权代码应具有时效性，且仅能使用一次。
- `state`
    - **条件必须**：如应用在该次授权请求中提供了 `state` 参数，则**必须具有**。其值必须与应用在该次授权请求中提供的 `state` 参数值一致。

以下是一个回调示例：

```
https://demo.com/oauth/callback?code=AUTHORIZATION_CODE&state=abcd1234
```

应用需要校验授权响应中的 `state` 的值是否与授权请求中的一致，并暂存授权代码，以备之后请求颁发访问令牌。

> [!TIP]
> 如授权过程中发生错误，认证服务器也需要将用户重定向至应用提供的回调 URL，并在查询参数中添加错误响应参数。详见 [在应用回调 URL 的查询参数中返回错误](#在应用回调-URL-的查询参数中返回错误) 以及 [错误类型](#错误类型)。

### 获取访问令牌

#### 请求

获取到授权代码后，应用需要在后端向认证服务器的令牌端点发送 POST 请求，并在请求体中携带以下表单参数（Content-Type 为 `application/x-www-form-urlencoded`），以请求颁发访问令牌：

- `grant_type`
    - **必须提供**：固定为 `authorization_code`。
- `client_id`
    - **必须提供**：请求用户授权时使用的应用 ID。
- `client_secret`
    - **必须提供**：应用 ID 对应的应用机密。
- `redirect_uri`
    - **必须提供**：请求用户授权时使用的回调 URL。
- `code`
    - **必须提供**：上一步中获得到的授权代码。

以下是一个请求示例：

```http
POST /oauth/token HTTP/1.1
Accept: application/json
Content-Type: application/x-www-form-urlencoded
Host: example.com

grant_type=authorization_code&client_id=DEMO_CLIENT&client_secret=CLIENT_SECRET&redirect_uri=https%3A%2F%2Fdemo.com%2Foauth%2Fcallback&code=AUTHORIZATION_CODE
```

#### 响应

如请求有误，认证服务器应在响应体中返回错误，详见 [在 HTTP 响应体中返回错误](#在-HTTP-响应体中返回错误) 以及 [错误类型](#错误类型)。

如请求无误，认证服务器应返回 JSON 响应，并在其中包含下列参数，以向应用颁发令牌：

- `token_type`
    - **必须提供**：固定为 `Bearer`。
- `expires_in`
    - **必须提供**：访问令牌的有效期，单位为秒。
- `access_token`
    - **必须提供**：访问令牌。
- `refresh_token`
    - **条件必须**：刷新令牌。
    - 如应用在请求用户授权时申请了 `offline_access` 权限范围，则必须提供。
- `id_token`
    - **条件必须**：刷新令牌。
    - 如应用在请求用户授权时申请了 `openid` 权限范围，则必须提供。

以下是一个响应示例：

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "token_type": "Bearer",
  "expires_in": 86400,
  "access_token": "ACCESS_TOKEN",
  "refresh_token": "REFRESH_TOKEN",
  "id_token": "eyJ..."
}
```

## 设备代码流

RFC 8628 中描述的 OAuth 2.0 授权方式。

![Image](https://github.com/user-attachments/assets/8dfa7d62-997e-4213-82f1-fa0b16663f0b)

<!-- https://www.plantuml.com/plantuml/svg/VP8zRzD06CVt-nId3cnKWh43QXHbWuKg6nAw9aTwgdjdx8k4c1fUm06tIPjGL4WABQc466mwe4Y9rNwPtFayvIjmuN652rK7MxB-F_sU5p-hlYIUR6uvQ8FLANuYX5mNpv2_oRXBFBA5VVgqINcDFg2-JngqvB06ntNcqPfaWYCBILPZBk4IBwNzxpeOBs7YuqhrQgGcVPl-YSfN4nEDJDpIWntrxbWT0b9QGmrFD5ryPncRUApFNe1QxmPw-1ALyUrxbbd9CnETgz7RsVHR-hMbzaD0uHELrXPisQ8NVVNvw0OKh9Ng2bPd7zBHf9XP54fdnx-ouGckFhoFAjNBBdIxfvBj8Z1FGdFUKwzF_-i5AfZu9FiO5MVIhpggkrUGGgYweKq0GPJNyxNSNSRwowcrG99EU_feW6zXipjMdGCJNLZxR3fAso5oX73_BanrzhBj5aImF4GSULdivoSz-A6YK0TT4F-xlgn_QE9OzNRixtp4vqb0cd93UEmvMHp3OzTso7XZdhGHTNoQQ_Nx_NGwpCSC3g2i7hIj2Qrxb6pUL6KnT546tSqcRy1tlG3cAmYApwfzsNl_3G00 -->

### 请求用户授权

#### 请求

首先，应用需要向认证服务器的设备授权端点发送 POST 请求，并在请求体中携带以下表单参数（Content-Type 为 `application/x-www-form-urlencoded`），以获取设备代码和用户代码：

- `client_id`
    - **必须提供**：应用标识符。
- `scope`
    - **必须提供**：应用所申请的权限范围列表，多个权限范围以空格分隔。

以下是一个请求示例：

```http
POST /oauth/devicecode HTTP/1.1
Accept: application/json
Content-Type: application/x-www-form-urlencoded

client_id=DEMO_CLIENT&scope=openid%20offline_access%20Yggdrasil.PlayerProfiles.Select
```

#### 响应

如请求无误，认证服务器应返回 JSON 响应（Content-Type 为 `application/json`），并在其中包含下列参数：

- `device_code`
    - **必须提供**：本次授权请求的设备代码，用于应用轮询授权结果，不应展示给用户。
- `user_code`
    - **必须提供**：本次授权请求的用户代码，需要展示给用户，让用户在授权页面输入此代码以授予应用权限。
- `verification_uri`
    - **必须提供**：认证服务器提供的授权页面的 URL，需要将用户引导至此 URL 输入授权代码以进行授权。
- `verification_uri_complete`
    - **可选提供**：带用户代码的授权页面 URL，如用户访问此 URL，则授权代码将自动代入输入框中，无需用户手动输入。
- `expires_in`
    - **必须提供**：本次授权请求的有效期，单位为秒。
    - 授权请求过期后，设备代码和用户代码都会失效。
- `interval`
    - **可选提供**：应用轮询授权结果时的最小轮询间隔时间，单位为秒。
    - 如未提供，则轮询间隔默认为 5s。

以下是一个响应示例：

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
    "user_code": "USER_CODE",
    "device_code": "DEVICE_CODE",
    "verification_uri": "https://example.com/oauth/link",
    "verification_uri_complete": "https://example.com/oauth/link?user_code=USER_CODE",
    "expires_in": 300,
    "interval": 5
}
```

如请求有误，认证服务器应在 HTTP 响应体中返回错误，详见 [在 HTTP 响应体中返回错误](#在-HTTP-响应体中返回错误)。

获取到设备代码和用户代码后，应用应引导用户访问授权页面，并按页面提示操作。

认证服务器应让用户在授权页面中输入用户代码，以识别授权请求，然后向用户展示应用信息及其申请的权限，并让用户决定是否授权。

### 获取授权结果和访问令牌

#### 请求

获取到设备代码后，应用需要在后台以 `interval` 为间隔，向认证服务器的令牌端点发送 POST 请求，并在请求体中携带以下表单参数（Content-Type 为 `application/x-www-form-urlencoded`），以查询授权结果：

- `grant_type`
    - **必须提供**：固定为 `urn:ietf:params:oauth:grant-type:device_code`
- `client_id`
    - **必须提供**：请求设备代码时使用的应用 ID
- `device_code`
    - **必须提供**：上一步中获得的设备代码

以下是一个请求示例：

```http
POST /oauth/token HTTP/1.1
Accept: application/json
Content-Type: application/x-www-form-urlencoded
Host: example.com

grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=DEMO_CLIENT&device_code=DEVICE_CODE
```

#### 响应

如请求有误，或用户还未完成授权，认证服务器应在响应体中返回错误：

- 如用户还未完成授权，认证服务器应返回 `authorization_pending` 错误。
- 如用户或认证服务器最终拒绝授权，认证服务器应返回 `access_denied` 错误。
- 如设备代码已过期，认证服务器应返回 `expired_token` 错误。

详见 [在 HTTP 响应体中返回错误](#在-HTTP-响应体中返回错误) 以及 [错误类型](#错误类型)。

如请求无误，且用户已完成授权，则认证服务器应返回 JSON 响应，并在其中包含下列参数，以向应用颁发令牌：

- `token_type`
    - **必须提供**：固定为 `Bearer`。
- `expires_in`
    - **必须提供**：访问令牌的有效期，单位为秒。
- `access_token`
    - **必须提供**：访问令牌。
- `refresh_token`
    - **条件必须**：刷新令牌。
    - 如应用在请求用户授权时申请了 `offline_access` 权限范围，则必须提供。
- `id_token`
    - **条件必须**：刷新令牌。
    - 如应用在请求用户授权时申请了 `openid` 权限范围，则必须提供。

以下是一个响应示例：

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "token_type": "Bearer",
  "expires_in": 86400,
  "access_token": "ACCESS_TOKEN",
  "refresh_token": "REFRESH_TOKEN",
  "id_token": "eyJ..."
}
```

## 令牌的刷新

为了延长单次授权的有效期，可在访问令牌有效期及过期后一段时间内使用刷新令牌请求刷新访问令牌，以获取一个新的访问令牌。

### 请求

应用需要向认证服务器的令牌端点发送 POST 请求，并在请求体中携带以下表单参数（Content-Type 为 `application/x-www-form-urlencoded`）：

- `grant_type`
    - **必须提供**：固定为 `refresh_token`
- `client_id`
    - **必须提供**：先前请求访问令牌时使用的应用 ID
- `client_secret`
    - **条件必须**：应用 ID 对应的应用机密
    - 如先前的访问令牌是使用授权代码流获取的，则必须提供。
- `refresh_token`
    - **必须提供**：先前获取到的刷新令牌

以下是一个请求示例：

```http
POST /oauth/token HTTP/1.1
Accept: application/json
Content-Type: application/x-www-form-urlencoded
Host: example.com

grant_type=refresh_token&client_id=DEMO_CLIENT&client_secret=CLIENT_SECRET&refresh_token=REFRESH_TOKEN
```

### 响应

如请求有误，认证服务器应在响应体中返回错误，详见 [在 HTTP 响应体中返回错误](#在-HTTP-响应体中返回错误) 以及 [错误类型](#错误类型)。

如请求无误，认证服务器应返回 JSON 响应，并在其中包含下列参数，以向应用颁发令牌：

- `token_type`
    - **必须提供**：固定为 `Bearer`。
- `expires_in`
    - **必须提供**：访问令牌的有效期，单位为秒。
- `access_token`
    - **必须提供**：新的访问令牌。
- `refresh_token`
    - **条件必须**：新的刷新令牌。
    - 如应用在请求用户授权时申请了 `offline_access` 权限范围，则必须提供。
- `id_token`
    - **条件必须**：ID 令牌。
    - 如应用在请求用户授权时申请了 `openid` 权限范围，则必须提供。

以下是一个响应示例：

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "token_type": "Bearer",
  "expires_in": 86400,
  "access_token": "ACCESS_TOKEN",
  "refresh_token": "REFRESH_TOKEN",
  "id_token": "eyJ..."
}
```

# 用户信息的获取

## 使用 ID 令牌

ID 令牌中已包含部分用户信息，直接对 ID 令牌进行 JWT 解码即可获得用户信息。

除必须具有的声明外，根据应用申请的权限范围的不同，ID 令牌中可能还包含更多可选声明，以及其它认证服务器自定义的声明。

> [!NOTE]
> 应用**必须**忽略 ID 令牌中其无法识别的声明。详见 [ID 令牌](#ID-令牌)。

在从 ID 令牌中获取用户信息之前，应用**必须**先验证 ID 令牌的有效性。无效的 ID 令牌是不可信的，因此不应从无效的 ID 令牌中获取用户信息。详见 [ID 令牌有效性的验证](#ID-令牌有效性的验证)。

## 用户信息端点

用户信息端点是一个受 OAuth 2.0 保护的 API 端点，用于向应用提供用户信息。其返回的信息是 ID 令牌中的声明的超集，但不包含 `iss` 声明、`iat` 声明和 `exp` 声明。

应用可以通过认证服务器的 OpenID 提供者元数据中的 `userinfo_endpoint` 字段的值来获取认证服务器的用户信息端点的 URL，按 OAuth 2.0 规范向其发送 GET 请求即可获取当前授权令牌所属的用户信息：

```http
GET /userinfo HTTP/1.1
Host: example.com
Accept: application/json
Authorization: Bearer ACCESS_TOKEN
```

以下是一个用户信息端点响应的示例：

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
    "sub": "user_id",
    "aud": "client_id",
    "selectedProfile": {
        "id": "f702c5d39d5c457f80c691c664757092",
        "name": "SSSSSteven"
    }
}
```

除必须具有的声明外，根据应用申请的权限范围的不同，用户信息端点的响应中可能还包含更多可选声明，以及认证服务器自定义的其它声明。

> [!NOTE]
> 应用**必须**忽略用户信息端点的响应中的无法识别的声明。详见 [ID 令牌](#ID-令牌)。

> [!IMPORTANT]
> 出于用户隐私安全考虑，认证服务器可以选择不向应用提供其请求的部分声明。
>
> 如认证服务器决定不向应用提供某些声明，**必须**直接在用户信息端点的响应中省略对应的声明，而不是将声明值设为空值或 `null`。
>
> 除认证服务器未提供必须具有的声明的情况外，应用不应将“认证服务器未提供应用所请求的声明”视为错误。
