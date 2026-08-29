//! ZCode OAuth 登录导入（CLI 轮询通道版）。
//!
//! 历史演进：本地 127.0.0.1 回调 → 被服务端 redirect_uri 白名单拒绝；
//! 中转页 + 自定义深链接 → 被中转页前端 JS 的 zcode:// 硬校验拒绝。
//! 现采用 ZCode 3.10.1 官方 CLI 同款轮询通道（无需任何回调/协议注册）：
//!   1. POST zcode.z.ai/api/v1/oauth/cli/init → flow_id + 服务端托管的
//!      authorize_url + poll_token（redirect_uri 由服务端自行管理）
//!   2. 用户浏览器完成授权，结果由服务端保管
//!   3. GET /api/v1/oauth/cli/poll/<flow_id>（Bearer poll_token）轮询：
//!      pending → 继续等；ready → 响应直接携带全部 token（服务端已完成
//!      code 交换，客户端无需再调 token 接口）
//!   4. POST api.z.ai/api/auth/z/login 把 zai access_token 换业务 token
//!   5. 组装 portable JSON，复用 profile::import_profile_json 导入账号

use rand::RngCore;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    sync::{Mutex, OnceLock},
    time::Duration,
};
use tokio::sync::oneshot;

const TOKEN_URL: &str = "https://zcode.z.ai/api/v1/oauth/token";
const USERINFO_URL: &str = "https://chat.z.ai/api/oauth/userinfo";
const BUSINESS_LOGIN_URL: &str = "https://api.z.ai/api/auth/z/login";
const CLI_INIT_URL: &str = "https://zcode.z.ai/api/v1/oauth/cli/init";
const CLI_POLL_BASE: &str = "https://zcode.z.ai/api/v1/oauth/cli/poll";
const DEFAULT_DEADLINE_SECONDS: u64 = 600;
const HTTP_TIMEOUT_SECONDS: u64 = 20;
/// 本应用协议名（保留深链接入口的识别，仅用于兼容旧启动参数场景）
const APP_SCHEME: &str = "zcodeswitcher";

#[derive(Debug, Serialize)]
pub struct OAuthInit {
    pub flow_id: String,
    pub authorize_url: String,
    pub poll_token: String,
}

struct PendingFlow {
    state: String,
    redirect_uri: String,
    receiver: Option<oneshot::Receiver<Result<CallbackData, String>>>,
    shutdown: Option<oneshot::Sender<()>>,
    poll: Option<PollFlow>,
}

/// CLI 轮询流程（ZCode 3.10.1 同款通道）
struct PollFlow {
    flow_id: String,
    poll_token: String,
    /// Unix 秒
    expires_at: i64,
    poll_interval_sec: u64,
}

/// 深链接回调投递通道：协议拉起本 exe 时（启动参数带回调 URL），
/// 把 URL 塞进这里，正在等待的 OAuth 流程从另一端取走。
fn deep_link_channel() -> &'static Mutex<Option<oneshot::Sender<Result<CallbackData, String>>>> {
    static CHANNEL: OnceLock<Mutex<Option<oneshot::Sender<Result<CallbackData, String>>>>> =
        OnceLock::new();
    CHANNEL.get_or_init(|| Mutex::new(None))
}

/// 早到的深链接缓存：回调比 oauth_init 先到时（单实例转发竞态）暂存，
/// oauth_init 建立通道后立即消费。
fn early_deep_link() -> &'static Mutex<Option<CallbackData>> {
    static EARLY: OnceLock<Mutex<Option<CallbackData>>> = OnceLock::new();
    EARLY.get_or_init(|| Mutex::new(None))
}

/// 处理通过启动参数传入的深链接回调 URL（zcodeswitcher://oauth/callback?...）。
/// 返回 true 表示 URL 是有效的 OAuth 回调且已投递给等待中的流程（或已暂存）。
pub fn handle_deep_link_argument(arg: &str) -> bool {
    let arg = arg.trim();
    if !arg
        .to_ascii_lowercase()
        .starts_with(&format!("{}://", APP_SCHEME))
    {
        return false;
    }
    let Some(callback) = parse_callback_url(arg) else {
        return false;
    };
    let sender = deep_link_channel()
        .lock()
        .ok()
        .and_then(|mut slot| slot.take());
    match sender {
        Some(sender) => sender.send(Ok(callback)).is_ok(),
        None => {
            // 没有等待中的流程：暂存，oauth_init 时若发现直接消费
            if let Ok(mut slot) = early_deep_link().lock() {
                *slot = Some(callback);
                true
            } else {
                false
            }
        }
    }
}

#[derive(Debug)]
struct CallbackData {
    code: String,
    state: String,
}

#[derive(Debug, Deserialize)]
struct TokenEnvelope {
    #[serde(default)]
    code: Option<Value>,
    #[serde(default)]
    msg: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    data: Option<TokenData>,
}

#[derive(Debug, Deserialize)]
struct TokenData {
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    user: Option<Value>,
    #[serde(default)]
    zai: Option<ZaiTokens>,
    // cli/init 响应字段
    #[serde(default)]
    flow_id: Option<String>,
    #[serde(default, rename = "flowId")]
    flow_id_alt: Option<String>,
    #[serde(default, rename = "authorize_url")]
    authorize_url: Option<String>,
    #[serde(default, rename = "authorizeUrl")]
    authorize_url_alt: Option<String>,
    #[serde(default)]
    poll_token: Option<String>,
    #[serde(default, rename = "pollToken")]
    poll_token_alt: Option<String>,
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default, rename = "expiresAt")]
    expires_at_alt: Option<i64>,
    #[serde(default)]
    poll_interval_sec: Option<u64>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    bigmodel: Option<ZaiTokens>,
}

#[derive(Debug, Deserialize, Default)]
struct ZaiTokens {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default, rename = "accessToken")]
    access_token_camel: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default, rename = "refreshToken")]
    refresh_token_camel: Option<String>,
}

impl ZaiTokens {
    fn access_token(&self) -> String {
        self.access_token
            .as_deref()
            .or(self.access_token_camel.as_deref())
            .unwrap_or_default()
            .trim()
            .to_string()
    }

    fn refresh_token(&self) -> String {
        self.refresh_token
            .as_deref()
            .or(self.refresh_token_camel.as_deref())
            .unwrap_or_default()
            .trim()
            .to_string()
    }
}

#[derive(Debug, Deserialize)]
struct BusinessEnvelope {
    #[serde(default)]
    code: Option<Value>,
    #[serde(default)]
    success: Option<bool>,
    #[serde(default)]
    msg: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    data: Option<Value>,
}

fn pending_flow() -> &'static Mutex<Option<PendingFlow>> {
    static PENDING: OnceLock<Mutex<Option<PendingFlow>>> = OnceLock::new();
    PENDING.get_or_init(|| Mutex::new(None))
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

fn http_client() -> Result<Client, String> {
    Client::builder()
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECONDS))
        .build()
        .map_err(|e| format!("HTTP 客户端创建失败:{}", e))
}

fn is_success_code(code: Option<&Value>) -> bool {
    match code {
        None | Some(Value::Null) => true,
        Some(Value::Number(n)) => n.as_i64().map(|v| v == 0 || v == 200).unwrap_or(false),
        Some(Value::String(s)) => {
            let s = s.trim();
            s == "0" || s == "200"
        }
        _ => false,
    }
}

fn envelope_message(msg: Option<String>, message: Option<String>, fallback: &str) -> String {
    msg.or(message)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

fn body_preview(body: &str) -> String {
    body.chars().take(300).collect::<String>()
}

/// 从回调 URL（深链接或 HTTP）解析 code/state
fn parse_callback_url(url_str: &str) -> Option<CallbackData> {
    let url = reqwest::Url::parse(url_str.trim()).ok()?;
    let mut code = None;
    let mut state = None;
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "code" | "authCode" => code = Some(v.into_owned()),
            "state" => state = Some(v.into_owned()),
            _ => {}
        }
    }
    let code = code?;
    let state = state.unwrap_or_default();
    if code.is_empty() {
        return None;
    }
    Some(CallbackData { code, state })
}

/// 初始化新版 Z.ai OAuth 轮询流程。
///
/// 服务端提供 CLI 轮询通道（ZCode 3.10.1 同款）：
///   1. POST /api/v1/oauth/cli/init  → 拿 flow_id + 服务端托管的 authorize_url + poll_token
///   2. 用户浏览器完成授权后，结果由服务端保管
///   3. GET /api/v1/oauth/cli/poll/<flow_id>（Bearer poll_token）轮询，
///      status: pending → 等待；ready → 直接携带全部 token（服务端已完成 code 交换）
///
/// 为了兼容前端旧接口字段：
/// - flow_id = 服务端 flow_id
/// - poll_token = 服务端 poll_token
#[tauri::command]
pub async fn oauth_init() -> Result<OAuthInit, String> {
    let client = http_client()?;

    // 客户端随机 token 用于 init 请求；服务端会在响应里返回正式 poll_token
    let bootstrap_token = random_hex(32);
    let resp = client
        .post(CLI_INIT_URL)
        .header("Authorization", format!("Bearer {}", bootstrap_token))
        .json(&serde_json::json!({ "provider": "zai" }))
        .send()
        .await
        .map_err(|e| format!("OAuth 初始化请求失败:{}", e))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("OAuth 初始化响应读取失败:{}", e))?;
    if !status.is_success() {
        return Err(format!("OAuth 初始化 HTTP {}:{}", status, body_preview(&body)));
    }
    let envelope: TokenEnvelope = serde_json::from_str(&body)
        .map_err(|e| format!("OAuth 初始化响应解析失败:{}", e))?;
    if !is_success_code(envelope.code.as_ref()) {
        return Err(format!(
            "OAuth 初始化被拒绝:{}",
            envelope_message(envelope.msg, envelope.message, "未知错误")
        ));
    }
    let data = envelope.data.ok_or("OAuth 初始化响应缺少 data")?;

    let flow_id = data
        .flow_id
        .clone()
        .or_else(|| data.flow_id_alt.clone())
        .unwrap_or_default();
    let authorize_url = data
        .authorize_url
        .clone()
        .or_else(|| data.authorize_url_alt.clone())
        .unwrap_or_default();
    let poll_token = data
        .poll_token
        .clone()
        .or_else(|| data.poll_token_alt.clone())
        .unwrap_or_default();
    let expires_at = data.expires_at.or(data.expires_at_alt).unwrap_or(0);
    let poll_interval = data.poll_interval_sec.unwrap_or(2).max(1);
    if flow_id.is_empty() || authorize_url.is_empty() || poll_token.is_empty() || expires_at == 0
    {
        return Err("OAuth 初始化响应字段不完整".into());
    }

    let mut pending = pending_flow()
        .lock()
        .map_err(|_| "OAuth 流程状态锁定失败".to_string())?;
    if let Some(mut old) = pending.take() {
        if let Some(shutdown) = old.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
    *pending = Some(PendingFlow {
        state: flow_id.clone(),
        redirect_uri: poll_token.clone(),
        receiver: None,
        shutdown: None,
        poll: Some(PollFlow {
            flow_id,
            poll_token,
            expires_at,
            poll_interval_sec: poll_interval,
        }),
    });

    Ok(OAuthInit {
        flow_id: pending.as_ref().unwrap().state.clone(),
        authorize_url,
        poll_token: pending.as_ref().unwrap().redirect_uri.clone(),
    })
}

/// 等待本地回调，交换 token，并导入账号。
#[tauri::command]
pub async fn oauth_acquire_and_import(
    flow_id: String,
    poll_token: String,
    deadline_seconds: Option<u64>,
) -> Result<crate::profile::Profile, String> {
    let pending = {
        let mut guard = pending_flow()
            .lock()
            .map_err(|_| "OAuth 流程状态锁定失败".to_string())?;
        match guard.take() {
            Some(flow) if flow.state == flow_id && flow.redirect_uri == poll_token => flow,
            Some(flow) => {
                *guard = Some(flow);
                return Err("OAuth 流程不匹配，请重新发起登录".into());
            }
            None => return Err("没有正在等待的 OAuth 登录流程，请重新发起登录".into()),
        }
    };

    let profile = acquire_with_pending(pending, deadline_seconds).await;
    profile
}

async fn acquire_with_pending(
    pending: PendingFlow,
    deadline_seconds: Option<u64>,
) -> Result<crate::profile::Profile, String> {
    let PendingFlow {
        state: _,
        redirect_uri: _,
        receiver,
        mut shutdown,
        poll,
    } = pending;

    // 轮询模式：CLI 轮询通道（主方案）
    if let Some(poll_flow) = poll {
        shutdown_pending(&mut shutdown);
        let _ = receiver; // 轮询模式无回调通道
        return acquire_via_polling(poll_flow, deadline_seconds).await;
    }

    // 回调模式（保留兼容：万一走到没有 poll 的流程）
    let Some(receiver) = receiver else {
        return Err("OAuth 流程状态无效，请重新发起登录".into());
    };
    let deadline = Duration::from_secs(deadline_seconds.unwrap_or(DEFAULT_DEADLINE_SECONDS));
    let callback = match tokio::time::timeout(deadline, receiver).await {
        Ok(Ok(Ok(callback))) => callback,
        Ok(Ok(Err(e))) => {
            shutdown_pending(&mut shutdown);
            return Err(e);
        }
        Ok(Err(_)) => {
            shutdown_pending(&mut shutdown);
            return Err("OAuth 回调通道已关闭，请重新发起登录".into());
        }
        Err(_) => {
            shutdown_pending(&mut shutdown);
            return Err("等待 OAuth 登录超时".into());
        }
    };
    shutdown_pending(&mut shutdown);

    let client = http_client()?;
    let token_data = exchange_oauth_token(&client, &callback.code, "", "").await?;
    finish_import_from_token_data(&client, token_data).await
}

/// CLI 轮询通道：循环 GET /api/v1/oauth/cli/poll/<flow_id>，
/// status=ready 时响应直接携带全部 token（服务端已完成 code 交换）。
async fn acquire_via_polling(
    poll_flow: PollFlow,
    deadline_seconds: Option<u64>,
) -> Result<crate::profile::Profile, String> {
    let PollFlow {
        flow_id,
        poll_token,
        expires_at,
        poll_interval_sec,
    } = poll_flow;

    let client = http_client()?;
    let poll_url = format!("{}/{}", CLI_POLL_BASE, urlencode(&flow_id));
    let deadline = Duration::from_secs(deadline_seconds.unwrap_or(DEFAULT_DEADLINE_SECONDS));
    let hard_deadline = tokio::time::Instant::now() + deadline;
    // 服务端给的有效期（Unix 秒 → Instant），轮询不能超过它
    let server_deadline = tokio::time::Instant::now()
        + Duration::from_secs((expires_at - chrono_now_secs()).max(1) as u64);
    let effective_deadline = hard_deadline.min(server_deadline);
    let interval = Duration::from_secs(poll_interval_sec.min(5));

    loop {
        if tokio::time::Instant::now() >= effective_deadline {
            return Err("等待 OAuth 登录超时".into());
        }
        let resp = client
            .get(&poll_url)
            .header("Authorization", format!("Bearer {}", poll_token))
            .send()
            .await;
        match resp {
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                if status.is_success() {
                    if let Ok(envelope) = serde_json::from_str::<TokenEnvelope>(&body) {
                        if is_success_code(envelope.code.as_ref()) {
                            if let Some(data) = envelope.data {
                                match data.status.as_deref() {
                                    Some("pending") | None => {}
                                    Some("failed") => {
                                        return Err("OAuth flow 授权失败".into())
                                    }
                                    Some("ready") => {
                                        return finish_import_from_token_data(&client, data)
                                            .await;
                                    }
                                    Some(other) => {
                                        return Err(format!("OAuth flow 状态异常:{}", other))
                                    }
                                }
                            }
                        } else {
                            return Err(format!(
                                "OAuth 轮询被拒绝:{}",
                                envelope_message(
                                    envelope.msg,
                                    envelope.message,
                                    "未知错误"
                                )
                            ));
                        }
                    }
                } else if status.as_u16() >= 400 && status.as_u16() < 500 {
                    // 4xx（除限流）：流程已失效，直接报错
                    return Err(format!(
                        "OAuth 轮询失败（HTTP {}）:{}",
                        status,
                        body_preview(&body)
                    ));
                }
                // 5xx/429/解析失败：当作临时故障继续轮询
            }
            Err(_) => {
                // 网络错误：继续轮询直到 deadline
            }
        }
        tokio::time::sleep(interval).await;
    }
}

fn chrono_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{:02X}", byte)),
        }
    }
    out
}

/// 从 token 数据（轮询 ready 响应或 token 交换响应）完成导入。
async fn finish_import_from_token_data(
    client: &Client,
    token_data: TokenData,
) -> Result<crate::profile::Profile, String> {
    let zcode_jwt = token_data
        .token
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_string();
    if zcode_jwt.is_empty() {
        return Err("Token 交换失败:响应缺少 data.token".into());
    }
    let zai_tokens = token_data.zai.unwrap_or_default();
    let zai_access_token = zai_tokens.access_token();
    if zai_access_token.is_empty() {
        return Err("Token 交换失败:响应缺少 data.zai.access_token".into());
    }
    let business_access_token = exchange_business_token(client, &zai_access_token).await?;
    let mut user = token_data
        .user
        .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
    if !has_meaningful_user(&user) {
        if let Some(fetched) = fetch_user_info(client, &business_access_token).await {
            user = fetched;
        }
    }

    import_from_token_set(
        zcode_jwt,
        business_access_token,
        zai_tokens.refresh_token(),
        user,
    )
}

fn shutdown_pending(shutdown: &mut Option<oneshot::Sender<()>>) {
    if let Some(shutdown) = shutdown.take() {
        let _ = shutdown.send(());
    }
}

async fn exchange_oauth_token(
    client: &Client,
    code: &str,
    redirect_uri: &str,
    state: &str,
) -> Result<TokenData, String> {
    let resp = client
        .post(TOKEN_URL)
        .json(&serde_json::json!({
            "provider": "zai",
            "code": code,
            "redirect_uri": redirect_uri,
            "state": state,
        }))
        .send()
        .await
        .map_err(|e| format!("Token 交换网络失败:{}", e))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("Token 交换响应读取失败:{}", e))?;
    if !status.is_success() {
        return Err(format!(
            "Token 交换 HTTP {}:{}",
            status,
            body_preview(&body)
        ));
    }
    let env: TokenEnvelope =
        serde_json::from_str(&body).map_err(|e| format!("Token 交换响应解析失败:{}", e))?;
    if !is_success_code(env.code.as_ref()) {
        return Err(envelope_message(
            env.msg,
            env.message,
            "ZAI 后端 token 交换失败",
        ));
    }
    env.data
        .ok_or_else(|| "Token 交换响应缺少 data".to_string())
}

async fn exchange_business_token(
    client: &Client,
    zai_access_token: &str,
) -> Result<String, String> {
    let resp = client
        .post(BUSINESS_LOGIN_URL)
        .json(&serde_json::json!({ "token": zai_access_token }))
        .send()
        .await
        .map_err(|e| format!("业务 token 交换网络失败:{}", e))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("业务 token 交换响应读取失败:{}", e))?;
    if !status.is_success() {
        return Err(format!(
            "业务 token 交换 HTTP {}:{}",
            status,
            body_preview(&body)
        ));
    }
    let env: BusinessEnvelope =
        serde_json::from_str(&body).map_err(|e| format!("业务 token 响应解析失败:{}", e))?;
    if env.success == Some(false) || !is_success_code(env.code.as_ref()) {
        return Err(envelope_message(
            env.msg,
            env.message,
            "ZAI 业务 token 交换失败",
        ));
    }
    let data = env
        .data
        .ok_or_else(|| "业务 token 响应缺少 data".to_string())?;
    let token = pick(&data, &["access_token", "accessToken"]);
    if token.is_empty() {
        return Err("业务 token 响应缺少 access_token".into());
    }
    Ok(token)
}

async fn fetch_user_info(client: &Client, business_access_token: &str) -> Option<Value> {
    let resp = client
        .get(USERINFO_URL)
        .bearer_auth(business_access_token)
        .header("Content-Type", "application/json")
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let value: Value = resp.json().await.ok()?;
    Some(value.get("data").cloned().unwrap_or(value))
}

fn has_meaningful_user(user: &Value) -> bool {
    !pick(user, &["email", "mail"]).is_empty()
        || !pick(
            user,
            &[
                "phone",
                "phone_number",
                "phoneNumber",
                "mobile",
                "mobile_phone",
                "mobilePhone",
            ],
        )
        .is_empty()
        || !pick(user, &["user_id", "userId", "id", "customerNumber", "sub"]).is_empty()
}

fn pick(user: &Value, keys: &[&str]) -> String {
    for key in keys {
        if let Some(value) = user.get(*key) {
            match value {
                Value::String(s) if !s.trim().is_empty() => return s.trim().to_string(),
                Value::Number(n) => return n.to_string(),
                _ => {}
            }
        }
    }
    String::new()
}

fn import_from_token_set(
    zcode_jwt: String,
    business_access_token: String,
    refresh_token: String,
    user: Value,
) -> Result<crate::profile::Profile, String> {
    let email = pick(&user, &["email", "mail"]);
    let phone = pick(
        &user,
        &[
            "phone",
            "phone_number",
            "phoneNumber",
            "mobile",
            "mobile_phone",
            "mobilePhone",
        ],
    );
    let name = pick(&user, &["name", "username", "nickName", "displayName"]);
    let avatar = pick(&user, &["avatar", "avatarUrl", "picture"]);
    let user_id = pick(&user, &["user_id", "userId", "id", "customerNumber", "sub"]);

    let user_info_json = serde_json::to_string(&serde_json::json!({
        "email": email,
        "phone": phone,
        "phone_number": phone,
        "name": name,
        "avatar": avatar,
        "user_id": user_id,
    }))
    .map_err(|e| format!("user_info 序列化失败:{}", e))?;

    let mut credentials = serde_json::Map::new();
    credentials.insert(
        "oauth:active_provider".to_string(),
        Value::String("zai".into()),
    );
    credentials.insert(
        "oauth:zai:user_info".to_string(),
        Value::String(user_info_json),
    );
    credentials.insert("zcodejwttoken".to_string(), Value::String(zcode_jwt));
    credentials.insert(
        "oauth:zai:access_token".to_string(),
        Value::String(business_access_token),
    );
    if !refresh_token.is_empty() {
        credentials.insert(
            "oauth:zai:refresh_token".to_string(),
            Value::String(refresh_token),
        );
    }

    let default_name = if let Some(at) = email.find('@') {
        email[..at].to_string()
    } else if !phone.is_empty() {
        format!("账号 {}", phone)
    } else if !user_id.is_empty() {
        user_id.clone()
    } else {
        "未命名".to_string()
    };

    let portable = serde_json::json!({
        "schema": "zcode-switcher-account/v1",
        "exported_at": chrono::Local::now().timestamp() as f64,
        "profile": {
            "name": if name.is_empty() { default_name } else { name },
            "user_id": user_id,
            "email": email,
            "phone": phone,
            "avatar": avatar,
        },
        "credentials": Value::Object(credentials),
        "family": "zai",
        "mode": "oauth",
        "provider_api_keys": {},
    });

    let portable_text =
        serde_json::to_string(&portable).map_err(|e| format!("portable 序列化失败:{}", e))?;
    crate::profile::import_profile_json(portable_text).map_err(|e| e.to_string())
}
