use std::{collections::HashMap, fmt::Display, hash::Hash};
pub mod macros {
    #[macro_export]
    #[cfg(debug_assertions)]
    macro_rules!  my_dbg {
    () => {
        $crate::eprintln!("[{}:{}:{}]", $crate::file!(), $crate::line!(), $crate::column!())
    };
    ($val:expr $(,)?) => {
        dbg!($val)
    };
    ($($val:expr),+ $(,)?) => {
        ($($crate::dbg!($val)),+,)
    };
}
    #[macro_export]
    #[cfg(not(debug_assertions))]
    macro_rules! my_dbg {
    () => {
        $crate::eprintln!("[{}:{}:{}]", $crate::file!(), $crate::line!(), $crate::column!())
    };
    ($val:expr $(,)?) => {
        $val
    };
    ($($val:expr),+ $(,)?) => {
        ($($val),+,)
    };
}
}
#[derive(Debug)]
pub struct WebLogin {
    pub base_url: &'static str,
    pub account: &'static str,
    pub password: &'static str,
    pub headers: HashMap<String, String>,
}
impl WebLogin {
    pub fn new(base_url: &'static str, account: &'static str, password: &'static str) -> Self {
        Self {
            base_url,
            account,
            password,
            headers: HashMap::from([
                (
                    "User-Agent".to_string(),
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36".to_string(),
                ),
                ("Accept-Encoding".to_string(), "gzip, deflate".to_string()),
                ("Accept".to_string(), "*/*".to_string()),
                ("Connection".to_string(), "keep-alive".to_string()),
            ]),
        }
    }
    pub fn empty() -> Self {
        Self {
            base_url: "",
            account: "",
            password: "",
            headers: HashMap::new(),
        }
    }
    pub fn login(
        account: &'static str,
        password: &'static str,
    ) -> Result<(WebLogin, bool), Box<dyn std::error::Error>> {
        let mut login = WebLogin::new("http://202.119.196.6:8080", account, password);
        let params = HashMap::from([("302", "LI")]);
        let resp1 = login.get("/Self/login/", params)?;
        let random_code = rand::random::<f64>().to_string();
        let params: HashMap<&str, &str> = HashMap::from([("t", random_code.as_str())]);
        let check_code = get_check_code(resp1.as_str()?).ok_or("无法获取验证码")?;
        login.get("/Self/login/randomCode", params)?;

        let resp3 = login.post_for_vertify(&check_code);
        let end_str = resp3?.as_str()?.to_string();
        Ok((login, is_success(&end_str)))
    }
    pub fn get_online_users(&mut self) -> Result<Vec<OnlineUser>, Box<dyn std::error::Error>> {
        let resp = self.get(
            "/Self/dashboard/getOnlineList",
            HashMap::from([("order", "asc")]),
        )?;
        let mut online_users: Vec<OnlineUser> = Vec::new();
        let out = resp.as_str()?;

        for value in OnlineUser::from_json(out) {
            if online_users.contains(&value) {
                continue;
            } else {
                online_users.push(value);
            }
        }
        online_users.sort();
        Ok(online_users)
    }
    fn get_with_base(
        &mut self,
        base_url: &'static str,
        location: &str,
        params: HashMap<&str, &str>,
        set_cookie: bool,
    ) -> Result<minreq::Response, Box<dyn std::error::Error>> {
        let url = format!("{}{}", base_url, location);
        let mut get = minreq::get(url).with_headers(self.headers.clone());
        for (k, v) in params {
            get = get.with_param(k, v);
        }
        let resp = get.send()?;
        let headers = &resp.headers;
        if set_cookie && let Some(cookie) = headers.get("set-cookie") {
            self.headers.insert(
                "Cookie".to_string(),
                cookie
                    .split_once(";")
                    .ok_or("无法获取jessionid")?
                    .0
                    .to_string(),
            );
        }
        Ok(resp)
    }
    pub fn to_offline(&mut self, user: &OnlineUser) -> Result<bool, Box<dyn std::error::Error>> {
        let t = &[
            31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 211, 168, 86, 42, 74, 45, 46, 205, 41, 81, 178, 82,
            50, 84, 210, 81, 202, 45, 78, 7, 178, 158, 109, 94, 241, 114, 74, 195, 179, 142, 9, 79,
            187, 230, 43, 213, 106, 2, 0, 210, 223, 201, 245, 37, 0, 0, 0,
        ];
        Ok(my_dbg!(
            self.get_with_base(
                "http://10.2.5.251:801",
                "/eportal/",
                HashMap::from([
                    ("wlan_user_ip", user.ip.as_str()),
                    ("a", "logout"),
                    ("c", "Portal")
                ]),
                false
            )?
            .as_bytes()
        ) == t)
    }
    fn post_for_vertify(
        &self,
        checkcode: &str,
    ) -> std::result::Result<minreq::Response, minreq::Error> {
        let params = HashMap::from([
            ("foo", ""),
            ("bar", ""),
            ("checkcode", checkcode),
            ("account", self.account),
            ("password", self.password),
            ("code", ""),
        ]);
        let mut post = minreq::post(format!("{}/Self/login/verify", self.base_url))
            .with_headers(self.headers.clone());
        for (k, v) in params {
            post = post.with_param(k, v);
        }

        post.send()
    }
    fn get(
        &mut self,
        location: &str,
        params: HashMap<&str, &str>,
    ) -> Result<minreq::Response, Box<dyn std::error::Error>> {
        self.get_with_base(self.base_url, location, params, true)
    }
}

#[derive(Debug)]
pub struct OnlineUser {
    pub ip: String,
    pub login_time: String,
    pub mac: String,
    pub session_id: String,
    pub use_time: String,
}
impl OnlineUser {
    pub fn new(
        ip: String,
        login_time: String,
        mac: String,
        session_id: String,
        use_time: String,
    ) -> Self {
        Self {
            ip,
            login_time,
            mac,
            session_id,
            use_time,
        }
    }
    pub fn from_json_str_line(json_len: &str) -> Option<Self> {
        if json_len.trim().trim_matches(' ').is_empty() {
            return None;
        }
        let map: HashMap<&str, &str> = json_len
            .trim_start_matches("{")
            .split(",")
            .map(|item| {
                let (l, r) = item.split_once(":").unwrap_or(("", ""));
                (l.trim_matches('"'), r.trim_matches('"'))
            })
            .filter(|item| matches!(item.0, "ip" | "loginTime" | "mac" | "sessionId" | "useTime"))
            .collect();
        Some(Self::new(
            map.get("ip")?.to_string(),
            map.get("loginTime")?.to_string(),
            map.get("mac")?.to_string(),
            map.get("sessionId")?.to_string(),
            map.get("useTime")?.to_string(),
        ))
    }
    pub fn from_json(json: &str) -> Vec<Self> {
        json[1..json.len() - 1]
            .split("},")
            .filter_map(Self::from_json_str_line)
            .collect()
    }
}
impl PartialEq for OnlineUser {
    fn eq(&self, other: &Self) -> bool {
        self.ip == other.ip && self.mac == other.mac
    }
}
impl Eq for OnlineUser {}
impl PartialOrd for OnlineUser {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for OnlineUser {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.ip.cmp(&other.ip)
    }
}
impl Hash for OnlineUser {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.ip.hash(state);
        self.mac.hash(state);
    }
}
impl Display for OnlineUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "ip: {}, 登录时间: {}, 已登录时间: {}",
            self.ip, self.login_time, self.use_time,
        ))
    }
}
fn is_success(text: &str) -> bool {
    !text.contains("没有注册请点击这里")
}
fn get_check_code(text: &str) -> Option<String> {
    let begin = text.find(r#"name="checkcode" value=""#)? + r#"name="checkcode" value=""#.len();
    let end = text[begin..].find("\"")? + begin;
    Some(text[begin..end].to_string())
}
