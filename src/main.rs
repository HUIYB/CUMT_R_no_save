use base64::{Engine, prelude::BASE64_URL_SAFE};
use encoding_rs::GBK;
use http::WebLogin;
use http::my_dbg;
use std::{
    collections::HashMap,
    io::{self, stdin},
    process::{Command, Stdio},
    str::FromStr,
    sync::LazyLock,
    thread::sleep,
    time::Duration,
};
static HEADERS: LazyLock<HashMap<String, String>> = LazyLock::new(|| {
    HashMap::from([
        (
            "User-Agent".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36".to_string(),
        ),
        ("Accept-Encoding".to_string(), "utf-8, deflate".to_string()),
        ("Accept".to_string(), "*/*".to_string()),
        ("Connection".to_string(), "keep-alive".to_string()),
    ])
});

const USER_ACCOUNT: &str = "USER_ACCOUNT";
const USER_PASSWORD: &str = "USER_PASSWORD";

const MAC_ID: &str = "000000000000";
#[derive(Debug, Clone, PartialEq)]
enum State {
    IsLogined,
    Success,
    LimitUsers,
    PasswordError,
    UnKnowedUser,
    Other(String),
}
fn get_ipv4_by_cmd() -> Option<String> {
    let ipconfig = Command::new("ipconfig")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("无法获取ip");
    if let Ok(out) = ipconfig.wait_with_output() {
        let config = String::from_str(&GBK.decode(&out.stdout).0).ok()?;
        let mut l1 = config
            .find("无线局域网适配器 WLAN")
            .or_else(|| config.find("Wireless LAN adapter WLAN"))
            .unwrap();
        let l2 = config[l1..].find("IPv4 ").unwrap();
        l1 += l2;
        let ls = config[l1..].find(":").unwrap();
        let str = config.split_at_checked(l1 + ls + 2).unwrap().1;
        Some(
            str.split_at_checked(str.find("\r\n").unwrap())
                .unwrap()
                .0
                .to_string(),
        )
    } else {
        None
    }
}
fn get_ipv4_by_udp() -> io::Result<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    socket.local_addr().map(|item| item.ip().to_string())
}
fn parse_output(output: String) -> HashMap<String, String> {
    let mut s = output.trim().split("\"");
    s.next();
    let mut map = HashMap::new();
    let mut key: String = String::new();
    for str in s {
        if str == ":" || str == "," {
            continue;
        } else if key.is_empty() {
            key = str.to_string();
        } else {
            map.insert(key, str.to_string());
            key = String::new()
        }
    }
    if let Some(base64) = map.get("msg") {
        if base64 == "认证成功" {
            map.insert("msg".to_string(), "认证成功".to_string());
        } else {
            map.insert("msg".to_string(), output_decode(base64));
        }
    }
    map
}
fn output_decode(base64: &str) -> String {
    let de_vec = BASE64_URL_SAFE
        .decode(base64)
        .unwrap_or_else(|_| panic!("base64解码失败:{}", base64));
    let vec_2 = de_vec.clone();

    String::from_utf8(de_vec)
        .unwrap_or_else(|e| panic!("转换成字符串时出错:{:?},eeeor: {:?}", vec_2.clone(), e))
}
fn get_state(map: &HashMap<String, String>) -> State {
    if map.get("ret_code") == Some(&"2".to_string()) {
        return State::IsLogined;
    }
    match map.get("msg").unwrap_or(&"".to_string()).as_str() {
        "userid error1" => State::UnKnowedUser,
        "ldap auth error" => State::PasswordError,
        "认证成功" => State::Success,
        "Rad:Limit Users Err" => State::LimitUsers,
        other => State::Other(other.to_string()),
    }
}
fn login_wifi(ipv4: &str) -> Result<State, Box<dyn std::error::Error>> {
    let sign_parameter = format!(
        "http://10.2.5.251:801/eportal/?c=Portal&a=login&callback=dr1740318353616&login_method=1&user_account={USER_ACCOUNT}%40telecom&user_password={USER_PASSWORD}&wlan_user_ip={ipv4}&wlan_user_mac={MAC_ID}&wlan_ac_ip=&wlan_ac_name=NAS&jsVersion=3.0&_=1740318341152"
    );
    my_dbg!(&sign_parameter);
    let output = minreq::get(sign_parameter.clone())
        .with_headers(HEADERS.clone())
        .with_timeout(3)
        .send()?;
    // print!("{:?}", output.into_bytes());
    let text = output.as_str()?.to_string();
    let map = parse_output(text);
    let state = get_state(&map);
    Ok(state)
}
fn log_state(state: State) {
    match state {
        State::IsLogined => println!("校园网已登录: {}", USER_ACCOUNT),
        State::Success => println!("校园网登录成功: {}", USER_ACCOUNT),
        State::LimitUsers => println!("在线用户过多"),
        State::PasswordError => println!("密码错误"),
        State::UnKnowedUser => println!("未知账户，请检查学号是否正确"),
        State::Other(other) => println!("意料之外的情况: {}", other),
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut is_first = true;
    let mut to_offline = false;
    let mut is_ok = false;
    let mut _login_state = State::Other("".to_string());
    let mut online_users: Vec<http::OnlineUser> = Vec::new();
    let mut loginer = WebLogin::empty();
    let ipv4 = get_ipv4_by_udp().unwrap_or_else(|e| {
        println!("UDP获取本机IPv4地址失败，尝试使用ipconfig命令: {:?}", e);
        get_ipv4_by_cmd().unwrap_or_else(|| {
            println!("无法获取本机IPv4地址: {:?}", e);
            "----------".to_string()
        })
    });
    println!("{}", ipv4);

    'outer: loop {
        if !to_offline {
            _login_state = login_wifi(&ipv4)?;
            log_state(_login_state.clone());
        }
        if is_first && !is_ok {
            let r = WebLogin::login(USER_ACCOUNT, USER_PASSWORD).unwrap_or_else(|e| {
                println!("登录自助服务时出错: {:?}", e);
                (WebLogin::empty(), false)
            });
            loginer = r.0;
            is_ok = r.1;
            if is_ok {
                println!("登录自助服务成功: {}", USER_ACCOUNT);
            }
            is_first = false;
        }
        if is_ok {
            let mut new_online_users = loginer.get_online_users()?;
            loop {
                if new_online_users != online_users {
                    break;
                }
                sleep(Duration::from_secs_f32(0.2));
                new_online_users = loginer.get_online_users()?;
            }
            online_users = new_online_users;

            println!("以下为在线用户:");
            for (timer, i) in online_users.iter().enumerate() {
                print!("{timer}: {i}");

                if i.ip == ipv4 {
                    print!("<== Self")
                }
                println!()
            }
            println!("\n输入序号以将对应用户离线，输入r重来，输入其他以退出...");
            let mut input = String::new();
            stdin().read_line(&mut input).unwrap();
            if let Ok(index) = input.trim().parse::<usize>() {
                let ip = &online_users[index].ip;
                if ip == &ipv4 {
                    loop {
                        println!("是否将自己离线? (y/n)");
                        input.clear();
                        stdin().read_line(&mut input).unwrap();
                        match input.trim() {
                            "y" => {
                                to_offline = true;
                                break;
                            }
                            "n" => {
                                continue 'outer;
                            }
                            _ => {
                                continue;
                            }
                        }
                    }
                }
                if loginer.to_offline(&online_users[index])? {
                    println!("ip 为 {} 的用户已成功离线", ip)
                } else {
                    println!("离线失败")
                };
                continue 'outer;
            }
            if input.trim() == "r" {
                is_first = true;
                to_offline = false;
                online_users.clear();
                continue 'outer;
            }
        } else {
            println!("由于自助服务登录失败，无法获取在线用户列表");
            println!("输入r重来，输入其他以退出...");
            let mut input = String::new();
            stdin().read_line(&mut input).unwrap();
            if input.trim() == "r" {
                is_first = true;
                to_offline = false;
                online_users.clear();
                continue 'outer;
            }
        }
        return Ok(());
    }
}
