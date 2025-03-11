use log::info;
use reqwest::Url;
use shared::bff_rest_dtos::LoginDTO;

#[tokio::main]
async fn main() {
    env_logger::init();

    let bff_host = "localhost:1234/idphandson/bff";
    let username = "alice";
    let password = "alice";

    let login_result = login(bff_host, username, password).await.unwrap();

    info!("login_result: {:?}", login_result);
}

pub async fn login(bff_host: &str, username: &str, password: &str
) -> Result<(), reqwest::Error> {
    let url = Url::parse(&format!(
        "http://{}/login", bff_host
    ));

    info!("url: {:?}", url);

    let login_info = LoginDTO {
        username: username.to_string(),
        password: password.to_string()
    };

    let response = reqwest::Client::new()
        .post(url.unwrap())
        .json(&login_info)
        .send()
        .await?;
    response.json().await
}
