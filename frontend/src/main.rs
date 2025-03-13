use std::{thread, time::Duration};

use log::info;
use rand::Rng;
use reqwest::Url;
use shared::{bff_rest_dtos::LoginDTO, get_from_env_or_panic};

static USER_ID_HEADER: &str = "Idphandson-User-Id";

#[tokio::main]
async fn main() {
    env_logger::init();

    let bff_host = get_from_env_or_panic("BFF_HOST");

    // NOTE: alice has admin and sachbearbeiter roles, bob only sachbearbeiter
    let username = get_from_env_or_panic("FRONTEND_USERNAME");
    let password = get_from_env_or_panic("FRONTEND_PASSWORD");

    let user_id = login(&bff_host, &username, &password).await.unwrap();
    info!("login_result: {}", user_id);

    let mut rng = rand::rng();

    loop {
        let admin_only_result = admin_only(&bff_host, &user_id).await.unwrap();
        info!("admin_only_result: {:?}", admin_only_result);

        let all_roles_result = all_roles(&bff_host, &user_id).await.unwrap();
        info!("all_roles_result: {:?}", all_roles_result);

        let sleep_sec = rng.random_range(1..=5);

        thread::sleep(Duration::from_secs(sleep_sec));
    }
}

async fn login(bff_host: &str, username: &str, password: &str) -> Result<String, reqwest::Error> {
    let url = Url::parse(&format!("http://{}/idphandson/bff/rest/login", bff_host));

    let login_info = LoginDTO {
        username: username.to_string(),
        password: password.to_string(),
    };

    let response = reqwest::Client::new()
        .post(url.unwrap())
        .json(&login_info)
        .send()
        .await?;

    response.text().await
}

async fn admin_only(bff_host: &str, user_id: &str) -> Result<String, reqwest::Error> {
    let url = Url::parse(&format!(
        "http://{}/idphandson/bff/rest/adminonly",
        bff_host
    ));

    let response = reqwest::Client::new()
        .get(url.unwrap())
        .header(USER_ID_HEADER, user_id)
        .send()
        .await?;

    info!("admin_only response status: {}", response.status());

    response.text().await
}

async fn all_roles(bff_host: &str, user_id: &str) -> Result<String, reqwest::Error> {
    let url = Url::parse(&format!("http://{}/idphandson/bff/rest/allroles", bff_host));

    let response = reqwest::Client::new()
        .get(url.unwrap())
        .header(USER_ID_HEADER, user_id)
        .send()
        .await?;

    info!("all_roles response status: {}", response.status());

    response.text().await
}
