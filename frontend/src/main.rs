use log::info;
use reqwest::Url;
use shared::bff_rest_dtos::LoginDTO;

#[tokio::main]
async fn main() {
    env_logger::init();

    // TODO: load from env
    let bff_host = "localhost:1234/idphandson/bff";

    // NOTE: alice has admin and sachbearbeiter roles, bob only sachbearbeiter
    let username = "bob";
    let password = "bob";

    let user_id = login(bff_host, username, password).await.unwrap();
    info!("login_result: {}", user_id);

    let admin_only_result = admin_only(bff_host, &user_id).await.unwrap();
    info!("admin_only_result: {:?}", admin_only_result);

    let all_roles_result = all_roles(bff_host, &user_id).await.unwrap();
    info!("all_roles_result: {:?}", all_roles_result);
}

async fn login(bff_host: &str, username: &str, password: &str) -> Result<String, reqwest::Error> {
    let url = Url::parse(&format!("http://{}/login", bff_host));

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
    let url = Url::parse(&format!("http://{}/adminonly", bff_host));

    let response = reqwest::Client::new()
        .get(url.unwrap())
        .header("user_id", user_id)
        .send()
        .await?;

    info!("admin_only response status: {}", response.status());

    response.text().await
}

async fn all_roles(bff_host: &str, user_id: &str) -> Result<String, reqwest::Error> {
    let url = Url::parse(&format!("http://{}/allroles", bff_host));

    let response = reqwest::Client::new()
        .get(url.unwrap())
        .header("user_id", user_id)
        .send()
        .await?;

    info!("all_roles response status: {}", response.status());

    response.text().await
}
