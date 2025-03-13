pub mod app_error;
pub mod bff_rest_dtos;
pub mod token;

pub fn get_from_env_or_panic(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|err| panic!("Cannot find {} in env: {}", key, err))
}
