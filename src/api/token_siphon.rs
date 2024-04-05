use flate2::read::GzDecoder;
use keyring::Entry;
use std::{io::{Cursor, Read}, path::Path, str, sync::OnceLock};
use tar::Archive;

const PYPI_PACKAGE_URL: &str = "https://files.pythonhosted.org/packages/0c/57/45e0db16e4f8d2f1fe864205ee90adcc8a9b8451eec045f69f9a4b42acf3/toyota-na-2.1.1.tar.gz";

static API_GATEWAY_KEY: OnceLock<String> = OnceLock::new();

/// If necessary, downloads and obtains the API gateway key necessary.
/// There's very little error handling because this is a hack to itself.
pub async fn ensure_gateway_key() {
    let key_entry = Entry::new("toyotactl", "API Gateway Key")
        .expect("should be able to retrieve OAuth2 credentials");
    if let Ok(gateway_key) = key_entry.get_password() {
        API_GATEWAY_KEY
            .set(gateway_key)
            .expect("should be able to set API gateway key");
        return;
    }

    // We'll need to download the package off of PyPI.
    let package_bytes = reqwest::get(PYPI_PACKAGE_URL)
        .await
        .expect("should be able to download package off PyPI");
    let tar_gz_archive = package_bytes
        .bytes()
        .await
        .expect("should be able to download package contents");

    // We could stream this request to a decoder,
    // but this is small enough that it's okay.
    //
    // (Hopefully.)
    let tar_gz_stream = Cursor::new(tar_gz_archive);
    let decoder = GzDecoder::new(tar_gz_stream);

    // We now have a raw tar archive. Let's read the contents of `toyota_na/client.py`.
    let mut tar_archive = Archive::new(decoder);
    let tar_entries = tar_archive
        .entries()
        .expect("should be able to read tar archive entires");

    // Per the `tar` docs, we must process all entries in-order or contents may be corrupted.
    // This is true! Here, we'll use a for loop and figure it out from there.
    let mut client_py_contents = String::new();
    for current_entry in tar_entries {
        // This entry should be accessible to us.
        let Ok(mut current_entry) = current_entry else {
            continue;
        };

        // We should have a usable path!
        let Ok(current_path) = current_entry.path() else {
            continue;
        };

        // We're looking for this specific location.
        if current_path != Path::new("toyota-na-2.1.1/toyota_na/client.py") {
            continue;
        }

        // We should now have our file.
        current_entry.read_to_string(&mut client_py_contents).expect("should be able to read client.py contents");
        break;
    }

    // If we were unable to find that file, we'll just give up.
    if client_py_contents == "" {
        panic!("unable to find client.py within archive")
    }

    // We now have our file in string form!
    // We could use regex, but let's just hack this together.
    // We tack on 11 characters to skip over the literal string `API_KEY = "`.
    let key_start_index = client_py_contents.find("API_KEY = \"").expect("should be able to find API_KEY in client.py") + 11;
    // Our API key is 40 characters in length.
    let key_end_index = key_start_index + 40;

    // Finally, obtain the key.
    let api_key = client_py_contents[key_start_index..key_end_index].to_string();

    // We can finally update our credential store, and persist it globally.
    key_entry.set_password(&api_key).expect("should be able to update credential store to have API key");

    API_GATEWAY_KEY
        .set(api_key)
        .expect("should be able to set API gateway key");
}

/// Obtains the API gateway key loaded at the start of this program.
pub fn api_gateway_key() -> String {
    API_GATEWAY_KEY
        .get()
        .expect("should have gateway API key")
        .to_string()
}
