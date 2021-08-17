use anyhow::{Context, Result};

// Securely read a password and query the Pwned Passwords API to
// determine if it's been breached ever.

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let pass = rpassword::prompt_password_stdout("Password: ")
        .context("failed to read password from stdin")?;

    let digest = sha1::Sha1::from(pass).digest().to_string().to_uppercase();
    let (prefix, suffix) = (&digest[..5], &digest[5..]);

    // API requires us to submit just the first 5 characters of the hash

    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
    let response = reqwest::get(&url)
        .await
        .with_context(|| format!("failed to GET {}", url))?;

    let body = response
        .text()
        .await
        .context("failed to parse request as text")?;

    // Reponse is a series of lines like
    //
    //  suffix:N
    //
    // Where N is the number of times that password has appeared.

    for line in body.lines() {
        let (hash, count) = line
            .split_once(':')
            .context("expected hash:count on each line")?;
        if hash == suffix {
            println!("{} matches found.", count);
            return Ok(());
        }
    }

    println!("No matches found.");

    Ok(())
}
