use libkeri;

#[tokio::main]
async fn main() {
    // Initialize the library
    if let Err(e) = libkeri::init() {
        eprintln!("Failed to initialize KERI library: {}", e);
        return;
    }

    println!("Hello KERI!");
}
