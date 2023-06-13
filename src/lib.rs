use std::path::PathBuf;

use tokio::{net::{TcpListener, TcpStream}, fs::File as AsyncFile};

pub async fn upload_file(file_path: PathBuf) -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("server listening on 8080");

    let (mut stream, _) = listener.accept().await?;
    println!("client connected");

    let mut file = AsyncFile::open(file_path).await?;
    let bytes_copied = tokio::io::copy(&mut file, &mut stream).await?;

    println!("transfer complete: {} bytes", bytes_copied);
    Ok(())
}


pub async fn download_file(file_path: PathBuf) -> std::io::Result<()> {
    let mut stream = TcpStream::connect("127.0.0.1:8080").await?;
    println!("connected to server");

    let mut file = AsyncFile::create(file_path).await?;

    let bytes_copied = tokio::io::copy(&mut stream, &mut file).await?;

    println!("transfer complete: {} bytes", bytes_copied);
    Ok(())
}
