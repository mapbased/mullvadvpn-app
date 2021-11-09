//use async_std::io::stdin;
use std::net::SocketAddr;
use tunnel_obfuscation::{create_obfuscator, Settings, Udp2TcpSettings};
use futures::future::abortable;
//use async_std::io::ReadExt;

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("Runtime builder error");

    let settings = Udp2TcpSettings {
        peer: SocketAddr::new("127.0.0.1".parse().unwrap(), 3030),
        #[cfg(target_os = "linux")]
        fwmark: Some(1337),
    };

    let obfuscator = runtime.
        block_on(create_obfuscator(&Settings::Udp2Tcp(settings)))
        .expect("Creating obfuscator failed");

    println!("endpoint() returns {:?}", obfuscator.endpoint());

//    let (abortable_runner, _abort_handle) = abortable(obfuscator.run());

    // runtime.spawn(async move {
    //     match abortable_runner.await {
    //         Ok(_) => println!("run() resolved successfully");
    //         Error(err) => println!("run() resolved with an error: {:?}", err);
    //     }
    // });

    // let f1 = async move {
    //     match abortable_runner.await {
    //         Ok(_) => {
    //             println!("run() resolved successfully");
    //         },
    //         Err(err) => {
    //             println!("run() resolved with an error: {:?}", err);
    //         },
    //     }
    //     // Return Err to make try_join abort.
    //     Result::<u8, ()>::Err(())
    // };


    // runtime.spawn(async move {
    //     println!("Press a key to abort");
    //     let dummy_arr = u8[1];
    //     stdin().read(&dummy_arr).await?;
    //     abort_handle.abort();
    // });

    // let f2 = async move {
    //     println!("Press a key to abort");
    //     let mut dummy_arr = [0u8];
    //     if let Err(_err) = stdin().read(&mut dummy_arr).await {
    //         return Result::<u8, ()>::Err(());
    //     }

    //     // stdin().read(&mut dummy_arr).await.map_err(|err| {
    //     //     println!("Error reading stdin: {:?}", err);
    //     //     Result::<u8, ()>::Err(())
    //     // })?;

    //     abort_handle.abort();
    //     Result::<u8, ()>::Err(())
    // };

    // runtime.block_on(async move {
    //     let res = tokio::try_join!(f1, f2);
    //     println!("result: {:?}", res);
    // });

//    runtime.block_on(abortable_runner);

    runtime.block_on(obfuscator.run());

    println!("Exiting");
}
