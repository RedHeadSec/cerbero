use cerbero::{run,init_log};
use cerbero::args::{args, ArgumentsParser};
use log::error;

fn main() {
    init_log(2);
    let args = ArgumentsParser::parse(&args().get_matches());

    if let Err(error) = run(args) {
        error!("{}", error);
    }
}