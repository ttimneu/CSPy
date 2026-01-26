use clap::{Parser, ValueEnum};
use colored::*;
use std::path::PathBuf;

mod scanner;
mod checks;
mod output;

use scanner::Scanner;
use output::OutputFormat;

#[derive(Parser, Debug)]
#[command(name = "CSPy")]
#[command(author = "Security Researcher")]
#[command(version = "0.1.0")]
#[command(about = "🔒 Content Security Policy & HTTP Security Headers Analyzer", long_about = None)]
struct Args {
    /// Target URL to scan
    #[arg(value_name = "URL")]
    url: Option<String>,

    /// Input file containing URLs (one per line)
    #[arg(short, long, value_name = "FILE")]
    input: Option<PathBuf>,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Pretty)]
    output: OutputFormat,

    /// Save results to file
    #[arg(short = 'f', long, value_name = "FILE")]
    output_file: Option<PathBuf>,

    /// Silent mode (minimal output)
    #[arg(short, long)]
    silent: bool,

    /// Follow redirects
    #[arg(short, long, default_value_t = true)]
    redirect: bool,

    /// Maximum redirects to follow
    #[arg(long, default_value_t = 10)]
    max_redirects: usize,

    /// Request timeout in seconds
    #[arg(short, long, default_value_t = 10)]
    timeout: u64,

    /// Custom User-Agent
    #[arg(short = 'A', long)]
    user_agent: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Print banner unless silent
    if !args.silent {
        print_banner();
    }

    // Collect URLs to scan
    let urls = if let Some(url) = args.url {
        vec![url]
    } else if let Some(input_file) = args.input {
        read_urls_from_file(&input_file)?
    } else {
        eprintln!("{}", "Error: Please provide a URL or input file (-i)".red().bold());
        std::process::exit(1);
    };

    // Create scanner
    let scanner = Scanner::new(
        args.timeout,
        args.redirect,
        args.max_redirects,
        args.user_agent,
    );

    // Scan URLs
    let mut all_results = Vec::new();
    
    for url in urls {
        if !args.silent {
            println!("\n{} {}", "→".cyan().bold(), url.bright_white().bold());
        }

        match scanner.scan(&url).await {
            Ok(result) => {
                if !args.silent {
                    output::print_result(&result, &args.output);
                }
                all_results.push(result);
            }
            Err(e) => {
                eprintln!("{} {}: {}", "✖".red().bold(), url, e);
            }
        }
    }

    // Save to file if requested
    if let Some(output_file) = args.output_file {
        output::save_to_file(&all_results, &output_file, &args.output)?;
        if !args.silent {
            println!("\n{} Results saved to: {}", "✓".green().bold(), output_file.display());
        }
    }

    Ok(())
}

fn print_banner() {
    println!("{}", r#"
  ______     ______     ______   __  __    
/\  ___\   /\  ___\   /\  == \ /\ \_\ \   
\ \ \____  \ \___  \  \ \  _-/ \ \____ \  
 \ \_____\  \/\_____\  \ \_\    \/\_____\ 
  \/_____/   \/_____/   \/_/     \/_____/ 
                                          
    "#.bright_cyan().bold());
    println!("{}", "Content Security Policy & HTTP Security Headers Analyzer".bright_white());
    println!("{}\n", "By Security Researcher | v0.1.0".dim());
}

fn read_urls_from_file(path: &PathBuf) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let urls: Vec<String> = content
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(String::from)
        .collect();
    
    if urls.is_empty() {
        return Err("No valid URLs found in file".into());
    }
    
    Ok(urls)
}
