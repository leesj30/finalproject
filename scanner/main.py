import argparse
from Vscanner import WebScanner

def main():
    parser = argparse.ArgumentParser(description='Web Security Scanner')
    parser.add_argument('url', help='Base URL of the website to scan')
    parser.add_argument('--depth', type=int, default=3, help='Crawl depth (default: 3)')
    args = parser.parse_args()

    scanner = WebScanner(args.url, args.depth)
    scanner.run_security_checks()

if __name__ == '__main__':
    main()
