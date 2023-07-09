import cfscrape
from bs4 import BeautifulSoup
import csv
import time

scraper = cfscrape.create_scraper()

# Open the CSV file for writing
with open('../Utils/contracts.csv', 'w', newline='') as file:
    writer = csv.writer(file)
    # Write the header row
    writer.writerow(["Contract Number", "Contract Address"])

    # Iterate over the pages
    for i in range(1, 11):  # From page 1 to 10
        response = scraper.get(f"https://etherscan.io/tokens?ps=100&p={i}")
        soup = BeautifulSoup(response.content, "html.parser")
        table_rows = soup.find_all("tr")

        for row in table_rows:
            # Get contract number (first td in each tr)
            contract_number = row.find("td")
            if contract_number is not None:  # Ensure we found the td
                contract_number = contract_number.get_text()

            # Get smart contract address
            anchor_tag = row.find(
                "a", class_="d-flex align-items-center gap-1 link-dark")
            if anchor_tag is not None:  # Ensure we found the link
                href = anchor_tag.get("href")  # get href value
                if href.startswith("/token/"):
                    contract_address = href.replace("/token/", "")
                    # Write the contract number and address to the CSV
                    writer.writerow([contract_number, contract_address])

        time.sleep(10)
