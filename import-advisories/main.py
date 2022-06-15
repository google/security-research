#!/usr/bin/env python3

import frontmatter
from io import BytesIO
import os
from pathlib import Path
import scrapy
from scrapyscript import Job, Processor
import typer


class AdvisoriesSpider(scrapy.Spider):
    name = "advisories"

    def start_requests(self):
        start_urls = [
            "https://github.com/google/security-research/security/advisories?state=published",
        ]

        cookies = [kv.split("=", 1) for kv in os.environ["COOKIE"].split("; ")]

        for url in start_urls:
            yield scrapy.Request(
                url=url,
                callback=self.parse,
                cookies=dict(cookies),
            )

    def parse(self, response):
        advisory_links = response.css("#advisories .Link--primary")
        yield from response.follow_all(advisory_links, self.parse_advisory)

        for next_page in response.css("a.next_page"):
            yield response.follow(next_page, self.parse)

    def parse_advisory(self, response):
        products = []
        for p in response.xpath('//affected-product-row[local-name(..) != "template"]'):
            ecosystem = p.css(".js-ecosystem-selection option[selected]::text").get(
                default="Other"
            )
            if ecosystem == "Other":
                ecosystem = p.xpath(
                    './/input[contains(@class, "js-ecosystem-other")]/@value'
                ).get(default="Other")

            products.append(
                {
                    "ecosystem": ecosystem,
                    "package_name": p.xpath(
                        './/input[contains(@class, "js-advisory-package-name")]/@value'
                    ).get(),
                    "affected_versions": p.xpath(
                        './/input[contains(@id, "_affected_versions")]/@value'
                    ).get(),
                    "patched_versions": p.xpath(
                        './/input[contains(@id, "_patches")]/@value'
                    ).get(),
                }
            )

        credits = []
        for c in response.xpath('//li[contains(@class, "js-advisory-credit-row")]'):
            id = c.xpath('.//img[contains(@class, "avatar-user")]/@alt').get()[1:]
            name = c.css(".user-select-contain::text").get(default=id).strip()
            if name == "":
                name = id
            credits.append(
                {
                    "github_user_id": id,
                    "name": name,
                    "avatar": c.xpath(
                        './/img[contains(@class, "avatar-user")]/@src'
                    ).get(),
                }
            )

        weaknesses = []
        for w in response.xpath('//div[contains(@class, "js-cwe-link")]'):
            weaknesses.append(
                {
                    "id": w.xpath("./@data-cwe-id").get(),
                    "name": w.xpath("./@data-cwe-name").get(),
                }
            )

        yield {
            "title": response.xpath(
                '//input[@id="repository_advisory_title"]/@value'
            ).get(),
            "published": response.xpath(
                '//div[contains(@class, "gh-header-meta")]//relative-time/@datetime'
            ).get(),
            "severity": response.css(
                "#repository_advisory_severity option[selected]::text"
            ).get(),
            "ghsa_id": response.request.url.split("/").pop(),
            "cve_id": response.xpath(
                '//input[@id="repository_advisory_cve_id"]/@value'
            ).get(),
            "weaknesses": weaknesses,
            "products": products,
            "cvss": response.xpath(
                '//input[@id="repository_advisory_cvss_v3"]/@value'
            ).get(),
            "credits": credits,
            "description": response.css("#description::text")
            .get()
            .strip()
            .replace("\r\n", "\n"),
        }


def main(repo: Path):
    if "COOKIE" not in os.environ:
        typer.echo("Missing github.com COOKIE in environment")
        raise typer.Exit(code=1)

    base_path = os.path.join(repo, "advisories")
    if not os.path.isdir(base_path):
        os.mkdir(base_path)

    advisories = Processor().run([Job(AdvisoriesSpider)])
    for advisory in advisories:
        path = os.path.join(base_path, advisory["ghsa_id"] + ".md")

        meta = {k: v for k, v in advisory.items() if k != "description"}
        post = frontmatter.Post(advisory["description"], **meta)
        buf = BytesIO()
        frontmatter.dump(post, buf, sort_keys=False)

        with open(path, "w") as fp:
            fp.write(buf.getvalue().decode("utf-8"))


if __name__ == "__main__":
    typer.run(main)
