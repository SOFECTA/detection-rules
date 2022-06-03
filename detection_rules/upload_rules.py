#!/usr/bin/env python

import requests
import pytoml
import click
import os
import logging
from uuid import uuid4


def create_rules(url, createbody, user, password):
    logging.info("create_rules")

    resp = requests.post(
        url="https://{}/api/detection_engine/rules/_bulk_create".format(url),
        json=createbody,
        headers={"Content-Type": "application/json", "kbn-xsrf": uuid4()},
        auth=(user, password),
        verify=False,
    )
    logging.info("Create rules: " + str(resp.status_code) + " Reason: " + resp.reason)
    for response in resp.json():
        failure = False
        try:
            if response["statusCode"] in range(400, 599):
                response["statusCode"]
                print(resp.json())
                print(
                    "====================================================================="
                )
                print(createbody)
                failure = True
            if failure:
                print(response)
                raise ValueError("Failed to create rule")
        except Exception as err:
            print("Exception: {}".format(err))
            print(response)
            raise ValueError("Failed to create rule")


@click.command()
@click.option("--url", help="Kibana host", prompt=True)
@click.option(
    "--rules_directory",
    default="rules/",
    help="Directory with rules",
    show_default=True,
)
@click.option(
    "--prefix", default=None, help="Prefix to filter rules", show_default=True
)
@click.option("--user", prompt=True, help="Kibana User")
@click.option("--password", prompt=True, hide_input=True, help="Kibana Password")
@click.option(
    "--loglevel",
    default="WARNING",
    help="Log level",
    show_default=True,
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
)
def get_rules(url, rules_directory, prefix, user, password, loglevel):
    print(url)
    logging.basicConfig(
        level=loglevel,
        format="%(asctime)s rulemanager %(levelname)s: %(message)s",
    )
    logging.info("URL: " + url)
    logging.info("User: " + user)
    if prefix:
        logging.info("Prefix: " + prefix)
    logging.info("Rule directory: " + rules_directory)

    rules = [rules_directory]
    # Get all the custom rules; aka those prefixed with your custom prefix
    logging.info("Get all the custom rules; aka those prefixed with your custom prefix")
    for root, dirs, files in os.walk(rules_directory):
        files = [fi for fi in files if fi.endswith(".toml")]
        for file in files:
            if prefix:
                if file.startswith(prefix):
                    rules.append(os.path.join(root, file))
            else:
                rules.append(os.path.join(root, file))

    # read in toml
    logging.info("read in toml")
    toml_rules = []
    for rulefile in rules:
        try:
            with open(rulefile, "r") as f:
                rule = f.read()
                t_rule = pytoml.loads(rule)
                customers = t_rule.get("metadata", {}).get("customers")
                for customer in customers:
                    if customer in url:
                        logging.debug("Found customer")
                        t_rule["rule"]["enabled"] = True
                toml_rules.append(t_rule)
        except Exception as err:
            print("Failed to parse {} with error: {}".format(rulefile, err))
            pass

    updatebody = []
    for r in toml_rules:
        rule = r["rule"]
        if "rule_id" not in rule:
            continue
        else:
            updatebody.append(rule)

    # bulk request to update
    logging.info("bulk request to update")
    resp = requests.put(
        url="{}/api/detection_engine/rules/_bulk_update".format(url),
        json=updatebody,
        headers={"Content-Type": "application/json", "kbn-xsrf": str(uuid4())},
        auth=(user, password),
        verify=True,
    )
    response = resp.json()

    logging.info("Update rules: " + str(resp.status_code) + " Reason: " + resp.reason)
    if "error" in response:
        print(response["message"])
        exit(1)

    createbody = []

    for rule_resp in resp.json():
        try:
            if "error" in rule_resp and "not found" in rule_resp["error"]["message"]:
                print(rule_resp["error"]["message"])
                # find rule in body and create the rule
                for r in updatebody:
                    if r["rule_id"] in rule_resp["error"]["message"]:
                        createbody.append(r)
        except TypeError:
            print(rule_resp)

    if createbody == []:
        created = True
    else:
        created = False

    while not created:
        try:
            create_rules(url, createbody, user, password)
        except Exception:
            pass
        else:
            created = True
        created = True


if __name__ == "__main__":
    get_rules(auto_envvar_prefix="kibana")
